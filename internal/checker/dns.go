package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	ednsSize   = 1232
	maxQueries = 128
)

// client sends DNSSEC-aware queries to one resolver. It is used sequentially by a single check.
type client struct {
	server     string      // host:port
	tls        *tls.Config // set for DNS over TLS
	timeout    time.Duration
	maxQueries int
	sent       int
}

// newClient builds a client for a resolver from ParseResolver. roots replaces the system
// certificate pool for DNS over TLS when set.
func newClient(resolver string, timeout time.Duration, max int, roots *x509.CertPool) *client {
	c := &client{server: resolver, timeout: timeout, maxQueries: max}
	if rest, ok := strings.CutPrefix(resolver, "tls://"); ok {
		addr, name, _ := strings.Cut(rest, "#")
		if name == "" {
			name, _, _ = net.SplitHostPort(addr)
		}
		c.server = addr
		c.tls = &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return c
}

var errQueryLimit = errors.New("query limit reached")

// query sends one question with EDNS0 (DO=1, RD=1). Over UDP it falls back to TCP when
// the reply is truncated. It retries once after a transport error. Every packet sent
// counts against the query limit.
func (c *client) query(ctx context.Context, name string, qtype uint16, cd bool) Query {
	q := Query{Name: name, Type: dns.TypeToString[qtype], CD: cd, Server: c.server}
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	m.CheckingDisabled = cd
	m.SetEdns0(ednsSize, true)

	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if c.tls != nil {
			q.Transport = "tls"
			q.msg, err = c.exchange(ctx, m, "tcp-tls")
		} else {
			q.Transport = "udp"
			q.msg, err = c.exchange(ctx, m, "udp")
			if err == nil && q.msg.Truncated {
				q.Transport = "tcp"
				q.msg, err = c.exchange(ctx, m, "tcp")
			}
		}
		if err == nil || errors.Is(err, errQueryLimit) || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		q.msg = nil
		q.Error = err.Error()
		return q
	}
	q.Response = summarize(q.msg)
	return q
}

func (c *client) exchange(ctx context.Context, m *dns.Msg, network string) (*dns.Msg, error) {
	if c.sent >= c.maxQueries {
		return nil, fmt.Errorf("%w (%d)", errQueryLimit, c.maxQueries)
	}
	c.sent++
	actx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	dc := &dns.Client{Net: network, Timeout: c.timeout, UDPSize: ednsSize, TLSConfig: c.tls}
	conn, err := dc.DialContext(actx, c.server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// miekg/dns honours only the context deadline; closing the connection makes an
	// interrupt take effect at once.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	r, _, err := dc.ExchangeWithConnContext(actx, m, conn)
	return r, err
}

func summarize(m *dns.Msg) *Response {
	r := &Response{Rcode: dns.RcodeToString[m.Rcode], AD: m.AuthenticatedData, EDE: []EDE{}}
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if e, ok := o.(*dns.EDNS0_EDE); ok {
				r.EDE = append(r.EDE, EDE{Code: e.InfoCode, Name: dns.ExtendedErrorCodeToString[e.InfoCode], Text: e.ExtraText})
			}
		}
	}
	return r
}

// ParseResolver accepts an IP address with an optional port ("192.0.2.1", "2001:db8::1",
// "192.0.2.1:53", "[2001:db8::1]:53"), or the same after "tls://" for DNS over TLS
// (port 853 by default). For TLS the certificate must be valid for the IP address, or for
// a name given after "#": "tls://192.0.2.1#dns.example.net". Host names are rejected.
func ParseResolver(s string) (string, error) {
	addr, name, port, hasName := s, "", uint16(53), false
	rest, isTLS := strings.CutPrefix(s, "tls://")
	if isTLS {
		addr, name, hasName = strings.Cut(rest, "#")
		port = 853
	}
	bad := fmt.Errorf("invalid resolver %q: want an IP address with an optional port, optionally after tls://", s)
	if hasName && name == "" {
		return "", bad
	}
	var ap netip.AddrPort
	if a, err := netip.ParseAddr(addr); err == nil {
		ap = netip.AddrPortFrom(a, port)
	} else if ap, err = netip.ParseAddrPort(addr); err != nil || ap.Port() == 0 {
		return "", bad
	}
	if !isTLS {
		return ap.String(), nil
	}
	out := "tls://" + ap.String()
	if name != "" {
		n, err := Normalize(name)
		if err != nil {
			return "", fmt.Errorf("invalid TLS name in resolver %q: %v", s, err)
		}
		out += "#" + strings.TrimSuffix(n, ".")
	}
	return out, nil
}

// SystemResolver returns the first name server from resolv.conf. Only one is used so that
// answers from different resolvers are never mixed.
func SystemResolver(path string) (string, error) {
	cfg, err := dns.ClientConfigFromFile(path)
	if err != nil || len(cfg.Servers) == 0 {
		return "", fmt.Errorf("no system resolver found in %s; use --resolver", path)
	}
	return ParseResolver(net.JoinHostPort(cfg.Servers[0], cfg.Port))
}
