package checker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

const (
	ednsSize   = 1232
	maxQueries = 64
)

// client sends DNSSEC-aware queries to one resolver. It is used sequentially by a single check.
type client struct {
	server     string
	timeout    time.Duration
	maxQueries int
	sent       int
}

var errQueryLimit = errors.New("query limit reached")

// query sends one question with EDNS0 (DO=1, RD=1). It falls back to TCP when the UDP
// reply is truncated and retries once after a transport error. Every packet sent counts
// against the query limit.
func (c *client) query(ctx context.Context, name string, qtype uint16, cd bool) Query {
	q := Query{Name: name, Type: dns.TypeToString[qtype], CD: cd, Server: c.server, Transport: "udp"}
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	m.CheckingDisabled = cd
	m.SetEdns0(ednsSize, true)

	var err error
	for attempt := 0; attempt < 2; attempt++ {
		q.Transport = "udp"
		q.msg, err = c.exchange(ctx, m, "udp")
		if err == nil && q.msg.Truncated {
			q.Transport = "tcp"
			q.msg, err = c.exchange(ctx, m, "tcp")
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
	// ponytail: miekg/dns honours only the context deadline, not cancellation, so an
	// interrupt waits for at most one per-attempt timeout.
	actx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	dc := &dns.Client{Net: network, Timeout: c.timeout, UDPSize: ednsSize}
	r, _, err := dc.ExchangeContext(actx, m, c.server)
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
// "192.0.2.1:53", "[2001:db8::1]:53") and returns host:port. Host names are rejected.
func ParseResolver(s string) (string, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(a, 53).String(), nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil || ap.Port() == 0 {
		return "", fmt.Errorf("invalid resolver %q: want an IP address with an optional port", s)
	}
	return ap.String(), nil
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
