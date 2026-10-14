// Package dnstest runs a local fake recursive resolver on UDP and TCP with synthetic zones
// signed by keys generated in the test. It is used by tests only.
package dnstest

import (
	"crypto"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Reply is what the fake resolver returns for one question.
type Reply struct {
	Rcode      int
	AD         bool
	EDE        []uint16
	Answer, Ns []dns.RR
	Truncate   bool // UDP replies are empty with TC=1, TCP replies are complete
	Drop       int  // drop this many UDP queries without replying; negative drops all
}

type Server struct {
	Addr    string
	mu      sync.Mutex
	replies map[string]*Reply
	hits    map[string]int
}

func key(name string, qtype uint16, cd bool) string {
	k := dns.CanonicalName(name) + " " + dns.TypeToString[qtype]
	if cd {
		k += " CD"
	}
	return k
}

// Start listens on UDP and TCP on the same random 127.0.0.1 port.
func Start(t testing.TB) *Server {
	t.Helper()
	s := &Server{replies: map[string]*Reply{}, hits: map[string]int{}}
	var pc net.PacketConn
	var l net.Listener
	for i := 0; ; i++ {
		var err error
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if l, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		pc.Close()
		if i == 10 {
			t.Fatal(err)
		}
	}
	s.Addr = pc.LocalAddr().String()
	var wg sync.WaitGroup
	wg.Add(2)
	udp := &dns.Server{PacketConn: pc, Handler: s, NotifyStartedFunc: wg.Done}
	tcp := &dns.Server{Listener: l, Handler: s, NotifyStartedFunc: wg.Done}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	wg.Wait()
	t.Cleanup(func() {
		udp.Shutdown()
		tcp.Shutdown()
	})
	return s
}

// Set installs the reply for CD=0 queries; CD=1 queries get it too unless SetCD is used.
func (s *Server) Set(name string, qtype uint16, r Reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replies[key(name, qtype, false)] = &r
}

func (s *Server) SetCD(name string, qtype uint16, r Reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replies[key(name, qtype, true)] = &r
}

// Hits returns how many packets arrived over network ("udp" or "tcp") for a question.
func (s *Server) Hits(network, name string, qtype uint16, cd bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[network+" "+key(name, qtype, cd)]
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	q := req.Question[0]
	network := w.LocalAddr().Network()
	s.mu.Lock()
	k := key(q.Name, q.Qtype, req.CheckingDisabled)
	s.hits[network+" "+k]++
	r, ok := s.replies[k]
	if !ok && req.CheckingDisabled {
		r, ok = s.replies[key(q.Name, q.Qtype, false)]
	}
	drop := false
	if ok && network == "udp" && r.Drop != 0 {
		drop = true
		if r.Drop > 0 {
			r.Drop--
		}
	}
	var reply Reply
	if ok {
		reply = *r
	}
	s.mu.Unlock()
	if drop {
		return
	}

	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	if !ok {
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}
	m.Rcode, m.AuthenticatedData = reply.Rcode, reply.AD
	m.Answer, m.Ns = reply.Answer, reply.Ns
	opt := m.SetEdns0(1232, true).IsEdns0()
	for _, c := range reply.EDE {
		opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: c})
	}
	if network == "udp" && reply.Truncate {
		m.Truncated, m.Answer, m.Ns = true, nil, nil
	}
	w.WriteMsg(m)
}

// RR parses one record in zone file syntax.
func RR(t testing.TB, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// Zone is a synthetic zone with ECDSA P-256 keys. Its signatures are valid from From to
// Until.
type Zone struct {
	Name        string
	Keys        []*dns.DNSKEY // may be reordered or extended with keys that cannot sign
	From, Until time.Time
	signers     map[*dns.DNSKEY]crypto.Signer
}

// NewZone generates one key per flags value (257 = KSK, 256 = ZSK). Signatures are valid
// from a day before now to 30 days after.
func NewZone(t testing.TB, name string, now time.Time, flags ...uint16) *Zone {
	t.Helper()
	z := &Zone{Name: name, From: now.Add(-24 * time.Hour), Until: now.Add(30 * 24 * time.Hour), signers: map[*dns.DNSKEY]crypto.Signer{}}
	for _, f := range flags {
		k := &dns.DNSKEY{
			Hdr:   dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags: f, Protocol: 3, Algorithm: dns.ECDSAP256SHA256,
		}
		p, err := k.Generate(256)
		if err != nil {
			t.Fatal(err)
		}
		z.Keys = append(z.Keys, k)
		z.signers[k] = p.(crypto.Signer)
	}
	return z
}

func (z *Zone) SOA(t testing.TB) dns.RR {
	return RR(t, z.Name+" 3600 IN SOA ns1.example.net. hostmaster.example.net. 1 7200 3600 1209600 3600")
}

func (z *Zone) NS(t testing.TB) dns.RR { return RR(t, z.Name+" 3600 IN NS ns1.example.net.") }

func (z *Zone) KeySet() []dns.RR {
	out := []dns.RR{}
	for _, k := range z.Keys {
		out = append(out, k)
	}
	return out
}

func (z *Zone) DS(i int) *dns.DS { return z.Keys[i].ToDS(dns.SHA256) }

// Anchor returns the DS of key 0, for use as a trust anchor of a test root zone.
func (z *Zone) Anchor() []*dns.DS { return []*dns.DS{z.DS(0)} }

// Sign signs set with key i for the period [from, until].
func (z *Zone) Sign(t testing.TB, i int, set []dns.RR, from, until time.Time) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:    dns.RR_Header{Name: set[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		KeyTag: z.Keys[i].KeyTag(), SignerName: z.Name, Algorithm: z.Keys[i].Algorithm,
		Inception: uint32(from.Unix()), Expiration: uint32(until.Unix()),
	}
	if err := sig.Sign(z.signers[z.Keys[i]], set); err != nil {
		t.Fatal(err)
	}
	return sig
}

// Signed returns set followed by its RRSIG made with the zone's last key (the ZSK).
func (z *Zone) Signed(t testing.TB, set ...dns.RR) []dns.RR {
	return append(set, z.Sign(t, len(z.Keys)-1, set, z.From, z.Until))
}

// Serve installs the apex answers of z: DNSKEY signed by key 0, SOA and NS by the last
// key. AD=1 on all of them.
func (s *Server) Serve(t testing.TB, z *Zone) {
	keys := z.KeySet()
	s.Set(z.Name, dns.TypeSOA, Reply{AD: true, Answer: z.Signed(t, z.SOA(t))})
	s.Set(z.Name, dns.TypeDNSKEY, Reply{AD: true, Answer: append(keys, z.Sign(t, 0, keys, z.From, z.Until))})
	s.Set(z.Name, dns.TypeNS, Reply{AD: true, Answer: []dns.RR{z.NS(t)}})
}

// Delegate publishes in parent a DS for key 0 of child, signed by parent.
func (s *Server) Delegate(t testing.TB, parent, child *Zone) {
	s.Set(child.Name, dns.TypeDS, Reply{AD: true, Answer: parent.Signed(t, child.DS(0))})
}

// NoDS answers the DS query for name with NODATA from parent and a signed NSEC at name
// listing types.
func (s *Server) NoDS(t testing.TB, parent *Zone, name, types string) {
	nsec := RR(t, name+" 3600 IN NSEC zz."+name+" "+types)
	s.Set(name, dns.TypeDS, Reply{AD: true, Ns: append(parent.Signed(t, parent.SOA(t)), parent.Signed(t, nsec)...)})
}

// ServeUnsigned installs the apex answers of an unsigned zone.
func (s *Server) ServeUnsigned(t testing.TB, name string) {
	z := &Zone{Name: name}
	s.Set(name, dns.TypeSOA, Reply{Answer: []dns.RR{z.SOA(t)}})
	s.Set(name, dns.TypeDNSKEY, Reply{Ns: []dns.RR{z.SOA(t)}})
	s.Set(name, dns.TypeNS, Reply{Answer: []dns.RR{z.NS(t)}})
}

// Chain serves the signed chain . -> com. -> example.com. Pass root.Anchor() as the
// trust anchor.
func Chain(t testing.TB, s *Server, now time.Time) (root, com, example *Zone) {
	root = NewZone(t, ".", now, 257, 256)
	com = NewZone(t, "com.", now, 257, 256)
	example = NewZone(t, "example.com.", now, 257, 256)
	for _, z := range []*Zone{root, com, example} {
		s.Serve(t, z)
	}
	s.Delegate(t, root, com)
	s.Delegate(t, com, example)
	return root, com, example
}
