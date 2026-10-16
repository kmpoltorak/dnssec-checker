package checker

import (
	"strings"
	"testing"

	"github.com/kmpoltorak/dnssec-checker/internal/dnstest"
	"github.com/miekg/dns"
)

func TestWildcardCloserEncloser(t *testing.T) {
	for _, proof := range []string{
		"b.example.com. 3600 IN NSEC c.b.example.com. TXT RRSIG NSEC",
		"a.example.com. 3600 IN NSEC c.b.example.com. TXT RRSIG NSEC",
	} {
		for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
			t.Run(dns.TypeToString[typ]+"/"+strings.Fields(proof)[0], func(t *testing.T) {
				f := chain(t)
				name := "a.b.example.com."
				nsec := dnstest.RR(t, proof)
				setAll(f.srv, name, negative(t, f.example, dns.RcodeNameError, nsec))
				f.srv.Set("b.example.com.", dns.TypeDS, negative(t, f.example, dns.RcodeSuccess, nsec))
				data := map[uint16]string{dns.TypeA: "A 192.0.2.1", dns.TypeAAAA: "AAAA 2001:db8::1", dns.TypeCNAME: "CNAME www.example.com."}
				ans := f.example.Signed(t, dnstest.RR(t, "*.example.com. 3600 IN "+data[typ]))
				for _, rr := range ans {
					rr.Header().Name = name
				}
				queryType := typ
				if typ == dns.TypeCNAME {
					queryType = dns.TypeA
					f.srv.Host(t, f.example, "www.example.com.")
					ans = append(ans, f.srv.Get("www.example.com.", queryType).Answer...)
				}
				f.srv.SetCD(name, queryType, dnstest.Reply{Answer: ans, Ns: f.example.Signed(t, nsec)})
				f.srv.Set(name, queryType, dnstest.Reply{Rcode: dns.RcodeServerFailure})
				rep := f.run(t, name)
				wantStatus(t, rep, Bogus)
				if !strings.Contains(lookupDetail(rep, dns.TypeToString[queryType]), "no valid signed proof") {
					t.Errorf("lookups %+v", rep.Lookups)
				}
			})
		}
	}
}

func TestWildcardNSECEncloserProof(t *testing.T) {
	for _, tt := range []struct {
		name, ce, owner, next string
		want                  bool
	}{
		{"zone wildcard", zone, "*.example.com.", "www.example.com.", true},
		{"case-insensitive parent", "EXAMPLE.COM.", "*.example.com.", "www.example.com.", true},
		{"nested wildcard", "b.example.com.", "*.b.example.com.", "c.b.example.com.", true},
		{"closer owner", zone, "b.example.com.", "c.b.example.com.", false},
		{"closer next name", zone, "a.example.com.", "c.b.example.com.", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n := dnstest.RR(t, tt.owner+" 3600 IN NSEC "+tt.next+" TXT RRSIG NSEC").(*dns.NSEC)
			p := &proofs{zone: zone, nsec: []*dns.NSEC{n}}
			if got := p.noExactMatch("a.b.example.com.", tt.ce); got != tt.want {
				t.Errorf("noExactMatch = %t, want %t", got, tt.want)
			}
		})
	}
}
