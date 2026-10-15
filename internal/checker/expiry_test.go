package checker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kmpoltorak/dnssec-checker/internal/dnstest"
	"github.com/miekg/dns"
)

func TestNameSignatureExpiry(t *testing.T) {
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeDNAME, dns.TypeDS} {
		t.Run(dns.TypeToString[qt], func(t *testing.T) {
			f := chain(t)
			sign := func(z *dnstest.Zone, rr dns.RR) []dns.RR {
				return []dns.RR{rr, z.Sign(t, len(z.Keys)-1, []dns.RR{rr}, now.Add(-28*24*time.Hour), now.Add(48*time.Hour))}
			}
			name, owner := zone, zone
			switch qt {
			case dns.TypeA, dns.TypeAAAA:
				addr := "192.0.2.1"
				if qt == dns.TypeAAAA {
					addr = "2001:db8::1"
				}
				f.srv.Set(zone, qt, dnstest.Reply{AD: true, Answer: sign(f.example, dnstest.RR(t, zone+" 3600 IN "+dns.TypeToString[qt]+" "+addr))})
			case dns.TypeDS:
				f.srv.Set(zone, qt, dnstest.Reply{AD: true, Answer: sign(f.com, f.example.DS(0))})
			case dns.TypeCNAME, dns.TypeDNAME:
				f.srv.Host(t, f.example, "www.example.com.")
				name, owner = "alias.example.com.", "alias.example.com."
				if qt == dns.TypeDNAME {
					name, owner = "www.old.example.com.", "old.example.com."
					f.srv.Set(owner, dns.TypeSOA, dnstest.Reply{Ns: f.example.Signed(t, f.example.SOA(t))})
				}
				f.srv.NoDS(t, f.example, owner, dns.TypeToString[qt]+" RRSIG NSEC")
				alias := sign(f.example, dnstest.RR(t, owner+" 300 IN CNAME www.example.com."))
				if qt == dns.TypeDNAME {
					alias = append(sign(f.example, dnstest.RR(t, owner+" 300 IN DNAME example.com.")), dnstest.RR(t, name+" 300 IN CNAME www.example.com."))
				}
				for _, typ := range []uint16{dns.TypeSOA, dns.TypeA, dns.TypeAAAA} {
					reply := f.srv.Get("www.example.com.", typ)
					reply.Answer = append(append([]dns.RR{}, alias...), reply.Answer...)
					f.srv.Set(name, typ, reply)
				}
			}
			rep := f.run(t, name)
			wantStatus(t, rep, Secure)
			want := "the " + dns.TypeToString[qt] + " signature of " + owner
			if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], want) {
				t.Errorf("warnings %v, want one warning containing %q", rep.Warnings, want)
			}
		})
	}
}

func TestNameSignatureExpiryPolicy(t *testing.T) {
	for _, tt := range []struct {
		name              string
		from, until, warn time.Duration
		status            Status
	}{
		{"online signer", -time.Hour, 24 * time.Hour, 168 * time.Hour, Secure},
		{"disabled", -28 * 24 * time.Hour, 48 * time.Hour, 0, Secure},
		{"outside warning window", -28 * 24 * time.Hour, 48 * time.Hour, 24 * time.Hour, Secure},
		{"expired", -28 * 24 * time.Hour, -time.Hour, 168 * time.Hour, Bogus},
		{"not yet valid", time.Hour, 30 * 24 * time.Hour, 168 * time.Hour, Bogus},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := chain(t)
			a := dnstest.RR(t, "example.com. 3600 IN A 192.0.2.1")
			sig := f.example.Sign(t, 1, []dns.RR{a}, now.Add(tt.from), now.Add(tt.until))
			f.srv.Set(zone, dns.TypeA, dnstest.Reply{Answer: []dns.RR{a, sig}})
			cfg := f.config()
			cfg.WarnExpiry = tt.warn
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			rep, err := Run(ctx, cfg, zone)
			if err != nil {
				t.Fatal(err)
			}
			wantStatus(t, rep, tt.status)
			for _, w := range rep.Warnings {
				if strings.Contains(w, "A signature of") {
					t.Errorf("unexpected expiry warning: %s", w)
				}
			}
		})
	}
}
