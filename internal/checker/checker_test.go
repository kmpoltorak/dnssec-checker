package checker

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kmpoltorak/dnssec-checker/internal/dnstest"
	"github.com/miekg/dns"
)

var now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

const zone = "example.com."

type fixture struct {
	srv                *dnstest.Server
	root, com, example *dnstest.Zone
}

// chain serves the signed chain . -> com. -> example.com.
func chain(t *testing.T) fixture {
	srv := dnstest.Start(t)
	root, com, example := dnstest.Chain(t, srv, now)
	return fixture{srv, root, com, example}
}

func (f fixture) config() Config {
	return Config{
		Resolver: f.srv.Addr, Timeout: 200 * time.Millisecond, WarnExpiry: 168 * time.Hour,
		Now: func() time.Time { return now }, Anchors: f.root.Anchor(),
	}
}

func (f fixture) run(t *testing.T, domain string) *Report {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rep, err := Run(ctx, f.config(), domain)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func wantStatus(t *testing.T, rep *Report, want Status) {
	t.Helper()
	if rep.Status != want {
		t.Errorf("status = %s, want %s: %s\nchain %+v\nerrors %v", rep.Status, want, rep.Summary, rep.Chain, rep.Errors)
	}
	if rep.DNSSEC != statuses[want].verdict {
		t.Errorf("dnssec = %q", rep.DNSSEC)
	}
}

// wantChain checks zone:result of every step.
func wantChain(t *testing.T, rep *Report, want ...string) {
	t.Helper()
	var got []string
	for _, s := range rep.Chain {
		got = append(got, s.Zone+":"+s.Result)
	}
	if !slices.Equal(got, want) {
		t.Errorf("chain = %v, want %v", got, want)
	}
}

func lastDetail(rep *Report) string {
	if len(rep.Chain) == 0 {
		return ""
	}
	return rep.Chain[len(rep.Chain)-1].Detail
}

func TestSecure(t *testing.T) {
	f := chain(t)
	rep := f.run(t, "Example.COM")
	wantStatus(t, rep, Secure)
	wantChain(t, rep, ".:ok", "com.:ok", "example.com.:ok", "example.com.:ok")
	if *rep.Zone != zone || !*rep.NameExists || rep.Resolver.Agrees == nil || !*rep.Resolver.Agrees {
		t.Errorf("zone %v, exists %v, agrees %v", *rep.Zone, *rep.NameExists, rep.Resolver.Agrees)
	}
	ev := strings.Join(rep.Chain[2].Records, "\n")
	for _, want := range []string{
		"example.com. DS ", "RRSIG DS 13 by com.",
		fmt.Sprintf("(key tag %d, KSK)", f.example.Keys[0].KeyTag()), "RRSIG DNSKEY 13 by example.com.",
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence lacks %q:\n%s", want, ev)
		}
	}
	if len(rep.Warnings) != 0 || len(rep.Errors) != 0 {
		t.Errorf("warnings %v, errors %v", rep.Warnings, rep.Errors)
	}
}

func TestNameInZone(t *testing.T) {
	t.Run("NODATA below the apex", func(t *testing.T) {
		f := chain(t)
		f.srv.Set("www.example.com.", dns.TypeSOA, dnstest.Reply{Ns: f.example.Signed(t, f.example.SOA(t))})
		rep := f.run(t, "www.example.com")
		wantStatus(t, rep, Secure)
		if *rep.Zone != zone || !*rep.NameExists {
			t.Errorf("zone %v, exists %v", *rep.Zone, *rep.NameExists)
		}
	})
	t.Run("NXDOMAIN", func(t *testing.T) {
		f := chain(t)
		f.srv.Set("nope.example.com.", dns.TypeSOA, dnstest.Reply{Rcode: dns.RcodeNameError, Ns: f.example.Signed(t, f.example.SOA(t))})
		rep := f.run(t, "nope.example.com")
		wantStatus(t, rep, Secure) // the zone status is independent of the name
		if *rep.Zone != zone || *rep.NameExists {
			t.Errorf("zone %v, exists %v", *rep.Zone, *rep.NameExists)
		}
	})
	t.Run("no authority section, walks to the parent", func(t *testing.T) {
		f := chain(t)
		f.srv.Set("a.b.example.com.", dns.TypeSOA, dnstest.Reply{})
		f.srv.Set("b.example.com.", dns.TypeSOA, dnstest.Reply{})
		rep := f.run(t, "a.b.example.com")
		wantStatus(t, rep, Secure)
		if *rep.Zone != zone {
			t.Errorf("zone %v", *rep.Zone)
		}
	})
	t.Run("signed delegated subdomain", func(t *testing.T) {
		f := chain(t)
		sub := dnstest.NewZone(t, "sub.example.com.", now, 257)
		f.srv.Serve(t, sub)
		f.srv.Delegate(t, f.example, sub)
		rep := f.run(t, "sub.example.com")
		wantStatus(t, rep, Secure)
		wantChain(t, rep, ".:ok", "com.:ok", "example.com.:ok", "sub.example.com.:ok", "sub.example.com.:ok")
	})
	t.Run("labels that are not delegations are skipped", func(t *testing.T) {
		f := chain(t)
		sub := dnstest.NewZone(t, "a.b.example.com.", now, 257)
		f.srv.Serve(t, sub)
		f.srv.Delegate(t, f.example, sub)
		f.srv.NoDS(t, f.example, "b.example.com.", "A RRSIG NSEC")
		rep := f.run(t, "a.b.example.com")
		wantStatus(t, rep, Secure)
		wantChain(t, rep, ".:ok", "com.:ok", "example.com.:ok", "a.b.example.com.:ok", "a.b.example.com.:ok")
	})
}

func TestInsecure(t *testing.T) {
	t.Run("NSEC at the delegation", func(t *testing.T) {
		f := chain(t)
		f.srv.ServeUnsigned(t, zone)
		f.srv.NoDS(t, f.com, zone, "NS RRSIG NSEC")
		rep := f.run(t, zone)
		wantStatus(t, rep, Insecure)
		wantChain(t, rep, ".:ok", "com.:ok", "example.com.:insecure")
		if !strings.Contains(strings.Join(rep.Chain[2].Records, "\n"), "example.com. NSEC zz.example.com. NS RRSIG NSEC") {
			t.Errorf("evidence %v", rep.Chain[2].Records)
		}
		if rep.Resolver.Agrees == nil || !*rep.Resolver.Agrees {
			t.Errorf("resolver answered AD=0 and should agree: %+v", rep.Resolver)
		}
	})
	t.Run("NSEC3 at the delegation", func(t *testing.T) {
		f := chain(t)
		f.srv.ServeUnsigned(t, zone)
		match := nsec3("com.", hashOf(zone), succ(hashOf(zone)), 0, dns.TypeNS)
		f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Ns: f.com.Signed(t, match)})
		rep := f.run(t, zone)
		wantStatus(t, rep, Insecure)
		if !strings.Contains(lastDetail(rep), "NSEC3 record") {
			t.Errorf("detail %q", lastDetail(rep))
		}
	})
	t.Run("NSEC3 opt-out", func(t *testing.T) {
		f := chain(t)
		f.srv.ServeUnsigned(t, zone)
		ce := nsec3("com.", hashOf("com."), succ(hashOf("com.")), 0, dns.TypeNS, dns.TypeSOA)
		cover := nsec3("com.", "00000000000000000000000000000000", maxHash, 1, dns.TypeNS)
		f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Ns: append(f.com.Signed(t, ce), f.com.Signed(t, cover)...)})
		rep := f.run(t, zone)
		wantStatus(t, rep, Insecure)
		if !strings.Contains(lastDetail(rep), "opt-out") {
			t.Errorf("detail %q", lastDetail(rep))
		}
	})
	t.Run("zone below an unsigned zone", func(t *testing.T) {
		f := chain(t)
		f.srv.ServeUnsigned(t, zone)
		f.srv.NoDS(t, f.com, zone, "NS RRSIG NSEC")
		f.srv.ServeUnsigned(t, "sub.example.com.")
		rep := f.run(t, "sub.example.com")
		wantStatus(t, rep, Insecure)
		wantChain(t, rep, ".:ok", "com.:ok", "example.com.:insecure")
		if !strings.Contains(rep.Summary, "below example.com.") {
			t.Errorf("summary %q", rep.Summary)
		}
	})
	t.Run("only unsupported algorithm", func(t *testing.T) {
		f := chain(t)
		ds := f.example.DS(0)
		ds.Algorithm = dns.ED448
		f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Answer: f.com.Signed(t, ds)})
		rep := f.run(t, zone)
		wantStatus(t, rep, Insecure)
		wantChain(t, rep, ".:ok", "com.:ok", "example.com.:insecure")
	})
	t.Run("only unsupported digest", func(t *testing.T) {
		f := chain(t)
		ds := f.example.DS(0)
		ds.DigestType = dns.GOST94
		f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Answer: f.com.Signed(t, ds)})
		wantStatus(t, f.run(t, zone), Insecure)
	})
}

func TestBogus(t *testing.T) {
	day := 24 * time.Hour
	tests := []struct {
		name   string
		break_ func(t *testing.T, f fixture)
		at     string // zone of the failing step
		why    string // part of the step detail
	}{
		{"DS digest does not match", func(t *testing.T, f fixture) {
			ds := f.example.DS(0)
			ds.Digest = strings.Repeat("00", 32) // same key tag and algorithm
			f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Answer: f.com.Signed(t, ds)})
		}, zone, "no DNSKEY matches the DS"},
		{"DS for a key that is not published", func(t *testing.T, f fixture) {
			other := dnstest.NewZone(t, zone, now, 257)
			f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Answer: f.com.Signed(t, other.DS(0))})
		}, zone, "no DNSKEY matches the DS"},
		{"DNSKEY missing", func(t *testing.T, f fixture) {
			f.srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{Ns: f.example.Signed(t, f.example.SOA(t))})
		}, zone, "publishes no DNSKEY"},
		{"DNSKEY set signed only by a key without DS", func(t *testing.T, f fixture) {
			keys := f.example.KeySet()
			f.srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{Answer: f.example.Signed(t, keys...)})
		}, zone, "not validly signed by the key the DS points to"},
		{"DNSKEY signature expired", func(t *testing.T, f fixture) {
			keys := f.example.KeySet()
			f.srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{Answer: append(keys, f.example.Sign(t, 0, keys, now.Add(-30*day), now.Add(-day)))})
		}, zone, "is valid only from"},
		{"SOA signature corrupted", func(t *testing.T, f fixture) {
			set := f.example.Signed(t, f.example.SOA(t))
			sig := set[1].(*dns.RRSIG)
			b, _ := base64.StdEncoding.DecodeString(sig.Signature)
			b[0] ^= 0xff
			sig.Signature = base64.StdEncoding.EncodeToString(b)
			f.srv.Set(zone, dns.TypeSOA, dnstest.Reply{Answer: set})
		}, zone, "does not verify"},
		{"SOA signature expired", func(t *testing.T, f fixture) {
			soa := []dns.RR{f.example.SOA(t)}
			f.srv.Set(zone, dns.TypeSOA, dnstest.Reply{Answer: append(soa, f.example.Sign(t, 1, soa, now.Add(-30*day), now.Add(-day)))})
		}, zone, "is valid only from"},
		{"SOA signature not yet valid", func(t *testing.T, f fixture) {
			soa := []dns.RR{f.example.SOA(t)}
			f.srv.Set(zone, dns.TypeSOA, dnstest.Reply{Answer: append(soa, f.example.Sign(t, 1, soa, now.Add(day), now.Add(30*day)))})
		}, zone, "is valid only from"},
		{"SOA not signed", func(t *testing.T, f fixture) {
			f.srv.Set(zone, dns.TypeSOA, dnstest.Reply{Answer: []dns.RR{f.example.SOA(t)}})
		}, zone, "no RRSIG covers the SOA"},
		{"DS not signed", func(t *testing.T, f fixture) {
			f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Answer: []dns.RR{f.example.DS(0)}})
		}, zone, "no RRSIG covers the DS"},
		{"DS signed by the child instead of the parent", func(t *testing.T, f fixture) {
			f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Answer: f.example.Signed(t, f.example.DS(0))})
		}, zone, "signed by example.com. instead of com."},
		{"no DS and no proof", func(t *testing.T, f fixture) {
			f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Ns: f.com.Signed(t, f.com.SOA(t))})
		}, zone, "no valid signed proof"},
		{"proof says DS exists", func(t *testing.T, f fixture) {
			f.srv.NoDS(t, f.com, zone, "NS DS RRSIG NSEC")
		}, zone, "no valid signed proof"},
		{"unsigned proof", func(t *testing.T, f fixture) {
			nsec := dnstest.RR(t, "example.com. 3600 IN NSEC zz.example.com. NS RRSIG NSEC")
			f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Ns: []dns.RR{nsec}})
		}, zone, "no valid signed proof"},
		{"proof signed by the child", func(t *testing.T, f fixture) {
			nsec := dnstest.RR(t, "example.com. 3600 IN NSEC zz.example.com. NS RRSIG NSEC")
			f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Ns: f.example.Signed(t, nsec)})
		}, zone, "no valid signed proof"},
		{"NSEC3 without opt-out does not prove an unsigned delegation", func(t *testing.T, f fixture) {
			ce := nsec3("com.", hashOf("com."), succ(hashOf("com.")), 0, dns.TypeNS, dns.TypeSOA)
			cover := nsec3("com.", "00000000000000000000000000000000", maxHash, 0, dns.TypeNS)
			f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Ns: append(f.com.Signed(t, ce), f.com.Signed(t, cover)...)})
		}, zone, "no valid signed proof"},
		{"parent proves the zone is not a delegation", func(t *testing.T, f fixture) {
			f.srv.NoDS(t, f.com, zone, "A RRSIG NSEC")
		}, zone, "is not a delegation"},
		{"wrong trust anchor", func(t *testing.T, f fixture) {
			other := dnstest.NewZone(t, ".", now, 257)
			f.root.Keys = other.Keys // changes Anchor()
		}, ".", "no DNSKEY matches the trust anchor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := chain(t)
			tt.break_(t, f)
			rep := f.run(t, zone)
			wantStatus(t, rep, Bogus)
			s := rep.Chain[len(rep.Chain)-1]
			if s.Zone != tt.at || s.Result != StepFail || !strings.Contains(s.Detail, tt.why) {
				t.Errorf("last step %+v, want a failure at %s mentioning %q", s, tt.at, tt.why)
			}
		})
	}
}

func TestRolloverWithOneGoodSignature(t *testing.T) {
	f := chain(t)
	z := dnstest.NewZone(t, zone, now, 257, 257, 256) // new KSK, old KSK, ZSK
	f.srv.Serve(t, z)
	keys := z.KeySet()
	expired := z.Sign(t, 1, keys, now.Add(-60*24*time.Hour), now.Add(-time.Hour))
	good := z.Sign(t, 0, keys, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	f.srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{Answer: append(keys, expired, good)})
	stale := z.DS(1)
	stale.Digest = strings.Repeat("ab", 32)
	f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Answer: f.com.Signed(t, stale, z.DS(0))})
	wantStatus(t, f.run(t, zone), Secure)
}

func TestKeyTagCollision(t *testing.T) {
	f := chain(t)
	real := f.example.Keys[0]
	fake := &dns.DNSKEY{Hdr: real.Hdr, Flags: 257, Protocol: 3, Algorithm: real.Algorithm}
	b := make([]byte, 64)
	for fake.KeyTag() != real.KeyTag() {
		rand.Read(b)
		fake.PublicKey = base64.StdEncoding.EncodeToString(b)
	}
	keys := append([]dns.RR{fake}, f.example.KeySet()...) // the colliding key is tried first
	f.srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{Answer: append(keys, f.example.Sign(t, 0, keys, now.Add(-time.Hour), now.Add(time.Hour*720)))})
	wantStatus(t, f.run(t, zone), Secure)
}

func TestMixedSupportedAndUnsupportedDS(t *testing.T) {
	f := chain(t)
	gost := f.example.DS(0)
	gost.DigestType = dns.GOST94
	f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Answer: f.com.Signed(t, gost, f.example.DS(0))})
	wantStatus(t, f.run(t, zone), Secure)
}

func TestResolver(t *testing.T) {
	t.Run("strips RRSIG", func(t *testing.T) {
		f := chain(t)
		f.srv.Set(".", dns.TypeDNSKEY, dnstest.Reply{Answer: f.root.KeySet()})
		rep := f.run(t, zone)
		wantStatus(t, rep, Indeterminate)
		if !strings.Contains(rep.Summary, "does not pass DNSSEC records") {
			t.Errorf("summary %q", rep.Summary)
		}
	})
	t.Run("own validation disagrees, local result wins", func(t *testing.T) {
		f := chain(t)
		f.srv.SetCD(zone, dns.TypeSOA, dnstest.Reply{Answer: f.example.Signed(t, f.example.SOA(t))})
		f.srv.Set(zone, dns.TypeSOA, dnstest.Reply{Rcode: dns.RcodeServerFailure, EDE: []uint16{dns.ExtendedErrorCodeDNSBogus}})
		rep := f.run(t, zone)
		wantStatus(t, rep, Secure)
		if rep.Resolver.Agrees == nil || *rep.Resolver.Agrees || len(rep.Warnings) != 1 || rep.Resolver.Response.EDE[0].Code != 6 {
			t.Errorf("resolver %+v, warnings %v", rep.Resolver, rep.Warnings)
		}
	})
	t.Run("data queries use CD=1", func(t *testing.T) {
		f := chain(t)
		f.run(t, zone)
		if f.srv.Hits("udp", zone, dns.TypeDNSKEY, true) != 1 || f.srv.Hits("udp", zone, dns.TypeDNSKEY, false) != 0 {
			t.Error("DNSKEY was not queried with CD=1 only")
		}
	})
}

func TestAliases(t *testing.T) {
	t.Run("alias to another zone", func(t *testing.T) {
		f := chain(t)
		f.srv.Set("www.example.com.", dns.TypeSOA, dnstest.Reply{
			Answer: []dns.RR{dnstest.RR(t, "www.example.com. 300 IN CNAME www.example.net.")},
			Ns:     []dns.RR{dnstest.RR(t, "example.net. 900 IN SOA ns1.example.net. h.example.net. 1 1 1 1 1")},
		})
		rep := f.run(t, "www.example.com")
		wantStatus(t, rep, Secure)
		if *rep.Zone != zone || !slices.Equal(rep.AliasChain, []string{"www.example.net."}) || !*rep.NameExists {
			t.Errorf("zone %v, alias %v", *rep.Zone, rep.AliasChain)
		}
	})
	t.Run("alias loop", func(t *testing.T) {
		f := chain(t)
		f.srv.Set("a.example.com.", dns.TypeSOA, dnstest.Reply{Answer: []dns.RR{
			dnstest.RR(t, "a.example.com. 300 IN CNAME b.example.com."),
			dnstest.RR(t, "b.example.com. 300 IN CNAME a.example.com."),
		}})
		rep := f.run(t, "a.example.com")
		if *rep.Zone != zone || len(rep.AliasChain) != 1 || !slices.ContainsFunc(rep.Warnings, func(w string) bool { return strings.Contains(w, "alias loop") }) {
			t.Errorf("zone %v, alias %v, warnings %v", *rep.Zone, rep.AliasChain, rep.Warnings)
		}
	})
	t.Run("long alias chain is cut at the limit", func(t *testing.T) {
		f := chain(t)
		var c []dns.RR
		for i := range 12 {
			c = append(c, dnstest.RR(t, fmt.Sprintf("a%d.example.com. 300 IN CNAME a%d.example.com.", i, i+1)))
		}
		f.srv.Set("a0.example.com.", dns.TypeSOA, dnstest.Reply{Answer: c})
		if rep := f.run(t, "a0.example.com"); len(rep.AliasChain) != maxAliases {
			t.Errorf("alias chain %v", rep.AliasChain)
		}
	})
}

func TestFailuresKeepPartialReport(t *testing.T) {
	t.Run("REFUSED everywhere", func(t *testing.T) {
		f := fixture{srv: dnstest.Start(t), root: dnstest.NewZone(t, ".", now, 257)}
		rep := f.run(t, zone)
		wantStatus(t, rep, Indeterminate)
		if rep.Zone != nil || len(rep.Errors) == 0 {
			t.Errorf("zone %v, errors %v", rep.Zone, rep.Errors)
		}
	})
	t.Run("DS query times out", func(t *testing.T) {
		f := chain(t)
		f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Drop: -1})
		rep := f.run(t, zone)
		wantStatus(t, rep, Indeterminate) // a timeout must not look like a missing DS
		wantChain(t, rep, ".:ok", "com.:ok", "example.com.:error")
	})
	t.Run("SERVFAIL even with CD=1", func(t *testing.T) {
		f := chain(t)
		f.srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{Rcode: dns.RcodeServerFailure})
		rep := f.run(t, zone)
		wantStatus(t, rep, Indeterminate)
		wantChain(t, rep, ".:ok", "com.:ok", "example.com.:error")
	})
	t.Run("interrupted", func(t *testing.T) {
		f := chain(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		rep, _ := Run(ctx, f.config(), zone)
		wantStatus(t, rep, Indeterminate)
		if !slices.ContainsFunc(rep.Errors, func(e string) bool { return strings.Contains(e, "partial") }) {
			t.Errorf("errors %v", rep.Errors)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		f := chain(t)
		f.srv.Set(zone, dns.TypeSOA, dnstest.Reply{Drop: -1})
		cfg := f.config()
		cfg.Timeout = 5 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		start := time.Now()
		rep, _ := Run(ctx, cfg, zone)
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("run took %s", d)
		}
		wantStatus(t, rep, Indeterminate)
	})
	t.Run("query limit", func(t *testing.T) {
		f := chain(t)
		cfg := f.config()
		cfg.MaxQueries = 3
		rep, _ := Run(context.Background(), cfg, zone)
		wantStatus(t, rep, Indeterminate)
		if !slices.ContainsFunc(rep.Errors, func(e string) bool { return strings.Contains(e, "query limit") }) {
			t.Errorf("errors %v", rep.Errors)
		}
	})
}

func TestExpiryWarning(t *testing.T) {
	soaWith := func(t *testing.T, from, until time.Time) *Report {
		f := chain(t)
		soa := []dns.RR{f.example.SOA(t)}
		f.srv.Set(zone, dns.TypeSOA, dnstest.Reply{AD: true, Answer: append(soa, f.example.Sign(t, 1, soa, from, until))})
		return f.run(t, zone)
	}
	rep := soaWith(t, now.Add(-28*24*time.Hour), now.Add(48*time.Hour))
	wantStatus(t, rep, Secure) // a warning alone does not change the status
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "SOA signature of example.com.") {
		t.Errorf("warnings %v", rep.Warnings)
	}
	// An online signer issues short-lived signatures on every answer; no warning.
	if rep := soaWith(t, now.Add(-time.Hour), now.Add(24*time.Hour)); len(rep.Warnings) != 0 {
		t.Errorf("online signer: warnings %v", rep.Warnings)
	}
}

func TestDenyDS(t *testing.T) {
	z := dnstest.NewZone(t, zone, now, 257)
	keys := z.Keys
	msg := func(rrs ...dns.RR) *dns.Msg {
		m := new(dns.Msg)
		for _, rr := range rrs {
			m.Ns = append(m.Ns, z.Signed(t, rr)...)
		}
		return m
	}
	nsec := func(owner, next, types string) dns.RR {
		return dnstest.RR(t, owner+" 3600 IN NSEC "+next+" "+types)
	}
	tests := []struct {
		name string
		m    *dns.Msg
		want denial
	}{
		{"NSEC delegation without DS", msg(nsec("sub.example.com.", "z.example.com.", "NS RRSIG NSEC")), insecureDelegation},
		{"NSEC with DS bit", msg(nsec("sub.example.com.", "z.example.com.", "NS DS RRSIG NSEC")), noProof},
		{"NSEC without NS", msg(nsec("sub.example.com.", "z.example.com.", "A RRSIG NSEC")), notDelegation},
		{"NSEC with SOA comes from the child", msg(nsec("sub.example.com.", "z.example.com.", "NS SOA RRSIG NSEC")), noProof},
		{"empty non-terminal", msg(nsec("a.example.com.", "x.sub.example.com.", "A RRSIG NSEC")), notDelegation},
		{"NSEC that covers a different name", msg(nsec("x.example.com.", "z.example.com.", "A RRSIG NSEC")), noProof},
		{"NSEC owned after the name", msg(nsec("t.example.com.", "x.sub.example.com.", "A RRSIG NSEC")), noProof},
		{"NSEC3 match without DS", msg(nsec3(zone, hashOf("sub.example.com."), succ(hashOf("sub.example.com.")), 0, dns.TypeNS)), insecureDelegation},
		{"NSEC3 match with DS", msg(nsec3(zone, hashOf("sub.example.com."), succ(hashOf("sub.example.com.")), 0, dns.TypeNS, dns.TypeDS)), noProof},
		{"NSEC3 opt-out", msg(
			nsec3(zone, hashOf(zone), succ(hashOf(zone)), 0, dns.TypeNS, dns.TypeSOA),
			nsec3(zone, "00000000000000000000000000000000", maxHash, 1),
		), insecureDelegation},
		{"NSEC3 opt-out span without closest encloser", msg(nsec3(zone, "00000000000000000000000000000000", maxHash, 1)), noProof},
		{"nothing", new(dns.Msg), noProof},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _, _ := denyDS(tt.m, "sub.example.com.", zone, keys, now); got != tt.want {
				t.Errorf("denyDS = %d, want %d", got, tt.want)
			}
		})
	}
}

// succ returns the base32hex hash right after h, so that an NSEC3 record from h to succ(h)
// matches h and covers nothing else.
func succ(h string) string {
	const digits = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	i := strings.IndexByte(digits, h[len(h)-1])
	if i == len(digits)-1 {
		panic("hash ends in V; pick another test name")
	}
	return h[:len(h)-1] + string(digits[i+1])
}

// hashOf is the NSEC3 hash of name with SHA-1, no iterations and no salt.
func hashOf(name string) string { return dns.HashName(name, dns.SHA1, 0, "") }

const maxHash = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV"

// nsec3 builds an NSEC3 record of zone z. ownerHash and next are base32hex hashes; flags
// bit 1 is opt-out.
func nsec3(z, ownerHash, next string, flags uint8, types ...uint16) dns.RR {
	return &dns.NSEC3{
		Hdr:  dns.RR_Header{Name: strings.ToLower(ownerHash) + "." + z, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash: dns.SHA1, Flags: flags, HashLength: 20, NextDomain: next, TypeBitMap: types,
	}
}

func TestRunOverTLS(t *testing.T) {
	f := chain(t)
	addr, roots := f.srv.StartTLS(t)
	cfg := f.config()
	cfg.Resolver, cfg.TLSRoots = "tls://"+addr, roots
	rep, err := Run(context.Background(), cfg, zone)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, rep, Secure)
	if rep.Queries[0].Transport != "tls" || rep.Resolver.Address != "tls://"+addr {
		t.Errorf("transport %q, resolver %q", rep.Queries[0].Transport, rep.Resolver.Address)
	}
}
