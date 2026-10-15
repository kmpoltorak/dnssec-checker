package checker

import (
	"strings"
	"testing"

	"github.com/kmpoltorak/dnssec-checker/internal/dnstest"
	"github.com/miekg/dns"
)

// wantLookups checks type:result of every lookup.
func wantLookups(t *testing.T, rep *Report, want ...string) {
	t.Helper()
	var got []string
	for _, l := range rep.Lookups {
		got = append(got, l.Type+":"+l.Result)
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("lookups = %v, want %v\n%+v", got, want, rep.Lookups)
	}
}

func lookupDetail(rep *Report, typ string) string {
	for _, l := range rep.Lookups {
		if l.Type == typ {
			return l.Detail
		}
	}
	return ""
}

// negative builds a reply with rcode and, in authority, the signed SOA of z and the
// signed records rrs.
func negative(t *testing.T, z *dnstest.Zone, rcode int, rrs ...dns.RR) dnstest.Reply {
	ns := z.Signed(t, z.SOA(t))
	for _, rr := range rrs {
		ns = append(ns, z.Signed(t, rr)...)
	}
	return dnstest.Reply{Rcode: rcode, Ns: ns}
}

// setAll installs r for every query type used for name.
func setAll(srv *dnstest.Server, name string, r dnstest.Reply) {
	for _, qt := range []uint16{dns.TypeSOA, dns.TypeDS, dns.TypeA, dns.TypeAAAA} {
		srv.Set(name, qt, r)
	}
}

func TestLookups(t *testing.T) {
	t.Run("apex A and AAAA NODATA with an escaped NSEC next name", func(t *testing.T) {
		f := chain(t)
		rep := f.run(t, zone)
		wantStatus(t, rep, Secure)
		wantLookups(t, rep, "A:ok", "AAAA:ok")
		if !strings.Contains(lookupDetail(rep, "AAAA"), "no AAAA records, proven by a signed NSEC") {
			t.Errorf("AAAA detail %q", lookupDetail(rep, "AAAA"))
		}
	})
	t.Run("host inside the zone", func(t *testing.T) {
		f := chain(t)
		f.srv.Host(t, f.example, "www.example.com.")
		rep := f.run(t, "www.example.com")
		wantStatus(t, rep, Secure)
		wantLookups(t, rep, "A:ok", "AAAA:ok")
	})
	t.Run("NXDOMAIN proven by NSEC", func(t *testing.T) {
		f := chain(t)
		nsec := dnstest.RR(t, "example.com. 3600 IN NSEC www.example.com. A NS SOA RRSIG NSEC DNSKEY")
		setAll(f.srv, "nope.example.com.", negative(t, f.example, dns.RcodeNameError, nsec))
		rep := f.run(t, "nope.example.com")
		wantStatus(t, rep, Secure)
		wantLookups(t, rep, "A:ok", "AAAA:ok")
		if !strings.Contains(lookupDetail(rep, "A"), "does not exist (NXDOMAIN), proven by a signed NSEC") || *rep.NameExists {
			t.Errorf("detail %q, exists %v", lookupDetail(rep, "A"), *rep.NameExists)
		}
	})
	t.Run("NXDOMAIN proven by NSEC3", func(t *testing.T) {
		f := chain(t)
		ce := nsec3(zone, hashOf(zone), succ(hashOf(zone)), 0, dns.TypeNS, dns.TypeSOA)
		cover := nsec3(zone, "00000000000000000000000000000000", maxHash, 0, dns.TypeA)
		setAll(f.srv, "nope.example.com.", negative(t, f.example, dns.RcodeNameError, ce, cover))
		rep := f.run(t, "nope.example.com")
		wantStatus(t, rep, Secure)
		wantLookups(t, rep, "A:ok", "AAAA:ok")
	})
	t.Run("NXDOMAIN under NSEC3 opt-out", func(t *testing.T) {
		f := chain(t)
		ce := nsec3(zone, hashOf(zone), succ(hashOf(zone)), 0, dns.TypeNS, dns.TypeSOA)
		cover := nsec3(zone, "00000000000000000000000000000000", maxHash, 1)
		setAll(f.srv, "nope.example.com.", negative(t, f.example, dns.RcodeNameError, ce, cover))
		rep := f.run(t, "nope.example.com")
		wantStatus(t, rep, Insecure)
	})
	t.Run("NXDOMAIN without proof", func(t *testing.T) {
		f := chain(t)
		nsec := dnstest.RR(t, "example.com. 3600 IN NSEC www.example.com. A NS SOA RRSIG NSEC DNSKEY")
		setAll(f.srv, "nope.example.com.", negative(t, f.example, dns.RcodeNameError, nsec))
		f.srv.Set("nope.example.com.", dns.TypeA, negative(t, f.example, dns.RcodeNameError))
		rep := f.run(t, "nope.example.com")
		wantStatus(t, rep, Bogus)
		wantLookups(t, rep, "A:fail", "AAAA:ok")
	})
	t.Run("NXDOMAIN while a wildcard exists", func(t *testing.T) {
		f := chain(t)
		apex := dnstest.RR(t, "example.com. 3600 IN NSEC *.example.com. A NS SOA RRSIG NSEC DNSKEY")
		wild := dnstest.RR(t, "*.example.com. 3600 IN NSEC www.example.com. A RRSIG NSEC")
		setAll(f.srv, "nope.example.com.", negative(t, f.example, dns.RcodeSuccess, wild)) // DS: wildcard NODATA
		f.srv.Set("nope.example.com.", dns.TypeA, negative(t, f.example, dns.RcodeNameError, apex, wild))
		rep := f.run(t, "nope.example.com")
		wantStatus(t, rep, Bogus)
		wantLookups(t, rep, "A:fail", "AAAA:ok")
	})
	t.Run("NODATA without proof", func(t *testing.T) {
		f := chain(t)
		f.srv.Set(zone, dns.TypeAAAA, negative(t, f.example, dns.RcodeSuccess))
		rep := f.run(t, zone)
		wantStatus(t, rep, Bogus)
		wantLookups(t, rep, "A:ok", "AAAA:fail")
	})
	t.Run("NODATA proof that lists the type", func(t *testing.T) {
		f := chain(t)
		nsec := dnstest.RR(t, "example.com. 3600 IN NSEC \\000.example.com. A NS SOA AAAA RRSIG NSEC DNSKEY")
		f.srv.Set(zone, dns.TypeAAAA, negative(t, f.example, dns.RcodeSuccess, nsec))
		wantStatus(t, f.run(t, zone), Bogus)
	})
}

func TestBadAnswerSignature(t *testing.T) {
	// The A set was signed with two addresses but only one is passed on, as a filtering
	// resolver might do.
	setup := func(t *testing.T) fixture {
		f := chain(t)
		two := []dns.RR{dnstest.RR(t, "example.com. 3600 IN A 192.0.2.1"), dnstest.RR(t, "example.com. 3600 IN A 192.0.2.2")}
		signed := f.example.Signed(t, two...)
		f.srv.SetCD(zone, dns.TypeA, dnstest.Reply{Answer: []dns.RR{two[0], signed[2]}})
		return f
	}
	t.Run("resolver also rejects it", func(t *testing.T) {
		f := setup(t)
		f.srv.Set(zone, dns.TypeA, dnstest.Reply{Rcode: dns.RcodeServerFailure})
		rep := f.run(t, zone)
		wantStatus(t, rep, Bogus)
		wantLookups(t, rep, "A:fail", "AAAA:ok")
	})
	t.Run("resolver calls it valid", func(t *testing.T) {
		f := setup(t)
		f.srv.Set(zone, dns.TypeA, dnstest.Reply{AD: true, Answer: []dns.RR{dnstest.RR(t, "example.com. 3600 IN A 192.0.2.1")}})
		rep := f.run(t, zone)
		wantStatus(t, rep, Indeterminate)
		if !strings.Contains(rep.Summary, "changes answers") {
			t.Errorf("summary %q", rep.Summary)
		}
	})
}

func TestWildcard(t *testing.T) {
	setup := func(t *testing.T, proof bool) fixture {
		f := chain(t)
		wild := dnstest.RR(t, "*.example.com. 3600 IN A 192.0.2.9")
		signed := f.example.Signed(t, wild)
		a := dns.Copy(signed[0])
		a.Header().Name = "a.example.com."
		sig := dns.Copy(signed[1])
		sig.Header().Name = "a.example.com."
		nsec := dnstest.RR(t, "*.example.com. 3600 IN NSEC www.example.com. A RRSIG NSEC")
		reply := dnstest.Reply{Answer: []dns.RR{a, sig}}
		if proof {
			reply.Ns = f.example.Signed(t, nsec)
		}
		f.srv.Set("a.example.com.", dns.TypeA, reply)
		nodata := negative(t, f.example, dns.RcodeSuccess, nsec) // wildcard NODATA
		for _, qt := range []uint16{dns.TypeAAAA, dns.TypeDS, dns.TypeSOA} {
			f.srv.Set("a.example.com.", qt, nodata)
		}
		return f
	}
	t.Run("with proof", func(t *testing.T) {
		rep := setup(t, true).run(t, "a.example.com")
		wantStatus(t, rep, Secure)
		wantLookups(t, rep, "A:ok", "AAAA:ok")
		if !strings.Contains(lookupDetail(rep, "A"), "expanded from the wildcard *.example.com.") {
			t.Errorf("detail %q", lookupDetail(rep, "A"))
		}
	})
	t.Run("without proof", func(t *testing.T) {
		rep := setup(t, false).run(t, "a.example.com")
		wantStatus(t, rep, Bogus)
		wantLookups(t, rep, "A:fail", "AAAA:ok")
	})
}

func TestAliasAcrossZones(t *testing.T) {
	cname := func(t *testing.T, f fixture, target string, signed bool) {
		c := dnstest.RR(t, "www.example.com. 300 IN CNAME "+target)
		ans := []dns.RR{c}
		if signed {
			ans = f.example.Signed(t, c)
		}
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			f.srv.Set("www.example.com.", qt, dnstest.Reply{Answer: ans})
		}
		f.srv.Set("www.example.com.", dns.TypeSOA, dnstest.Reply{Answer: ans})
		nsec := dnstest.RR(t, "www.example.com. 3600 IN NSEC \\000.www.example.com. CNAME RRSIG NSEC")
		f.srv.Set("www.example.com.", dns.TypeDS, negative(t, f.example, dns.RcodeSuccess, nsec))
	}
	t.Run("to a signed zone", func(t *testing.T) {
		f := chain(t)
		net := dnstest.NewZone(t, "net.", now, 257)
		exnet := dnstest.NewZone(t, "example.net.", now, 257, 256)
		f.srv.Serve(t, net)
		f.srv.Serve(t, exnet)
		f.srv.Delegate(t, f.root, net)
		f.srv.Delegate(t, net, exnet)
		f.srv.Host(t, exnet, "www.example.net.")
		cname(t, f, "www.example.net.", true)
		// The answers carry the whole chain, as a resolver sends it.
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			c := dnstest.RR(t, "www.example.com. 300 IN CNAME www.example.net.")
			target := f.srv.Get("www.example.net.", qt)
			target.Answer = append(f.example.Signed(t, c), target.Answer...)
			f.srv.Set("www.example.com.", qt, target)
		}
		rep := f.run(t, "www.example.com")
		wantStatus(t, rep, Secure)
		wantLookups(t, rep, "A:ok", "AAAA:ok")
		if !strings.Contains(lookupDetail(rep, "A"), "followed CNAME to www.example.net.") {
			t.Errorf("detail %q", lookupDetail(rep, "A"))
		}
	})
	t.Run("to an unsigned zone", func(t *testing.T) {
		f := chain(t)
		f.srv.NoDS(t, f.root, "org.", "NS RRSIG NSEC")
		cname(t, f, "www.example.org.", true)
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			r := f.srv.Get("www.example.com.", qt)
			r.Answer = append(r.Answer, dnstest.RR(t, "www.example.org. 300 IN "+dns.TypeToString[qt]+" "+map[uint16]string{dns.TypeA: "192.0.2.7", dns.TypeAAAA: "2001:db8::7"}[qt]))
			f.srv.Set("www.example.com.", qt, r)
		}
		rep := f.run(t, "www.example.com")
		wantStatus(t, rep, Insecure)
		if !strings.Contains(rep.Summary, "www.example.org. is in an unsigned zone (no DS for org.)") {
			t.Errorf("summary %q", rep.Summary)
		}
		if rep.Resolver.Agrees == nil || !*rep.Resolver.Agrees || len(rep.Warnings) != 0 {
			t.Errorf("signed SOA agrees despite unsigned alias target: resolver %+v, warnings %v", rep.Resolver, rep.Warnings)
		}
		f.srv.Set("www.example.com.", dns.TypeA, dnstest.Reply{Rcode: dns.RcodeServerFailure})
		rep = f.run(t, "www.example.com")
		wantStatus(t, rep, Indeterminate)
		wantLookups(t, rep, "A:error", "AAAA:insecure")
	})
	t.Run("unsigned CNAME", func(t *testing.T) {
		f := chain(t)
		cname(t, f, "www.example.net.", false)
		wantStatus(t, f.run(t, "www.example.com"), Bogus)
	})
	t.Run("CNAME synthesized from a signed DNAME", func(t *testing.T) {
		f := chain(t)
		f.srv.Host(t, f.example, "www.example.com.")
		dname := f.example.Signed(t, dnstest.RR(t, "old.example.com. 300 IN DNAME example.com."))
		synth := dnstest.RR(t, "www.old.example.com. 300 IN CNAME www.example.com.")
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeSOA} {
			r := f.srv.Get("www.example.com.", qt)
			r.Answer = append(append(append([]dns.RR{}, dname...), synth), r.Answer...)
			f.srv.Set("www.old.example.com.", qt, r)
		}
		nsec := dnstest.RR(t, "old.example.com. 3600 IN NSEC \\000.old.example.com. DNAME RRSIG NSEC")
		for _, qt := range []uint16{dns.TypeDS, dns.TypeSOA} {
			f.srv.Set("old.example.com.", qt, negative(t, f.example, dns.RcodeSuccess, nsec))
		}
		rep := f.run(t, "www.old.example.com")
		wantStatus(t, rep, Secure)
		wantLookups(t, rep, "A:ok", "AAAA:ok")
		if !strings.Contains(lookupDetail(rep, "A"), "followed DNAME old.example.com. to www.example.com.") {
			t.Errorf("detail %q", lookupDetail(rep, "A"))
		}
	})
}

func TestLookupErrorIsIndeterminate(t *testing.T) {
	for i, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		for _, tt := range []struct {
			name  string
			reply dnstest.Reply
		}{
			{"timeout", dnstest.Reply{Drop: -1}},
			{"SERVFAIL", dnstest.Reply{Rcode: dns.RcodeServerFailure}},
			{"REFUSED", dnstest.Reply{Rcode: dns.RcodeRefused}},
		} {
			t.Run(dns.TypeToString[qt]+"/"+tt.name, func(t *testing.T) {
				f := chain(t)
				f.srv.Set(zone, qt, tt.reply)
				rep := f.run(t, zone)
				wantStatus(t, rep, Indeterminate)
				want := []string{"A:ok", "AAAA:ok"}
				want[i] = dns.TypeToString[qt] + ":error"
				wantLookups(t, rep, want...)
				wantChain(t, rep, ".:ok", "com.:ok", "example.com.:ok", "example.com.:ok")
				if !strings.Contains(rep.Summary, "could not be checked") || !strings.Contains(rep.Summary, dns.TypeToString[qt]+" answer") {
					t.Errorf("summary %q", rep.Summary)
				}
				if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], dns.TypeToString[qt]+" records") {
					t.Errorf("warnings %v", rep.Warnings)
				}
				if len(rep.Errors) == 0 {
					t.Error("missing query error")
				}
			})
		}
	}
}

func TestLookupFailureWithIncompleteAnswer(t *testing.T) {
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		t.Run(dns.TypeToString[qt], func(t *testing.T) {
			f := chain(t)
			f.srv.Set(zone, dns.TypeA, dnstest.Reply{Rcode: dns.RcodeServerFailure})
			f.srv.Set(zone, dns.TypeAAAA, dnstest.Reply{Rcode: dns.RcodeServerFailure})
			// The other answer is unavailable; this one has no signed NODATA proof.
			f.srv.Set(zone, qt, negative(t, f.example, dns.RcodeSuccess))
			rep := f.run(t, zone)
			wantStatus(t, rep, Bogus)
			if !strings.Contains(rep.Summary, dns.TypeToString[qt]+" answer") {
				t.Errorf("summary %q", rep.Summary)
			}
		})
	}
}

func TestBothLookupsIncomplete(t *testing.T) {
	f := chain(t)
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		f.srv.Set(zone, qt, dnstest.Reply{Rcode: dns.RcodeServerFailure})
	}
	rep := f.run(t, zone)
	wantStatus(t, rep, Indeterminate)
	wantLookups(t, rep, "A:error", "AAAA:error")
	if len(rep.Warnings) != 2 {
		t.Errorf("warnings %v", rep.Warnings)
	}
}

func TestNSEC3IterationLimit(t *testing.T) {
	f := chain(t)
	f.srv.ServeUnsigned(t, zone)
	n := nsec3("com.", hashOf(zone), succ(hashOf(zone)), 0, dns.TypeNS).(*dns.NSEC3)
	n.Iterations = 200
	n.Hdr.Name = strings.ToLower(dns.HashName(zone, dns.SHA1, 200, "")) + ".com."
	n.NextDomain = succ(dns.HashName(zone, dns.SHA1, 200, ""))
	f.srv.Set(zone, dns.TypeDS, dnstest.Reply{Ns: f.com.Signed(t, n)})
	rep := f.run(t, zone)
	wantStatus(t, rep, Insecure)
	if !strings.Contains(lastDetail(rep), "200 iterations, above the RFC 9276 limit of 150") {
		t.Errorf("detail %q", lastDetail(rep))
	}
}
