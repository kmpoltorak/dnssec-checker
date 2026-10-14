package checker

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kmpoltorak/dnssec-checker/internal/dnstest"
	"github.com/miekg/dns"
)

var now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

const zone = "example.com."

func testConfig(srv *dnstest.Server, trusted bool) Config {
	return Config{
		Resolver: srv.Addr, Trusted: trusted, Timeout: 200 * time.Millisecond,
		WarnExpiry: 168 * time.Hour, Now: func() time.Time { return now },
	}
}

func runCheck(t *testing.T, cfg Config, domain string) *Report {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rep, err := Run(ctx, cfg, domain)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func result(rep *Report, id string) Result {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c.Result
		}
	}
	return "missing"
}

func wantChecks(t *testing.T, rep *Report, want map[string]Result) {
	t.Helper()
	for id, w := range want {
		if got := result(rep, id); got != w {
			t.Errorf("check %s = %s, want %s", id, got, w)
		}
	}
}

func wantStatus(t *testing.T, rep *Report, want Status) {
	t.Helper()
	if rep.Status != want {
		t.Errorf("status = %s, want %s (%s); checks %+v; errors %v", rep.Status, want, rep.Summary, rep.Checks, rep.Errors)
	}
}

// signed starts a resolver serving a signed example.com with a KSK and a ZSK.
func signed(t *testing.T, ad bool) (*dnstest.Server, *dnstest.Zone) {
	srv := dnstest.Start(t)
	z := dnstest.NewZone(t, zone, 257, 256)
	srv.Signed(t, z, now, ad)
	return srv, z
}

func allPass() map[string]Result {
	return map[string]Result{
		"resolver.validation": Pass, "ds.match": Pass, "dnskey.present": Pass,
		"dnskey.signatures": Pass, "soa.signatures": Pass, "signatures.expiry": Pass,
	}
}

func TestSecure(t *testing.T) {
	srv, _ := signed(t, true)
	rep := runCheck(t, testConfig(srv, true), "Example.COM")
	wantStatus(t, rep, Secure)
	wantChecks(t, rep, allPass())
	if *rep.Zone != zone || !*rep.NameExists || rep.ValidationMode != modeTrusted {
		t.Errorf("zone %v, exists %v, mode %s", *rep.Zone, *rep.NameExists, rep.ValidationMode)
	}
	if len(rep.Records.DS) != 1 || rep.Records.DS[0].Match != "match" || len(rep.Records.DNSKEY) != 2 || len(rep.Records.RRSIG) != 2 {
		t.Errorf("records %+v", rep.Records)
	}
	if len(rep.Errors) != 0 || len(rep.Warnings) != 0 {
		t.Errorf("errors %v, warnings %v", rep.Errors, rep.Warnings)
	}
}

func TestSecureNeedsTrust(t *testing.T) {
	srv, _ := signed(t, true)
	rep := runCheck(t, testConfig(srv, false), zone)
	wantStatus(t, rep, Indeterminate)
	want := allPass()
	want["resolver.validation"] = Unknown
	wantChecks(t, rep, want)
}

func TestSignedButNotAuthenticated(t *testing.T) {
	srv, _ := signed(t, false)
	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Indeterminate)
	wantChecks(t, rep, map[string]Result{"resolver.validation": Unknown, "ds.match": Pass})
}

func TestInsecure(t *testing.T) {
	srv := dnstest.Start(t)
	srv.Unsigned(t, zone, "com.", true)
	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Insecure)
	wantChecks(t, rep, map[string]Result{"ds.match": NA, "dnskey.present": NA, "dnskey.signatures": NA, "soa.signatures": NA})
	if !rep.Records.NSEC || rep.Records.DS == nil || len(rep.Records.DS) != 0 {
		t.Errorf("NSEC %t, DS %v", rep.Records.NSEC, rep.Records.DS)
	}
}

func TestMissingDSWithoutProof(t *testing.T) {
	t.Run("AD=0", func(t *testing.T) {
		srv := dnstest.Start(t)
		srv.Unsigned(t, zone, "com.", false)
		wantStatus(t, runCheck(t, testConfig(srv, true), zone), Indeterminate)
	})
	t.Run("empty answer without parent SOA", func(t *testing.T) {
		srv := dnstest.Start(t)
		srv.Unsigned(t, zone, "com.", true)
		srv.Set(zone, dns.TypeDS, dnstest.Reply{AD: true})
		wantStatus(t, runCheck(t, testConfig(srv, true), zone), Indeterminate)
	})
	t.Run("negative answer carrying the zone's own SOA", func(t *testing.T) {
		srv := dnstest.Start(t)
		srv.Unsigned(t, zone, "com.", true)
		srv.Set(zone, dns.TypeDS, dnstest.Reply{AD: true, Ns: []dns.RR{dnstest.ParentSOA(t, zone)}})
		wantStatus(t, runCheck(t, testConfig(srv, true), zone), Indeterminate)
	})
	t.Run("untrusted", func(t *testing.T) {
		srv := dnstest.Start(t)
		srv.Unsigned(t, zone, "com.", true)
		wantStatus(t, runCheck(t, testConfig(srv, false), zone), Indeterminate)
	})
}

func TestIslandOfTrust(t *testing.T) {
	srv, _ := signed(t, false)
	srv.Set(zone, dns.TypeDS, dnstest.Reply{AD: true, Ns: []dns.RR{dnstest.ParentSOA(t, "com.")}})
	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Insecure)
	if !slices.ContainsFunc(rep.Warnings, func(w string) bool { return strings.Contains(w, "island of trust") }) {
		t.Errorf("warnings %v", rep.Warnings)
	}
}

func TestDSMismatch(t *testing.T) {
	srv, z := signed(t, true)
	ds := z.DS(0)
	ds.Digest = strings.Repeat("00", 32) // same key tag and algorithm, wrong digest
	srv.Set(zone, dns.TypeDS, dnstest.Reply{AD: true, Answer: []dns.RR{ds}})
	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Indeterminate)
	wantChecks(t, rep, map[string]Result{"ds.match": Fail, "resolver.validation": Pass})
	if rep.Records.DS[0].Match != "no_match" {
		t.Errorf("DS %+v", rep.Records.DS)
	}
}

func TestDNSKEYMissing(t *testing.T) {
	srv, z := signed(t, true)
	srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{AD: true, Ns: []dns.RR{z.SOA(t)}})
	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Indeterminate)
	wantChecks(t, rep, map[string]Result{"dnskey.present": Fail, "ds.match": Fail, "soa.signatures": Unknown})
}

func TestSOASignatureProblems(t *testing.T) {
	day := 24 * time.Hour
	tests := []struct {
		name      string
		from, to  time.Time
		corrupt   bool
		wantTime  string
		wantCheck Result
	}{
		{"corrupted", now.Add(-day), now.Add(30 * day), true, "valid", Fail},
		{"expired", now.Add(-30 * day), now.Add(-day), false, "expired", Fail},
		{"not yet valid", now.Add(day), now.Add(30 * day), false, "not_yet_valid", Fail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, z := signed(t, true)
			soa := []dns.RR{z.SOA(t)}
			sig := z.Sign(t, 1, soa, tt.from, tt.to)
			if tt.corrupt {
				b, _ := base64.StdEncoding.DecodeString(sig.Signature)
				b[0] ^= 0xff
				sig.Signature = base64.StdEncoding.EncodeToString(b)
			}
			srv.Set(zone, dns.TypeSOA, dnstest.Reply{AD: true, Answer: append(soa, sig)})
			rep := runCheck(t, testConfig(srv, true), zone)
			wantStatus(t, rep, Indeterminate) // AD=1 contradicts the local result
			wantChecks(t, rep, map[string]Result{"soa.signatures": tt.wantCheck, "dnskey.signatures": Pass})
			i := slices.IndexFunc(rep.Records.RRSIG, func(s RRSIG) bool { return s.Covers == "SOA" })
			if s := rep.Records.RRSIG[i]; s.Time != tt.wantTime || (s.Signature == "valid") == tt.corrupt {
				t.Errorf("RRSIG %+v", s)
			}
		})
	}
}

func TestRolloverWithOneGoodSignature(t *testing.T) {
	srv := dnstest.Start(t)
	z := dnstest.NewZone(t, zone, 257, 257, 256) // new KSK, old KSK, ZSK
	srv.Signed(t, z, now, true)
	keys := z.KeySet()
	expired := z.Sign(t, 1, keys, now.Add(-60*24*time.Hour), now.Add(-time.Hour))
	good := z.Sign(t, 0, keys, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{AD: true, Answer: append(keys, expired, good)})
	stale := z.DS(1)
	stale.Digest = strings.Repeat("ab", 32)
	srv.Set(zone, dns.TypeDS, dnstest.Reply{AD: true, Answer: []dns.RR{stale, z.DS(0)}})

	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Secure)
	wantChecks(t, rep, allPass())
}

func TestDNSKEYSignedOnlyByKeyWithoutDS(t *testing.T) {
	srv := dnstest.Start(t)
	z := dnstest.NewZone(t, zone, 257, 256)
	srv.Signed(t, z, now, true)
	keys := z.KeySet()
	srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{AD: true, Answer: append(keys, z.Sign(t, 1, keys, now.Add(-time.Hour), now.Add(720*time.Hour)))})
	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Indeterminate)
	wantChecks(t, rep, map[string]Result{"ds.match": Pass, "dnskey.signatures": Fail})
}

func TestKeyTagCollision(t *testing.T) {
	srv := dnstest.Start(t)
	z := dnstest.NewZone(t, zone, 257)
	real := z.Keys[0]
	fake := &dns.DNSKEY{Hdr: real.Hdr, Flags: 257, Protocol: 3, Algorithm: real.Algorithm}
	b := make([]byte, 64)
	for fake.KeyTag() != real.KeyTag() {
		rand.Read(b)
		fake.PublicKey = base64.StdEncoding.EncodeToString(b)
	}
	z.Keys = []*dns.DNSKEY{fake, real} // the colliding key is tried first
	from, until := now.Add(-time.Hour), now.Add(720*time.Hour)
	soa, keys := []dns.RR{z.SOA(t)}, z.KeySet()
	srv.Set(zone, dns.TypeSOA, dnstest.Reply{AD: true, Answer: append(soa, z.Sign(t, 1, soa, from, until))})
	srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{AD: true, Answer: append(keys, z.Sign(t, 1, keys, from, until))})
	srv.Set(zone, dns.TypeNS, dnstest.Reply{AD: true, Answer: []dns.RR{z.NS(t)}})
	srv.Set(zone, dns.TypeDS, dnstest.Reply{AD: true, Answer: []dns.RR{z.DS(1)}})

	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Secure)
	wantChecks(t, rep, allPass())
}

func TestUnsupportedAlgorithmIsNotBogus(t *testing.T) {
	srv := dnstest.Start(t)
	z := &dnstest.Zone{Name: zone}
	key := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ED448,
		PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 57)),
	}
	sig := func(covered uint16) *dns.RRSIG {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: covered, Algorithm: dns.ED448, Labels: 2, OrigTtl: 3600, KeyTag: key.KeyTag(), SignerName: zone,
			Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(720 * time.Hour).Unix()),
			Signature: base64.StdEncoding.EncodeToString(make([]byte, 114)),
		}
	}
	srv.Set(zone, dns.TypeSOA, dnstest.Reply{Answer: []dns.RR{z.SOA(t), sig(dns.TypeSOA)}})
	srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{Answer: []dns.RR{key, sig(dns.TypeDNSKEY)}})
	srv.Set(zone, dns.TypeNS, dnstest.Reply{Answer: []dns.RR{z.NS(t)}})
	srv.Set(zone, dns.TypeDS, dnstest.Reply{AD: true, Answer: []dns.RR{key.ToDS(dns.SHA256)}})

	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Indeterminate)
	wantChecks(t, rep, map[string]Result{"ds.match": Pass, "dnskey.signatures": Unknown, "soa.signatures": Unknown})
	for _, s := range rep.Records.RRSIG {
		if s.Signature != "unsupported" {
			t.Errorf("RRSIG %+v", s)
		}
	}
}

func TestUnsupportedDigest(t *testing.T) {
	srv, z := signed(t, true)
	ds := z.DS(0)
	ds.DigestType = dns.GOST94
	srv.Set(zone, dns.TypeDS, dnstest.Reply{AD: true, Answer: []dns.RR{ds}})
	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Indeterminate)
	wantChecks(t, rep, map[string]Result{"ds.match": Unknown})
	if rep.Records.DS[0].Match != "unsupported_digest" {
		t.Errorf("DS %+v", rep.Records.DS)
	}
}

func TestSERVFAIL(t *testing.T) {
	tests := []struct {
		name    string
		ede     []uint16
		trusted bool
		want    Status
	}{
		{"DNSSEC Bogus EDE, trusted", []uint16{dns.ExtendedErrorCodeDNSBogus}, true, Bogus},
		{"Signature Expired EDE, trusted", []uint16{dns.ExtendedErrorCodeSignatureExpired}, true, Bogus},
		{"DNSSEC Bogus EDE, untrusted", []uint16{dns.ExtendedErrorCodeDNSBogus}, false, Indeterminate},
		{"no EDE", nil, true, Indeterminate},
		{"unrelated EDE", []uint16{dns.ExtendedErrorCodeNoReachableAuthority, dns.ExtendedErrorCodeNetworkError}, true, Indeterminate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, z := signed(t, true)
			soa := []dns.RR{z.SOA(t)}
			srv.Set(zone, dns.TypeSOA, dnstest.Reply{Rcode: dns.RcodeServerFailure, EDE: tt.ede})
			srv.SetCD(zone, dns.TypeSOA, dnstest.Reply{Answer: append(soa, z.Sign(t, 1, soa, now.Add(-time.Hour), now.Add(720*time.Hour)))})
			rep := runCheck(t, testConfig(srv, tt.trusted), zone)
			wantStatus(t, rep, tt.want)
			if rep.Zone == nil || *rep.Zone != zone {
				t.Errorf("zone %v", rep.Zone)
			}
			// The CD=1 answer is used for local diagnostics only.
			wantChecks(t, rep, map[string]Result{"soa.signatures": Pass})
			if !slices.ContainsFunc(rep.Queries, func(q Query) bool { return q.CD && q.Type == "SOA" }) {
				t.Error("no CD=1 query recorded")
			}
		})
	}
}

func TestCDAnswerDoesNotMakeSecure(t *testing.T) {
	srv, z := signed(t, true)
	from, until := now.Add(-time.Hour), now.Add(720*time.Hour)
	soa, keys := []dns.RR{z.SOA(t)}, z.KeySet()
	for qtype, ans := range map[uint16][]dns.RR{
		dns.TypeSOA:    append(soa, z.Sign(t, 1, soa, from, until)),
		dns.TypeDNSKEY: append(keys, z.Sign(t, 0, keys, from, until)),
	} {
		srv.Set(zone, qtype, dnstest.Reply{Rcode: dns.RcodeServerFailure})
		srv.SetCD(zone, qtype, dnstest.Reply{AD: true, Answer: ans})
	}
	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Indeterminate)
	wantChecks(t, rep, map[string]Result{"ds.match": Pass, "dnskey.signatures": Pass, "soa.signatures": Pass, "resolver.validation": Unknown})
}

func TestNameInZone(t *testing.T) {
	t.Run("NXDOMAIN", func(t *testing.T) {
		srv, z := signed(t, true)
		srv.Set("nope.example.com.", dns.TypeSOA, dnstest.Reply{Rcode: dns.RcodeNameError, AD: true, Ns: []dns.RR{
			z.SOA(t), dnstest.RR(t, "example.com. 3600 IN NSEC www.example.com. NS SOA RRSIG NSEC DNSKEY"),
		}})
		rep := runCheck(t, testConfig(srv, true), "nope.example.com")
		wantStatus(t, rep, Secure) // the zone status is independent of the name
		if rep.NameExists == nil || *rep.NameExists || *rep.Zone != zone || !rep.Records.NSEC {
			t.Errorf("exists %v, zone %v, nsec %t", rep.NameExists, *rep.Zone, rep.Records.NSEC)
		}
	})
	t.Run("NODATA below the apex", func(t *testing.T) {
		srv, z := signed(t, true)
		srv.Set("www.example.com.", dns.TypeSOA, dnstest.Reply{AD: true, Ns: []dns.RR{z.SOA(t)}})
		rep := runCheck(t, testConfig(srv, true), "www.example.com")
		wantStatus(t, rep, Secure)
		if !*rep.NameExists || *rep.Zone != zone {
			t.Errorf("exists %v, zone %v", *rep.NameExists, *rep.Zone)
		}
	})
	t.Run("no authority section, walks to the parent", func(t *testing.T) {
		srv, _ := signed(t, true)
		srv.Set("a.b.example.com.", dns.TypeSOA, dnstest.Reply{AD: true})
		srv.Set("b.example.com.", dns.TypeSOA, dnstest.Reply{AD: true})
		rep := runCheck(t, testConfig(srv, true), "a.b.example.com")
		if rep.Zone == nil || *rep.Zone != zone {
			t.Errorf("zone %v", rep.Zone)
		}
	})
	t.Run("delegated subdomain", func(t *testing.T) {
		srv, _ := signed(t, true)
		sub := dnstest.NewZone(t, "sub.example.com.", 257)
		srv.Signed(t, sub, now, true)
		rep := runCheck(t, testConfig(srv, true), "sub.example.com")
		wantStatus(t, rep, Secure)
		if *rep.Zone != "sub.example.com." {
			t.Errorf("zone %v", *rep.Zone)
		}
	})
}

func TestAliases(t *testing.T) {
	t.Run("alias to another zone", func(t *testing.T) {
		srv, _ := signed(t, true)
		srv.Set("www.example.com.", dns.TypeSOA, dnstest.Reply{AD: true,
			Answer: []dns.RR{dnstest.RR(t, "www.example.com. 300 IN CNAME www.example.net.")},
			Ns:     []dns.RR{dnstest.ParentSOA(t, "example.net.")},
		})
		rep := runCheck(t, testConfig(srv, true), "www.example.com")
		if *rep.Zone != zone || !slices.Equal(rep.Records.AliasChain, []string{"www.example.net."}) || !*rep.NameExists {
			t.Errorf("zone %v, alias %v", *rep.Zone, rep.Records.AliasChain)
		}
		wantStatus(t, rep, Secure)
	})
	t.Run("alias loop", func(t *testing.T) {
		srv, _ := signed(t, true)
		srv.Set("a.example.com.", dns.TypeSOA, dnstest.Reply{Answer: []dns.RR{
			dnstest.RR(t, "a.example.com. 300 IN CNAME b.example.com."),
			dnstest.RR(t, "b.example.com. 300 IN CNAME a.example.com."),
		}})
		rep := runCheck(t, testConfig(srv, true), "a.example.com")
		if *rep.Zone != zone || len(rep.Records.AliasChain) != 1 {
			t.Errorf("zone %v, alias %v", *rep.Zone, rep.Records.AliasChain)
		}
		if !slices.ContainsFunc(rep.Warnings, func(w string) bool { return strings.Contains(w, "alias loop") }) {
			t.Errorf("warnings %v", rep.Warnings)
		}
	})
	t.Run("long alias chain is cut at the limit", func(t *testing.T) {
		srv, _ := signed(t, true)
		var chain []dns.RR
		for i := 0; i < 12; i++ {
			chain = append(chain, dnstest.RR(t, string(rune('a'+i))+".example.com. 300 IN CNAME "+string(rune('a'+i+1))+".example.com."))
		}
		srv.Set("a.example.com.", dns.TypeSOA, dnstest.Reply{Answer: chain})
		rep := runCheck(t, testConfig(srv, true), "a.example.com")
		if len(rep.Records.AliasChain) != maxAliases {
			t.Errorf("alias chain %v", rep.Records.AliasChain)
		}
	})
}

func TestFailuresKeepPartialReport(t *testing.T) {
	t.Run("REFUSED everywhere", func(t *testing.T) {
		rep := runCheck(t, testConfig(dnstest.Start(t), true), zone)
		wantStatus(t, rep, Indeterminate)
		if rep.Zone != nil || len(rep.Errors) == 0 || len(rep.Queries) == 0 {
			t.Errorf("zone %v, errors %v", rep.Zone, rep.Errors)
		}
	})
	t.Run("DS query times out", func(t *testing.T) {
		srv, _ := signed(t, true)
		srv.Set(zone, dns.TypeDS, dnstest.Reply{Drop: -1})
		rep := runCheck(t, testConfig(srv, true), zone)
		wantStatus(t, rep, Indeterminate)
		// A timeout must not look like a missing DS.
		wantChecks(t, rep, map[string]Result{"ds.match": Unknown, "dnskey.signatures": Pass})
		if rep.Records.DS != nil || len(rep.Errors) != 1 || len(rep.Records.DNSKEY) != 2 {
			t.Errorf("DS %v, errors %v", rep.Records.DS, rep.Errors)
		}
	})
	t.Run("DNSKEY query times out", func(t *testing.T) {
		srv, _ := signed(t, true)
		srv.Set(zone, dns.TypeDNSKEY, dnstest.Reply{Drop: -1})
		rep := runCheck(t, testConfig(srv, true), zone)
		wantStatus(t, rep, Indeterminate)
		wantChecks(t, rep, map[string]Result{"dnskey.present": Unknown, "ds.match": Unknown})
	})
	t.Run("interrupted", func(t *testing.T) {
		srv, _ := signed(t, true)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		rep, err := Run(ctx, testConfig(srv, true), zone)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus(t, rep, Indeterminate)
		if !slices.ContainsFunc(rep.Errors, func(e string) bool { return strings.Contains(e, "partial") }) {
			t.Errorf("errors %v", rep.Errors)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		srv := dnstest.Start(t)
		srv.Set(zone, dns.TypeSOA, dnstest.Reply{Drop: -1})
		cfg := testConfig(srv, true)
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
		srv, _ := signed(t, true)
		cfg := testConfig(srv, true)
		cfg.MaxQueries = 3
		rep := runCheck(t, cfg, zone)
		wantStatus(t, rep, Indeterminate)
		if len(rep.Queries) != 5 || !strings.Contains(rep.Errors[len(rep.Errors)-1], "query limit") {
			t.Errorf("queries %d, errors %v", len(rep.Queries), rep.Errors)
		}
	})
}

func TestExpiryWarning(t *testing.T) {
	srv, z := signed(t, true)
	soa := []dns.RR{z.SOA(t)}
	soon := z.Sign(t, 1, soa, now.Add(-time.Hour), now.Add(48*time.Hour))
	srv.Set(zone, dns.TypeSOA, dnstest.Reply{AD: true, Answer: append(soa, soon)})
	rep := runCheck(t, testConfig(srv, true), zone)
	wantStatus(t, rep, Secure) // a warning alone does not change the status
	wantChecks(t, rep, map[string]Result{"signatures.expiry": Warn, "soa.signatures": Pass})
	if len(rep.Warnings) != 1 {
		t.Errorf("warnings %v", rep.Warnings)
	}

	// A later valid signature covers for the one that expires soon.
	later := z.Sign(t, 1, soa, now.Add(-time.Hour), now.Add(720*time.Hour))
	srv.Set(zone, dns.TypeSOA, dnstest.Reply{AD: true, Answer: append(soa, soon, later)})
	rep = runCheck(t, testConfig(srv, true), zone)
	wantChecks(t, rep, map[string]Result{"signatures.expiry": Pass})
}

func TestRunRejectsInvalidDomain(t *testing.T) {
	if _, err := Run(context.Background(), Config{}, "http://example.com"); err == nil {
		t.Error("want error")
	}
}
