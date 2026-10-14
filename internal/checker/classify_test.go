package checker

import (
	"strings"
	"testing"
)

func reply(rcode string, ad bool, ede ...uint16) *Response {
	r := &Response{Rcode: rcode, AD: ad, EDE: []EDE{}}
	for _, c := range ede {
		r.EDE = append(r.EDE, EDE{Code: c})
	}
	return r
}

func TestClassify(t *testing.T) {
	secure := facts{
		trusted: true, delegation: true,
		soa: reply("NOERROR", true), dnskey: reply("NOERROR", true), ds: reply("NOERROR", true),
		dsMatch: Pass, dnskeySigs: Pass, soaSigs: Pass,
	}
	insecure := facts{
		trusted: true, delegation: true, dsNoData: true,
		soa: reply("NOERROR", false), dnskey: reply("NOERROR", false), ds: reply("NOERROR", true),
		dsMatch: NA, dnskeySigs: NA, soaSigs: NA,
	}
	with := func(f facts, change func(*facts)) facts { change(&f); return f }

	tests := []struct {
		name string
		f    facts
		want Status
	}{
		{"trusted AD=1 and local checks pass", secure, Secure},
		{"AD=1 from an untrusted resolver", with(secure, func(f *facts) { f.trusted = false }), Indeterminate},
		{"AD=0", with(secure, func(f *facts) { f.soa, f.dnskey = reply("NOERROR", false), reply("NOERROR", false) }), Indeterminate},
		{"AD=1 only for SOA", with(secure, func(f *facts) { f.dnskey = reply("NOERROR", false) }), Indeterminate},
		{"AD=1 with local DS mismatch", with(secure, func(f *facts) { f.dsMatch = Fail }), Indeterminate},
		{"AD=1 with unverifiable DNSKEY signature", with(secure, func(f *facts) { f.dnskeySigs = Unknown }), Indeterminate},
		{"AD=1 with bad SOA signature", with(secure, func(f *facts) { f.soaSigs = Fail }), Indeterminate},
		{"AD=1 with unsupported DS digest", with(secure, func(f *facts) { f.dsMatch = Unknown }), Indeterminate},
		{"root zone needs no DS", with(secure, func(f *facts) { f.root, f.ds, f.dsMatch = true, nil, NA }), Secure},
		{"missing DS reply", with(secure, func(f *facts) { f.ds = nil }), Indeterminate},
		{"missing SOA reply", with(secure, func(f *facts) { f.soa = nil }), Indeterminate},

		{"authenticated NODATA for DS", insecure, Insecure},
		{"NODATA for DS from an untrusted resolver", with(insecure, func(f *facts) { f.trusted = false }), Indeterminate},
		{"NODATA for DS with AD=0", with(insecure, func(f *facts) { f.ds = reply("NOERROR", false) }), Indeterminate},
		{"empty DS answer that is not NODATA", with(insecure, func(f *facts) { f.dsNoData = false }), Indeterminate},
		{"apex is not a delegation", with(insecure, func(f *facts) { f.delegation = false }), Indeterminate},
		{"no DS but SOA authenticated", with(insecure, func(f *facts) { f.soa = reply("NOERROR", true) }), Indeterminate},
		{"root zone is never insecure", with(insecure, func(f *facts) { f.root = true }), Indeterminate},

		{"SERVFAIL with EDE 6 from trusted resolver", with(secure, func(f *facts) { f.soa = reply("SERVFAIL", false, 6) }), Bogus},
		{"SERVFAIL with EDE 7 on DS", with(secure, func(f *facts) { f.ds = reply("SERVFAIL", false, 7) }), Bogus},
		{"SERVFAIL with EDE 9", with(secure, func(f *facts) { f.dnskey = reply("SERVFAIL", false, 9) }), Bogus},
		{"SERVFAIL with EDE 6 from untrusted resolver", with(secure, func(f *facts) { f.trusted = false; f.soa = reply("SERVFAIL", false, 6) }), Indeterminate},
		{"SERVFAIL without EDE", with(secure, func(f *facts) { f.soa = reply("SERVFAIL", false) }), Indeterminate},
		{"SERVFAIL with EDE 5 (DNSSEC Indeterminate)", with(secure, func(f *facts) { f.soa = reply("SERVFAIL", false, 5) }), Indeterminate},
		{"SERVFAIL with EDE 1 (unsupported algorithm)", with(secure, func(f *facts) { f.soa = reply("SERVFAIL", false, 1) }), Indeterminate},
		{"SERVFAIL with EDE 22 (no reachable authority)", with(secure, func(f *facts) { f.soa = reply("SERVFAIL", false, 22) }), Indeterminate},
		{"bogus EDE without SERVFAIL", with(secure, func(f *facts) { f.soa = reply("NOERROR", true, 6) }), Secure},
		{"local failures never make BOGUS", with(secure, func(f *facts) {
			f.soa, f.dnskey = reply("NOERROR", false), reply("NOERROR", false)
			f.dsMatch, f.dnskeySigs, f.soaSigs = Fail, Fail, Fail
		}), Indeterminate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, why := classify(tt.f)
			if got != tt.want {
				t.Errorf("status = %s, want %s (%s)", got, tt.want, why)
			}
			if why == "" {
				t.Error("empty reason")
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	ok := map[string]string{
		" Example.COM ":           "example.com.",
		"example.com.":            "example.com.",
		"www.example.com":         "www.example.com.",
		"bücher.example":          "xn--bcher-kva.example.",
		"BÜCHER.example":          "xn--bcher-kva.example.",
		"xn--bcher-kva.example":   "xn--bcher-kva.example.",
		"_443._tcp.example.com":   "_443._tcp.example.com.",
		"com":                     "com.",
		"a-b.example.net":         "a-b.example.net.",
		"0.example.net":           "0.example.net.",
		"\texample.net\n":         "example.net.",
		"example.com. ":           "example.com.",
		"EXAMPLE.net.":            "example.net.",
		"sub.sub.example.com":     "sub.sub.example.com.",
		"x.y-z.example.com.":      "x.y-z.example.com.",
		"a1.b2.example.com":       "a1.b2.example.com.",
		"example.xn--p1ai":        "example.xn--p1ai.",
		"пример.рф":               "xn--e1afmkfd.xn--p1ai.",
		"123.example.com":         "123.example.com.",
		"under_score.example.com": "under_score.example.com.",
	}
	for in, want := range ok {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", " ", ".", "..", "http://example.com", "example.com/path", "example.com:53",
		"192.0.2.1", "192.0.2.1.", "2001:db8::1", "[2001:db8::1]", "*.example.com", "a.*.example.com",
		"a..example.com", ".example.com", "exa mple.com", "ex!ample.com", "user@example.com",
		"-bad.example.com", "bad-.example.com", "example.123", "1.2.3",
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("a.", 127) + "com",
		"xn--zz.example", "example.com?x", "ex\x00ample.com",
	}
	for _, in := range bad {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want error", in, got)
		}
	}
}

func TestParseResolver(t *testing.T) {
	ok := map[string]string{
		"192.0.2.53":        "192.0.2.53:53",
		"192.0.2.53:5353":   "192.0.2.53:5353",
		"2001:db8::53":      "[2001:db8::53]:53",
		"[2001:db8::53]:53": "[2001:db8::53]:53",
	}
	for in, want := range ok {
		if got, err := ParseResolver(in); err != nil || got != want {
			t.Errorf("ParseResolver(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "dns.example.com", "192.0.2.53:0", "192.0.2.53:99999", "2001:db8::53:53x", "[2001:db8::53]", "192.0.2.53:"} {
		if got, err := ParseResolver(in); err == nil {
			t.Errorf("ParseResolver(%q) = %q, want error", in, got)
		}
	}
}
