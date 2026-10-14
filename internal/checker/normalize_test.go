package checker

import (
	"strings"
	"testing"
)

func TestCanonicalLess(t *testing.T) {
	// The example order from RFC 4034 section 6.1, without the escaped labels.
	order := []string{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.", "z.example."}
	for i := range order {
		for j := range order {
			if got := canonicalLess(order[i], order[j]); got != (i < j) {
				t.Errorf("canonicalLess(%q, %q) = %t", order[i], order[j], got)
			}
		}
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
