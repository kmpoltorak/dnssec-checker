package checker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kmpoltorak/dnssec-checker/internal/dnstest"
	"github.com/miekg/dns"
)

func TestCanonicalLess(t *testing.T) {
	// The example order from RFC 4034 section 6.1.
	order := []string{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.", "zABC.a.EXAMPLE.", "z.example.",
		"\\001.z.example.", "*.z.example.", "\\200.z.example."}
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

func TestSigTimeAcross2106(t *testing.T) {
	now := time.Date(2106, 2, 7, 0, 0, 0, 0, time.UTC) // just before uint32 seconds wrap
	later := now.Add(48 * time.Hour)
	if got := sigTime(uint32(later.Unix()), now); !got.Equal(later) {
		t.Errorf("sigTime = %s, want %s", got, later)
	}
	earlier := now.Add(-48 * time.Hour)
	if got := sigTime(uint32(earlier.Unix()), now); !got.Equal(earlier) {
		t.Errorf("sigTime = %s, want %s", got, earlier)
	}
}

func TestLoadAnchors(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, fmt.Sprint(len(body))+".txt")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	ds := ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n"
	got, err := LoadAnchors(write("; comment\n" + ds))
	if err != nil || len(got) != 1 || got[0].KeyTag != 20326 {
		t.Errorf("DS file: %v, %v", got, err)
	}
	key := dnstest.NewZone(t, ".", time.Now(), 257).Keys[0]
	got, err = LoadAnchors(write(key.String() + "\n"))
	if err != nil || len(got) != 1 || got[0].KeyTag != key.KeyTag() || got[0].DigestType != dns.SHA256 {
		t.Errorf("DNSKEY file: %v, %v", got, err)
	}
	for name, body := range map[string]string{
		"not root":  "example.com. IN DS 1 13 2 AAAA\n",
		"empty":     "; nothing\n",
		"wrong rr":  ". IN A 192.0.2.1\n",
		"bad input": ". IN DS nope\n",
	} {
		if _, err := LoadAnchors(write(body)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := LoadAnchors(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file: want error")
	}
}

func TestParseResolver(t *testing.T) {
	ok := map[string]string{
		"tls://192.0.2.53":                     "tls://192.0.2.53:853",
		"tls://192.0.2.53:8853":                "tls://192.0.2.53:8853",
		"tls://2001:db8::53":                   "tls://[2001:db8::53]:853",
		"tls://192.0.2.53#DNS.Example.NET":     "tls://192.0.2.53:853#dns.example.net",
		"tls://192.0.2.53:853#dns.example.net": "tls://192.0.2.53:853#dns.example.net",
		"192.0.2.53":                           "192.0.2.53:53",
		"192.0.2.53:5353":                      "192.0.2.53:5353",
		"2001:db8::53":                         "[2001:db8::53]:53",
		"[2001:db8::53]:53":                    "[2001:db8::53]:53",
	}
	for in, want := range ok {
		if got, err := ParseResolver(in); err != nil || got != want {
			t.Errorf("ParseResolver(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"tls://", "tls://dns.example.net", "tls://192.0.2.53#", "tls://192.0.2.53#bad name", "tls://[2001:db8::53]", "https://192.0.2.53", "", "dns.example.com", "192.0.2.53:0", "192.0.2.53:99999", "2001:db8::53:53x", "[2001:db8::53]", "192.0.2.53:"} {
		if got, err := ParseResolver(in); err == nil {
			t.Errorf("ParseResolver(%q) = %q, want error", in, got)
		}
	}
}
