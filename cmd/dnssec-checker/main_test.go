package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kmpoltorak/dnssec-checker/internal/dnstest"
	"github.com/miekg/dns"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"example.com", "example.net"},
		{"example.com", "--format", "json"}, // flags after the domain
		{"--bogus", "example.com"},
		{"--format", "xml", "example.com"},
		{"--timeout", "0s", "example.com"},
		{"--timeout", "abc", "example.com"},
		{"--deadline", "-1s", "example.com"},
		{"--warn-expiry", "-1h", "example.com"},
		{"--resolver", "dns.example.net", "example.com"},
		{"--trust-resolver", "example.com"}, // removed: the chain is validated locally
		{"https://example.com/"},
		{"192.0.2.1"},
	} {
		code, out, errOut := runCLI(t, args...)
		if code != 64 || out != "" || !strings.Contains(errOut, "error") {
			t.Errorf("%q: code %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
}

func TestHelpAndVersion(t *testing.T) {
	code, out, _ := runCLI(t, "--help")
	if code != 0 || !strings.Contains(out, "Usage: dnssec-checker [flags] domain") || !strings.Contains(out, "-resolver") {
		t.Errorf("help: code %d, %q", code, out)
	}
	code, out, _ = runCLI(t, "--version")
	if code != 0 || !strings.HasPrefix(out, "dnssec-checker ") {
		t.Errorf("version: code %d, %q", code, out)
	}
}

func TestNoSystemResolver(t *testing.T) {
	old := resolvConf
	resolvConf = filepath.Join(t.TempDir(), "missing")
	defer func() { resolvConf = old }()
	code, out, errOut := runCLI(t, "example.com")
	if code != 3 || out != "" || !strings.Contains(errOut, "--resolver") {
		t.Errorf("code %d, stdout %q, stderr %q", code, out, errOut)
	}
}

// serve starts a fake resolver with the signed chain . -> com. -> example.com. and makes
// the CLI trust the test root.
func serve(t *testing.T) (*dnstest.Server, *dnstest.Zone, *dnstest.Zone) {
	srv := dnstest.Start(t)
	root, com, example := dnstest.Chain(t, srv, time.Now())
	old := anchors
	anchors = root.Anchor()
	t.Cleanup(func() { anchors = old })
	return srv, com, example
}

func TestExitCodesAndJSON(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(s *dnstest.Server, com, example *dnstest.Zone)
		code   int
		status string
		dnssec string
	}{
		{"secure", func(*dnstest.Server, *dnstest.Zone, *dnstest.Zone) {}, 0, "SECURE", "yes"},
		{"insecure", func(s *dnstest.Server, com, _ *dnstest.Zone) {
			s.ServeUnsigned(t, "example.com.")
			s.NoDS(t, com, "example.com.", "NS RRSIG NSEC")
		}, 1, "INSECURE", "no"},
		{"bogus", func(s *dnstest.Server, _, example *dnstest.Zone) {
			s.Set("example.com.", dns.TypeSOA, dnstest.Reply{Answer: []dns.RR{example.SOA(t)}})
		}, 2, "BOGUS", "broken"},
		{"network failure", func(s *dnstest.Server, _, _ *dnstest.Zone) {
			s.Set("example.com.", dns.TypeSOA, dnstest.Reply{Drop: -1})
		}, 3, "INDETERMINATE", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, com, example := serve(t)
			tt.setup(srv, com, example)
			code, out, errOut := runCLI(t, "--resolver", srv.Addr, "--format", "json", "--timeout", "100ms", "example.com")
			if code != tt.code || errOut != "" {
				t.Errorf("code %d, want %d; stderr %q", code, tt.code, errOut)
			}
			if strings.Contains(out, "\x1b") {
				t.Error("ANSI escape in JSON output")
			}
			dec := json.NewDecoder(strings.NewReader(out))
			var rep map[string]any
			if err := dec.Decode(&rep); err != nil {
				t.Fatalf("invalid JSON: %v\n%s", err, out)
			}
			if _, err := dec.Token(); err != io.EOF {
				t.Errorf("more than one JSON value on stdout: %v", err)
			}
			if rep["status"] != tt.status || rep["dnssec"] != tt.dnssec || rep["schema_version"] != 2.0 {
				t.Errorf("status %v, dnssec %v, schema %v", rep["status"], rep["dnssec"], rep["schema_version"])
			}
			for _, k := range []string{"domain", "normalized_domain", "zone", "name_exists", "alias_chain", "summary", "chain",
				"ns", "resolver", "checked_at", "duration_ms", "queries", "warnings", "errors"} {
				if _, ok := rep[k]; !ok {
					t.Errorf("missing key %q", k)
				}
			}
			if _, err := time.Parse(time.RFC3339, rep["checked_at"].(string)); err != nil || !strings.HasSuffix(rep["checked_at"].(string), "Z") {
				t.Errorf("checked_at %v", rep["checked_at"])
			}
		})
	}
}

func TestTextOutput(t *testing.T) {
	srv, _, _ := serve(t)
	code, out, _ := runCLI(t, "--resolver", srv.Addr, "example.com")
	for _, want := range []string{
		"example.com.  DNSSEC: YES, valid (SECURE)", "Chain of trust", "✔ .", "✔ com.", "✔ example.com.",
		"matches the IANA root trust anchor", "example.com. DS ", "(agrees)",
		"Records of example.com.", "✔ A     1 record(s), signed by example.com.", "✔ AAAA  no AAAA records, proven by a signed NSEC record",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	if code != 0 || strings.Contains(out, "\x1b") {
		t.Errorf("code %d, or colors when stdout is not a terminal", code)
	}
}

func TestTrustAnchorFile(t *testing.T) {
	srv := dnstest.Start(t)
	root, _, _ := dnstest.Chain(t, srv, time.Now())
	dir := t.TempDir()
	good := filepath.Join(dir, "root.key")
	os.WriteFile(good, []byte(root.Keys[0].String()+"\n"), 0o600)
	// The built-in IANA anchors do not match the test root; the file does.
	if code, _, errOut := runCLI(t, "--resolver", srv.Addr, "--trust-anchor", good, "example.com"); code != 0 {
		t.Errorf("with the test root key: code %d, stderr %q", code, errOut)
	}
	if code, _, _ := runCLI(t, "--resolver", srv.Addr, "example.com"); code != 2 {
		t.Errorf("with the IANA anchors: code %d, want 2 (BOGUS)", code)
	}
	bad := filepath.Join(dir, "bad.key")
	os.WriteFile(bad, []byte("example.com. IN DS 1 13 2 AAAA\n"), 0o600)
	for _, f := range []string{bad, filepath.Join(dir, "missing")} {
		if code, out, errOut := runCLI(t, "--resolver", srv.Addr, "--trust-anchor", f, "example.com"); code != 64 || out != "" || errOut == "" {
			t.Errorf("%s: code %d, stdout %q, stderr %q", f, code, out, errOut)
		}
	}
}
