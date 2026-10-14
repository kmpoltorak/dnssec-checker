package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
	if code != 0 || !strings.Contains(out, "Usage: dnssec-checker [flags] domain") || !strings.Contains(out, "-trust-resolver") {
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

func TestExitCodesAndJSON(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name   string
		setup  func(*dnstest.Server)
		trust  bool
		code   int
		status string
	}{
		{"secure", func(s *dnstest.Server) { s.Signed(t, dnstest.NewZone(t, "example.com.", 257, 256), now, true) }, true, 0, "SECURE"},
		{"untrusted", func(s *dnstest.Server) { s.Signed(t, dnstest.NewZone(t, "example.com.", 257), now, true) }, false, 3, "INDETERMINATE"},
		{"insecure", func(s *dnstest.Server) { s.Unsigned(t, "example.com.", "com.", true) }, true, 1, "INSECURE"},
		{"bogus", func(s *dnstest.Server) {
			s.Signed(t, dnstest.NewZone(t, "example.com.", 257), now, true)
			s.Set("example.com.", dns.TypeDNSKEY, dnstest.Reply{Rcode: dns.RcodeServerFailure, EDE: []uint16{dns.ExtendedErrorCodeDNSKEYMissing}})
		}, true, 2, "BOGUS"},
		{"network failure", func(s *dnstest.Server) { s.Set("example.com.", dns.TypeSOA, dnstest.Reply{Drop: -1}) }, true, 3, "INDETERMINATE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := dnstest.Start(t)
			tt.setup(srv)
			args := []string{"--resolver", srv.Addr, "--format", "json", "--timeout", "100ms"}
			if tt.trust {
				args = append(args, "--trust-resolver")
			}
			code, out, errOut := runCLI(t, append(args, "example.com")...)
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
			if rep["status"] != tt.status || rep["schema_version"] != 1.0 {
				t.Errorf("status %v, schema %v", rep["status"], rep["schema_version"])
			}
			for _, k := range []string{"domain", "normalized_domain", "zone", "name_exists", "checked_at", "duration_ms",
				"resolver", "validation_mode", "summary", "records", "queries", "checks", "warnings", "errors"} {
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
	srv := dnstest.Start(t)
	srv.Signed(t, dnstest.NewZone(t, "example.com.", 257, 256), time.Now(), true)
	code, out, _ := runCLI(t, "--resolver", srv.Addr, "--trust-resolver", "example.com")
	for _, want := range []string{
		"Domain:       example.com.", "Zone:         example.com.", "(trusted by user)", "Status:       SECURE",
		"[PASS] ds.match", "[PASS] soa.signatures", "DS (1):", "DNSKEY (2):", "RRSIG (2):", "Summary: ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	if code != 0 {
		t.Errorf("code %d", code)
	}
}
