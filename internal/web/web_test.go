package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kmpoltorak/dnssec-checker/internal/checker"
	"github.com/kmpoltorak/dnssec-checker/internal/dnstest"
	"github.com/miekg/dns"
)

func setup(t *testing.T, limit int) (*httptest.Server, *dnstest.Server) {
	srv := dnstest.Start(t)
	root, _, _ := dnstest.Chain(t, srv, time.Now())
	cfg := checker.Config{Resolver: srv.Addr, Timeout: 200 * time.Millisecond, Anchors: root.Anchor()}
	ts := httptest.NewServer(Handler(cfg, 5*time.Second, limit))
	t.Cleanup(ts.Close)
	return ts, srv
}

func get(t *testing.T, ts *httptest.Server, path string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestPage(t *testing.T) {
	ts, _ := setup(t, 4)
	resp, body := get(t, ts, "/")
	if resp.StatusCode != 200 || !strings.Contains(body, `<form method="get" action="/"`) || strings.Contains(body, "Chain of trust") {
		t.Errorf("empty page: %d\n%s", resp.StatusCode, body)
	}
	for k, want := range map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"Content-Type":            "text/html; charset=utf-8",
	} {
		if got := resp.Header.Get(k); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	resp, body = get(t, ts, "/?domain=Example.COM")
	for _, want := range []string{
		`class="verdict yes"`, "DNSSEC: YES, valid", "SECURE", "Chain of trust", "matches the IANA root trust anchor",
		"Records of example.com.", "1 record(s), signed by example.com.", "example.com. DS ", "(agrees)",
		`value="Example.COM"`, `href="/api/check?domain=example.com."`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("result page lacks %q", want)
		}
	}
	if resp.StatusCode != 200 || strings.Contains(body, "<script") {
		t.Errorf("status %d or script in page", resp.StatusCode)
	}
}

func TestPageVerdicts(t *testing.T) {
	ts, srv := setup(t, 4)
	srv.Set("example.com.", dns.TypeSOA, dnstest.Reply{Drop: -1})
	if _, body := get(t, ts, "/?domain=example.com"); !strings.Contains(body, `class="verdict unknown"`) || !strings.Contains(body, "Error: ") {
		t.Errorf("network failure page:\n%s", body)
	}
}

func TestAPI(t *testing.T) {
	ts, _ := setup(t, 4)
	resp, body := get(t, ts, "/api/check?domain=example.com")
	var rep checker.Report
	if err := json.Unmarshal([]byte(body), &rep); err != nil || resp.StatusCode != 200 {
		t.Fatalf("status %d, %v\n%s", resp.StatusCode, err, body)
	}
	if rep.Status != checker.Secure || rep.DNSSEC != "yes" || resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("status %s, dnssec %s, type %q", rep.Status, rep.DNSSEC, resp.Header.Get("Content-Type"))
	}
}

func TestIncompleteLookupPageAndAPI(t *testing.T) {
	ts, srv := setup(t, 4)
	srv.Set("example.com.", dns.TypeAAAA, dnstest.Reply{Rcode: dns.RcodeServerFailure})
	resp, body := get(t, ts, "/?domain=example.com")
	for _, want := range []string{`class="verdict unknown"`, "INDETERMINATE", "AAAA answer for example.com. could not be checked", "SOA signed by key", "its own SOA answer: NOERROR AD=1", "(agrees)"} {
		if !strings.Contains(body, want) {
			t.Errorf("incomplete result page lacks %q", want)
		}
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("page status %d", resp.StatusCode)
	}
	resp, body = get(t, ts, "/api/check?domain=example.com")
	var rep checker.Report
	if err := json.Unmarshal([]byte(body), &rep); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, %v\n%s", resp.StatusCode, err, body)
	}
	if rep.Status != checker.Indeterminate || rep.DNSSEC != "unknown" {
		t.Errorf("status %s, dnssec %s", rep.Status, rep.DNSSEC)
	}
	if rep.Resolver.Agrees == nil || !*rep.Resolver.Agrees {
		t.Errorf("SOA comparison %v", rep.Resolver.Agrees)
	}
}

func TestBadInput(t *testing.T) {
	ts, _ := setup(t, 4)
	for _, d := range []string{"", "http://example.com/", "192.0.2.1", "exa<script>mple.com", strings.Repeat("a", 2000)} {
		q := "?domain=" + url.QueryEscape(d)
		resp, body := get(t, ts, "/api/check"+q)
		var e map[string]string
		if resp.StatusCode != 400 || json.Unmarshal([]byte(body), &e) != nil || e["error"] == "" {
			t.Errorf("api %q: %d %s", d, resp.StatusCode, body)
		}
		if d == "" {
			continue // the page without a domain is the empty form
		}
		resp, body = get(t, ts, "/"+q)
		if resp.StatusCode != 400 || !strings.Contains(body, `class="error"`) || strings.Contains(body, "<script>") {
			t.Errorf("page %q: %d, error shown: %t, raw script: %t", d, resp.StatusCode, strings.Contains(body, `class="error"`), strings.Contains(body, "<script>"))
		}
	}
}

func TestMethodsAndPaths(t *testing.T) {
	ts, _ := setup(t, 4)
	resp, err := http.Post(ts.URL+"/api/check?domain=example.com", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}
	if resp, _ := get(t, ts, "/nope"); resp.StatusCode != 404 {
		t.Errorf("unknown path: %d", resp.StatusCode)
	}
	if resp, body := get(t, ts, "/healthz"); resp.StatusCode != 200 || body != "ok\n" {
		t.Errorf("healthz: %d %q", resp.StatusCode, body)
	}
	if resp, body := get(t, ts, "/style.css"); resp.StatusCode != 200 || !strings.Contains(body, ".verdict") {
		t.Errorf("style.css: %d", resp.StatusCode)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	srv := dnstest.Start(t)
	srv.Set("example.com.", dns.TypeSOA, dnstest.Reply{Drop: -1}) // keeps the first check busy
	h := &handler{cfg: checker.Config{Resolver: srv.Addr, Timeout: time.Second}, deadline: 2 * time.Second, slots: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() { h.check(context.Background(), "example.com"); close(done) }()
	for start := time.Now(); len(h.slots) == 0; time.Sleep(time.Millisecond) {
		if time.Since(start) > time.Second {
			t.Fatal("the first check never took a slot")
		}
	}
	if _, status, _ := h.check(context.Background(), "example.com"); status != http.StatusTooManyRequests {
		t.Errorf("second check: %d, want 429", status)
	}
	if _, status, _ := h.check(context.Background(), "http://bad"); status != http.StatusBadRequest {
		t.Errorf("invalid input while busy: %d, want 400", status)
	}
	<-done
	if len(h.slots) != 0 {
		t.Error("slot not released")
	}
}

func TestServeShutsDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- Serve(ctx, "127.0.0.1:0", http.NotFoundHandler(), time.Second) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not stop")
	}
}

func TestPageDisagree(t *testing.T) {
	ts, srv := setup(t, 4)
	r := srv.Get("example.com.", dns.TypeSOA)
	srv.SetCD("example.com.", dns.TypeSOA, r)
	srv.Set("example.com.", dns.TypeSOA, dnstest.Reply{Rcode: dns.RcodeServerFailure})
	if _, body := get(t, ts, "/?domain=example.com"); !strings.Contains(body, "(disagrees)") || strings.Contains(body, "(agrees)") {
		t.Errorf("page does not show the disagreement")
	}
}
