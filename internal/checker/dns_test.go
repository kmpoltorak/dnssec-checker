package checker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kmpoltorak/dnssec-checker/internal/dnstest"
	"github.com/miekg/dns"
)

func testClient(srv *dnstest.Server) *client {
	return newClient(srv.Addr, 200*time.Millisecond, maxQueries, nil)
}

func TestQueryFlags(t *testing.T) {
	srv := dnstest.Start(t)
	srv.Set("example.com.", dns.TypeSOA, dnstest.Reply{AD: true, EDE: []uint16{3}})
	q := testClient(srv).query(context.Background(), "example.com.", dns.TypeSOA, true)
	if q.Response == nil || !q.Response.AD || q.Response.Rcode != "NOERROR" {
		t.Fatalf("response = %+v, error %q", q.Response, q.Error)
	}
	if len(q.Response.EDE) != 1 || q.Response.EDE[0].Code != 3 || q.Response.EDE[0].Name != "Stale Answer" {
		t.Errorf("EDE = %+v", q.Response.EDE)
	}
	if srv.Hits("udp", "example.com.", dns.TypeSOA, true) != 1 {
		t.Error("CD=1 query was not sent with the CD bit")
	}
}

func TestQuerySendsDNSSECOptions(t *testing.T) {
	captured := make(chan *dns.Msg, 1)
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		captured <- r.Copy()
		m := new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m)
	})
	s := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: h}
	started := make(chan struct{})
	s.NotifyStartedFunc = func() { close(started) }
	go s.ListenAndServe()
	<-started
	defer s.Shutdown()
	c := &client{server: s.PacketConn.LocalAddr().String(), timeout: time.Second, maxQueries: 1}
	if q := c.query(context.Background(), "example.com.", dns.TypeDS, false); q.Error != "" {
		t.Fatal(q.Error)
	}
	got := <-captured
	opt := got.IsEdns0()
	if !got.RecursionDesired || got.CheckingDisabled || opt == nil || !opt.Do() || opt.UDPSize() != ednsSize {
		t.Errorf("query flags: RD=%t CD=%t OPT=%v", got.RecursionDesired, got.CheckingDisabled, opt)
	}
}

func TestQueryTruncatedFallsBackToTCP(t *testing.T) {
	srv := dnstest.Start(t)
	srv.Set("example.com.", dns.TypeDNSKEY, dnstest.Reply{Truncate: true, Answer: []dns.RR{dnstest.RR(t, "example.com. 3600 IN DNSKEY 257 3 13 AAAA")}})
	q := testClient(srv).query(context.Background(), "example.com.", dns.TypeDNSKEY, false)
	if q.Transport != "tcp" || q.msg == nil || len(q.msg.Answer) != 1 {
		t.Fatalf("transport %q, msg %v, error %q", q.Transport, q.msg, q.Error)
	}
	if srv.Hits("tcp", "example.com.", dns.TypeDNSKEY, false) != 1 {
		t.Error("expected one TCP query")
	}
}

func TestQueryRetriesOnceAfterTimeout(t *testing.T) {
	srv := dnstest.Start(t)
	srv.Set("once.example.com.", dns.TypeSOA, dnstest.Reply{Drop: 1})
	srv.Set("never.example.com.", dns.TypeSOA, dnstest.Reply{Drop: -1})
	c := testClient(srv)

	if q := c.query(context.Background(), "once.example.com.", dns.TypeSOA, false); q.Response == nil {
		t.Errorf("expected success after one retry, got %q", q.Error)
	}
	if n := srv.Hits("udp", "once.example.com.", dns.TypeSOA, false); n != 2 {
		t.Errorf("once: %d attempts, want 2", n)
	}
	q := c.query(context.Background(), "never.example.com.", dns.TypeSOA, false)
	if q.Response != nil || !strings.Contains(q.Error, "timeout") {
		t.Errorf("expected timeout error, got %+v %q", q.Response, q.Error)
	}
	if n := srv.Hits("udp", "never.example.com.", dns.TypeSOA, false); n != 2 {
		t.Errorf("never: %d attempts, want 2", n)
	}
}

func TestQueryDoesNotRetryDNSErrors(t *testing.T) {
	srv := dnstest.Start(t)
	for name, rcode := range map[string]int{"nx.": dns.RcodeNameError, "sf.": dns.RcodeServerFailure} {
		srv.Set(name+"example.com.", dns.TypeSOA, dnstest.Reply{Rcode: rcode})
	}
	c := testClient(srv)
	for _, name := range []string{"nx.example.com.", "sf.example.com.", "refused.example.com."} {
		if q := c.query(context.Background(), name, dns.TypeSOA, false); q.Response == nil {
			t.Errorf("%s: %q", name, q.Error)
		}
		if n := srv.Hits("udp", name, dns.TypeSOA, false); n != 1 {
			t.Errorf("%s: %d attempts, want 1", name, n)
		}
	}
}

func TestQueryLimit(t *testing.T) {
	srv := dnstest.Start(t)
	c := testClient(srv)
	c.maxQueries = 1
	c.query(context.Background(), "example.com.", dns.TypeSOA, false)
	q := c.query(context.Background(), "example.com.", dns.TypeSOA, false)
	if !strings.Contains(q.Error, "query limit") {
		t.Errorf("error = %q", q.Error)
	}
	if n := srv.Hits("udp", "example.com.", dns.TypeSOA, false); n != 1 {
		t.Errorf("%d packets sent, want 1", n)
	}
}

func TestQueryHonoursDeadline(t *testing.T) {
	srv := dnstest.Start(t)
	srv.Set("example.com.", dns.TypeSOA, dnstest.Reply{Drop: -1})
	c := testClient(srv)
	c.timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	q := c.query(ctx, "example.com.", dns.TypeSOA, false)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("query took %s despite a 200ms deadline", d)
	}
	if q.Error != context.DeadlineExceeded.Error() {
		t.Errorf("error = %q", q.Error)
	}
}

func TestQueryInterruptIsImmediate(t *testing.T) {
	srv := dnstest.Start(t)
	srv.Set("example.com.", dns.TypeSOA, dnstest.Reply{Drop: -1})
	c := testClient(srv)
	c.timeout = 10 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	q := c.query(ctx, "example.com.", dns.TypeSOA, false)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("interrupt took %s with a 10s timeout", d)
	}
	if q.Error != context.Canceled.Error() {
		t.Errorf("error = %q", q.Error)
	}
}

func TestQueryOverTLS(t *testing.T) {
	srv := dnstest.Start(t)
	srv.Set("example.com.", dns.TypeSOA, dnstest.Reply{AD: true})
	addr, roots := srv.StartTLS(t)
	c := newClient("tls://"+addr, time.Second, maxQueries, roots)
	q := c.query(context.Background(), "example.com.", dns.TypeSOA, true)
	if q.Response == nil || q.Transport != "tls" || !q.Response.AD {
		t.Fatalf("response %+v, transport %q, error %q", q.Response, q.Transport, q.Error)
	}
	// The certificate is for 127.0.0.1, not for another name.
	c = newClient("tls://"+addr+"#dns.example.net", time.Second, maxQueries, roots)
	if q := c.query(context.Background(), "example.com.", dns.TypeSOA, true); q.Response != nil || !strings.Contains(q.Error, "certificate") {
		t.Errorf("wrong name: response %+v, error %q", q.Response, q.Error)
	}
	// An untrusted certificate is rejected.
	c = newClient("tls://"+addr, time.Second, maxQueries, nil)
	if q := c.query(context.Background(), "example.com.", dns.TypeSOA, true); q.Response != nil {
		t.Error("untrusted certificate accepted")
	}
}
