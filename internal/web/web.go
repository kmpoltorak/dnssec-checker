// Package web serves a small HTML page and a JSON API around checker.Run.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/kmpoltorak/dnssec-checker/internal/checker"
)

//go:embed page.html style.css
var files embed.FS

var page = template.Must(template.New("page.html").Funcs(template.FuncMap{
	"mark": func(result string) string {
		return map[string]string{checker.StepOK: "✔", checker.StepInsecure: "–", checker.StepFail: "✘", checker.StepError: "?"}[result]
	},
	"isZone": func(rep *checker.Report, zone string) bool { return rep.Zone != nil && *rep.Zone == zone },
	"deref":  func(b *bool) bool { return *b },
}).ParseFS(files, "page.html"))

// Handler serves the page, the API and a health check. cfg is the checker configuration,
// including the resolver chosen by the operator; users only supply a domain. At most
// limit checks run at the same time, each within deadline.
func Handler(cfg checker.Config, deadline time.Duration, limit int) http.Handler {
	h := &handler{cfg: cfg, deadline: deadline, slots: make(chan struct{}, limit)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.page)
	mux.HandleFunc("GET /api/check", h.api)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.Handle("GET /style.css", http.FileServerFS(files))
	return headers(mux)
}

type handler struct {
	cfg      checker.Config
	deadline time.Duration
	slots    chan struct{}
}

type view struct {
	Domain string
	Report *checker.Report
	Error  string
}

func (h *handler) page(w http.ResponseWriter, r *http.Request) {
	v := view{Domain: r.URL.Query().Get("domain")}
	status := http.StatusOK
	if v.Domain != "" {
		v.Report, status, v.Error = h.check(r.Context(), v.Domain)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	page.Execute(w, v)
}

func (h *handler) api(w http.ResponseWriter, r *http.Request) {
	rep, status, msg := h.check(r.Context(), r.URL.Query().Get("domain"))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if rep == nil {
		json.NewEncoder(w).Encode(map[string]string{"error": msg})
		return
	}
	rep.JSON(w)
}

// check runs one check, or returns an HTTP status and message for invalid input or when
// all slots are busy.
func (h *handler) check(ctx context.Context, domain string) (*checker.Report, int, string) {
	if strings.TrimSpace(domain) == "" {
		return nil, http.StatusBadRequest, "enter a domain name"
	}
	// Invalid input is rejected before it can take a slot.
	if _, err := checker.Normalize(domain); err != nil {
		return nil, http.StatusBadRequest, err.Error()
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		return nil, http.StatusTooManyRequests, "too many checks are running; try again in a few seconds"
	}
	ctx, cancel := context.WithTimeout(ctx, h.deadline)
	defer cancel()
	rep, err := checker.Run(ctx, h.cfg, domain)
	if err != nil {
		return nil, http.StatusBadRequest, err.Error()
	}
	return rep, http.StatusOK, ""
}

// headers adds security headers to every response. The page uses no scripts and only its
// own stylesheet.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// Serve listens on addr until ctx is cancelled, then shuts down gracefully.
func Serve(ctx context.Context, addr string, h http.Handler, deadline time.Duration) error {
	srv := &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: deadline + 10*time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		// Let running checks finish for a few seconds, then close what is left.
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if srv.Shutdown(sctx) != nil {
			srv.Close()
		}
		return nil
	}
}
