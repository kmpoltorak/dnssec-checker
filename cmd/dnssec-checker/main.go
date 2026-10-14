// Command dnssec-checker validates the DNSSEC chain of trust of the zone that contains one name.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/kmpoltorak/dnssec-checker/internal/checker"
	"github.com/kmpoltorak/dnssec-checker/internal/web"
	"github.com/miekg/dns"
)

// defaultResolver is Quad9 over TLS. Home routers and DNS filters often drop or change
// DNSSEC records, and Docker's DNS drops them; validation is local either way, so the
// resolver only has to pass records through unchanged.
const defaultResolver = "tls://9.9.9.9"

var anchors = checker.RootAnchors

// settings parses the resolver and loads the trust anchors shared by the check and serve.
func settings(resolver, anchorFile string) (string, []*dns.DS, error) {
	addr, err := checker.ParseResolver(resolver)
	if err != nil || anchorFile == "" {
		return addr, anchors, err
	}
	ta, err := checker.LoadAnchors(anchorFile)
	return addr, ta, err
}

// resolverDefault is $DNSSEC_RESOLVER when set, else defaultResolver.
func resolverDefault() string {
	if r := os.Getenv("DNSSEC_RESOLVER"); r != "" {
		return r
	}
	return defaultResolver
}

var exitCodes = map[checker.Status]int{
	checker.Secure:        0,
	checker.Insecure:      1,
	checker.Bogus:         2,
	checker.Indeterminate: 3,
}

const exitUsage = 64

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			return serve(ctx, args[1:], stderr)
		case "health":
			return health(args[1:], stderr)
		}
	}
	fs := flag.NewFlagSet("dnssec-checker", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	resolver := fs.String("resolver", resolverDefault(), "resolver to fetch records from: an IP address with optional port, e.g. 192.0.2.53 or\n[2001:db8::53]:53; prefix with tls:// for DNS over TLS, e.g. tls://192.0.2.53#dns.example.net\n(default: $DNSSEC_RESOLVER, else "+defaultResolver+", Quad9 over TLS)")
	anchorFile := fs.String("trust-anchor", "", "file with root trust anchors (DS or DNSKEY records for \".\" in zone file format)\n(default: the built-in IANA root keys)")
	format := fs.String("format", "text", "output format: text or json")
	timeout := fs.Duration("timeout", 3*time.Second, "time limit for one query attempt")
	deadline := fs.Duration("deadline", 20*time.Second, "time limit for the whole run")
	warnExpiry := fs.Duration("warn-expiry", 168*time.Hour, "warn when the latest valid signature expires within this time")
	version := fs.Bool("version", false, "print the version and exit")
	usage := func(w io.Writer) {
		fmt.Fprintln(w, "Usage: dnssec-checker [flags] domain\n       dnssec-checker serve [flags]   (web interface, see serve --help)\n\nFlags:")
		fs.SetOutput(w)
		fs.PrintDefaults()
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "error: "+format+"\n", a...)
		return exitUsage
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stdout)
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		usage(stderr)
		return exitUsage
	}
	if *version {
		fmt.Fprintln(stdout, "dnssec-checker", buildVersion())
		return 0
	}
	switch {
	case fs.NArg() != 1:
		return fail("expected exactly one domain, got %d arguments (flags go before the domain)", fs.NArg())
	case *format != "text" && *format != "json":
		return fail("--format must be text or json")
	case *timeout <= 0 || *deadline <= 0:
		return fail("--timeout and --deadline must be positive")
	case *warnExpiry < 0:
		return fail("--warn-expiry must not be negative")
	}
	if _, err := checker.Normalize(fs.Arg(0)); err != nil {
		return fail("%v", err)
	}

	addr, ta, err := settings(*resolver, *anchorFile)
	if err != nil {
		return fail("%v", err)
	}

	ctx, cancel := context.WithTimeout(ctx, *deadline)
	defer cancel()
	rep, err := checker.Run(ctx, checker.Config{
		Resolver: addr, Timeout: *timeout, WarnExpiry: *warnExpiry, Anchors: ta,
	}, fs.Arg(0))
	if err != nil {
		return fail("%v", err)
	}
	if *format == "json" {
		err = rep.JSON(stdout)
	} else {
		err = rep.Text(stdout, isTerminal(stdout) && os.Getenv("NO_COLOR") == "")
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitCodes[checker.Indeterminate]
	}
	return exitCodes[rep.Status]
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func buildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

// serve runs the web interface. The resolver is fixed by the operator (flag or the
// DNSSEC_RESOLVER environment variable); users of the page only enter a domain.
func serve(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("dnssec-checker serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	resolver := fs.String("resolver", resolverDefault(), "resolver, as for the check (default: $DNSSEC_RESOLVER, else "+defaultResolver+")")
	anchorFile := fs.String("trust-anchor", "", "root trust anchor file (default: the built-in IANA root keys)")
	timeout := fs.Duration("timeout", 3*time.Second, "time limit for one query attempt")
	deadline := fs.Duration("deadline", 20*time.Second, "time limit for one check")
	limit := fs.Int("max-checks", 4, "checks that may run at the same time")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return exitUsage
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "error: "+format+"\n", a...)
		return exitUsage
	}
	if fs.NArg() != 0 || *timeout <= 0 || *deadline <= 0 || *limit < 1 {
		return fail("serve takes no arguments; --timeout, --deadline and --max-checks must be positive")
	}
	addr, ta, err := settings(*resolver, *anchorFile)
	if err != nil {
		return fail("%v", err)
	}
	cfg := checker.Config{Resolver: addr, Timeout: *timeout, WarnExpiry: 168 * time.Hour, Anchors: ta}
	fmt.Fprintf(stderr, "dnssec-checker %s: listening on http://%s, resolver %s\n", buildVersion(), *listen, addr)
	if err := web.Serve(ctx, *listen, web.Handler(cfg, *deadline, *limit), *deadline); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitCodes[checker.Indeterminate]
	}
	return 0
}

// health checks a running web interface, for container health checks: exit 0 when
// /healthz answers 200 within two seconds.
func health(args []string, stderr io.Writer) int {
	url := "http://127.0.0.1:8080/healthz"
	if len(args) == 1 {
		url = args[0]
	}
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(stderr, "unhealthy:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "unhealthy:", resp.Status)
		return 1
	}
	return 0
}
