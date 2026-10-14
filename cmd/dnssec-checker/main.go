// Command dnssec-checker validates the DNSSEC chain of trust of the zone that contains one name.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/kmpoltorak/dnssec-checker/internal/checker"
)

var (
	resolvConf = "/etc/resolv.conf"
	anchors    = checker.RootAnchors
)

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
	fs := flag.NewFlagSet("dnssec-checker", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	resolver := fs.String("resolver", "", "resolver IP address with optional port, e.g. 192.0.2.53 or [2001:db8::53]:53\n(default: first nameserver in "+resolvConf+")")
	format := fs.String("format", "text", "output format: text or json")
	timeout := fs.Duration("timeout", 3*time.Second, "time limit for one query attempt")
	deadline := fs.Duration("deadline", 20*time.Second, "time limit for the whole run")
	warnExpiry := fs.Duration("warn-expiry", 168*time.Hour, "warn when the latest valid signature expires within this time")
	version := fs.Bool("version", false, "print the version and exit")
	usage := func(w io.Writer) {
		fmt.Fprintln(w, "Usage: dnssec-checker [flags] domain\n\nFlags:")
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

	var addr string
	var err error
	if *resolver != "" {
		if addr, err = checker.ParseResolver(*resolver); err != nil {
			return fail("%v", err)
		}
	} else if addr, err = checker.SystemResolver(resolvConf); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitCodes[checker.Indeterminate]
	}

	ctx, cancel := context.WithTimeout(ctx, *deadline)
	defer cancel()
	rep, err := checker.Run(ctx, checker.Config{
		Resolver: addr, Timeout: *timeout, WarnExpiry: *warnExpiry, Anchors: anchors,
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
