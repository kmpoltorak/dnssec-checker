package checker

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/miekg/dns"
)

type Status string

const (
	Secure        Status = "SECURE"
	Insecure      Status = "INSECURE"
	Bogus         Status = "BOGUS"
	Indeterminate Status = "INDETERMINATE"
)

// statuses holds, per status, the answer to "does this zone have working DNSSEC?", the
// text headline and its ANSI color.
var statuses = map[Status]struct{ verdict, headline, color string }{
	Secure:        {"yes", "DNSSEC: YES, valid (SECURE)", "32"},
	Insecure:      {"no", "DNSSEC: NO, not signed (INSECURE)", "33"},
	Bogus:         {"broken", "DNSSEC: BROKEN, validation fails (BOGUS)", "31"},
	Indeterminate: {"unknown", "DNSSEC: UNKNOWN, could not be checked (INDETERMINATE)", "33"},
}

// Step results in the chain of trust.
const (
	StepOK       = "ok"
	StepInsecure = "insecure"
	StepFail     = "fail"
	StepError    = "error"
)

// Report is shared by the text and JSON renderers. Missing data is null.
type Report struct {
	SchemaVersion    int      `json:"schema_version"`
	Domain           string   `json:"domain"`
	NormalizedDomain string   `json:"normalized_domain"`
	Zone             *string  `json:"zone"`
	NameExists       *bool    `json:"name_exists"`
	AliasChain       []string `json:"alias_chain"`
	Status           Status   `json:"status"`
	DNSSEC           string   `json:"dnssec"` // yes, no, broken, unknown
	Summary          string   `json:"summary"`
	Chain            []Step   `json:"chain"`
	NS               []string `json:"ns"`
	Resolver         Resolver `json:"resolver"`
	CheckedAt        string   `json:"checked_at"`
	DurationMS       int64    `json:"duration_ms"`
	Queries          []Query  `json:"queries"`
	Warnings         []string `json:"warnings"`
	Errors           []string `json:"errors"`
}

// Step is one link of the chain of trust, with the records that prove it.
type Step struct {
	Zone    string   `json:"zone"`
	Result  string   `json:"result"` // ok, insecure, fail, error
	Detail  string   `json:"detail"`
	Records []string `json:"records"`
}

// Resolver is the resolver's own view (CD=0), reported next to the local result.
type Resolver struct {
	Address  string    `json:"address"`
	Response *Response `json:"response"`
	Agrees   *bool     `json:"agrees"`
}

type Query struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	CD        bool      `json:"cd"`
	Server    string    `json:"server"`
	Transport string    `json:"transport"`
	Response  *Response `json:"response"` // null when no reply was received
	Error     string    `json:"error,omitempty"`

	msg *dns.Msg
}

type Response struct {
	Rcode string `json:"rcode"`
	AD    bool   `json:"ad"`
	EDE   []EDE  `json:"ede"`
}

type EDE struct {
	Code uint16 `json:"code"`
	Name string `json:"name"`
	Text string `json:"text,omitempty"`
}

func (r *Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

var mark = map[string]struct{ sym, color string }{
	StepOK:       {"✔", "32"}, // green
	StepInsecure: {"–", "33"}, // yellow
	StepFail:     {"✘", "31"}, // red
	StepError:    {"?", "33"},
}

// Text renders the report for people. color adds ANSI colors; use it only on a terminal.
func (r *Report) Text(w io.Writer, color bool) error {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	p("%s  %s", paint("1", r.NormalizedDomain), paint("1;"+statuses[r.Status].color, statuses[r.Status].headline))
	p("%s", r.Summary)

	if len(r.Chain) > 0 {
		p("")
		p("%s", paint("1", "Chain of trust (validated locally from the IANA root key)"))
		width := 0
		for _, s := range r.Chain {
			width = max(width, len(s.Zone))
		}
		last := r.Chain[len(r.Chain)-1].Zone
		for _, s := range r.Chain {
			m := mark[s.Result]
			p("  %s %-*s  %s", paint(m.color, m.sym), width, s.Zone, s.Detail)
			// Records are shown for the zone the verdict is about; JSON has all of them.
			if s.Zone == last {
				for _, rec := range s.Records {
					p("      %s", paint("2", rec))
				}
			}
		}
	}

	p("")
	zone := "unknown"
	if r.Zone != nil {
		zone = *r.Zone
	}
	exists := "unknown"
	if r.NameExists != nil {
		exists = map[bool]string{true: "yes", false: "no (NXDOMAIN)"}[*r.NameExists]
	}
	p("Zone:          %s", zone)
	p("Name exists:   %s", exists)
	if len(r.AliasChain) > 0 {
		p("Alias:         %s", strings.Join(append([]string{r.NormalizedDomain}, r.AliasChain...), " -> "))
	}
	if len(r.NS) > 0 {
		p("Name servers:  %s", strings.Join(r.NS, ", "))
	}
	resolver := r.Resolver.Address
	if q := r.Resolver.Response; q != nil {
		resolver += fmt.Sprintf(", its own answer: %s AD=%d", q.Rcode, b2i(q.AD))
		for _, e := range q.EDE {
			resolver += fmt.Sprintf(" EDE %d (%s)", e.Code, e.Name)
		}
		if r.Resolver.Agrees != nil {
			resolver += map[bool]string{true: " (agrees)", false: " (disagrees)"}[*r.Resolver.Agrees]
		}
	}
	p("Resolver:      %s", resolver)
	p("Checked:       %s, %d queries, %d ms", r.CheckedAt, len(r.Queries), r.DurationMS)
	for _, s := range r.Warnings {
		p("%s %s", paint("33", "Warning:"), s)
	}
	for _, s := range r.Errors {
		p("%s %s", paint("31", "Error:"), s)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
