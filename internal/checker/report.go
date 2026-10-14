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

type Result string

const (
	Pass    Result = "PASS"
	Warn    Result = "WARN"
	Fail    Result = "FAIL"
	Unknown Result = "UNKNOWN"
	NA      Result = "N/A"
)

// Report is shared by the text and JSON renderers. Missing data is null, never a
// value that looks like a passing result.
type Report struct {
	SchemaVersion    int      `json:"schema_version"`
	Domain           string   `json:"domain"`
	NormalizedDomain string   `json:"normalized_domain"`
	Zone             *string  `json:"zone"`
	NameExists       *bool    `json:"name_exists"`
	CheckedAt        string   `json:"checked_at"`
	DurationMS       int64    `json:"duration_ms"`
	Resolver         string   `json:"resolver"`
	ValidationMode   string   `json:"validation_mode"`
	Status           Status   `json:"status"`
	Summary          string   `json:"summary"`
	Records          Records  `json:"records"`
	Queries          []Query  `json:"queries"`
	Checks           []Check  `json:"checks"`
	Warnings         []string `json:"warnings"`
	Errors           []string `json:"errors"`
}

type Records struct {
	AliasChain []string `json:"alias_chain"`
	NS         []string `json:"ns"`
	DS         []DS     `json:"ds"`
	DNSKEY     []DNSKEY `json:"dnskey"`
	RRSIG      []RRSIG  `json:"rrsig"`
	NSEC       bool     `json:"nsec_present"`
	NSEC3      bool     `json:"nsec3_present"`
}

type DS struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
	Match      string `json:"match"` // match, no_match, unsupported_digest, unknown
}

type DNSKEY struct {
	KeyTag    uint16 `json:"key_tag"`
	Algorithm uint8  `json:"algorithm"`
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
}

type RRSIG struct {
	Covers     string `json:"covers"`
	Signer     string `json:"signer"`
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	Inception  string `json:"inception"`
	Expiration string `json:"expiration"`
	Signature  string `json:"signature"` // valid, invalid, no_key, unsupported, wrong_signer
	Time       string `json:"time"`      // valid, expired, not_yet_valid
	ExpiresIn  string `json:"expires_in"`

	key    *dns.DNSKEY // key that verified the signature
	expiry int64
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

type Check struct {
	ID          string `json:"id"`
	Result      Result `json:"result"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Suggestion  string `json:"suggestion,omitempty"`
}

func (r *Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

func (r *Report) Text(w io.Writer) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	p("Domain:       %s (input %q)", r.NormalizedDomain, r.Domain)
	p("Zone:         %s", orUnknown(r.Zone))
	p("Name exists:  %s", yesNo(r.NameExists))
	if len(r.Records.AliasChain) > 0 {
		p("Alias:        %s", strings.Join(append([]string{r.NormalizedDomain}, r.Records.AliasChain...), " -> "))
	}
	p("Checked at:   %s (%d ms)", r.CheckedAt, r.DurationMS)
	trust := "not trusted; AD is only an observation"
	if r.ValidationMode == modeTrusted {
		trust = "trusted by user"
	}
	p("Resolver:     %s (%s)", r.Resolver, trust)
	p("Validation:   resolver + local DS/DNSKEY/RRSIG diagnostics")
	p("Status:       %s", r.Status)
	p("")
	for _, c := range r.Checks {
		p("[%s] %s: %s", c.Result, c.ID, c.Description)
		p("       %s", c.Evidence)
		if c.Suggestion != "" {
			p("       Suggestion: %s", c.Suggestion)
		}
	}

	p("")
	p("NS (%d):", len(r.Records.NS))
	for _, ns := range r.Records.NS {
		p("  %s", ns)
	}
	p("DS (%d):", len(r.Records.DS))
	for _, d := range r.Records.DS {
		p("  tag %d, algorithm %s, digest type %s, %s: %s", d.KeyTag, alg(d.Algorithm), digest(d.DigestType), d.Digest, d.Match)
	}
	p("DNSKEY (%d):", len(r.Records.DNSKEY))
	for _, k := range r.Records.DNSKEY {
		p("  tag %d, algorithm %s, flags %d, protocol %d", k.KeyTag, alg(k.Algorithm), k.Flags, k.Protocol)
	}
	p("RRSIG (%d):", len(r.Records.RRSIG))
	for _, s := range r.Records.RRSIG {
		p("  %s by %s tag %d, algorithm %s, %s to %s: signature %s, time %s, expires in %s",
			s.Covers, s.Signer, s.KeyTag, alg(s.Algorithm), s.Inception, s.Expiration, s.Signature, s.Time, s.ExpiresIn)
	}
	p("NSEC present: %t, NSEC3 present: %t", r.Records.NSEC, r.Records.NSEC3)

	p("")
	p("Queries (%d):", len(r.Queries))
	for _, q := range r.Queries {
		line := fmt.Sprintf("  %s %s CD=%d via %s/%s: ", q.Name, q.Type, b2i(q.CD), q.Transport, q.Server)
		if q.Response == nil {
			p("%serror: %s", line, q.Error)
			continue
		}
		ede := make([]string, 0, len(q.Response.EDE))
		for _, e := range q.Response.EDE {
			ede = append(ede, fmt.Sprintf("%d (%s)", e.Code, e.Name))
		}
		p("%s%s AD=%d EDE=[%s]", line, q.Response.Rcode, b2i(q.Response.AD), strings.Join(ede, ", "))
	}
	for _, s := range r.Warnings {
		p("Warning: %s", s)
	}
	for _, s := range r.Errors {
		p("Error: %s", s)
	}
	p("")
	p("Summary: %s", r.Summary)
	_, err := io.WriteString(w, b.String())
	return err
}

func orUnknown(s *string) string {
	if s == nil {
		return "unknown"
	}
	return *s
}

func yesNo(b *bool) string {
	switch {
	case b == nil:
		return "unknown"
	case *b:
		return "yes"
	}
	return "no"
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func alg(a uint8) string {
	if n, ok := dns.AlgorithmToString[a]; ok {
		return fmt.Sprintf("%d (%s)", a, n)
	}
	return fmt.Sprint(a)
}

func digest(d uint8) string {
	if n, ok := dns.HashToString[d]; ok {
		return fmt.Sprintf("%d (%s)", d, n)
	}
	return fmt.Sprint(d)
}
