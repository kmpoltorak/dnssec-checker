// Package checker diagnoses the DNSSEC configuration of the zone that contains one name.
// Chain validation is delegated to the resolver; local checks are diagnostics only.
package checker

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

const (
	modeTrusted   = "trusted-resolver"
	modeUntrusted = "untrusted-resolver"
	maxAliases    = 8
)

type Config struct {
	Resolver   string // host:port, see ParseResolver
	Trusted    bool   // the user trusts the resolver's validation and the path to it
	Timeout    time.Duration
	WarnExpiry time.Duration
	Now        func() time.Time // clock for signature validity; time.Now when nil
	MaxQueries int              // packets per run; maxQueries when 0
}

var (
	labelRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$`)
	// Lookup mapping without the STD3 rules, so that labels such as _443._tcp are accepted.
	idnaProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(false))
)

// Normalize trims the input, converts IDN to ASCII, lowercases it and adds the final dot.
// URLs, IP addresses, wildcards, empty labels, odd characters, overlong names and the
// root are rejected.
func Normalize(in string) (string, error) {
	s := strings.TrimSpace(in)
	switch {
	case s == "":
		return "", errors.New("empty domain")
	case s == ".":
		return "", errors.New("the root zone is not supported")
	case strings.ContainsAny(s, "/:@?#[]\\ \t"):
		return "", fmt.Errorf("%q is not a domain name (URLs, ports and spaces are not accepted)", in)
	case net.ParseIP(strings.TrimSuffix(s, ".")) != nil:
		return "", fmt.Errorf("%q is an IP address, not a domain name", in)
	}
	a, err := idnaProfile.ToASCII(strings.TrimSuffix(s, "."))
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %v", in, err)
	}
	a = strings.ToLower(a)
	if len(a) > 253 {
		return "", fmt.Errorf("domain %q is longer than 253 characters", in)
	}
	labels := strings.Split(a, ".")
	for _, l := range labels {
		switch {
		case l == "":
			return "", fmt.Errorf("domain %q has an empty label", in)
		case l == "*":
			return "", fmt.Errorf("wildcard %q is not supported", in)
		case len(l) > 63:
			return "", fmt.Errorf("label %q is longer than 63 characters", l)
		case !labelRE.MatchString(l):
			return "", fmt.Errorf("label %q contains characters not allowed in a domain name", l)
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", fmt.Errorf("%q has a numeric top-level label", in)
	}
	return a + ".", nil
}

// Run normalizes domain and runs the full check. The error is only for invalid input;
// network problems end up in a partial report with status INDETERMINATE.
func Run(ctx context.Context, cfg Config, domain string) (*Report, error) {
	name, err := Normalize(domain)
	if err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxQueries == 0 {
		cfg.MaxQueries = maxQueries
	}
	start := time.Now()
	r := &run{
		c:   &client{server: cfg.Resolver, timeout: cfg.Timeout, maxQueries: cfg.MaxQueries},
		now: cfg.Now().UTC(),
		rep: &Report{
			SchemaVersion: 1, Domain: domain, NormalizedDomain: name, Resolver: cfg.Resolver,
			ValidationMode: modeUntrusted, Status: Indeterminate,
			Records: Records{AliasChain: []string{}}, Queries: []Query{}, Checks: []Check{},
			Warnings: []string{}, Errors: []string{},
		},
	}
	r.rep.CheckedAt = r.now.Format(time.RFC3339)
	if cfg.Trusted {
		r.rep.ValidationMode = modeTrusted
	}
	r.check(ctx, cfg, name)
	if ctx.Err() != nil {
		r.rep.Errors = append(r.rep.Errors, fmt.Sprintf("run stopped early (%v); the report is partial", ctx.Err()))
	}
	r.rep.DurationMS = time.Since(start).Milliseconds()
	return r.rep, nil
}

type run struct {
	c   *client
	now time.Time
	rep *Report
}

func (r *run) check(ctx context.Context, cfg Config, name string) {
	rep := r.rep
	zone := r.findZone(ctx, name)
	if zone == "" {
		rep.Summary = "The zone of " + name + " could not be determined; no DNSSEC status can be given."
		return
	}
	rep.Zone = &zone
	root := zone == "."

	soaR, soaM := r.ask(ctx, zone, dns.TypeSOA)
	keyR, keyM := r.ask(ctx, zone, dns.TypeDNSKEY)
	_, nsM := r.ask(ctx, zone, dns.TypeNS)
	var dsR *Response
	var dsM *dns.Msg
	if !root {
		dsR, dsM = r.ask(ctx, zone, dns.TypeDS)
	}

	if ns := answers[*dns.NS](nsM, zone); ns != nil {
		rep.Records.NS = []string{}
		for _, n := range ns {
			rep.Records.NS = append(rep.Records.NS, strings.ToLower(n.Ns))
		}
		slices.Sort(rep.Records.NS)
	}
	keys := answers[*dns.DNSKEY](keyM, zone)
	if keys != nil {
		rep.Records.DNSKEY = []DNSKEY{}
		for _, k := range keys {
			rep.Records.DNSKEY = append(rep.Records.DNSKEY, DNSKEY{k.KeyTag(), k.Algorithm, k.Flags, k.Protocol})
		}
		slices.SortFunc(rep.Records.DNSKEY, func(a, b DNSKEY) int {
			return cmp.Or(cmp.Compare(a.KeyTag, b.KeyTag), cmp.Compare(a.Flags, b.Flags), cmp.Compare(a.Algorithm, b.Algorithm))
		})
	}
	dss := answers[*dns.DS](dsM, zone)
	dsCheck, dsRecs, anchors := checkDS(root, dss, keys)
	rep.Records.DS = dsRecs
	keyCheck, keySigs := checkSigs("dnskey.signatures", zone, dns.TypeDNSKEY, keyM, keys, anchors, r.now)
	soaCheck, soaSigs := checkSigs("soa.signatures", zone, dns.TypeSOA, soaM, keys, nil, r.now)
	if keySigs != nil || soaSigs != nil {
		rep.Records.RRSIG = append(append([]RRSIG{}, keySigs...), soaSigs...)
	}
	expiry := checkExpiry(rep.Records.RRSIG, cfg.WarnExpiry, r.now)
	if expiry.Result == Warn {
		rep.Warnings = append(rep.Warnings, expiry.Evidence)
	}
	rep.Checks = []Check{
		checkResolver(cfg.Trusted, soaR, keyR),
		dsCheck,
		checkKeysPresent(keyM, keys, dss),
		keyCheck,
		soaCheck,
		expiry,
	}

	f := facts{
		trusted: cfg.Trusted, root: root,
		soa: soaR, dnskey: keyR, ds: dsR,
		delegation: len(answers[*dns.SOA](soaM, zone)) > 0 && len(rep.Records.NS) > 0,
		dsNoData:   isNoData(dsM, zone),
		dsMatch:    dsCheck.Result, dnskeySigs: keyCheck.Result, soaSigs: soaCheck.Result,
	}
	rep.Status, rep.Summary = classify(f)
	if rep.Status == Insecure && len(keys) > 0 {
		rep.Warnings = append(rep.Warnings, "the zone publishes DNSKEY records but the parent has no DS for it: possible island of trust; its signatures are not trusted by validators")
	}
}

// ask sends a CD=0 query. On SERVFAIL it repeats the query with CD=1 to collect
// diagnostic data. The returned Response is always the CD=0 one: a CD=1 answer never
// counts as validation by the resolver.
func (r *run) ask(ctx context.Context, name string, qtype uint16) (*Response, *dns.Msg) {
	q := r.record(r.c.query(ctx, name, qtype, false))
	if q.Response == nil || q.msg.Rcode != dns.RcodeServerFailure {
		return q.Response, q.msg
	}
	d := r.record(r.c.query(ctx, name, qtype, true))
	if d.msg == nil || (d.msg.Rcode != dns.RcodeSuccess && d.msg.Rcode != dns.RcodeNameError) {
		return q.Response, nil
	}
	if w := fmt.Sprintf("SERVFAIL for %s %s; records shown for it come from a CD=1 query and were not validated by the resolver", name, q.Type); !slices.Contains(r.rep.Warnings, w) {
		r.rep.Warnings = append(r.rep.Warnings, w)
	}
	return q.Response, d.msg
}

func (r *run) record(q Query) Query {
	r.rep.Queries = append(r.rep.Queries, q)
	if q.Error != "" {
		r.rep.Errors = append(r.rep.Errors, fmt.Sprintf("%s %s (CD=%d): %s", q.Name, q.Type, b2i(q.CD), q.Error))
	}
	if q.msg != nil {
		for _, rr := range slices.Concat(q.msg.Answer, q.msg.Ns) {
			switch rr.Header().Rrtype {
			case dns.TypeNSEC:
				r.rep.Records.NSEC = true
			case dns.TypeNSEC3:
				r.rep.Records.NSEC3 = true
			}
		}
	}
	return q
}

// findZone finds the zone that contains name from SOA answers, walking towards the root
// only when an answer does not place the name in a zone. For an alias the authority SOA
// belongs to the target, so the walk starts at the parent of the alias.
func (r *run) findZone(ctx context.Context, name string) string {
	_, m := r.ask(ctx, name, dns.TypeSOA)
	if m == nil {
		r.rep.Errors = append(r.rep.Errors, "could not determine the zone of "+name)
		return ""
	}
	if m.Rcode == dns.RcodeSuccess || m.Rcode == dns.RcodeNameError {
		exists := m.Rcode == dns.RcodeSuccess
		r.rep.NameExists = &exists
	}
	if chain := r.aliasChain(m, name); len(chain) > 0 {
		exists := true
		r.rep.NameExists = &exists
		r.rep.Records.AliasChain = chain
	} else if z := zoneOf(m, name); z != "" {
		return z
	}
	for p := name; p != "."; {
		p = parent(p)
		_, m := r.ask(ctx, p, dns.TypeSOA)
		if m == nil {
			break
		}
		if z := zoneOf(m, p); z != "" {
			return z
		}
	}
	r.rep.Errors = append(r.rep.Errors, "could not determine the zone of "+name)
	return ""
}

// zoneOf returns the zone that m places name in: an SOA owned by name in the answer, or,
// for a negative answer, an SOA in authority owned by name or one of its ancestors.
func zoneOf(m *dns.Msg, name string) string {
	if s := answers[*dns.SOA](m, name); len(s) > 0 {
		return name
	}
	if len(m.Answer) > 0 || (m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) {
		return ""
	}
	for _, rr := range m.Ns {
		if s, ok := rr.(*dns.SOA); ok && dns.IsSubDomain(s.Hdr.Name, name) {
			return strings.ToLower(s.Hdr.Name)
		}
	}
	return ""
}

func (r *run) aliasChain(m *dns.Msg, name string) []string {
	targets := map[string]string{}
	for _, rr := range m.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			targets[strings.ToLower(c.Hdr.Name)] = strings.ToLower(c.Target)
		}
	}
	chain := []string{}
	seen := map[string]bool{name: true}
	for cur := name; ; {
		next, ok := targets[cur]
		switch {
		case !ok:
			return chain
		case seen[next]:
			r.rep.Warnings = append(r.rep.Warnings, "alias loop detected at "+next)
			return chain
		case len(chain) == maxAliases:
			r.rep.Warnings = append(r.rep.Warnings, fmt.Sprintf("alias chain longer than %d; stopped following it", maxAliases))
			return chain
		}
		seen[next] = true
		chain = append(chain, next)
		cur = next
	}
}

func parent(name string) string {
	if i, end := dns.NextLabel(name, 0); !end {
		return name[i:]
	}
	return "."
}

// answers returns the records of type T owned by owner in the answer section; nil when
// there is no message at all, so that "unknown" differs from "none".
func answers[T dns.RR](m *dns.Msg, owner string) []T {
	if m == nil {
		return nil
	}
	out := []T{}
	for _, rr := range m.Answer {
		if t, ok := rr.(T); ok && strings.EqualFold(rr.Header().Name, owner) {
			out = append(out, t)
		}
	}
	return out
}

// isNoData reports a NOERROR/NODATA DS answer that carries the SOA of a proper ancestor
// of zone, that is, a negative answer from the parent side. An empty answer alone is not
// enough.
func isNoData(m *dns.Msg, zone string) bool {
	if m == nil || m.Rcode != dns.RcodeSuccess || len(m.Answer) > 0 {
		return false
	}
	for _, rr := range m.Ns {
		if s, ok := rr.(*dns.SOA); ok && dns.IsSubDomain(s.Hdr.Name, zone) && !strings.EqualFold(s.Hdr.Name, zone) {
			return true
		}
	}
	return false
}

func isZoneKey(k *dns.DNSKEY) bool { return k.Flags&dns.ZONE != 0 && k.Protocol == 3 }

// checkDS compares every DS with every zone key by algorithm, key tag and computed
// digest. One matching DS is enough (rollover); colliding key tags are all tried.
// It returns the DS-referenced keys.
func checkDS(root bool, dss []*dns.DS, keys []*dns.DNSKEY) (Check, []DS, []*dns.DNSKEY) {
	c := Check{ID: "ds.match", Description: "A DS record at the parent matches a DNSKEY of the zone"}
	switch {
	case root:
		c.Result, c.Evidence = NA, "the root zone has no parent DS"
		return c, nil, nil
	case dss == nil:
		c.Result, c.Evidence = Unknown, "no usable answer to the DS query"
		return c, nil, nil
	case len(dss) == 0:
		c.Result, c.Evidence = NA, "no DS records were returned for the zone"
		return c, []DS{}, nil
	}
	out := []DS{}
	var matched []*dns.DNSKEY
	var tags []string
	unsupported := 0
	for _, d := range dss {
		e := DS{d.KeyTag, d.Algorithm, d.DigestType, strings.ToUpper(d.Digest), "no_match"}
		if keys == nil {
			e.Match = "unknown"
		}
		for _, k := range keys {
			if !isZoneKey(k) || k.Algorithm != d.Algorithm || k.KeyTag() != d.KeyTag {
				continue
			}
			got := k.ToDS(d.DigestType)
			if got == nil {
				e.Match = "unsupported_digest"
				unsupported++
				break
			}
			if strings.EqualFold(got.Digest, d.Digest) {
				e.Match = "match"
				matched = append(matched, k)
				tags = append(tags, fmt.Sprint(d.KeyTag))
				break
			}
		}
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b DS) int {
		return cmp.Or(cmp.Compare(a.KeyTag, b.KeyTag), cmp.Compare(a.Algorithm, b.Algorithm),
			cmp.Compare(a.DigestType, b.DigestType), strings.Compare(a.Digest, b.Digest))
	})
	c.Evidence = fmt.Sprintf("%d of %d DS records match a DNSKEY", len(matched), len(dss))
	switch {
	case len(matched) > 0:
		c.Result = Pass
		c.Evidence += " (key tags " + strings.Join(tags, ", ") + ")"
	case keys == nil:
		c.Result, c.Evidence = Unknown, "DS records found, but no usable answer to the DNSKEY query"
	case unsupported > 0:
		c.Result = Unknown
		c.Evidence += fmt.Sprintf("; %d use a digest type this tool cannot compute", unsupported)
	default:
		c.Result = Fail
		c.Suggestion = "If other resolvers show the same data, compare the DS records at the parent with the zone's current DNSKEY records; a DS left over from a key rollover is a common cause."
	}
	return c, out, matched
}

// checkSigs verifies the RRSIGs over the zone's RRset of type covered. One valid and
// current signature is enough; old extra signatures do not invalidate it. When anchors
// is set, the passing signature must come from one of those keys.
func checkSigs(id, zone string, covered uint16, m *dns.Msg, keys, anchors []*dns.DNSKEY, now time.Time) (Check, []RRSIG) {
	t := dns.TypeToString[covered]
	c := Check{ID: id, Description: t + " RRset has a valid, current signature from a zone key"}
	if m == nil {
		c.Result, c.Evidence = Unknown, "no usable answer to the "+t+" query"
		return c, nil
	}
	var set []dns.RR
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == covered && strings.EqualFold(rr.Header().Name, zone) {
			set = append(set, rr)
		}
	}
	if len(set) == 0 {
		c.Result, c.Evidence = NA, "no "+t+" RRset to check"
		return c, nil
	}
	sigs := []RRSIG{}
	for _, rr := range m.Answer {
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == covered && strings.EqualFold(s.Hdr.Name, zone) {
			sigs = append(sigs, evalSig(s, zone, set, keys, now))
		}
	}
	slices.SortFunc(sigs, func(a, b RRSIG) int {
		return cmp.Or(cmp.Compare(a.KeyTag, b.KeyTag), cmp.Compare(a.expiry, b.expiry), strings.Compare(a.Signature, b.Signature))
	})
	if len(sigs) == 0 {
		if len(keys) == 0 {
			c.Result, c.Evidence = NA, "the zone publishes no DNSKEY and the "+t+" RRset is unsigned"
		} else {
			c.Result, c.Evidence = Fail, "no RRSIG covers the "+t+" RRset"
		}
		return c, sigs
	}
	var good, anchored, cryptoOK, undetermined int
	for _, s := range sigs {
		switch s.Signature {
		case "valid":
			cryptoOK++
			if s.Time == "valid" {
				good++
				if anchors == nil || slices.Contains(anchors, s.key) {
					anchored++
				}
			}
		case "unsupported", "no_key":
			undetermined++
		}
	}
	c.Evidence = fmt.Sprintf("%d of %d signatures are cryptographically valid and current", good, len(sigs))
	switch {
	case anchored > 0:
		c.Result = Pass
	case good > 0:
		c.Result = Fail
		c.Evidence += "; none was made by a key referenced by a DS record"
	case cryptoOK > 0:
		c.Result = Fail
		c.Evidence += "; the cryptographically valid ones are outside their validity period"
		c.Suggestion = "Check that the zone signer is running and re-signing the zone, and that its clock is correct."
	case undetermined > 0:
		c.Result = Unknown
		c.Evidence += "; some could not be verified locally (unsupported algorithm or no matching key)"
	default:
		c.Result = Fail
	}
	return c, sigs
}

func evalSig(s *dns.RRSIG, zone string, set []dns.RR, keys []*dns.DNSKEY, now time.Time) RRSIG {
	// ponytail: uint32 RRSIG times read as Unix seconds, correct until 2106.
	inc, exp := time.Unix(int64(s.Inception), 0).UTC(), time.Unix(int64(s.Expiration), 0).UTC()
	e := RRSIG{
		Covers: dns.TypeToString[s.TypeCovered], Signer: strings.ToLower(s.SignerName), KeyTag: s.KeyTag,
		Algorithm: s.Algorithm, Inception: inc.Format(time.RFC3339), Expiration: exp.Format(time.RFC3339),
		Signature: "no_key", Time: "valid", ExpiresIn: exp.Sub(now).Round(time.Second).String(), expiry: exp.Unix(),
	}
	switch {
	case s.ValidityPeriod(now):
	case now.Before(inc):
		e.Time = "not_yet_valid"
	default:
		e.Time = "expired"
	}
	if !strings.EqualFold(s.SignerName, zone) {
		e.Signature = "wrong_signer"
		return e
	}
	for _, k := range keys {
		if !isZoneKey(k) || k.Algorithm != s.Algorithm || k.KeyTag() != s.KeyTag {
			continue
		}
		err := s.Verify(k, set)
		switch {
		case err == nil:
			e.Signature, e.key = "valid", k
			return e
		case errors.Is(err, dns.ErrAlg):
			e.Signature = "unsupported"
		case e.Signature != "unsupported":
			e.Signature = "invalid"
		}
	}
	return e
}

func checkExpiry(sigs []RRSIG, warn time.Duration, now time.Time) Check {
	c := Check{ID: "signatures.expiry", Description: fmt.Sprintf("Valid signatures do not expire within %s", warn)}
	best := map[string]int64{}
	for _, s := range sigs {
		if s.Signature == "valid" && s.Time == "valid" && s.expiry > best[s.Covers] {
			best[s.Covers] = s.expiry
		}
	}
	if len(best) == 0 {
		c.Result, c.Evidence = NA, "no valid, current signature to evaluate"
		return c
	}
	c.Result = Pass
	var parts []string
	for _, t := range slices.Sorted(maps.Keys(best)) {
		exp := time.Unix(best[t], 0).UTC()
		left := exp.Sub(now)
		parts = append(parts, fmt.Sprintf("%s signature expires %s (in %s)", t, exp.Format(time.RFC3339), left.Round(time.Second)))
		if left < warn {
			c.Result = Warn
		}
	}
	c.Evidence = "latest valid " + strings.Join(parts, "; ")
	if c.Result == Warn {
		c.Suggestion = "Make sure the zone is re-signed before the signatures expire; this alone does not make the zone bogus."
	}
	return c
}

func checkResolver(trusted bool, soa, key *Response) Check {
	c := Check{ID: "resolver.validation", Description: "Resolver authenticated SOA and DNSKEY (AD=1)"}
	if soa == nil || key == nil {
		c.Result, c.Evidence = Unknown, "no reply to the SOA or DNSKEY query"
		return c
	}
	c.Evidence = fmt.Sprintf("SOA %s AD=%d, DNSKEY %s AD=%d", soa.Rcode, b2i(soa.AD), key.Rcode, b2i(key.AD))
	switch {
	case soa.Rcode == "SERVFAIL" || key.Rcode == "SERVFAIL":
		c.Result = Unknown
		if trusted && (bogusEDE(soa) != nil || bogusEDE(key) != nil) {
			c.Result = Fail
		}
	case soa.AD && key.AD && trusted:
		c.Result = Pass
	case soa.AD && key.AD:
		c.Result = Unknown
		c.Evidence += "; the resolver is not trusted (see --trust-resolver)"
	default:
		c.Result = Unknown
	}
	return c
}

func checkKeysPresent(m *dns.Msg, keys []*dns.DNSKEY, dss []*dns.DS) Check {
	c := Check{ID: "dnskey.present", Description: "The zone publishes DNSKEY records"}
	switch {
	case m == nil:
		c.Result, c.Evidence = Unknown, "no usable answer to the DNSKEY query"
	case len(keys) > 0:
		c.Result, c.Evidence = Pass, fmt.Sprintf("%d DNSKEY records", len(keys))
	case len(dss) > 0:
		c.Result, c.Evidence = Fail, "the parent publishes DS records but the zone returned no DNSKEY"
		c.Suggestion = "A signed delegation needs the zone to publish the DNSKEY referenced by the DS records."
	default:
		c.Result, c.Evidence = NA, "no DNSKEY records and no DS records: the zone appears unsigned"
	}
	return c
}

// bogusEDE returns the first EDE code that reports a DNSSEC validation failure
// (RFC 8914 codes 6-12). Codes such as 1/2 (unsupported algorithm/digest, which make a
// zone insecure) and 5 (indeterminate) are deliberately excluded.
func bogusEDE(r *Response) *EDE {
	for i, e := range r.EDE {
		if e.Code >= dns.ExtendedErrorCodeDNSBogus && e.Code <= dns.ExtendedErrorCodeNSECMissing {
			return &r.EDE[i]
		}
	}
	return nil
}

type facts struct {
	trusted, root bool
	delegation    bool      // SOA and NS found at the zone apex
	dsNoData      bool      // DS answer is NOERROR/NODATA with the parent's SOA
	soa, dnskey   *Response // CD=0 replies; nil when no reply was received
	ds            *Response
	dsMatch       Result
	dnskeySigs    Result
	soaSigs       Result
}

// classify turns the evidence into a status. SECURE and INSECURE need a trusted resolver;
// local checks can only block them, never produce BOGUS on their own.
func classify(f facts) (Status, string) {
	type reply struct {
		what string
		r    *Response
	}
	replies := []reply{{"SOA", f.soa}, {"DNSKEY", f.dnskey}}
	if !f.root {
		replies = append(replies, reply{"DS", f.ds})
	}
	for _, x := range replies {
		if x.r == nil || x.r.Rcode != "SERVFAIL" {
			continue
		}
		if e := bogusEDE(x.r); e != nil {
			if f.trusted {
				return Bogus, fmt.Sprintf("The trusted resolver reported a DNSSEC validation failure: SERVFAIL with EDE %d (%s) for %s.", e.Code, e.Name, x.what)
			}
			return Indeterminate, fmt.Sprintf("The resolver reported a DNSSEC validation failure (EDE %d for %s), but it is not trusted; rerun against a trusted validating resolver with --trust-resolver.", e.Code, x.what)
		}
	}
	for _, x := range replies {
		if x.r == nil {
			return Indeterminate, "No reply to the " + x.what + " query; the DNSSEC status cannot be determined."
		}
		if x.r.Rcode == "SERVFAIL" {
			return Indeterminate, "SERVFAIL for " + x.what + " without a DNSSEC-specific EDE: a DNSSEC failure is possible but not proven."
		}
	}
	if !f.trusted {
		return Indeterminate, "The resolver is not trusted, so its AD bit is only an observation; local checks alone cannot prove the chain of trust. Use --trust-resolver with a validating resolver you trust."
	}
	if f.soa.AD && f.dnskey.AD && f.soa.Rcode == "NOERROR" && f.dnskey.Rcode == "NOERROR" {
		if (f.root || f.dsMatch == Pass) && f.dnskeySigs == Pass && f.soaSigs == Pass {
			return Secure, "The trusted resolver validated SOA and DNSKEY (AD=1) and the local DS/DNSKEY/RRSIG checks agree. This covers the checked zone and RRsets only."
		}
		return Indeterminate, fmt.Sprintf("The resolver set AD=1, but local checks disagree or are incomplete (ds.match %s, dnskey.signatures %s, soa.signatures %s); answers or caches may be inconsistent.", f.dsMatch, f.dnskeySigs, f.soaSigs)
	}
	if !f.root && f.delegation && f.dsNoData && f.ds.AD && !f.soa.AD && !f.dnskey.AD {
		return Insecure, "The trusted resolver authenticated that the parent has no DS for the zone (NOERROR/NODATA, AD=1): the zone is not protected by DNSSEC. This is not a DNS failure."
	}
	if f.dsNoData && !f.ds.AD {
		return Indeterminate, "The parent returned no DS for the zone, but without AD=1 (for example an NSEC3 opt-out proof), so the absence of DNSSEC protection is not authenticated."
	}
	return Indeterminate, "The resolver did not authenticate the zone (AD=0) and the absence of a DS record was not proven; the zone may be unsigned or below an unsigned parent, which this tool cannot confirm."
}
