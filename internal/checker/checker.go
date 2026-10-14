// Package checker validates the DNSSEC chain of trust of the zone that contains one name,
// locally, from the IANA root trust anchor down (RFC 4033-4035, RFC 5155).
package checker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

const maxAliases = 8

// RootAnchors are the root zone trust anchors published by IANA in
// https://data.iana.org/root-anchors/root-anchors.xml (KSK-2017 and KSK-2024).
var RootAnchors = []*dns.DS{
	mustDS(". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
	mustDS(". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
}

func mustDS(s string) *dns.DS {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr.(*dns.DS)
}

type Config struct {
	Resolver   string // host:port, see ParseResolver
	Timeout    time.Duration
	WarnExpiry time.Duration
	Now        func() time.Time // clock for signature validity; time.Now when nil
	MaxQueries int              // packets per run; maxQueries when 0
	Anchors    []*dns.DS        // root trust anchors; RootAnchors when nil
}

// Algorithms and DS digest types this tool validates (RFC 8624). A zone whose DS
// records use none of them is treated as insecure (RFC 4035 section 5.2).
var (
	supportedAlg = map[uint8]bool{
		dns.RSASHA1: true, dns.RSASHA1NSEC3SHA1: true, dns.RSASHA256: true, dns.RSASHA512: true,
		dns.ECDSAP256SHA256: true, dns.ECDSAP384SHA384: true, dns.ED25519: true,
	}
	supportedDigest = map[uint8]bool{dns.SHA1: true, dns.SHA256: true, dns.SHA384: true}
)

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
	if cfg.Anchors == nil {
		cfg.Anchors = RootAnchors
	}
	start := time.Now()
	r := &run{
		cfg: cfg,
		c:   &client{server: cfg.Resolver, timeout: cfg.Timeout, maxQueries: cfg.MaxQueries},
		now: cfg.Now().UTC(),
		rep: &Report{
			SchemaVersion: 2, Domain: domain, NormalizedDomain: name, Status: Indeterminate,
			AliasChain: []string{}, Chain: []Step{}, Resolver: Resolver{Address: cfg.Resolver},
			Queries: []Query{}, Warnings: []string{}, Errors: []string{},
		},
	}
	r.rep.CheckedAt = r.now.Format(time.RFC3339)
	if zone := r.findZone(ctx, name); zone == "" {
		r.rep.Summary = "The zone of " + name + " could not be determined, so DNSSEC could not be checked."
	} else {
		r.rep.Zone = &zone
		r.rep.Status, r.rep.Summary = r.validate(ctx, zone)
		r.nameServers(ctx, zone)
		r.resolverView(ctx, zone)
	}
	if ctx.Err() != nil {
		r.rep.Errors = append(r.rep.Errors, fmt.Sprintf("run stopped early (%v); the report is partial", ctx.Err()))
	}
	r.rep.DNSSEC = statuses[r.rep.Status].verdict
	r.rep.DurationMS = time.Since(start).Milliseconds()
	return r.rep, nil
}

type run struct {
	cfg Config
	c   *client
	now time.Time
	rep *Report
}

// q sends a CD=1 query, so that the resolver passes data through even when its own
// validation fails; all validation is done here. It returns nil unless the answer is
// NOERROR or NXDOMAIN.
func (r *run) q(ctx context.Context, name string, qtype uint16) *dns.Msg {
	q := r.record(r.c.query(ctx, name, qtype, true))
	if q.msg != nil && q.msg.Rcode != dns.RcodeSuccess && q.msg.Rcode != dns.RcodeNameError {
		r.rep.Errors = append(r.rep.Errors, fmt.Sprintf("%s %s: the resolver answered %s", name, q.Type, q.Response.Rcode))
		return nil
	}
	return q.msg
}

func (r *run) record(q Query) Query {
	r.rep.Queries = append(r.rep.Queries, q)
	if q.Error != "" {
		r.rep.Errors = append(r.rep.Errors, fmt.Sprintf("%s %s: %s", q.Name, q.Type, q.Error))
	}
	return q
}

func (r *run) step(zone, result, detail string, records []string) {
	if records == nil {
		records = []string{}
	}
	r.rep.Chain = append(r.rep.Chain, Step{zone, result, detail, records})
}

// validate walks from the root to zone. At every label it asks for DS: a validly signed
// DS leads to the child's DNSKEY set; a signed NSEC/NSEC3 proof shows either that the
// label is not a delegation (keep walking) or an insecure delegation (stop).
func (r *run) validate(ctx context.Context, zone string) (Status, string) {
	keys, st, why := r.zoneKeys(ctx, ".", "", r.cfg.Anchors, nil)
	if st != "" {
		return st, why
	}
	cur := "."
	labels := dns.SplitDomainName(zone)
	for i := len(labels) - 1; i >= 0; i-- {
		name := dns.Fqdn(strings.Join(labels[i:], "."))
		m := r.q(ctx, name, dns.TypeDS)
		if m == nil {
			r.step(name, StepError, "no usable answer to the DS query", nil)
			return Indeterminate, "The DS query for " + name + " failed, so the chain of trust could not be followed."
		}
		if dss := answers[*dns.DS](m, name); len(dss) > 0 {
			_, sig, why := verify(m.Answer, name, dns.TypeDS, cur, keys, r.now)
			ev := rrLines(dss)
			if sig == nil {
				r.step(name, StepFail, "DS in "+cur+" is not validly signed: "+why, ev)
				return Bogus, fmt.Sprintf("The DS record of %s in %s is not validly signed (%s), so DNSSEC validation fails.", name, cur, why)
			}
			if keys, st, why = r.zoneKeys(ctx, name, cur, dss, append(ev, sigLine(sig))); st != "" {
				return st, why
			}
			cur = name
			continue
		}
		switch kind, proof, ev := denyDS(m, name, cur, keys, r.now); kind {
		case notDelegation:
			continue
		case insecureDelegation:
			r.step(name, StepInsecure, "no DS in "+cur+"; the absence is proven by a signed "+proof+" record", ev)
			if name == zone {
				return Insecure, fmt.Sprintf("%s is not signed: its parent %s proves with a signed record that there is no DS for it.", zone, cur)
			}
			return Insecure, fmt.Sprintf("%s is not protected by DNSSEC: it is below %s, which is not signed (%s proves there is no DS for it).", zone, name, cur)
		default:
			r.step(name, StepFail, "no DS in "+cur+" and no valid signed proof that it is absent", ev)
			return Bogus, fmt.Sprintf("%s is signed, but it neither has a DS record for %s nor a valid signed proof that there is none.", cur, name)
		}
	}
	if cur != zone {
		r.step(zone, StepFail, "the parent zone "+cur+" proves that "+zone+" is not a delegation", nil)
		return Bogus, fmt.Sprintf("%s has an SOA record, but its signed parent %s proves it is not a delegation.", zone, cur)
	}
	m := r.q(ctx, zone, dns.TypeSOA)
	if m == nil {
		r.step(zone, StepError, "no usable answer to the SOA query", nil)
		return Indeterminate, "The SOA query for " + zone + " failed."
	}
	set, sig, why := verify(m.Answer, zone, dns.TypeSOA, zone, keys, r.now)
	ev := rrLines(set)
	if sig == nil {
		r.step(zone, StepFail, "SOA is not validly signed: "+why, ev)
		return Bogus, fmt.Sprintf("The SOA record of %s is not validly signed (%s), so DNSSEC validation fails.", zone, why)
	}
	r.step(zone, StepOK, fmt.Sprintf("SOA signed by key %d, valid until %s", sig.KeyTag, ts(sig.Expiration)), append(ev, sigLine(sig)))
	r.warnExpiry(zone, sig)
	return Secure, fmt.Sprintf("DNSSEC is enabled and valid: every link from the IANA root key to the SOA record of %s verifies.", zone)
}

// zoneKeys fetches the DNSKEY set of zone and checks it against the DS records (or the
// trust anchors for the root): a DNSKEY must match a DS by algorithm, key tag and digest,
// and that key must sign the DNSKEY set. It returns the zone's keys, now trusted.
func (r *run) zoneKeys(ctx context.Context, zone, parentZone string, dss []*dns.DS, ev []string) ([]*dns.DNSKEY, Status, string) {
	from := "DS"
	if zone == "." {
		from = "trust anchor"
	}
	usable := slices.DeleteFunc(slices.Clone(dss), func(d *dns.DS) bool {
		return !supportedAlg[d.Algorithm] || !supportedDigest[d.DigestType]
	})
	if len(usable) == 0 {
		r.step(zone, StepInsecure, "every DS uses an algorithm or digest type this tool cannot validate; treated as insecure (RFC 4035 section 5.2)", ev)
		return nil, Insecure, fmt.Sprintf("%s uses only DNSSEC algorithms or digest types this tool does not support; validators treat such zones as insecure.", zone)
	}
	m := r.q(ctx, zone, dns.TypeDNSKEY)
	if m == nil {
		r.step(zone, StepError, "no usable answer to the DNSKEY query", ev)
		return nil, Indeterminate, "The DNSKEY query for " + zone + " failed, so the chain of trust could not be followed."
	}
	if zone == "." && !slices.ContainsFunc(m.Answer, func(rr dns.RR) bool { return rr.Header().Rrtype == dns.TypeRRSIG }) {
		r.step(zone, StepError, "the resolver returned no RRSIG records", nil)
		return nil, Indeterminate, "The resolver does not pass DNSSEC records (no RRSIG for the root DNSKEY set); use another resolver with --resolver."
	}
	all := answers[*dns.DNSKEY](m, zone)
	for _, k := range all {
		ev = append(ev, keyLine(k))
	}
	if len(all) == 0 {
		r.step(zone, StepFail, "the parent has a DS record, but the zone publishes no DNSKEY", ev)
		return nil, Bogus, fmt.Sprintf("%s has a DS record in its parent but publishes no DNSKEY, so DNSSEC validation fails.", zone)
	}
	var matched []*dns.DNSKEY
	for _, d := range usable {
		for _, k := range all {
			if isZoneKey(k) && k.Algorithm == d.Algorithm && k.KeyTag() == d.KeyTag && strings.EqualFold(k.ToDS(d.DigestType).Digest, d.Digest) {
				matched = append(matched, k)
			}
		}
	}
	if len(matched) == 0 {
		r.step(zone, StepFail, "no DNSKEY matches the "+from+" records (key tag "+tags(usable)+")", ev)
		return nil, Bogus, fmt.Sprintf("No DNSKEY of %s matches its %s records (key tag %s), so DNSSEC validation fails. A DS left over from a key rollover is a common cause.", zone, from, tags(usable))
	}
	_, sig, why := verify(m.Answer, zone, dns.TypeDNSKEY, zone, matched, r.now)
	if sig == nil {
		r.step(zone, StepFail, "the DNSKEY set is not validly signed by the key the "+from+" points to: "+why, ev)
		return nil, Bogus, fmt.Sprintf("The DNSKEY set of %s is not validly signed by the key its %s points to (%s), so DNSSEC validation fails.", zone, from, why)
	}
	detail := fmt.Sprintf("DS %d in %s → DNSKEY %d; DNSKEY set signed by key %d", sig.KeyTag, parentZone, sig.KeyTag, sig.KeyTag)
	if zone == "." {
		detail = fmt.Sprintf("DNSKEY %d matches the IANA root trust anchor; DNSKEY set signed by key %d", sig.KeyTag, sig.KeyTag)
	}
	r.step(zone, StepOK, detail, append(ev, sigLine(sig)))
	r.warnExpiry(zone, sig)
	return slices.DeleteFunc(all, func(k *dns.DNSKEY) bool { return !isZoneKey(k) }), "", ""
}

// verify returns the owner/t RRset from rrs and an RRSIG over it that is made by signer
// with one of keys, cryptographically valid and current. On failure sig is nil and why
// says what was wrong.
func verify(rrs []dns.RR, owner string, t uint16, signer string, keys []*dns.DNSKEY, now time.Time) (set []dns.RR, sig *dns.RRSIG, why string) {
	name := dns.TypeToString[t]
	var sigs []*dns.RRSIG
	for _, rr := range rrs {
		if !strings.EqualFold(rr.Header().Name, owner) {
			continue
		}
		if rr.Header().Rrtype == t {
			set = append(set, rr)
		} else if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == t {
			sigs = append(sigs, s)
		}
	}
	switch {
	case len(set) == 0:
		return nil, nil, "no " + name + " records"
	case len(sigs) == 0:
		return set, nil, "no RRSIG covers the " + name + " records"
	}
	why = "no trusted key with the RRSIG's key tag"
	for _, s := range sigs {
		if !strings.EqualFold(s.SignerName, signer) {
			why = fmt.Sprintf("signed by %s instead of %s", s.SignerName, signer)
			continue
		}
		for _, k := range keys {
			if k.KeyTag() != s.KeyTag || k.Algorithm != s.Algorithm {
				continue
			}
			switch err := s.Verify(k, set); {
			case err != nil:
				why = fmt.Sprintf("signature by key %d does not verify (%v)", s.KeyTag, err)
			case !s.ValidityPeriod(now):
				why = fmt.Sprintf("signature by key %d is valid only from %s to %s", s.KeyTag, ts(s.Inception), ts(s.Expiration))
			default:
				return set, s, ""
			}
		}
	}
	return set, nil, why
}

type denial int

const (
	noProof denial = iota
	notDelegation
	insecureDelegation
)

// denyDS checks a DS answer without DS records for a proof, signed by zone, that name has
// no DS: an NSEC or NSEC3 record at name (RFC 4035 section 5.4, RFC 5155 section 8.5),
// an NSEC that shows name is an empty non-terminal, or an NSEC3 opt-out span (RFC 5155
// section 8.6). The proof also tells whether name is a delegation at all. proof names
// the record type that proved it.
func denyDS(m *dns.Msg, name, zone string, keys []*dns.DNSKEY, now time.Time) (kind denial, proof string, ev []string) {
	var nsec []*dns.NSEC
	var nsec3 []*dns.NSEC3
	for _, rr := range m.Ns {
		owner, t := rr.Header().Name, rr.Header().Rrtype
		if t != dns.TypeNSEC && t != dns.TypeNSEC3 {
			continue
		}
		if t == dns.TypeNSEC3 && !strings.EqualFold(parent(owner), zone) {
			continue
		}
		if _, sig, _ := verify(m.Ns, owner, t, zone, keys, now); sig != nil {
			ev = append(ev, rrLine(rr), sigLine(sig))
			if n, ok := rr.(*dns.NSEC); ok {
				nsec = append(nsec, n)
			} else {
				nsec3 = append(nsec3, rr.(*dns.NSEC3))
			}
		}
	}
	byBitmap := func(types []uint16) denial {
		switch {
		case slices.Contains(types, dns.TypeDS):
			return noProof
		case slices.Contains(types, dns.TypeNS) && !slices.Contains(types, dns.TypeSOA):
			return insecureDelegation
		case !slices.Contains(types, dns.TypeNS):
			return notDelegation
		}
		return noProof // SOA at name: the answer came from the child, not the parent
	}
	for _, n := range nsec {
		if strings.EqualFold(n.Hdr.Name, name) {
			return byBitmap(n.TypeBitMap), "NSEC", ev
		}
		if canonicalLess(n.Hdr.Name, name) && dns.IsSubDomain(name, n.NextDomain) && !strings.EqualFold(n.NextDomain, name) {
			return notDelegation, "NSEC", ev // empty non-terminal: the next name is below name
		}
	}
	for _, n := range nsec3 {
		if n.Match(name) {
			return byBitmap(n.TypeBitMap), "NSEC3", ev
		}
	}
	next := name
	for ce := parent(name); dns.IsSubDomain(zone, ce); next, ce = ce, parent(ce) {
		if slices.ContainsFunc(nsec3, func(n *dns.NSEC3) bool { return n.Match(ce) }) {
			if slices.ContainsFunc(nsec3, func(n *dns.NSEC3) bool { return n.Flags&1 == 1 && n.Cover(next) }) {
				return insecureDelegation, "NSEC3 opt-out (RFC 5155)", ev
			}
			break
		}
		if strings.EqualFold(ce, zone) {
			break
		}
	}
	return noProof, "", ev
}

// canonicalLess orders names as in RFC 4034 section 6.1: label by label from the right.
func canonicalLess(a, b string) bool {
	la, lb := dns.SplitDomainName(strings.ToLower(a)), dns.SplitDomainName(strings.ToLower(b))
	for i := 1; i <= len(la) && i <= len(lb); i++ {
		if c := strings.Compare(la[len(la)-i], lb[len(lb)-i]); c != 0 {
			return c < 0
		}
	}
	return len(la) < len(lb)
}

// warnExpiry warns about a signature that expires within --warn-expiry and in less than
// a quarter of its validity period. The second condition keeps online signers, which
// issue short-lived signatures on every answer, from always warning.
func (r *run) warnExpiry(zone string, s *dns.RRSIG) {
	inc, exp := sigTime(s.Inception), sigTime(s.Expiration)
	if left := exp.Sub(r.now); left < r.cfg.WarnExpiry && left < exp.Sub(inc)/4 {
		r.rep.Warnings = append(r.rep.Warnings, fmt.Sprintf("the %s signature of %s (key %d) expires in %s, at %s",
			dns.TypeToString[s.TypeCovered], zone, s.KeyTag, left.Round(time.Minute), ts(s.Expiration)))
	}
}

func (r *run) nameServers(ctx context.Context, zone string) {
	if ns := answers[*dns.NS](r.q(ctx, zone, dns.TypeNS), zone); ns != nil {
		r.rep.NS = []string{}
		for _, n := range ns {
			r.rep.NS = append(r.rep.NS, strings.ToLower(n.Ns))
		}
		slices.Sort(r.rep.NS)
	}
}

// resolverView records the resolver's own validation (CD=0) of the zone SOA. It is only
// compared with the local result and never changes it.
func (r *run) resolverView(ctx context.Context, zone string) {
	q := r.record(r.c.query(ctx, zone, dns.TypeSOA, false))
	r.rep.Resolver.Response = q.Response
	if q.Response == nil {
		return
	}
	var agrees bool
	switch r.rep.Status {
	case Secure:
		agrees = q.Response.AD
	case Insecure:
		agrees = !q.Response.AD && q.Response.Rcode != "SERVFAIL"
	case Bogus:
		agrees = q.Response.Rcode == "SERVFAIL"
	default:
		return
	}
	r.rep.Resolver.Agrees = &agrees
	if !agrees {
		r.rep.Warnings = append(r.rep.Warnings, fmt.Sprintf("the resolver's own answer (%s, AD=%d) does not match the local result; it may not validate DNSSEC, or its cache differs", q.Response.Rcode, b2i(q.Response.AD)))
	}
}

// findZone finds the zone that contains name from SOA answers, walking towards the root
// only when an answer does not place the name in a zone. For an alias the authority SOA
// belongs to the target, so the walk starts at the parent of the alias.
func (r *run) findZone(ctx context.Context, name string) string {
	m := r.q(ctx, name, dns.TypeSOA)
	if m == nil {
		r.rep.Errors = append(r.rep.Errors, "could not determine the zone of "+name)
		return ""
	}
	chain := r.aliasChain(m, name)
	exists := m.Rcode == dns.RcodeSuccess || len(chain) > 0
	r.rep.NameExists, r.rep.AliasChain = &exists, chain
	if len(chain) == 0 {
		if z := zoneOf(m, name); z != "" {
			return z
		}
	}
	for p := name; p != "."; {
		p = parent(p)
		m := r.q(ctx, p, dns.TypeSOA)
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
	if len(m.Answer) > 0 {
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

func isZoneKey(k *dns.DNSKEY) bool { return k.Flags&dns.ZONE != 0 && k.Protocol == 3 }

func tags(dss []*dns.DS) string {
	var s []string
	for _, d := range dss {
		s = append(s, fmt.Sprint(d.KeyTag))
	}
	return strings.Join(s, ", ")
}

// ponytail: uint32 RRSIG times read as Unix seconds, correct until 2106.
func sigTime(t uint32) time.Time { return time.Unix(int64(t), 0).UTC() }

func ts(t uint32) string { return sigTime(t).Format("2006-01-02 15:04 UTC") }

// rrLine prints a record in zone file format without TTL and class.
func rrLine(rr dns.RR) string {
	h := rr.Header()
	return h.Name + " " + dns.TypeToString[h.Rrtype] + " " + strings.TrimPrefix(rr.String(), h.String())
}

func rrLines[T dns.RR](rrs []T) []string {
	out := []string{}
	for _, rr := range rrs {
		out = append(out, rrLine(rr))
	}
	return out
}

// keyLine prints a DNSKEY without its key material.
func keyLine(k *dns.DNSKEY) string {
	role := "ZSK"
	if k.Flags&dns.SEP != 0 {
		role = "KSK"
	}
	return fmt.Sprintf("%s DNSKEY %d %d %d (key tag %d, %s)", k.Hdr.Name, k.Flags, k.Protocol, k.Algorithm, k.KeyTag(), role)
}

func sigLine(s *dns.RRSIG) string {
	return fmt.Sprintf("%s RRSIG %s %d by %s key %d, valid %s to %s",
		s.Hdr.Name, dns.TypeToString[s.TypeCovered], s.Algorithm, s.SignerName, s.KeyTag, ts(s.Inception), ts(s.Expiration))
}
