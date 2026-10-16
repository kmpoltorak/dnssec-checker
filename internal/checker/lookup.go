package checker

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Lookup is the validation of the input name's own records of one type, following
// aliases into other zones.
type Lookup struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Result  string   `json:"result"` // ok, insecure, fail, error
	Detail  string   `json:"detail"`
	Records []string `json:"records"`
}

// checkName validates the A and AAAA answers of name, so that the verdict covers the name
// itself and not only its zone. A failed answer makes the status BOGUS; an answer that
// leads into an unsigned zone makes it INSECURE. An incomplete check is INDETERMINATE.
func (r *run) checkName(ctx context.Context, name, zone string) {
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		r.rep.Lookups = append(r.rep.Lookups, r.lookup(ctx, name, t))
	}
	for _, l := range r.rep.Lookups {
		if l.Result == StepError {
			r.rep.Warnings = append(r.rep.Warnings, fmt.Sprintf("the %s records of %s could not be checked: %s", l.Type, name, l.Detail))
		}
	}
	for _, want := range []string{StepFail, StepError, StepInsecure} {
		for _, l := range r.rep.Lookups {
			if l.Result != want {
				continue
			}
			if want == StepFail {
				r.rep.Status = Bogus
				r.rep.Summary = fmt.Sprintf("The zone %s validates, but the %s answer for %s does not: %s.", zone, l.Type, name, l.Detail)
				// A resolver that calls the same answer valid has validated it before it, or
				// something on the way, changed it: the zone cannot be blamed.
				q := r.record(r.c.query(ctx, name, dns.StringToType[l.Type], false))
				if q.Response != nil && q.Response.Rcode == "NOERROR" && q.Response.AD {
					r.rep.Status = Indeterminate
					r.rep.Summary = fmt.Sprintf("The zone %s validates, but the %s answer for %s received from the resolver does not (%s). "+
						"The resolver itself marks that answer as valid (AD=1), so the resolver or something on the way probably changes answers, "+
						"for example a DNS filter that drops records. Check again with another resolver using --resolver.", zone, l.Type, name, l.Detail)
				}
			} else if want == StepError {
				r.rep.Status = Indeterminate
				r.rep.Summary = fmt.Sprintf("The zone %s validates, but the %s answer for %s could not be checked: %s.", zone, l.Type, name, l.Detail)
			} else {
				r.rep.Status = Insecure
				r.rep.Summary = fmt.Sprintf("The zone %s is signed, but the %s answer for %s is not protected: %s.", zone, l.Type, name, l.Detail)
			}
			return
		}
	}
	r.rep.Summary = fmt.Sprintf("DNSSEC is enabled and valid: the chain of trust to %s and the A and AAAA answers for %s validate.", zone, name)
}

func (r *run) lookup(ctx context.Context, name string, qtype uint16) Lookup {
	l := Lookup{Name: name, Type: dns.TypeToString[qtype], Records: []string{}}
	m := r.q(ctx, name, qtype)
	if m == nil {
		l.Result, l.Detail = StepError, "no usable answer to the query"
		return l
	}
	var path []string // aliases followed, for the detail
	cur := name
	for range maxAliases + 1 {
		if set := rrset(m.Answer, cur, qtype); len(set) > 0 {
			r.positive(ctx, &l, m, cur, qtype, set)
			break
		}
		cn := answers[*dns.CNAME](m, cur)
		if len(cn) == 0 {
			r.negative(ctx, &l, m, cur, qtype)
			break
		}
		via, ok := r.alias(ctx, &l, m, cur, cn[0])
		if !ok {
			return l
		}
		cur = strings.ToLower(cn[0].Target)
		path = append(path, via+" to "+cur)
	}
	if l.Result == "" {
		l.Result, l.Detail = StepError, fmt.Sprintf("alias chain longer than %d", maxAliases)
	}
	if len(path) > 0 && l.Result == StepOK {
		l.Detail += "; followed " + strings.Join(path, ", ")
	}
	return l
}

// trusted returns the chain for owner, or fills l and returns false when the chain does
// not end in a signed zone.
func (r *run) trusted(ctx context.Context, l *Lookup, owner string) (trust, bool) {
	t := r.chain(ctx, owner)
	switch t.status {
	case "":
		return t, true
	case Insecure:
		l.Result, l.Detail = StepInsecure, fmt.Sprintf("%s is in an unsigned zone (no DS for %s)", owner, t.at)
	case Bogus:
		l.Result, l.Detail = StepFail, strings.TrimSuffix(t.why, ".")
	default:
		l.Result, l.Detail = StepError, strings.TrimSuffix(t.why, ".")
	}
	return t, false
}

func (r *run) positive(ctx context.Context, l *Lookup, m *dns.Msg, owner string, t uint16, set []dns.RR) {
	l.Records = append(l.Records, rrLines(set)...)
	z, ok := r.trusted(ctx, l, owner)
	if !ok {
		return
	}
	_, sig, why := verify(m.Answer, owner, t, z.zone, z.keys, r.now)
	if sig == nil {
		l.Result, l.Detail = StepFail, fmt.Sprintf("the %s records of %s are not validly signed (%s)", l.Type, owner, why)
		return
	}
	r.warnExpiry(owner, sig)
	l.Records = append(l.Records, sigLine(sig, r.now))
	l.Result, l.Detail = StepOK, fmt.Sprintf("%d record(s), signed by %s key %d", len(set), z.zone, sig.KeyTag)
	r.wildcard(l, m, owner, z, sig)
}

// wildcard checks the proof required for any wildcard expansion, including CNAMEs.
func (r *run) wildcard(l *Lookup, m *dns.Msg, owner string, z trust, sig *dns.RRSIG) bool {
	if labels := dns.SplitDomainName(owner); int(sig.Labels) < len(labels) {
		// Expanded from a wildcard: the name itself must be proven not to exist.
		ce := dns.Fqdn(strings.Join(labels[len(labels)-int(sig.Labels):], "."))
		p := collectProofs(m.Ns, z.zone, z.keys, r.now)
		l.Records = append(l.Records, p.ev...)
		if !p.noExactMatch(owner, ce) {
			l.Result, l.Detail = StepFail, fmt.Sprintf("the answer is expanded from *.%s, but there is no valid signed proof that %s does not exist", ce, owner)
			return false
		}
		l.Detail += fmt.Sprintf(", expanded from the wildcard *.%s", ce)
	}
	return true
}

// alias validates the CNAME at owner. A CNAME synthesized from a DNAME is unsigned
// (RFC 6672 section 5.3.1); then the DNAME is validated instead.
func (r *run) alias(ctx context.Context, l *Lookup, m *dns.Msg, owner string, cn *dns.CNAME) (string, bool) {
	l.Records = append(l.Records, rrLine(cn))
	if d := dnameFor(m, owner, cn.Target); d != nil && len(rrset(m.Answer, owner, dns.TypeRRSIG)) == 0 {
		l.Records = append(l.Records, rrLine(d))
		z, ok := r.trusted(ctx, l, d.Hdr.Name)
		if !ok {
			return "", false
		}
		_, sig, why := verify(m.Answer, d.Hdr.Name, dns.TypeDNAME, z.zone, z.keys, r.now)
		if sig == nil {
			l.Result, l.Detail = StepFail, fmt.Sprintf("the DNAME at %s is not validly signed (%s)", d.Hdr.Name, why)
			return "", false
		}
		r.warnExpiry(d.Hdr.Name, sig)
		l.Records = append(l.Records, sigLine(sig, r.now))
		return "DNAME " + strings.ToLower(d.Hdr.Name), true
	}
	z, ok := r.trusted(ctx, l, owner)
	if !ok {
		return "", false
	}
	_, sig, why := verify(m.Answer, owner, dns.TypeCNAME, z.zone, z.keys, r.now)
	if sig == nil {
		l.Result, l.Detail = StepFail, fmt.Sprintf("the CNAME at %s is not validly signed (%s)", owner, why)
		return "", false
	}
	r.warnExpiry(owner, sig)
	l.Records = append(l.Records, sigLine(sig, r.now))
	if !r.wildcard(l, m, owner, z, sig) {
		return "", false
	}
	return "CNAME", true
}

// dnameFor returns the DNAME in m that synthesizes the CNAME owner -> target.
func dnameFor(m *dns.Msg, owner, target string) *dns.DNAME {
	for _, rr := range m.Answer {
		d, ok := rr.(*dns.DNAME)
		if ok && dns.IsSubDomain(d.Hdr.Name, owner) && !strings.EqualFold(d.Hdr.Name, owner) &&
			strings.EqualFold(owner[:len(owner)-len(d.Hdr.Name)]+d.Target, target) {
			return d
		}
	}
	return nil
}

func (r *run) negative(ctx context.Context, l *Lookup, m *dns.Msg, owner string, t uint16) {
	z, ok := r.trusted(ctx, l, owner)
	if !ok {
		return
	}
	p := collectProofs(m.Ns, z.zone, z.keys, r.now)
	l.Records = append(l.Records, p.ev...)
	if why := p.costly(); why != "" {
		l.Result, l.Detail = StepInsecure, why+", treated as insecure"
		return
	}
	if m.Rcode == dns.RcodeNameError {
		// An opt-out span here already ended the chain for owner as insecure.
		if via, ok, _ := p.nxDomain(owner); ok {
			l.Result, l.Detail = StepOK, owner+" does not exist (NXDOMAIN), proven by a signed "+via+" record"
		} else {
			l.Result, l.Detail = StepFail, "NXDOMAIN for "+owner+" without a valid signed proof"
		}
		return
	}
	if via, ok := p.noData(owner, t); ok {
		l.Result, l.Detail = StepOK, "no "+l.Type+" records, proven by a signed "+via+" record"
		return
	}
	l.Result, l.Detail = StepFail, "no "+l.Type+" records for "+owner+" and no valid signed proof of that"
}

// rrset returns the records of type t owned by owner.
func rrset(rrs []dns.RR, owner string, t uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype == t && strings.EqualFold(rr.Header().Name, owner) {
			out = append(out, rr)
		}
	}
	return out
}
