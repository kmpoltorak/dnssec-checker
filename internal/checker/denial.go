package checker

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// maxIterations is the NSEC3 iteration count above which a proof is treated as insecure,
// as RFC 9276 section 3.2 allows. 150 is the default of Unbound and BIND.
const maxIterations = 150

// proofs holds the NSEC and NSEC3 records of one answer that carry a valid signature by
// zone. NSEC3 records above maxIterations are set aside in tooCostly.
type proofs struct {
	zone      string
	nsec      []*dns.NSEC
	nsec3     []*dns.NSEC3
	tooCostly *dns.NSEC3
	ev        []string // the records and their signatures, for the report
}

func collectProofs(rrs []dns.RR, zone string, keys []*dns.DNSKEY, now time.Time) *proofs {
	p := &proofs{zone: zone}
	for _, rr := range rrs {
		owner, t := rr.Header().Name, rr.Header().Rrtype
		if t != dns.TypeNSEC && t != dns.TypeNSEC3 {
			continue
		}
		if t == dns.TypeNSEC3 && !strings.EqualFold(parent(owner), zone) {
			continue
		}
		_, sig, _ := verify(rrs, owner, t, zone, keys, now)
		if sig == nil {
			continue
		}
		p.ev = append(p.ev, rrLine(rr), sigLine(sig, now))
		switch n := rr.(type) {
		case *dns.NSEC:
			p.nsec = append(p.nsec, n)
		case *dns.NSEC3:
			if n.Iterations > maxIterations {
				p.tooCostly = n
			} else {
				p.nsec3 = append(p.nsec3, n)
			}
		}
	}
	return p
}

// costly explains why the proof is treated as insecure, or returns "".
func (p *proofs) costly() string {
	if p.tooCostly == nil {
		return ""
	}
	return fmt.Sprintf("NSEC3 with %d iterations, above the RFC 9276 limit of %d", p.tooCostly.Iterations, maxIterations)
}

func (p *proofs) nsecAt(name string) *dns.NSEC {
	for _, n := range p.nsec {
		if strings.EqualFold(n.Hdr.Name, name) {
			return n
		}
	}
	return nil
}

// nsecCovering returns an NSEC whose span (owner, next) contains name. The last NSEC of
// a zone points back to the apex and covers everything after its owner.
func (p *proofs) nsecCovering(name string) *dns.NSEC {
	for _, n := range p.nsec {
		if canonicalLess(n.Hdr.Name, name) && (canonicalLess(name, n.NextDomain) || !canonicalLess(n.Hdr.Name, n.NextDomain)) {
			return n
		}
	}
	return nil
}

// emptyNonTerminal reports an NSEC showing that name exists only because names below it
// do: the NSEC before name points to a descendant of name.
func (p *proofs) emptyNonTerminal(name string) bool {
	for _, n := range p.nsec {
		if canonicalLess(n.Hdr.Name, name) && dns.IsSubDomain(name, n.NextDomain) && !strings.EqualFold(n.NextDomain, name) {
			return true
		}
	}
	return false
}

func (p *proofs) nsec3At(name string) *dns.NSEC3 {
	for _, n := range p.nsec3 {
		if n.Match(name) {
			return n
		}
	}
	return nil
}

func (p *proofs) nsec3Covering(name string) *dns.NSEC3 {
	for _, n := range p.nsec3 {
		if n.Cover(name) {
			return n
		}
	}
	return nil
}

// closestEncloser is the closest encloser proof of RFC 5155 section 8.3: an NSEC3 that
// matches an ancestor of name and one that covers the next closer name below it.
func (p *proofs) closestEncloser(name string) (ce string, cover *dns.NSEC3) {
	next := name
	for c := parent(name); ; next, c = c, parent(c) {
		if p.nsec3At(c) != nil {
			if cover = p.nsec3Covering(next); cover != nil {
				return c, cover
			}
			return "", nil
		}
		if strings.EqualFold(c, p.zone) || c == "." {
			return "", nil
		}
	}
}

// nsecEncloser derives the closest encloser of name from a covering NSEC (RFC 4035
// section 5.4): the longer common ancestor of name with the NSEC's owner or next name.
func nsecEncloser(name string, n *dns.NSEC) string {
	k := max(dns.CompareDomainName(name, n.Hdr.Name), dns.CompareDomainName(name, n.NextDomain))
	labels := dns.SplitDomainName(name)
	return dns.Fqdn(strings.Join(labels[len(labels)-k:], "."))
}

func lacks(types []uint16, t uint16) bool {
	return !slices.Contains(types, t) && !slices.Contains(types, dns.TypeCNAME)
}

// noData proves that name exists but has no records of type t (RFC 4035 section 5.4,
// RFC 5155 sections 8.5 and 8.7), including empty non-terminals and wildcard NODATA.
func (p *proofs) noData(name string, t uint16) (string, bool) {
	if n := p.nsecAt(name); n != nil {
		return "NSEC", lacks(n.TypeBitMap, t)
	}
	if p.emptyNonTerminal(name) {
		return "NSEC (empty non-terminal)", true
	}
	if c := p.nsecCovering(name); c != nil {
		if w := p.nsecAt("*." + nsecEncloser(name, c)); w != nil && lacks(w.TypeBitMap, t) {
			return "NSEC (wildcard)", true
		}
	}
	if n := p.nsec3At(name); n != nil {
		return "NSEC3", lacks(n.TypeBitMap, t)
	}
	if ce, _ := p.closestEncloser(name); ce != "" {
		if w := p.nsec3At("*." + ce); w != nil && lacks(w.TypeBitMap, t) {
			return "NSEC3 (wildcard)", true
		}
	}
	return "", false
}

// nxDomain proves that name does not exist: no name and no wildcard at its closest
// encloser (RFC 4035 section 5.4, RFC 5155 section 8.4). optOut reports an NSEC3 opt-out
// span, under which name may be an unsigned delegation.
func (p *proofs) nxDomain(name string) (via string, ok, optOut bool) {
	if c := p.nsecCovering(name); c != nil {
		wc := "*." + nsecEncloser(name, c)
		if p.nsecAt(wc) == nil && p.nsecCovering(wc) != nil {
			return "NSEC", true, false
		}
	}
	if ce, cover := p.closestEncloser(name); ce != "" {
		if p.nsec3Covering("*."+ce) != nil {
			return "NSEC3", true, cover.Flags&1 == 1
		}
	}
	return "", false, false
}

// noExactMatch proves, for an answer expanded from the wildcard *.ce, that name itself
// does not exist (RFC 4035 section 5.3.4, RFC 5155 section 8.8).
func (p *proofs) noExactMatch(name, ce string) bool {
	if p.nsecCovering(name) != nil {
		return true
	}
	next := name
	for !strings.EqualFold(parent(next), ce) && next != "." {
		next = parent(next)
	}
	return p.nsec3Covering(next) != nil
}

type denial int

const (
	noProof denial = iota
	notDelegation
	insecureDelegation
)

// denyDS checks a DS answer without DS records for a proof, signed by zone, that name has
// no DS: an NSEC or NSEC3 record at name (RFC 4035 section 5.4, RFC 5155 section 8.5),
// an empty non-terminal, a proven NXDOMAIN, or an NSEC3 opt-out span (RFC 5155 section
// 8.6). The proof also tells whether name is a delegation at all. proof names the record
// type that proved it.
func denyDS(m *dns.Msg, name, zone string, keys []*dns.DNSKEY, now time.Time) (kind denial, proof string, ev []string) {
	p := collectProofs(m.Ns, zone, keys, now)
	if why := p.costly(); why != "" {
		return insecureDelegation, why + ", treated as insecure", p.ev
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
	if m.Rcode == dns.RcodeNameError {
		switch via, ok, optOut := p.nxDomain(name); {
		case ok && optOut:
			return insecureDelegation, "NSEC3 opt-out (RFC 5155)", p.ev
		case ok:
			return notDelegation, via, p.ev
		}
		return noProof, "", p.ev
	}
	if n := p.nsecAt(name); n != nil {
		return byBitmap(n.TypeBitMap), "NSEC", p.ev
	}
	if p.emptyNonTerminal(name) {
		return notDelegation, "NSEC", p.ev
	}
	if n := p.nsec3At(name); n != nil {
		return byBitmap(n.TypeBitMap), "NSEC3", p.ev
	}
	if via, ok := p.noData(name, dns.TypeDS); ok {
		return notDelegation, via, p.ev // wildcard NODATA: a wildcard is never a delegation
	}
	if ce, cover := p.closestEncloser(name); ce != "" && cover.Flags&1 == 1 {
		return insecureDelegation, "NSEC3 opt-out (RFC 5155)", p.ev
	}
	return noProof, "", p.ev
}

// canonicalLess orders names as in RFC 4034 section 6.1: label by label from the right,
// comparing the raw label bytes with ASCII letters lowercased. Escapes such as \000 are
// decoded first.
func canonicalLess(a, b string) bool {
	la, lb := wireLabels(a), wireLabels(b)
	for i := 1; i <= len(la) && i <= len(lb); i++ {
		if c := strings.Compare(la[len(la)-i], lb[len(lb)-i]); c != 0 {
			return c < 0
		}
	}
	return len(la) < len(lb)
}

func wireLabels(name string) []string {
	buf := make([]byte, 256)
	n, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		return nil
	}
	var out []string
	for i := 0; i < n && buf[i] != 0; i += int(buf[i]) + 1 {
		l := buf[i+1 : i+1+int(buf[i])]
		for j, c := range l {
			if 'A' <= c && c <= 'Z' {
				l[j] = c + 'a' - 'A'
			}
		}
		out = append(out, string(l))
	}
	return out
}
