# dnssec-checker

[![CI](https://github.com/kmpoltorak/dnssec-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/kmpoltorak/dnssec-checker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A command-line tool that answers one question: does this domain have working DNSSEC?
It validates the chain of trust itself, from the IANA root key down to the zone that
contains the name, and shows the records that prove the answer.

```text
$ dnssec-checker example.com
example.com.  DNSSEC: YES, valid (SECURE)
DNSSEC is enabled and valid: every link from the IANA root key to the SOA record of example.com. verifies.

Chain of trust (validated locally from the IANA root key)
  ✔ .             DNSKEY 20326 matches the IANA root trust anchor; DNSKEY set signed by key 20326
  ✔ com.          DS 19718 in . → DNSKEY 19718; DNSKEY set signed by key 19718
  ✔ example.com.  DS 370 in com. → DNSKEY 370; DNSKEY set signed by key 370
      example.com. DS 370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C
      example.com. RRSIG DS 13 by com. key 19718, valid 2026-10-08 02:24 UTC to 2026-10-15 03:34 UTC
      example.com. DNSKEY 257 3 13 (key tag 370, KSK)
      ...
```

An unsigned and a broken zone look like this:

```text
example.net.  DNSSEC: NO, not signed (INSECURE)
  ✔ .             DNSKEY 20326 matches the IANA root trust anchor; DNSKEY set signed by key 20326
  ✔ net.          DS 37331 in . → DNSKEY 37331; DNSKEY set signed by key 37331
  – example.net.  no DS in net.; the absence is proven by a signed NSEC3 opt-out (RFC 5155) record

example.org.  DNSSEC: BROKEN, validation fails (BOGUS)
  ✔ .             DNSKEY 20326 matches the IANA root trust anchor; DNSKEY set signed by key 20326
  ✔ org.          DS 26974 in . → DNSKEY 26974; DNSKEY set signed by key 26974
  ✘ example.org.  no DNSKEY matches the DS records (key tag 42069)
```

These outputs are illustrations, not real measurements.

## Install

Requires Go 1.27.2 or newer.

```sh
go install github.com/kmpoltorak/dnssec-checker/cmd/dnssec-checker@latest
```

Or build from a checkout:

```sh
go build ./cmd/dnssec-checker
```

## Usage

Flags go before the domain. None are needed for a normal check.

```sh
dnssec-checker example.com
dnssec-checker --resolver 192.0.2.53 example.com
dnssec-checker --format json --timeout 3s --deadline 20s example.com
dnssec-checker --help
dnssec-checker --version
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--resolver` | first `nameserver` in `/etc/resolv.conf` | Resolver to fetch records from: an IP address with an optional port, e.g. `192.0.2.53`, `192.0.2.53:5353`, `2001:db8::53`, `[2001:db8::53]:53`. Host names are rejected. |
| `--format` | `text` | `text` or `json` |
| `--timeout` | `3s` | Time limit for one query attempt |
| `--deadline` | `20s` | Time limit for the whole run |
| `--warn-expiry` | `168h` | Warn when a signature used for validation expires within this time (see [Warnings](#warnings)) |

If no resolver is configured on the system, the tool exits with an error that asks for
`--resolver`. It never falls back to a public DNS provider.

In scripts, use the exit code (see [Status](#status)) or the JSON `dnssec` field:

```sh
if dnssec-checker example.com >/dev/null; then echo "DNSSEC is valid"; fi
dnssec-checker --format json example.com | jq -r .dnssec   # yes, no, broken or unknown
```

### Input

The domain is trimmed, converted from IDN to ASCII (`bücher.example` becomes
`xn--bcher-kva.example.`), lowercased and given a trailing dot. Labels may contain
`a-z`, `0-9`, `-` and `_` (so `_443._tcp.example.com` works). The tool rejects URLs,
ports, IP addresses, wildcards, empty labels, labels over 63 characters, names over
253 characters, a numeric top-level label, and the root `.` on its own.

## How it decides

The tool is a validating stub resolver (RFC 4033 section 4.9.3). The resolver only
fetches records; every signature is checked locally, so the result does not depend on
whether the resolver validates or on the network path to it.

1. **Find the zone.** An SOA query for the name gives the zone that contains it. If an
   answer does not say, the parent labels are queried towards the root. For an alias
   (CNAME) the zone of the alias itself is checked, and the alias chain is reported.
2. **Root.** The root DNSKEY set must contain a key that matches a built-in IANA trust
   anchor (KSK-2017, key tag 20326, and KSK-2024, key tag 38696, from
   [root-anchors.xml](https://data.iana.org/root-anchors/root-anchors.xml)), and that key
   must sign the set.
3. **Each label down to the zone.** The tool asks for the DS record:
   - A DS record that is validly signed by the parent leads to the child's DNSKEY set.
     A DNSKEY must match the DS by algorithm, key tag and recomputed digest, and that
     key must sign the DNSKEY set. One matching DS is enough (key rollover); keys with
     colliding key tags are all tried.
   - No DS record: the parent must prove it with a signed NSEC or NSEC3 record
     (RFC 4035 section 5.4, RFC 5155 section 8.5), or an NSEC3 opt-out span
     (RFC 5155 section 8.6). If the proof shows a delegation without DS, the zone is
     insecure. If it shows the label is not a delegation (or is an empty non-terminal),
     the walk goes on with the same keys.
4. **Zone apex.** The SOA record of the zone must be signed by one of its validated keys.

Every signature check covers the signer name, the key, the cryptographic signature and
the validity period. An old or broken extra signature does not hide a good one.

Queries use EDNS0 with a 1232-byte buffer, DO=1, RD=1 and CD=1 (so the resolver passes
data through even when its own validation fails). A truncated answer is retried over
TCP, a transport error is retried once, and DNS errors are not retried. One run sends at
most 64 packets and follows at most 8 aliases.

## Status

| Status | DNSSEC | When | Exit code |
| --- | --- | --- | --- |
| `SECURE` | yes | Every link from the root key to the zone's SOA verifies. | 0 |
| `INSECURE` | no | A signed parent proves there is no DS for the zone or one of its ancestors, or every DS uses an algorithm or digest type the tool cannot validate (treated as insecure, RFC 4035 section 5.2). | 1 |
| `BOGUS` | broken | A link fails: a DS that matches no DNSKEY, no DNSKEY at all, a missing, invalid, expired or not yet valid signature, or no DS without a valid signed proof. | 2 |
| `INDETERMINATE` | unknown | The check could not finish: a query failed or timed out, the resolver answered SERVFAIL or REFUSED even with CD=1, or it does not pass DNSSEC records (no RRSIG for the root DNSKEY set). | 3 |

Exit code 64 means invalid command-line arguments; `--help` and `--version` exit with 0.
Exit codes describe the DNSSEC result, not whether the name exists.

Supported algorithms: RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512,
ECDSAP256SHA256, ECDSAP384SHA384 and ED25519. Supported DS digest types: SHA-1, SHA-256
and SHA-384.

`name_exists` is reported separately from the status: an NXDOMAIN name in a signed zone
is still `SECURE`.

## The resolver's own answer

After the local check, the tool sends one normal (CD=0) SOA query and shows the
resolver's RCODE, AD bit and Extended DNS Errors, and whether that agrees with the local
result (AD=1 for `SECURE`, AD=0 for `INSECURE`, SERVFAIL for `BOGUS`). A disagreement is
a warning; it never changes the status.

## Warnings

A signature used for validation gives a warning when it expires within `--warn-expiry`
**and** has less than a quarter of its validity period left. The second condition keeps
online signers, which issue short-lived signatures with every answer, from always
warning. A warning does not change the status.

## Output

The text report starts with the verdict and a one-sentence explanation, then lists the
chain of trust with one line per link (`✔` valid, `–` not signed, `✘` broken, `?` could
not check). The records that prove the result are printed under the steps for the
checked zone: DS, DNSKEY (without key material), RRSIG, and NSEC/NSEC3 for an unsigned
zone. Then come the zone, whether the name exists, aliases, name servers, the
resolver's own answer, warnings and errors. Colors are used only when stdout is a
terminal and `NO_COLOR` is not set.

JSON is a single object on stdout. Errors and usage messages go to stderr. Fields:
`schema_version` (2), `domain`, `normalized_domain`, `zone`, `name_exists`,
`alias_chain`, `status`, `dnssec` (`yes`, `no`, `broken`, `unknown`), `summary`,
`chain` (each step has `zone`, `result` — `ok`, `insecure`, `fail` or `error` —
`detail` and `records` for every zone), `ns`, `resolver` (`address`, `response`,
`agrees`), `checked_at` (RFC 3339, UTC), `duration_ms`, `queries`, `warnings`, `errors`.
Unknown values are `null`. The report is printed even when the network fails.

## Limitations

- Only the SOA and DNSKEY records of the zone are validated, not the records of the
  input name itself (for example its A record or a wildcard answer).
- Authoritative servers are not queried one by one; everything comes through one
  resolver. Only the first `nameserver` in `/etc/resolv.conf` is used. Systems without
  that file (such as Windows) need `--resolver`.
- NSEC3 records with a high iteration count are accepted; the RFC 9276 limits are not
  applied.
- Names with escaped characters in NSEC records are compared without unescaping.
- Aliases are read from the CNAME records in the SOA answer. DNAME is not handled
  separately.
- Plain UDP/TCP only: no DNS over TLS or HTTPS.
- An interrupt (Ctrl-C) can wait up to one `--timeout` for the current query, because
  the DNS library honors only the deadline of a context.
- The trust anchors are built in. After a root key rollover the tool needs an update.
- RRSIG times are read as Unix seconds, which is correct until 2106.

## Testing

```sh
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/dnssec-checker
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

The tests run offline. `internal/dnstest` starts a fake recursive resolver on random
UDP and TCP ports on `127.0.0.1` and serves a synthetic chain `.` → `com.` →
`example.com.`, signed with ECDSA P-256 keys generated during the test and checked
against a test trust anchor. Signature validity uses an injected clock. No real keys or
secrets are in the repository. Results do not depend on any public domain.
`govulncheck` needs network access to the Go vulnerability database. CI runs the same
commands on every push and pull request.

## Contributing

Bug reports and pull requests are welcome. Please open an issue first for larger
changes. A pull request should keep CI green and add a test for every behavior change;
see [AGENTS.md](AGENTS.md) for the full rules (they apply to people and AI agents
alike). Tests must stay offline and use only `example.com` / `example.net` names and
RFC 5737 addresses.

## Security

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/kmpoltorak/dnssec-checker/security/advisories/new),
not in public issues.

## License

MIT, see [LICENSE](LICENSE).
