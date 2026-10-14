# dnssec-checker

[![CI](https://github.com/kmpoltorak/dnssec-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/kmpoltorak/dnssec-checker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A command-line tool and web page that answer one question: does this domain have
working DNSSEC? It validates the chain of trust itself, from the IANA root key down to
the zone that contains the name and to the name's own A and AAAA records, and shows the
records that prove the answer.

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
dnssec-checker --resolver tls://192.0.2.53 example.com
dnssec-checker --trust-anchor root.key example.com
dnssec-checker --format json --timeout 3s --deadline 20s example.com
dnssec-checker --help
dnssec-checker --version
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--resolver` | `$DNSSEC_RESOLVER`, else `tls://9.9.9.9` (Quad9 over TLS) | Resolver to fetch records from: an IP address with an optional port, e.g. `192.0.2.53`, `192.0.2.53:5353`, `2001:db8::53`, `[2001:db8::53]:53`. Prefix it with `tls://` for DNS over TLS (port 853 by default); the certificate must be valid for the IP address, or for a name after `#`: `tls://192.0.2.53#dns.example.net`. Host names are rejected. |
| `--trust-anchor` | built-in IANA root keys | File with root trust anchors: DS or DNSKEY records for `.` in zone file format, e.g. `. IN DS 20326 8 2 E06D…`. DNSKEY records are turned into SHA-256 DS records. Useful after a root key rollover or for a test root. |
| `--format` | `text` | `text` or `json` |
| `--timeout` | `3s` | Time limit for one query attempt |
| `--deadline` | `20s` | Time limit for the whole run |
| `--warn-expiry` | `168h` | Warn when a signature used for validation expires within this time (see [Warnings](#warnings)) |

By default the tool fetches records from Quad9 over DNS over TLS, not from the system
resolver. Home routers and DNS filters (for example AdGuard Home or Pi-hole) often
drop or change records, and Docker's DNS drops DNSSEC records altogether; then the
result would be `INDETERMINATE` even for a correctly signed domain. Validation is always
local, so the resolver only has to pass records through unchanged; it does see which
names you check. To use another one, set `--resolver` or the `DNSSEC_RESOLVER`
environment variable, for example `export DNSSEC_RESOLVER=tls://192.0.2.53`.

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

## Web interface and Docker

The same checks are available as a web page with a JSON API. With Docker:

```sh
cp .env.example .env   # optional: choose the resolver and port
docker compose up -d --build
```

Then open http://127.0.0.1:8080. The page shows the verdict, the chain of trust and the
records of the name, the same as the text report; `GET /api/check?domain=example.com`
returns the JSON report, and `GET /healthz` answers `ok`.

Settings in `.env` (see `.env.example`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `DNSSEC_RESOLVER` | `tls://9.9.9.9` (Quad9 over TLS) | Resolver the server fetches records from, in `--resolver` format. Docker's built-in DNS drops DNSSEC records, so it cannot be used. Validation stays local; the resolver only fetches records. |
| `PORT` | `8080` | Port on `127.0.0.1` where the page is published |

Without Docker, run the server directly:

```sh
dnssec-checker serve --listen 127.0.0.1:8080 --resolver tls://192.0.2.53
```

`serve` flags: `--listen` (default `127.0.0.1:8080`), `--resolver` (default
`$DNSSEC_RESOLVER`, else `tls://9.9.9.9`), `--trust-anchor` (default:
the built-in IANA root keys), `--timeout` (3s), `--deadline` (20s per check) and
`--max-checks` (4 checks at the same time; more get HTTP 429).
`dnssec-checker health [URL]` exits with 0 when `/healthz` answers; the image uses it as
its health check.

Security:

- Users only enter a domain. The resolver is set by whoever runs the server, so the page
  cannot be used to send queries to other addresses.
- Input is validated before a check starts; checks are limited in number and time; the
  HTTP server has read, write and idle timeouts.
- The page uses no JavaScript; responses carry a strict Content-Security-Policy,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and
  `Cache-Control: no-store`. Record data is HTML-escaped.
- The container runs as a non-root user on a distroless image, with a read-only file
  system, no Linux capabilities and `no-new-privileges`. Compose publishes the port on
  `127.0.0.1` only; there is no login, so put a reverse proxy with access control in
  front of it before exposing it to a network.

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
5. **The name itself.** The A and AAAA answers for the name are validated too:
   - records must be signed by the zone that the chain of trust reaches for their owner;
   - an answer expanded from a wildcard (RRSIG label count below the owner's) needs a
     signed proof that the name itself does not exist;
   - each CNAME in an alias chain must be signed by its zone, even in another zone; a
     CNAME synthesized from a DNAME is unsigned (RFC 6672), so the DNAME is validated;
   - "no records" needs a signed NODATA proof and NXDOMAIN a signed proof that neither
     the name nor a wildcard exists (RFC 4035 section 5.4, RFC 5155 sections 8.4-8.7).

Every signature check covers the signer name, the key, the cryptographic signature and
the validity period. An old or broken extra signature does not hide a good one.

Queries use EDNS0 with a 1232-byte buffer, DO=1, RD=1 and CD=1 (so the resolver passes
data through even when its own validation fails). A truncated answer is retried over
TCP, a transport error is retried once, and DNS errors are not retried. One run sends at
most 128 packets and follows at most 8 aliases. With `tls://` every query goes over DNS
over TLS (RFC 7858) instead.

## Status

| Status | DNSSEC | When | Exit code |
| --- | --- | --- | --- |
| `SECURE` | yes | Every link from the root key to the zone's SOA verifies, and so do the name's A and AAAA answers. | 0 |
| `INSECURE` | no | A signed parent proves there is no DS for the zone or one of its ancestors; or every DS uses an algorithm or digest type the tool cannot validate (treated as insecure, RFC 4035 section 5.2); or a proof uses NSEC3 with more than 150 iterations (treated as insecure, RFC 9276 section 3.2); or the zone is signed but the name's answer leads into an unsigned zone (for example a CNAME to an unsigned CDN). | 1 |
| `BOGUS` | broken | A link fails: a DS that matches no DNSKEY, no DNSKEY at all, a missing, invalid, expired or not yet valid signature, no DS without a valid signed proof, or a name answer without a valid signature or proof. | 2 |
| `INDETERMINATE` | unknown | The check could not finish: a query failed or timed out, the resolver answered SERVFAIL or REFUSED even with CD=1, or it does not pass DNSSEC records (no RRSIG for the root DNSKEY set). Also when a name answer fails validation but the resolver itself marks it valid (AD=1): the resolver or something on the way then changes answers, for example a DNS filter that drops records. | 3 |

Exit code 64 means invalid command-line arguments; `--help` and `--version` exit with 0.
Exit codes describe the DNSSEC result, not whether the name exists.

Supported algorithms: RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512,
ECDSAP256SHA256, ECDSAP384SHA384 and ED25519. Supported DS digest types: SHA-1, SHA-256
and SHA-384.

`name_exists` is reported separately: an NXDOMAIN name in a signed zone is `SECURE`
when the non-existence is proven. If an A or AAAA query fails (for example a timeout),
that answer is shown as not checked with a warning, and the status comes from the zone.

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
zone. A second section, "Records of <name>", shows the result for the A and AAAA
answers with their records and signatures. Then come the zone, whether the name exists,
aliases, name servers, the resolver's own answer, warnings and errors. Colors are used only when stdout is a
terminal and `NO_COLOR` is not set.

JSON is a single object on stdout. Errors and usage messages go to stderr. Fields:
`schema_version` (2), `domain`, `normalized_domain`, `zone`, `name_exists`,
`alias_chain`, `status`, `dnssec` (`yes`, `no`, `broken`, `unknown`), `summary`,
`chain` (each step has `zone`, `result` — `ok`, `insecure`, `fail` or `error` —
`detail` and `records` for every zone), `lookups` (for A and AAAA: `name`, `type`,
`result`, `detail`, `records`), `ns`, `resolver` (`address`, `response`,
`agrees`), `checked_at` (RFC 3339, UTC), `duration_ms`, `queries`, `warnings`, `errors`.
Unknown values are `null`. The report is printed even when the network fails.

## Limitations

- Only A and AAAA answers of the name are validated, not other types such as MX or TXT.
- Authoritative servers are not queried one by one; everything comes through one
  resolver.
- When the chosen resolver changes answers after validating them (some DNS filters and
  home routers drop records), the result is `INDETERMINATE`; use another resolver.
- Only the root zone can have a trust anchor; trust anchors for other zones are not
  supported.
- DNS over HTTPS is not supported.

## Testing

```sh
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/dnssec-checker
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
docker compose config --quiet && docker build .
```

The tests run offline. `internal/dnstest` starts a fake recursive resolver on random
UDP, TCP and DNS over TLS ports on `127.0.0.1` and serves a synthetic chain `.` → `com.` →
`example.com.`, signed with ECDSA P-256 keys generated during the test and checked
against a test trust anchor. Signature validity uses an injected clock. No real keys or
secrets are in the repository. Results do not depend on any public domain.
The web handlers are tested against the same fake resolver. `govulncheck` needs network
access to the Go vulnerability database. CI runs the same commands on every push and
pull request, and also starts the image and checks `/healthz`, the page and a rejected
request.

## Contributing

Bug reports and pull requests are welcome. Please open an issue first for larger
changes. A pull request should keep CI green and add a test for every behavior change.
[AGENTS.md](AGENTS.md) lists the rules this repository is developed with. Tests must
stay offline and use only reserved example names (RFC 2606, such as `example.com`) and
RFC 5737 addresses.

## Security

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/kmpoltorak/dnssec-checker/security/advisories/new),
not in public issues.

## License

MIT, see [LICENSE](LICENSE).
