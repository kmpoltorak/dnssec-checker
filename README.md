# dnssec-checker

[![CI](https://github.com/kmpoltorak/dnssec-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/kmpoltorak/dnssec-checker/actions/workflows/ci.yml)

A command-line tool and web page that answer one question: does this domain
have working DNSSEC? It validates the chain of trust itself, from the IANA root
key down to the zone and the name's own A and AAAA records, and shows the
records that prove the answer. A resolver only fetches the records, so the
result does not depend on whether that resolver validates.

```text
$ dnssec-checker example.com
example.com.  DNSSEC: YES, valid (SECURE)
DNSSEC is enabled and valid: the chain of trust to example.com. and the A and AAAA answers for example.com. validate.

Chain of trust (validated locally from the IANA root key)
  ✔ .             DNSKEY 38696 matches the IANA root trust anchor; DNSKEY set signed by key 38696
  ✔ com.          DS 19718 in . → DNSKEY 19718; DNSKEY set signed by key 19718
  ✔ example.com.  DS 2371 in com. → DNSKEY 2371; DNSKEY set signed by key 2371
      example.com. DS 2371 13 2 C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A
      ...
Records of example.com.
  ✔ A     2 record(s), signed by example.com. key 34505
  ...
Resolver:      tls://9.9.9.9:853, its own SOA answer: NOERROR AD=1 (agrees)
Checked:       2026-10-23T19:58:40Z, 11 queries, 453 ms
```

- Every signature is checked locally: signer, key, cryptographic signature and validity period. An old or broken extra signature does not hide a good one.
- A missing DS or record counts as insecure only with a signed NSEC or NSEC3 proof; otherwise the result is `BOGUS`.
- A check that cannot finish (timeout, SERVFAIL, a resolver that strips DNSSEC records) is `INDETERMINATE`, never `SECURE`.
- Each run is bounded: at most 128 packets, 8 aliases, `--timeout` per query and `--deadline` per run. The report is printed even when the network fails.
- The default resolver is Quad9 over TLS, because home routers, DNS filters and Docker's DNS often drop DNSSEC records.

## Install

Requires Go 1.27.2 or newer.

```sh
go install github.com/kmpoltorak/dnssec-checker/cmd/dnssec-checker@latest
dnssec-checker --version
```

The binary lands in `$(go env GOPATH)/bin` (usually `~/go/bin`) or `$GOBIN`; add
it to `PATH` if needed. `@latest` is the newest release tag; for the newest
commit use `GOPROXY=direct go install ...@main`. From a checkout:
`go build ./cmd/dnssec-checker`.

## Quick start

```sh
dnssec-checker example.com
dnssec-checker --format json example.com | jq -r .dnssec   # yes, no, broken or unknown
if dnssec-checker example.com >/dev/null; then echo "DNSSEC is valid"; fi
```

Web page and JSON API with Docker:

```sh
cp .env.example .env   # optional: resolver and port
docker compose up -d --build
```

Open http://127.0.0.1:8080. `GET /api/check?domain=example.com` returns the JSON
report and `GET /healthz` answers `ok`.

## Usage

Flags go before the domain.

| Flag | Default | Meaning |
|---|---|---|
| `--resolver` | `$DNSSEC_RESOLVER`, else `tls://9.9.9.9` | IP with optional port (`192.0.2.53:5353`, `[2001:db8::53]:53`); `tls://` for DNS over TLS on 853, with `#name` when the certificate is for a name (`tls://192.0.2.53#dns.example.net`). Host names are rejected. |
| `--trust-anchor` | built-in IANA root keys (20326, 38696) | file with DS or DNSKEY records for `.`, e.g. after a root key rollover |
| `--format` | `text` | `text` or `json` |
| `--timeout` | `3s` | one query attempt |
| `--deadline` | `20s` | the whole run |
| `--warn-expiry` | `168h` | warn when a signature used for validation expires within this time and has under a quarter of its validity left |

The domain is converted from IDN to ASCII, lowercased and given a trailing dot.
Labels may contain `a-z`, `0-9`, `-` and `_`. URLs, ports, IP addresses,
wildcards and the root `.` are rejected.

| Status | `dnssec` | When | Exit |
|---|---|---|---|
| `SECURE` | yes | every link from the root key to the zone's SOA verifies, and so do the A and AAAA answers | 0 |
| `INSECURE` | no | a signed parent proves there is no DS; or every DS uses an unsupported algorithm or digest; or NSEC3 has more than 150 iterations; or the answer leads into an unsigned zone (e.g. a CNAME to an unsigned CDN) | 1 |
| `BOGUS` | broken | a DS matches no DNSKEY, a signature is missing, invalid, expired or not yet valid, or a proof of absence is missing or invalid | 2 |
| `INDETERMINATE` | unknown | a query failed or timed out, SERVFAIL or REFUSED even with CD=1, no DNSSEC records passed, or the resolver marks valid (AD=1) an answer that fails local validation | 3 |

Exit 64 means invalid arguments. Exit codes describe DNSSEC, not whether the
name exists; `name_exists` is reported separately, and a proven NXDOMAIN in a
signed zone is `SECURE`. Algorithms: RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256,
RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, ED25519. DS digests: SHA-1,
SHA-256, SHA-384.

Queries use EDNS0 (1232-byte buffer) with DO, RD and CD set, so the resolver
passes data through even when its own validation fails. A truncated answer is
retried over TCP and a transport error once; DNS errors are not retried. After
the check, one normal (CD=0) SOA query shows the resolver's own RCODE, AD
bit and Extended DNS Errors and whether they agree with the local result
(`resolver.agrees`). A disagreement is a warning and never changes the status.

JSON (`schema_version` 2) is one object on stdout: `domain`, `zone`,
`name_exists`, `alias_chain`, `status`, `dnssec`, `summary`, `chain`, `lookups`,
`ns`, `resolver`, `checked_at`, `duration_ms`, `queries`, `warnings`, `errors`.
Unknown values are `null`. Text output uses colors only on a terminal without
`NO_COLOR`.

### Web server

`.env` sets `DNSSEC_RESOLVER` (Docker's built-in DNS cannot be used) and `PORT`
(default `8080`, published on `127.0.0.1`). Without Docker:

```sh
dnssec-checker serve --listen 127.0.0.1:8080 --resolver tls://192.0.2.53
```

`serve` also takes `--trust-anchor`, `--timeout`, `--deadline` (per check) and
`--max-checks` (default 4 at once; more get HTTP 429).
`dnssec-checker health [URL]` exits 0 when `/healthz` answers. Users enter only
a domain, so the page cannot send queries anywhere else. The page has no
JavaScript and sends a strict Content-Security-Policy, `nosniff`,
`no-referrer` and `no-store`. The container runs as non-root on a distroless
image with a read-only file system, no capabilities and `no-new-privileges`.

## Limitations

- Only the A and AAAA answers of the name are validated, not MX, TXT or other types.
- Everything comes through one resolver; authoritative servers are not queried one by one.
- A resolver that changes answers after validating them (some DNS filters and home routers) makes the result `INDETERMINATE`; use another resolver.
- Trust anchors only for the root zone. No DNS over HTTPS.
- NSEC and NSEC3 proof signatures are validated but do not give expiry warnings.
- The resolver sees which names you check.
- The web server has no login: put a reverse proxy with access control in front of it before exposing it beyond `127.0.0.1`.

## Development

There is no Makefile; CI runs these on every push and pull request:

```sh
gofmt -l .
go vet ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
docker compose config --quiet && docker build .
```

The tests run offline. `internal/dnstest` starts a fake recursive resolver on
random UDP, TCP and DNS over TLS ports on `127.0.0.1`, serving a synthetic
`.` → `com.` → `example.com.` chain signed with keys generated during the test,
with an injected clock for signature validity. They cover the CLI exit codes and
JSON, the web page and API, timeouts, SERVFAIL and REFUSED after a valid zone,
and wildcard and CNAME proofs (missing, unsigned, expired, replayed and
wrongly placed). CI also starts the image and checks `/healthz`, the page and a
rejected request.

Built with an AI coding assistant. I wrote the spec and reviewed every change.

## License

MIT, see [LICENSE](LICENSE).
