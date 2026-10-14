# dnssec-checker

A command-line tool that checks the DNSSEC configuration of the zone containing one
domain name. It asks a validating resolver for its verdict and runs local diagnostic
checks on DS, DNSKEY and RRSIG records. It prints a text summary or a JSON report.

The report covers the zone it finds and the RRsets it checks (SOA, DNSKEY, NS, DS). It
does not audit every record, every authoritative server, or the operator's whole setup.

## Install

Requires Go 1.27.2 or newer.

```sh
go install github.com/kmpoltorak/dnssec-checker/cmd/dnssec-checker@latest
```

While the repository is private, set `GOPRIVATE=github.com/kmpoltorak/*` and make sure
Git can authenticate to GitHub. You can also build from a checkout:

```sh
go build ./cmd/dnssec-checker
```

## Usage

Flags go before the domain.

```sh
dnssec-checker example.com
dnssec-checker --resolver 127.0.0.1:53 --trust-resolver example.com
dnssec-checker --format json --timeout 3s --deadline 20s example.com
dnssec-checker --help
dnssec-checker --version
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--resolver` | first `nameserver` in `/etc/resolv.conf` | Resolver IP address with an optional port: `192.0.2.53`, `192.0.2.53:5353`, `2001:db8::53`, `[2001:db8::53]:53`. Host names are rejected. |
| `--trust-resolver` | `false` | You trust the resolver's DNSSEC validation and the network path to it |
| `--format` | `text` | `text` or `json` |
| `--timeout` | `3s` | Time limit for one query attempt |
| `--deadline` | `20s` | Time limit for the whole run |
| `--warn-expiry` | `168h` | Warn when the latest valid signature for an RRset expires within this time |

If no resolver is configured on the system, the tool exits with an error that asks for
`--resolver`. It never falls back to a public DNS provider.

### Input

The domain is trimmed, converted from IDN to ASCII (`bücher.example` becomes
`xn--bcher-kva.example.`), lowercased and given a trailing dot. Labels may contain
`a-z`, `0-9`, `-` and `_` (so `_443._tcp.example.com` works). The tool rejects URLs,
ports, IP addresses, wildcards, empty labels, labels over 63 characters, names over
253 characters, a numeric top-level label, and the root `.` on its own.

## Trust model

- The resolver does the full chain validation from its trust anchor. This tool records
  its answer (RCODE, AD bit, Extended DNS Errors) and runs local checks.
- By default the resolver is **not trusted**: its AD bit is only an observation and the
  status is never `SECURE`, even with AD=1.
- `--trust-resolver` declares that you trust the resolver and the path to it, for
  example a local validating Unbound on `127.0.0.1`. The flag does not encrypt anything
  and does not check the network.
- A DS that matches a DNSKEY and a valid signature do not prove, on their own, that a
  key is authentic or that the chain of trust is complete.
- NSEC/NSEC3 records are only reported as present or absent. Checking proofs of
  non-existence is left to the resolver.

## How a check runs

1. Normalize the name and find its zone from SOA answers (an SOA owned by the name in
   the answer, or an SOA in the authority section of a negative answer). If an answer
   does not place the name in a zone, the tool queries each parent label towards the
   root. For an alias (CNAME), the authority SOA belongs to the target, so the tool
   starts from the alias's parent and reports the alias chain separately.
2. Query SOA, DNSKEY and NS at the zone apex, and DS for the apex (skipped for the root).
3. Every query uses EDNS0 with a 1232-byte buffer and DO=1, RD=1, CD=0 over UDP. A
   truncated (TC=1) answer is retried over TCP. After a transport error the query is
   tried once more. NXDOMAIN, REFUSED and SERVFAIL are never retried.
4. On SERVFAIL the query is repeated with CD=1. That answer feeds the local checks only
   and never counts as validation by the resolver.
5. Local checks run, then the status is computed.

One run sends at most 64 packets, follows at most 8 aliases and detects alias loops.
Every query stays within `--deadline`. Results from before a failure are kept: a timed
out DS query shows as `UNKNOWN`, not as a missing DS.

## Checks

Each check has a stable `id`, a result (`PASS`, `WARN`, `FAIL`, `UNKNOWN`, `N/A`), a
description, evidence and an optional suggestion.

| id | What it checks |
| --- | --- |
| `resolver.validation` | The resolver set AD=1 for SOA and DNSKEY. `PASS` only with `--trust-resolver`. |
| `ds.match` | A DS record matches a zone DNSKEY by algorithm, key tag and recomputed digest. One match is enough (rollover); colliding key tags are all tried. |
| `dnskey.present` | The zone publishes DNSKEY records. `FAIL` when DS exists but DNSKEY does not. |
| `dnskey.signatures` | The DNSKEY RRset has a cryptographically valid, current RRSIG from a key that a DS references. |
| `soa.signatures` | The SOA RRset has a cryptographically valid, current RRSIG from a zone key. |
| `signatures.expiry` | The latest valid signature of each RRset does not expire within `--warn-expiry`. |

Signature checks verify the signature and its validity period separately, so a correct
signature outside its period is reported as such. An extra old or broken signature does
not hide a good one. An algorithm or digest type that the
[miekg/dns](https://github.com/miekg/dns) library cannot verify (for example Ed448 or
GOST) gives `UNKNOWN`, not `FAIL`.

## Status

| Status | When |
| --- | --- |
| `SECURE` | A trusted resolver set AD=1 for SOA and DNSKEY, and `ds.match`, `dnskey.signatures` and `soa.signatures` all pass (`ds.match` is `N/A` for the root). |
| `INSECURE` | A trusted resolver answered the DS query with NOERROR/NODATA, AD=1 and the parent's SOA in the authority section; the apex has SOA and NS; SOA and DNSKEY have AD=0. |
| `BOGUS` | A trusted resolver answered SOA, DNSKEY or DS with SERVFAIL and an Extended DNS Error from 6 to 12 (DNSSEC Bogus, Signature Expired, Signature Not Yet Valid, DNSKEY Missing, RRSIGs Missing, No Zone Key Bit Set, NSEC Missing). |
| `INDETERMINATE` | Anything else: untrusted resolver, missing replies, SERVFAIL without one of those EDE codes, AD=1 that contradicts a local check, unsupported algorithms, or an absence of DS that was not authenticated. |

Rules that follow from this:

- AD=0 never means `INSECURE` by itself, and an empty DS answer is not NODATA unless it
  carries the parent's SOA.
- Local failures (a DS mismatch, a bad signature) are shown as check results but never
  turn into `BOGUS`. If they contradict AD=1, the status is `INDETERMINATE`.
- A zone with DNSKEY records under an authenticated missing DS is `INSECURE` with a
  warning about a possible island of trust.
- A signature that expires soon gives a warning, not a different status.
- `name_exists` is reported separately from the zone status. An NXDOMAIN name in a
  signed zone can still be `SECURE`.

## Output

Text and JSON carry the same information: input and normalized name, zone, whether the
name exists, alias chain, UTC check time, duration, resolver and trust mode, status and
summary, NS, DS (tag, algorithm, digest type, digest, match), DNSKEY (tag, algorithm,
flags, protocol; no key material), RRSIG (covered type, signer, tag, algorithm,
inception, expiration, signature and time results, time to expiry), NSEC/NSEC3
presence, every query with RCODE, AD, CD and EDE, the checks, warnings and errors.

JSON is a single object on stdout. Errors and usage messages go to stderr. Top-level
fields: `schema_version` (1), `domain`, `normalized_domain`, `zone`, `name_exists`,
`checked_at`, `duration_ms`, `resolver`, `validation_mode` (`trusted-resolver` or
`untrusted-resolver`), `status`, `summary`, `records`, `queries`, `checks`,
`warnings`, `errors`. Times are RFC 3339 in UTC. Unknown values are `null`; for
example `records.ds` is `null` when the DS query failed and `[]` when it returned none.
The report is printed even when the network fails.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | `SECURE` (warnings that do not affect validation are allowed); also `--help` and `--version` |
| 1 | `INSECURE` |
| 2 | `BOGUS` |
| 3 | `INDETERMINATE`, or an operational error such as no system resolver |
| 64 | Invalid command-line arguments |

Exit codes describe the DNSSEC result, not whether the name exists or the service works.

## Limitations

- No local chain validation from the root trust anchor, and no checking of NSEC/NSEC3
  proofs.
- Only the resolver's view is used. Authoritative servers are not queried one by one.
- Only the first `nameserver` in `/etc/resolv.conf` is used, so answers from different
  resolvers are never mixed. Systems without that file (such as Windows) need
  `--resolver`.
- `INSECURE` needs an authenticated NODATA answer for DS. An absence proven with NSEC3
  opt-out is not authenticated (RFC 5155), so a resolver usually returns AD=0 and the
  status is `INDETERMINATE`. The same applies below an unsigned parent.
- Aliases are read from the CNAME records in the SOA answer. DNAME is not handled
  separately.
- Plain UDP/TCP only: no DNS over TLS or HTTPS.
- An interrupt (Ctrl-C) can wait up to one `--timeout` for the current query, because
  the DNS library honors only the deadline of a context.
- RRSIG times are read as Unix seconds, which is correct until 2106.

## Testing

```sh
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/dnssec-checker
```

The tests run offline. `internal/dnstest` starts a fake recursive resolver on random
UDP and TCP ports on `127.0.0.1` and serves synthetic `example.com` / `example.net`
zones, signed with ECDSA P-256 keys generated during the test. Signature validity uses
an injected clock. No real keys or secrets are in the repository. Results do not depend
on any public domain. CI runs the same commands on every push and pull request.

## License

MIT, see [LICENSE](LICENSE).
