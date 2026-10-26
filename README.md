# certpeek

**Check TLS certificates from the command line: expiry, hostname, trust chain and TLS version, for one host or hundreds at once.** Exit codes made for cron and CI.

[![CI](https://github.com/celaldrg/certpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/celaldrg/certpeek/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/celaldrg/certpeek?sort=semver)](https://github.com/celaldrg/certpeek/releases)
![Go](https://img.shields.io/badge/go-1.24%2B-00ADD8)
![No dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen)

A single static binary, Go standard library only. It reports on broken certificates instead of just failing to connect, so you can see *why* a site is broken.

## Example

Real output (26 October 2026):

```text
$ certpeek github.com google.com https://example.com/path expired.badssl.com \
    wrong.host.badssl.com self-signed.badssl.com untrusted-root.badssl.com
STATUS    TARGET                     EXPIRES     DAYS   ISSUER                                                             TLS     NOTES
CRITICAL  expired.badssl.com         2015-04-12  -4215  COMODO CA Limited (COMODO RSA Domain Validation Secure Server CA)  TLS1.2  expired
OK        github.com                 2026-11-29  34     Sectigo Limited (Sectigo Public Server Authentication CA DV E36)   TLS1.3  
OK        google.com                 2026-12-21  56     Google Trust Services (WE2)                                        TLS1.3  
OK        https://example.com/path   2026-12-25  60     SSL Corporation (Cloudflare TLS Issuing ECC CA 3)                  TLS1.3  
CRITICAL  wrong.host.badssl.com      2026-12-28  63     Let's Encrypt (YR1)                                                TLS1.2  hostname mismatch
CRITICAL  self-signed.badssl.com     2028-10-19  724    BadSSL (*.badssl.com)                                              TLS1.2  self-signed
CRITICAL  untrusted-root.badssl.com  2028-10-19  724    BadSSL (BadSSL Untrusted Root Certificate Authority)               TLS1.2  untrusted issuer

$ echo $?
2
```

JSON for scripts and dashboards (`printf 'github.com\nexpired.badssl.com\n' | certpeek -json -f -`, first entry):

```json
[
  {
    "target": "expired.badssl.com",
    "address": "expired.badssl.com:443",
    "status": "CRITICAL",
    "subject": "*.badssl.com",
    "issuer": "COMODO CA Limited (COMODO RSA Domain Validation Secure Server CA)",
    "dns_names": [
      "*.badssl.com",
      "badssl.com"
    ],
    "not_before": "2015-04-09T00:00:00Z",
    "not_after": "2015-04-12T23:59:59Z",
    "days_left": -4215,
    "tls_version": "TLS1.2",
    "problems": [
      "expired"
    ]
  },
```

## Install

```bash
go install github.com/celaldrg/certpeek@latest
```

or download a binary for Linux, macOS or Windows from the [latest release](https://github.com/celaldrg/certpeek/releases/latest).

## Usage

```text
certpeek [flags] host[:port]|URL ...

  -warn 21       warn when a certificate expires within this many days
  -crit 7        critical when it expires within this many days
  -f FILE        read targets from a file (one per line, # comments allowed; - for stdin)
  -json          JSON output
  -c 16          hosts checked in parallel
  -timeout 8s    per-host timeout
  -sort days     sort by days (default), target, or input order
```

Targets can be `example.com`, `example.com:8443`, `[::1]:8443` or a full URL.

**Exit codes:** `0` all OK, `1` at least one warning, `2` at least one critical or connection error, `3` usage error.

### Cron / CI

```bash
# Fail a scheduled job when anything expires within 14 days
certpeek -warn 30 -crit 14 -f domains.txt || notify-team
```

```yaml
# GitHub Actions: weekly certificate check
on:
  schedule: [{ cron: "0 8 * * 1" }]
jobs:
  certs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: stable }
      - run: go run github.com/celaldrg/certpeek@v0.1.0 -f domains.txt
```

## What it reports

| Status | When |
|---|---|
| `OK` | Trusted, matches the hostname, more than `-warn` days left |
| `WARN` | Expires within `-warn` days, or the server still negotiates TLS 1.0/1.1 |
| `CRITICAL` | Expires within `-crit` days, already expired, not valid yet, hostname mismatch, self-signed or untrusted issuer |
| `ERROR` | DNS failure, refused connection, timeout or handshake failure |

The certificate is verified against your system's trust store, with the intermediates the server sent.

## Why

`openssl s_client -connect host:443 | openssl x509 -noout -enddate` works for one host and is hard to read. Hosted monitors need an account. certpeek is the small tool in between: readable for humans, JSON for machines, parallel for long lists, exit codes for automation.

## Development

```bash
go test -race ./...
go vet ./...
```

Tests run against local TLS servers (`net/http/httptest`) with a fixed clock, so they cover OK, warning, critical, expired, untrusted and hostname-mismatch cases without the network.

## License

[MIT](LICENSE) © Celalettin Durğaç
