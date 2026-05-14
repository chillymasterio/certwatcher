# certwatcher

**SSL/TLS certificate monitoring from the command line.**

```
$ certwatcher google.com github.com expired.badssl.com

google.com:443
  Status:      VALID (68 days remaining)
  Subject:     *.google.com
  Issuer:      /C=US/O=Google Trust Services/CN=WR2
  Valid until: 2026-07-21 08:20:41 UTC
  Key:         EC 256 bits
  TLS:         TLSv1.3 (TLS_AES_256_GCM_SHA384, 256 bits)
  Chain:       3 certificates, valid

github.com:443
  Status:      VALID (204 days remaining)
  Subject:     github.com
  Issuer:      /C=US/O=DigiCert Inc/CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
  Valid until: 2026-12-04 23:59:59 UTC
  Key:         EC 256 bits
  TLS:         TLSv1.3 (TLS_AES_128_GCM_SHA256, 128 bits)
  Chain:       2 certificates, valid

expired.badssl.com:443
  Status:      EXPIRED (expired 3241 days ago)
  ...
```

## Why?

Every sysadmin has been woken up at 3 AM because a certificate expired. Monitoring tools exist, but they're either SaaS ($$$), require agents, or are bloated with features you don't need.

`certwatcher` is a single binary that checks certificates and tells you what matters:
- **Is it valid?** How many days left?
- **Is the chain correct?** Any trust issues?
- **What's the crypto?** Key type, size, TLS version, cipher

Zero config. Zero dependencies (besides OpenSSL). Works in cron, CI/CD, or interactive use.

## Install

```bash
# Build from source (requires libssl-dev / openssl-devel)
cmake -B build && cmake --build build

# Or with Make
make

# Or compile directly
gcc -O2 -o certwatcher certwatcher.c -lssl -lcrypto
```

## Usage

```bash
# Check one or more hosts
certwatcher example.com github.com

# Custom port
certwatcher -p 8443 internal-api.example.com

# host:port syntax
certwatcher example.com:8443

# Check from a file
certwatcher -f hosts.txt

# Verbose (SANs, fingerprint, serial, full chain)
certwatcher -v example.com

# One-line per host (great for dashboards)
certwatcher -1 google.com github.com cloudflare.com

# Only show expiring/expired certs
certwatcher --expired-only -w 30 -f hosts.txt

# JSON output for automation
certwatcher --json example.com | jq .

# CSV for spreadsheets
certwatcher --csv -f hosts.txt > certs.csv

# Exit code 1 if any cert expires within 14 days
certwatcher --exit-warn -w 14 -f hosts.txt || send-alert
```

### Options

| Flag | Description |
|------|-------------|
| `-p <port>` | Port (default: 443) |
| `-t <sec>` | Connection timeout (default: 10) |
| `-w <days>` | Warning threshold (default: 30) |
| `-f <file>` | Read hosts from file |
| `-s <name>` | Override SNI hostname |
| `-v` | Verbose (SANs, serial, fingerprint, chain) |
| `-1` | One-line output per host |
| `--csv` | CSV output |
| `--json` | JSON output |
| `--no-color` | Disable colors |
| `--expired-only` | Only show expiring certs |
| `--exit-warn` | Exit 1 if any cert near expiry |
| `-V` | Show version |

### Host file format

```
# Production servers
api.example.com
web.example.com:8443
db.example.com:5432

# Third-party services
github.com
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All certificates valid |
| 1 | At least one certificate expiring (with --exit-warn) |
| 2 | Connection error |

## Use cases

- **Cron job**: check all certs nightly, alert if any expire within 14 days
- **CI/CD**: verify staging certs before deploy
- **Audit**: dump all cert details as JSON/CSV for compliance
- **Troubleshooting**: check chain validity, TLS version, cipher strength

## License

MIT
