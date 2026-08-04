# Changelog

## v1.5.1 (2026-08-04)

### Fixed
- Build regression: added missing `<sys/select.h>` and `<sys/time.h>`
  includes required for `fd_set` / `select()` / `struct timeval`.
- Removed four stray help-text string literals that had been dropped
  into the middle of the argument-parse `else if` chain and broke
  the C syntax on Linux and macOS (regression since v1.5.0).
- Merged three duplicated `--stdin` / `--exclude` / `--max-parallel`
  argument-handler blocks into a single set of cases.

## v1.4.0 (2026-05-15)

### New Features
- `--chain` to display certificate chain hierarchy
- `--expiry-date` for raw expiry date output
- `--subject-only` for minimal subject output
- `--cipher-only` for TLS version and cipher info
- `--serial-only` for certificate serial number output
- `--key-only` for public key type and size
- `--ocsp-only` for OCSP stapling status
- `--timing-only` for connection timing breakdown
- `--sig-algo` for signature algorithm output
- `--self-signed-only` filter for self-signed certificates
- `--weak` filter for weak crypto (old TLS, small keys)
- XMPP STARTTLS protocol support
- LDAP STARTTLS protocol support
- Reorganized help text with extraction and filter sections

## v1.3.0 (2026-05-15)

### New Features
- `--version-json` for machine-readable version info
- `--color=always/never/auto` for explicit color control
- `--ndjson` newline-delimited JSON output
- `--fingerprint` for SHA256 fingerprint-only output
- `--issuer-only` for minimal issuer output per host
- `--san-list` to display all Subject Alternative Names
- `--brief` compact status overview (host + status + days)

### Fixed
- strncpy truncation warning replaced with snprintf

## v1.2.0 (2026-05-14)

### New Features
- `--retries` flag for automatic retry on connection failure
- `--delay` flag for rate limiting between host checks
- `--timestamp` flag to show check time in output
- `--ciphers` flag to restrict TLS cipher suites
- `--days-only` flag for minimal days-remaining output
- `--header` flag for column headers in one-line mode
- `--fail-ocsp` flag to fail on OCSP revoked status
- POP3 STARTTLS protocol support
- Auto-detect port from STARTTLS protocol
- Specific error messages (DNS, timeout, TLS handshake)

## v1.1.0 (2026-05-14)

### New Features
- `--parallel` flag for concurrent host checking with threads
- `--verify` flag for strict certificate chain verification
- `--min-tls` flag to enforce minimum TLS version
- `--min-key` flag to warn on weak key sizes
- `--no-sni` flag to disable Server Name Indication
- `--ca-file` flag for custom CA certificate bundles
- `--grace` flag to suppress warnings for recently-issued certs
- `--count` flag for statistics-only output
- `--format-date` flag for custom date formatting
- `-4`/`-6` flags to force IPv4/IPv6
- OCSP stapling status detection
- Certificate lifetime and elapsed percentage display

## v1.0.0 (2026-05-14)

Initial release.

### Features
- SSL/TLS certificate checking with full details (subject, issuer, validity, key info)
- Multiple output formats: normal, one-line, CSV, JSON, PEM
- Host file support for batch checking
- Warning threshold with `--exit-warn` for monitoring scripts
- STARTTLS support for SMTP, IMAP, FTP
- Non-blocking connect with configurable timeout
- Connection timing (TCP, TLS, total)
- Human-readable relative expiry dates
- Resolved IP address display
- Self-signed certificate detection
- Hostname/SAN matching verification
- Sort results by expiry date
- Quiet mode for scripting
- Output to file
- SNI override
- Verbose mode with SANs, serial, fingerprint, chain details
- Cross-platform: Linux, macOS, Windows
- Man page

## [1.5.0] - 2026-05-16

### Added
- `--sni HOST` — override SNI hostname during TLS handshake
- `-o, --output FILE` — write results to file instead of stdout
- `--sort KEY` — sort results by days, host, issuer, or tls
- `--min-days N` / `--max-days N` — filter by certificate lifetime
- `--max-parallel N` — limit concurrent connection threads (default: 32)
- `--include PATTERN` / `--exclude PATTERN` — hostname pattern filters
- `--stdin` — read hostnames from standard input pipe
- `--connect-timeout N` — TCP connection timeout in seconds
