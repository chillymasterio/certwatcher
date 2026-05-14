# Changelog

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
