# Changelog

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
