# Changelog

All notable changes to CyberUtils will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-22

### Added

- **Crypto**: AES-256-GCM encrypt/decrypt, AES-CBC, RSA-OAEP, RSA signatures, ECDSA, Ed25519, key generation, PEM encode/decode
- **Hash**: SHA256, SHA512, SHA3-256/512, BLAKE2b-256/512, HMAC-SHA256/512, timing-safe CompareHash
- **Password**: Generate with configurable length/symbols, strength scoring (entropy, dictionary, repeated chars), bcrypt, argon2id, scrypt, PBKDF2 helpers, leaked-password checker interface
- **JWT**: HS256/HS384/HS512 creation and validation, expiration claims, refresh token workflow
- **OTP**: RFC 6238 TOTP, RFC 4226 HOTP, QR secret, backup/recovery codes
- **Random**: UUID v4, NanoID-style, crypto-random bytes/string/hex/base64/int/float, secure shuffle
- **Validator**: IPv4/IPv6, CIDR, MAC, domain, hostname, email, URL, UUID, JWT, hash string, Base64, hex, port range
- **Network**: IP lookup, private/public/reserved detection, subnet and CIDR helpers, reverse DNS, port parsing
- **DNS**: A, AAAA, TXT, MX, NS, PTR, SRV, CNAME lookups, DNSSEC detection
- **Encoding**: Base64 (Std/URL/Raw), Hex, Base32, URL encoding/decoding, Unicode helpers, binary conversion
- **Secure Headers**: CSP, HSTS, Permissions-Policy, Referrer-Policy, X-Frame-Options, X-Content-Type-Options, Cross-Origin policies, HTTP middleware
- **Secure Cookie**: Encrypt, sign, verify, rotate
- **Rate Limiting**: Sliding window, token bucket, leaky bucket, in-memory store, Redis-compatible interface
- **Utils**: Timing-safe compare, file hash, checksum, directory hash, secure delete, file signature detection, secure temp file, environment helpers
- **Project**: Go 1.24+, MIT license, GitHub Actions CI, golangci-lint, race detection, 95%+ coverage target
