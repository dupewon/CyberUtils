<<<<<<< HEAD
# cyberutils
A modern, high-performance cybersecurity toolkit for Go developers.
=======
# CyberUtils

Go security toolkit. Zero dependencies outside the stdlib (`golang.org/x/crypto` for hashing, KDFs).

```
go get github.com/dupewon/cyberutils
```

```go
pwd, _ := password.Generate(24, true)
strength := password.Check(pwd)

token, _ := jwt.New(claims, []byte("secret"))
parsed, _ := jwt.Parse(token, []byte("secret"))

totp := otp.NewTOTP(secret)
code := totp.Generate()

ciphertext, _ := crypto.EncryptGCM(key, []byte("hello"))
plaintext, _ := crypto.DecryptGCM(key, ciphertext)

valid := validator.Email("user@example.com")
uuid  := random.UUID()
```

## Packages

| Package | What |
|---------|------|
| `pkg/crypto` | AES-256-GCM, AES-CBC, RSA-OAEP, RSA-PSS, ECDSA, Ed25519, PEM |
| `pkg/hash` | SHA256/512, SHA3-256/512, BLAKE2b, HMAC, timing-safe compare |
| `pkg/password` | Generate, strength/entropy, bcrypt, argon2id, scrypt, pbkdf2 |
| `pkg/jwt` | HS256/384/512, create, parse, refresh |
| `pkg/otp` | TOTP (RFC 6238), HOTP (RFC 4226), backup codes |
| `pkg/random` | UUIDv4, NanoID, bytes, hex, base64, shuffle |
| `pkg/validator` | IP, CIDR, MAC, email, URL, UUID, JWT, port, etc |
| `pkg/network` | Private/public/reserved IP, subnet, reverse DNS |
| `pkg/dns` | A, AAAA, TXT, MX, NS, PTR, SRV, CNAME |
| `pkg/encoding` | Base64, Hex, Base32, URL, Unicode, Binary |
| `pkg/headers` | CSP, HSTS, Permissions-Policy, net/http middleware |
| `pkg/securecookie` | Encrypt, sign, verify, key rotation |
| `pkg/rate` | Sliding window, token bucket, leaky bucket |
| `pkg/utils` | File hash, checksum, secure delete, file signature |

## Layout

```
cyberutils/
├── pkg/
├── cmd/
├── examples/
├── tests/
├── benchmarks/
└── .github/workflows/
```

## Test

```bash
go test ./... -count=1
go test ./... -race -count=1
go test ./... -bench=. -benchmem
```

[MIT](LICENSE)
>>>>>>> 1f242c8 (init: CyberUtils v0.1.0)
