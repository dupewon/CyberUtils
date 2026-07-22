package main

import (
	"fmt"
	"time"

	"github.com/dupewon/cyberutils/pkg/crypto"
	"github.com/dupewon/cyberutils/pkg/encoding"
	"github.com/dupewon/cyberutils/pkg/hash"
	"github.com/dupewon/cyberutils/pkg/jwt"
	"github.com/dupewon/cyberutils/pkg/otp"
	"github.com/dupewon/cyberutils/pkg/password"
	"github.com/dupewon/cyberutils/pkg/random"
	"github.com/dupewon/cyberutils/pkg/validator"
)

func main() {
	pwd, _ := password.Generate(20, true)
	s := password.Check(pwd)
	fmt.Printf("password: %s (strength: %s, entropy: %.1f)\n", pwd, s.Label, s.Entropy)

	fmt.Printf("sha256: %s\n", hash.SHA256([]byte("hello")))
	fmt.Printf("uuid: %s\n", random.UUID())

	claims := jwt.Claims{Subject: "demo", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	token, _ := jwt.New(claims, []byte("secret"))
	parsed, _ := jwt.Parse(token, []byte("secret"))
	fmt.Printf("jwt: %s (sub: %s)\n", token, parsed.Claims.Subject)

	secret, _ := otp.GenerateTOTPSecret()
	totp := otp.NewTOTP(secret)
	fmt.Printf("totp: %s\n", totp.Generate())

	key, _ := crypto.GenerateSymmetricKey(32)
	ct, _ := crypto.EncryptGCM(key, []byte("sensitive"))
	pt, _ := crypto.DecryptGCM(key, ct)
	fmt.Printf("aes-gcm: %s -> %s\n", encoding.HexEncode(ct), pt)

	fmt.Printf("email valid: %v\n", validator.Email("user@example.com"))
}
