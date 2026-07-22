package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

var (
	ErrInvalidSecret = fmt.Errorf("otp: invalid secret")
	ErrInvalidCode   = fmt.Errorf("otp: invalid code")
)

type TOTP struct {
	secret   []byte
	interval int64
	digits   int
}

func NewTOTP(secret []byte) *TOTP {
	return &TOTP{secret: secret, interval: 30, digits: 6}
}

func (t *TOTP) WithInterval(sec int64) *TOTP {
	t.interval = sec
	return t
}

func (t *TOTP) WithDigits(d int) *TOTP {
	t.digits = d
	return t
}

func (t *TOTP) Generate() string {
	return t.GenerateAt(time.Now())
}

func (t *TOTP) GenerateAt(tm time.Time) string {
	counter := tm.Unix() / t.interval
	return t.generateCode(counter)
}

func (t *TOTP) Validate(code string) bool {
	return t.ValidateAt(code, time.Now(), 1)
}

func (t *TOTP) ValidateAt(code string, tm time.Time, window int) bool {
	counter := tm.Unix() / t.interval
	for i := -window; i <= window; i++ {
		if t.generateCode(counter+int64(i)) == code {
			return true
		}
	}
	return false
}

func (t *TOTP) generateCode(counter int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))
	mac := hmac.New(sha1.New, t.secret)
	mac.Write(buf)
	hash := mac.Sum(nil)
	offset := hash[len(hash)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	mod := uint32(math.Pow10(t.digits))
	code := truncated % mod
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", t.digits), code)
}

func GenerateTOTPSecret() ([]byte, error) {
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	return secret, err
}

func TOTPSecretFromString(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

func TOTPSecretToString(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

func GenerateTOTPURI(secret []byte, issuer, account string) string {
	secretStr := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, account, secretStr, issuer)
}

type HOTP struct {
	secret  []byte
	counter uint64
	digits  int
}

func NewHOTP(secret []byte, counter uint64) *HOTP {
	return &HOTP{secret: secret, counter: counter, digits: 6}
}

func (h *HOTP) WithDigits(d int) *HOTP {
	h.digits = d
	return h
}

func (h *HOTP) Generate() string {
	code := h.generateCode(h.counter)
	h.counter++
	return code
}

func (h *HOTP) Validate(code string) bool {
	return h.generateCode(h.counter) == code
}

func (h *HOTP) generateCode(counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, h.secret)
	mac.Write(buf)
	hash := mac.Sum(nil)
	offset := hash[len(hash)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	mod := uint32(math.Pow10(h.digits))
	code := truncated % mod
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", h.digits), code)
}
