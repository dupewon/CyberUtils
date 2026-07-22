package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
	"math"
	"math/big"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const (
	Lowercase = "abcdefghijklmnopqrstuvwxyz"
	Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digits    = "0123456789"
	Symbols   = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
)

var ErrPasswordTooShort = errors.New("password: minimum length is 8 characters")

func Generate(length int, useSymbols bool) (string, error) {
	if length < 8 {
		return "", ErrPasswordTooShort
	}
	charset := Lowercase + Uppercase + Digits
	if useSymbols {
		charset += Symbols
	}
	pwd := make([]byte, length)
	for i := range pwd {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		pwd[i] = charset[n.Int64()]
	}
	return string(pwd), nil
}

type Strength struct {
	Score       int      `json:"score"`
	Label       string   `json:"label"`
	Entropy     float64  `json:"entropy"`
	Length      int      `json:"length"`
	HasLower    bool     `json:"has_lower"`
	HasUpper    bool     `json:"has_upper"`
	HasDigit    bool     `json:"has_digit"`
	HasSymbol   bool     `json:"has_symbol"`
	IsCommon    bool     `json:"is_common"`
	HasRepeats  bool     `json:"has_repeats"`
	Suggestions []string `json:"suggestions,omitempty"`
}

const (
	Weak       = "Weak"
	Fair       = "Fair"
	Good       = "Good"
	Strong     = "Strong"
	VeryStrong = "Very Strong"
)

var commonPasswords = map[string]bool{
	"password": true, "123456": true, "12345678": true, "qwerty": true,
	"abc123": true, "monkey": true, "letmein": true, "dragon": true,
	"111111": true, "baseball": true, "iloveyou": true, "trustno1": true,
	"sunshine": true, "master": true, "welcome": true, "shadow": true,
	"ashley": true, "football": true, "jesus": true, "michael": true,
	"ninja": true, "mustang": true, "password1": true, "admin": true,
}

func Check(pwd string) Strength {
	var s Strength
	s.Length = len(pwd)
	for _, c := range pwd {
		switch {
		case unicode.IsLower(c):
			s.HasLower = true
		case unicode.IsUpper(c):
			s.HasUpper = true
		case unicode.IsDigit(c):
			s.HasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			s.HasSymbol = true
		}
	}
	charsetSize := 0
	if s.HasLower {
		charsetSize += 26
	}
	if s.HasUpper {
		charsetSize += 26
	}
	if s.HasDigit {
		charsetSize += 10
	}
	if s.HasSymbol {
		charsetSize += 33
	}
	if charsetSize > 0 {
		s.Entropy = float64(s.Length) * math.Log2(float64(charsetSize))
	}
	s.IsCommon = commonPasswords[strings.ToLower(pwd)]
	s.HasRepeats = hasRepeatedChars(pwd, 3)

	score := 0
	if s.Length >= 8 {
		score += 10
	}
	if s.Length >= 12 {
		score += 10
	}
	if s.Length >= 16 {
		score += 10
	}
	if s.HasLower && s.HasUpper {
		score += 15
	}
	if s.HasDigit {
		score += 10
	}
	if s.HasSymbol {
		score += 15
	}
	if !s.IsCommon {
		score += 15
	}
	if !s.HasRepeats {
		score += 10
	}
	if s.Entropy >= 60 {
		score += 5
	}
	s.Score = min(score, 100)

	switch {
	case s.Score < 30:
		s.Label = Weak
	case s.Score < 50:
		s.Label = Fair
	case s.Score < 70:
		s.Label = Good
	case s.Score < 90:
		s.Label = Strong
	default:
		s.Label = VeryStrong
	}
	if s.Length < 8 {
		s.Suggestions = append(s.Suggestions, "Use at least 8 characters")
	}
	if !s.HasLower {
		s.Suggestions = append(s.Suggestions, "Add lowercase letters")
	}
	if !s.HasUpper {
		s.Suggestions = append(s.Suggestions, "Add uppercase letters")
	}
	if !s.HasDigit {
		s.Suggestions = append(s.Suggestions, "Add digits")
	}
	if !s.HasSymbol {
		s.Suggestions = append(s.Suggestions, "Add special characters")
	}
	if s.IsCommon {
		s.Suggestions = append(s.Suggestions, "Avoid common passwords")
	}
	if s.HasRepeats {
		s.Suggestions = append(s.Suggestions, "Avoid repeated characters")
	}
	return s
}

func (s Strength) EntropyBits() float64 { return s.Entropy }

func BcryptHash(password []byte, cost int) ([]byte, error) {
	if cost <= 0 {
		cost = bcrypt.DefaultCost
	}
	return bcrypt.GenerateFromPassword(password, cost)
}

func BcryptVerify(password, hash []byte) bool {
	return bcrypt.CompareHashAndPassword(hash, password) == nil
}

func Argon2IDHash(password, salt []byte, time uint32, memory uint32, threads uint8, keyLen uint32) []byte {
	if salt == nil {
		salt = make([]byte, 16)
		rand.Read(salt)
	}
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

func ScryptHash(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	return scrypt.Key(password, salt, N, r, p, keyLen)
}

func PBKDF2Hash(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	return pbkdf2.Key(password, salt, iter, keyLen, h)
}

const DefaultBcryptCost = 12

var RecommendedArgon2Params = struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}{
	Time: 3, Memory: 64 * 1024, Threads: 4, KeyLen: 32,
}

type LeakedChecker interface {
	IsLeaked(password string) (bool, error)
}

func hasRepeatedChars(s string, threshold int) bool {
	count := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			count++
			if count >= threshold {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}

func EncodeHash(algorithm string, hash, salt []byte) string {
	encoded := base64.RawStdEncoding.EncodeToString(hash)
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	return "$" + algorithm + "$" + encodedSalt + "$" + encoded
}

func VerifyConstantTime(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
