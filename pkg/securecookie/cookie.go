package securecookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

var (
	ErrInvalidKey     = errors.New("securecookie: invalid key size")
	ErrInvalidValue   = errors.New("securecookie: invalid value")
	ErrInvalidHMAC    = errors.New("securecookie: invalid HMAC")
	ErrTamperedCookie = errors.New("securecookie: cookie has been tampered with")
)

type Cookie struct {
	encKey []byte
	sigKey []byte
}

func New(encKey, sigKey []byte) (*Cookie, error) {
	if len(encKey) != 16 && len(encKey) != 24 && len(encKey) != 32 {
		return nil, ErrInvalidKey
	}
	if len(sigKey) == 0 {
		sigKey = make([]byte, 32)
		io.ReadFull(rand.Reader, sigKey)
	}
	return &Cookie{encKey: encKey, sigKey: sigKey}, nil
}

func (c *Cookie) Encrypt(value interface{}) (string, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(c.encKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	mac := hmac.New(sha256.New, c.sigKey)
	mac.Write(ciphertext)
	signature := mac.Sum(nil)
	combined := append(signature, ciphertext...)
	return base64.RawStdEncoding.EncodeToString(combined), nil
}

func (c *Cookie) Decrypt(value string, dest interface{}) error {
	combined, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return ErrInvalidValue
	}
	if len(combined) < sha256.Size {
		return ErrInvalidHMAC
	}
	signature := combined[:sha256.Size]
	ciphertext := combined[sha256.Size:]
	mac := hmac.New(sha256.New, c.sigKey)
	mac.Write(ciphertext)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return ErrTamperedCookie
	}
	block, err := aes.NewCipher(c.encKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return ErrInvalidValue
	}
	nonce := ciphertext[:gcm.NonceSize()]
	encrypted := ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return ErrTamperedCookie
	}
	return json.Unmarshal(plaintext, dest)
}

func (c *Cookie) Sign(value string) (string, error) {
	mac := hmac.New(sha256.New, c.sigKey)
	mac.Write([]byte(value))
	sig := mac.Sum(nil)
	combined := append(sig, []byte(value)...)
	return base64.RawStdEncoding.EncodeToString(combined), nil
}

func (c *Cookie) Verify(value string) (string, error) {
	combined, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return "", ErrInvalidValue
	}
	if len(combined) < sha256.Size {
		return "", ErrInvalidHMAC
	}
	signature := combined[:sha256.Size]
	payload := combined[sha256.Size:]
	mac := hmac.New(sha256.New, c.sigKey)
	mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return "", ErrTamperedCookie
	}
	return string(payload), nil
}

type Rotator struct {
	current  *Cookie
	previous []*Cookie
}

func NewRotator(current *Cookie) *Rotator {
	return &Rotator{current: current}
}

func (r *Rotator) AddPreviousKey(encKey, sigKey []byte) error {
	c, err := New(encKey, sigKey)
	if err != nil {
		return err
	}
	r.previous = append(r.previous, c)
	return nil
}

func (r *Rotator) Decrypt(value string, dest interface{}) error {
	err := r.current.Decrypt(value, dest)
	if err == nil {
		return nil
	}
	for _, prev := range r.previous {
		if err := prev.Decrypt(value, dest); err == nil {
			return nil
		}
	}
	return err
}

func GenerateKey(n int) ([]byte, error) {
	key := make([]byte, n)
	_, err := rand.Read(key)
	return key, err
}

func SanitizeCookieValue(s string) string {
	return strings.NewReplacer("\n", "", "\r", "", ";", "").Replace(s)
}
