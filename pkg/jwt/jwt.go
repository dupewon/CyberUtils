package jwt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

var (
	ErrInvalidToken     = errors.New("jwt: invalid token format")
	ErrInvalidSignature = errors.New("jwt: invalid signature")
	ErrTokenExpired     = errors.New("jwt: token has expired")
	ErrInvalidClaims    = errors.New("jwt: invalid claims")
)

type Algorithm int

const (
	HS256 Algorithm = iota
	HS384
	HS512
)

type Claims struct {
	Issuer    string                 `json:"iss,omitempty"`
	Subject   string                 `json:"sub,omitempty"`
	Audience  string                 `json:"aud,omitempty"`
	ExpiresAt int64                  `json:"exp,omitempty"`
	NotBefore int64                  `json:"nbf,omitempty"`
	IssuedAt  int64                  `json:"iat,omitempty"`
	JWTID     string                 `json:"jti,omitempty"`
	Custom    map[string]interface{} `json:"-"`
}

type Token struct {
	Header    map[string]interface{}
	Claims    Claims
	Signature []byte
	raw       string
}

func New(claims Claims, secret []byte) (string, error) {
	return NewWithAlgorithm(claims, secret, HS256)
}

func NewWithAlgorithm(claims Claims, secret []byte, alg Algorithm) (string, error) {
	header := map[string]interface{}{"typ": "JWT", "alg": alg.String()}
	if claims.IssuedAt == 0 {
		claims.IssuedAt = time.Now().Unix()
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jwt: failed to encode header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwt: failed to encode claims: %w", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims
	signature := sign(signingInput, secret, alg)
	encodedSig := base64.RawURLEncoding.EncodeToString(signature)
	return encodedHeader + "." + encodedClaims + "." + encodedSig, nil
}

func Parse(tokenStr string, secret []byte) (*Token, error) {
	return ParseWithAlgorithm(tokenStr, secret, HS256)
}

func ParseWithAlgorithm(tokenStr string, secret []byte, alg Algorithm) (*Token, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: invalid header encoding: %w", err)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: invalid claims encoding: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("jwt: invalid header JSON: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("jwt: invalid claims JSON: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	expectedSig := sign(signingInput, secret, alg)
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidSignature
	}
	if !hmac.Equal(sigBytes, expectedSig) {
		return nil, ErrInvalidSignature
	}
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}
	if claims.NotBefore > 0 && now < claims.NotBefore {
		return nil, ErrInvalidClaims
	}
	return &Token{Header: header, Claims: claims, Signature: sigBytes, raw: tokenStr}, nil
}

func Refresh(tokenStr string, secret []byte, expiration time.Duration) (string, error) {
	token, err := Parse(tokenStr, secret)
	if err != nil {
		return "", err
	}
	newClaims := token.Claims
	newClaims.IssuedAt = time.Now().Unix()
	newClaims.ExpiresAt = time.Now().Add(expiration).Unix()
	return New(newClaims, secret)
}

func Validate(tokenStr string, secret []byte) error {
	_, err := Parse(tokenStr, secret)
	return err
}

func sign(input string, secret []byte, alg Algorithm) []byte {
	var h hash.Hash
	switch alg {
	case HS256:
		h = hmac.New(sha256.New, secret)
	case HS384:
		h = hmac.New(sha512.New384, secret)
	case HS512:
		h = hmac.New(sha512.New, secret)
	}
	h.Write([]byte(input))
	return h.Sum(nil)
}

func (a Algorithm) String() string {
	switch a {
	case HS256:
		return "HS256"
	case HS384:
		return "HS384"
	case HS512:
		return "HS512"
	default:
		return "HS256"
	}
}

func GenerateRefreshToken(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
