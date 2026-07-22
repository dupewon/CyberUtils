package jwt

import (
	"testing"
	"time"
)

func TestNewAndParse(t *testing.T) {
	secret := []byte("my-secret-key")
	claims := Claims{
		Subject:   "user123",
		Issuer:    "cyberutils",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	token, err := New(claims, secret)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	parsed, err := Parse(token, secret)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed.Claims.Subject != "user123" {
		t.Fatalf("expected subject 'user123', got '%s'", parsed.Claims.Subject)
	}
}

func TestParse_InvalidSignature(t *testing.T) {
	secret := []byte("correct-secret")
	wrongSecret := []byte("wrong-secret")

	claims := Claims{Subject: "test"}
	token, err := New(claims, secret)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Parse(token, wrongSecret)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestParse_ExpiredToken(t *testing.T) {
	secret := []byte("secret")
	claims := Claims{
		Subject:   "temp",
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	}

	token, err := New(claims, secret)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Parse(token, secret)
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestParse_InvalidFormat(t *testing.T) {
	_, err := Parse("not-a-jwt", []byte("secret"))
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestParse_MalformedToken(t *testing.T) {
	_, err := Parse("a.b.c", []byte("secret"))
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestRefresh(t *testing.T) {
	secret := []byte("secret")
	claims := Claims{
		Subject:   "refresh-test",
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	}

	token, err := New(claims, secret)
	if err != nil {
		t.Fatal(err)
	}

	refreshed, err := Refresh(token, secret, time.Hour)
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	parsed, err := Parse(refreshed, secret)
	if err != nil {
		t.Fatalf("refreshed token should be valid: %v", err)
	}

	if parsed.Claims.Subject != "refresh-test" {
		t.Fatal("refreshed token should retain subject")
	}

	if parsed.Claims.ExpiresAt <= claims.ExpiresAt {
		t.Fatal("refreshed token should have later expiration")
	}
}

func TestValidate(t *testing.T) {
	secret := []byte("secret")
	claims := Claims{Subject: "test", ExpiresAt: time.Now().Add(time.Hour).Unix()}

	token, err := New(claims, secret)
	if err != nil {
		t.Fatal(err)
	}

	if err := Validate(token, secret); err != nil {
		t.Fatalf("Validate should succeed: %v", err)
	}

	if err := Validate(token, []byte("wrong")); err == nil {
		t.Fatal("Validate should fail with wrong secret")
	}
}

func TestAlgorithms(t *testing.T) {
	secret := []byte("secret")
	claims := Claims{Subject: "alg-test", ExpiresAt: time.Now().Add(time.Hour).Unix()}

	algs := []Algorithm{HS256, HS384, HS512}
	for _, alg := range algs {
		t.Run(alg.String(), func(t *testing.T) {
			token, err := NewWithAlgorithm(claims, secret, alg)
			if err != nil {
				t.Fatal(err)
			}

			parsed, err := ParseWithAlgorithm(token, secret, alg)
			if err != nil {
				t.Fatalf("ParseWithAlgorithm failed: %v", err)
			}

			if parsed.Claims.Subject != "alg-test" {
				t.Fatal("subject mismatch")
			}
		})
	}
}

func TestNotBefore(t *testing.T) {
	secret := []byte("secret")
	claims := Claims{
		Subject:   "nbf-test",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		NotBefore: time.Now().Add(time.Hour).Unix(),
	}

	token, err := New(claims, secret)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Parse(token, secret)
	if err != ErrInvalidClaims {
		t.Fatalf("expected ErrInvalidClaims for future nbf, got %v", err)
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	token, err := GenerateRefreshToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) == 0 {
		t.Fatal("expected non-empty token")
	}
}

func TestDefaultIssuedAt(t *testing.T) {
	secret := []byte("secret")
	claims := Claims{Subject: "iat-test"}

	token, err := New(claims, secret)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := Parse(token, secret)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Claims.IssuedAt == 0 {
		t.Fatal("IssuedAt should be set automatically")
	}
}

func BenchmarkJWTNew(b *testing.B) {
	secret := []byte("benchmark-secret")
	claims := Claims{Subject: "bench", ExpiresAt: time.Now().Add(time.Hour).Unix()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		New(claims, secret)
	}
}

func BenchmarkJWTParse(b *testing.B) {
	secret := []byte("benchmark-secret")
	claims := Claims{Subject: "bench", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	token, _ := New(claims, secret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Parse(token, secret)
	}
}
