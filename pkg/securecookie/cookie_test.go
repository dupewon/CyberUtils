package securecookie

import (
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	encKey := make([]byte, 32)
	sigKey := make([]byte, 32)
	GenerateKey(32) // just use random, actually let's use fixed

	cookie, err := New(encKey, sigKey)
	if err != nil {
		t.Fatal(err)
	}

	value := map[string]interface{}{
		"user_id": 12345,
		"role":    "admin",
	}

	encoded, err := cookie.Encrypt(value)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	var decoded map[string]interface{}
	if err := cookie.Decrypt(encoded, &decoded); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if decoded["user_id"] != float64(12345) {
		t.Fatalf("expected user_id 12345, got %v", decoded["user_id"])
	}
	if decoded["role"] != "admin" {
		t.Fatalf("expected role 'admin', got %v", decoded["role"])
	}
}

func TestTamperedCookie(t *testing.T) {
	encKey := make([]byte, 32)
	sigKey := make([]byte, 32)

	cookie, _ := New(encKey, sigKey)
	encoded, _ := cookie.Encrypt("test-value")

	// Tamper with the encoded value
	tampered := encoded + "x"

	var result string
	err := cookie.Decrypt(tampered, &result)
	if err == nil {
		t.Fatal("expected error for tampered cookie")
	}
}

func TestInvalidKey(t *testing.T) {
	_, err := New([]byte("short"), []byte("key"))
	if err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestSignVerify(t *testing.T) {
	encKey := make([]byte, 32)
	sigKey := make([]byte, 32)

	cookie, _ := New(encKey, sigKey)

	signed, err := cookie.Sign("my-value")
	if err != nil {
		t.Fatal(err)
	}

	verified, err := cookie.Verify(signed)
	if err != nil {
		t.Fatal(err)
	}

	if verified != "my-value" {
		t.Fatalf("expected 'my-value', got '%s'", verified)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	encKey := make([]byte, 32)
	sigKey := []byte("correct-signing-key")
	wrongKey := []byte("wrong-signing-key-different")

	cookie, _ := New(encKey, sigKey)
	signed, _ := cookie.Sign("test")

	wrongCookie, _ := New(encKey, wrongKey)
	_, err := wrongCookie.Verify(signed)
	if err == nil {
		t.Fatal("expected error for wrong signing key")
	}
}

func TestRotator(t *testing.T) {
	oldEncKey := make([]byte, 32)
	oldSigKey := make([]byte, 32)
	newEncKey := make([]byte, 32)
	newSigKey := make([]byte, 32)

	oldCookie, _ := New(oldEncKey, oldSigKey)
	newCookie, _ := New(newEncKey, newSigKey)

	encoded, _ := oldCookie.Encrypt("old-value")

	rotator := NewRotator(newCookie)
	rotator.AddPreviousKey(oldEncKey, oldSigKey)

	var result string
	err := rotator.Decrypt(encoded, &result)
	if err != nil {
		t.Fatalf("Rotator Decrypt failed: %v", err)
	}

	if result != "old-value" {
		t.Fatalf("expected 'old-value', got '%s'", result)
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(key))
	}
}

func TestSanitizeCookieValue(t *testing.T) {
	dirty := "value\nwith\tspecial;chars, and spaces"
	sanitized := SanitizeCookieValue(dirty)
	if strings.Contains(sanitized, "\n") || strings.Contains(sanitized, ";") {
		t.Fatal("sanitized value should not contain invalid characters")
	}
}

func TestEncryptString(t *testing.T) {
	encKey := make([]byte, 32)
	sigKey := make([]byte, 32)

	cookie, _ := New(encKey, sigKey)
	encoded, err := cookie.Encrypt("hello")
	if err != nil {
		t.Fatal(err)
	}

	var decoded string
	if err := cookie.Decrypt(encoded, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded != "hello" {
		t.Fatalf("expected 'hello', got '%s'", decoded)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	encKey := make([]byte, 32)
	sigKey := make([]byte, 32)
	cookie, _ := New(encKey, sigKey)
	value := map[string]interface{}{"user_id": 12345}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cookie.Encrypt(value)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	encKey := make([]byte, 32)
	sigKey := make([]byte, 32)
	cookie, _ := New(encKey, sigKey)
	encoded, _ := cookie.Encrypt(map[string]interface{}{"user_id": 12345})
	var result map[string]interface{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cookie.Decrypt(encoded, &result)
	}
}
