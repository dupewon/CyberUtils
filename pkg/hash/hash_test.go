package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSHA256(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte("")},
		{"hello", []byte("hello world")},
		{"unicode", []byte("merhaba dünya 🎯")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SHA256(tt.data)
			if len(result) != 64 {
				t.Fatalf("expected 64 hex chars, got %d", len(result))
			}
			if _, err := hex.DecodeString(result); err != nil {
				t.Fatalf("invalid hex: %v", err)
			}
		})
	}
}

func TestSHA512(t *testing.T) {
	result := SHA512([]byte("test"))
	if len(result) != 128 {
		t.Fatalf("expected 128 hex chars, got %d", len(result))
	}
}

func TestSHA3(t *testing.T) {
	tests := []struct {
		name string
		fn   func([]byte) string
		size int
	}{
		{"SHA3-256", SHA3_256, 64},
		{"SHA3-512", SHA3_512, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn([]byte("test"))
			if len(result) != tt.size {
				t.Fatalf("expected %d hex chars, got %d", tt.size, len(result))
			}
		})
	}
}

func TestBLAKE2b(t *testing.T) {
	tests := []struct {
		name string
		fn   func([]byte) string
		size int
	}{
		{"BLAKE2b-256", BLAKE2b_256, 64},
		{"BLAKE2b-512", BLAKE2b_512, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn([]byte("test"))
			if len(result) != tt.size {
				t.Fatalf("expected %d hex chars, got %d", tt.size, len(result))
			}
		})
	}
}

func TestHMAC(t *testing.T) {
	key := []byte("secret-key")
	data := []byte("message")

	tests := []struct {
		name string
		fn   func([]byte, []byte) string
		size int
	}{
		{"HMAC-SHA256", HMACSHA256, 64},
		{"HMAC-SHA512", HMACSHA512, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn(key, data)
			if len(result) != tt.size {
				t.Fatalf("expected %d hex chars, got %d", tt.size, len(result))
			}
		})
	}
}

func TestHMAC_DifferentKeys(t *testing.T) {
	key1 := []byte("key-one")
	key2 := []byte("key-two")
	data := []byte("same data")

	h1 := HMACSHA256(key1, data)
	h2 := HMACSHA256(key2, data)

	if h1 == h2 {
		t.Fatal("different keys should produce different HMACs")
	}
}

func TestCompareHash(t *testing.T) {
	data := []byte("hello")
	hash := SHA256(data)

	if !CompareHash(SHA256, data, hash) {
		t.Fatal("CompareHash should match")
	}

	if CompareHash(SHA256, []byte("wrong"), hash) {
		t.Fatal("CompareHash should not match wrong data")
	}
}

func TestTimingSafeCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"equal", []byte("abc"), []byte("abc"), true},
		{"not equal", []byte("abc"), []byte("abd"), false},
		{"different lengths", []byte("abc"), []byte("abcd"), false},
		{"empty", []byte{}, []byte{}, true},
		{"nil", nil, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TimingSafeCompare(tt.a, tt.b); got != tt.want {
				t.Fatalf("TimingSafeCompare(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestHashReader(t *testing.T) {
	r := strings.NewReader("hello world")
	result, err := HashReader(r, sha256.New)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 64 {
		t.Fatal("expected 64 hex chars")
	}
}

func TestConsistency(t *testing.T) {
	data := []byte("consistency check")
	h1 := SHA256(data)
	h2 := SHA256(data)
	if h1 != h2 {
		t.Fatal("SHA256 should be deterministic")
	}

	b1 := BLAKE2b_256(data)
	b2 := BLAKE2b_256(data)
	if b1 != b2 {
		t.Fatal("BLAKE2b should be deterministic")
	}
}

func TestHMAC_EmptyKey(t *testing.T) {
	result := HMACSHA256(nil, []byte("data"))
	if len(result) != 64 {
		t.Fatal("HMAC with nil key should still work")
	}
}

func BenchmarkSHA256(b *testing.B) {
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		SHA256(data)
	}
}

func BenchmarkBLAKE2b256(b *testing.B) {
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		BLAKE2b_256(data)
	}
}

func BenchmarkSHA3512(b *testing.B) {
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		SHA3_512(data)
	}
}

func BenchmarkHMACSHA256(b *testing.B) {
	key := make([]byte, 32)
	data := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HMACSHA256(key, data)
	}
}

func FuzzSHA256(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		result := SHA256(data)
		if len(result) != 64 {
			t.Fatalf("SHA256 should always produce 64 hex chars")
		}
		_, err := hex.DecodeString(result)
		if err != nil {
			t.Fatalf("invalid hex encoding: %v", err)
		}
	})
}
