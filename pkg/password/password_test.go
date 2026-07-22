package password

import (
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		symbols   bool
		wantErr   bool
		minLength int
	}{
		{"8 chars no symbols", 8, false, false, 8},
		{"16 chars with symbols", 16, true, false, 16},
		{"32 chars no symbols", 32, false, false, 32},
		{"too short", 4, false, true, 0},
		{"zero length", 0, false, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pwd, err := Generate(tt.length, tt.symbols)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pwd) != tt.minLength {
				t.Fatalf("expected length %d, got %d", tt.minLength, len(pwd))
			}
		})
	}
}

func TestGenerate_IncludesSymbols(t *testing.T) {
	pwd, err := Generate(32, true)
	if err != nil {
		t.Fatal(err)
	}

	hasSymbol := false
	for _, c := range pwd {
		if strings.ContainsAny(string(c), Symbols) {
			hasSymbol = true
			break
		}
	}
	if !hasSymbol {
		t.Fatal("expected at least one symbol character")
	}
}

func TestGenerate_NoSymbols(t *testing.T) {
	pwd, err := Generate(16, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range pwd {
		if strings.ContainsAny(string(c), Symbols) {
			t.Fatal("no symbols should be present")
		}
	}
}

func TestCheck_Empty(t *testing.T) {
	s := Check("")
	if s.Label != Weak {
		t.Fatalf("empty password should be Weak, got %s", s.Label)
	}
}

func TestCheck_Strong(t *testing.T) {
	s := Check("K#9mP2xL$vN!qR7wZ")
	if s.Label != VeryStrong && s.Label != Strong {
		t.Fatalf("expected Strong or VeryStrong, got %s", s.Label)
	}
}

func TestCheck_Common(t *testing.T) {
	s := Check("password")
	if !s.IsCommon {
		t.Fatal("'password' should be flagged as common")
	}
}

func TestCheck_RepeatedChars(t *testing.T) {
	s := Check("aaabbb123")
	if !s.HasRepeats {
		t.Fatal("should detect repeated characters")
	}
}

func TestCheck_Weak(t *testing.T) {
	s := Check("abc")
	if s.Label != Weak {
		t.Fatalf("expected Weak, got %s", s.Label)
	}
}

func TestBcryptHashVerify(t *testing.T) {
	password := []byte("my-secure-password-123")

	hash, err := BcryptHash(password, 4) // low cost for fast test
	if err != nil {
		t.Fatalf("BcryptHash failed: %v", err)
	}

	if !BcryptVerify(password, hash) {
		t.Fatal("BcryptVerify should succeed")
	}

	if BcryptVerify([]byte("wrong-password"), hash) {
		t.Fatal("BcryptVerify should fail for wrong password")
	}
}

func TestBcryptDefaultCost(t *testing.T) {
	hash, err := BcryptHash([]byte("test"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) == 0 {
		t.Fatal("expected non-empty hash")
	}
}

func TestArgon2ID(t *testing.T) {
	salt := make([]byte, 16)
	rand.Read(salt)

	hash := Argon2IDHash([]byte("password"), salt, 1, 64*1024, 1, 32)
	if len(hash) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(hash))
	}

	// Same inputs should produce same hash
	hash2 := Argon2IDHash([]byte("password"), salt, 1, 64*1024, 1, 32)
	if !VerifyConstantTime(hash, hash2) {
		t.Fatal("Argon2id should be deterministic with same salt")
	}
}

func TestArgon2ID_NilSalt(t *testing.T) {
	hash := Argon2IDHash([]byte("password"), nil, 1, 64*1024, 1, 32)
	if len(hash) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(hash))
	}
}

func TestScrypt(t *testing.T) {
	hash, err := ScryptHash([]byte("password"), []byte("saltysalt"), 16384, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(hash))
	}
}

func TestPBKDF2(t *testing.T) {
	hash := PBKDF2Hash([]byte("password"), []byte("salt"), 10000, 32, sha256.New)
	if len(hash) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(hash))
	}
}

func TestEncodeHash(t *testing.T) {
	hash := []byte{1, 2, 3, 4, 5}
	salt := []byte{6, 7, 8, 9, 10}
	encoded := EncodeHash("argon2id", hash, salt)

	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Fatal("expected argon2id prefix")
	}
}

func TestVerifyConstantTime(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"equal", []byte("abc"), []byte("abc"), true},
		{"not equal", []byte("abc"), []byte("xyz"), false},
		{"different lengths", []byte("abc"), []byte("abcd"), false},
		{"nil nil", nil, nil, true},
		{"nil empty", nil, []byte{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyConstantTime(tt.a, tt.b); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEntropyCalculation(t *testing.T) {
	s := Check("abc123")
	if s.Entropy <= 0 {
		t.Fatal("entropy should be positive")
	}
}

func BenchmarkGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Generate(16, true)
	}
}

func BenchmarkBcryptHash(b *testing.B) {
	password := []byte("benchmark-password")
	for i := 0; i < b.N; i++ {
		BcryptHash(password, 4)
	}
}

func BenchmarkCheck(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Check("K#9mP2xL$vN!qR7wZ")
	}
}
