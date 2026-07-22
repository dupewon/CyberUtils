package random

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestUUID(t *testing.T) {
	u := UUID()
	if len(u) != 36 {
		t.Fatalf("expected 36 chars, got %d: %s", len(u), u)
	}

	if u[14] != '4' {
		t.Fatalf("expected version 4 UUID, got '%c'", u[14])
	}

	if u[19] != '8' && u[19] != '9' && u[19] != 'a' && u[19] != 'b' {
		t.Fatalf("expected variant bits, got '%c'", u[19])
	}
}

func TestUUID_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		u := UUID()
		if seen[u] {
			t.Fatal("duplicate UUID detected")
		}
		seen[u] = true
	}
}

func TestUUIDHex(t *testing.T) {
	u := UUIDHex()
	if len(u) != 32 {
		t.Fatalf("expected 32 hex chars, got %d", len(u))
	}
	_, err := hex.DecodeString(u)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}
}

func TestNanoID(t *testing.T) {
	nano := NanoID(0)
	if len(nano) != 21 {
		t.Fatalf("expected default 21 chars, got %d", len(nano))
	}

	nano = NanoID(10)
	if len(nano) != 10 {
		t.Fatalf("expected 10 chars, got %d", len(nano))
	}
}

func TestNanoID_Characters(t *testing.T) {
	nano := NanoID(1000)
	for _, c := range nano {
		if !strings.ContainsRune(nanoIDChars, c) {
			t.Fatalf("invalid character '%c' in nanoid", c)
		}
	}
}

func TestBytes(t *testing.T) {
	b, err := Bytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
}

func TestBytes_Empty(t *testing.T) {
	b, err := Bytes(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Fatalf("expected 0 bytes, got %d", len(b))
	}
}

func TestString(t *testing.T) {
	s, err := String(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 16 {
		t.Fatalf("expected 16 chars, got %d", len(s))
	}

	for _, c := range s {
		if !strings.ContainsRune(alphanumeric, c) {
			t.Fatalf("invalid character '%c' in random string", c)
		}
	}
}

func TestHex(t *testing.T) {
	h := Hex(16)
	if len(h) != 32 {
		t.Fatalf("expected 32 hex chars, got %d", len(h))
	}
	_, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}
}

func TestBase64(t *testing.T) {
	b := Base64(16)
	if len(b) == 0 {
		t.Fatal("expected non-empty base64 string")
	}
}

func TestInt(t *testing.T) {
	n, err := Int(100)
	if err != nil {
		t.Fatal(err)
	}
	if n < 0 || n >= 100 {
		t.Fatalf("expected [0, 100), got %d", n)
	}
}

func TestInt_Zero(t *testing.T) {
	n, err := Int(0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 for max=0, got %d", n)
	}
}

func TestIntRange(t *testing.T) {
	n, err := IntRange(5, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n < 5 || n > 10 {
		t.Fatalf("expected [5, 10], got %d", n)
	}
}

func TestIntRange_Reversed(t *testing.T) {
	n, err := IntRange(10, 5)
	if err != nil {
		t.Fatal(err)
	}
	if n < 5 || n > 10 {
		t.Fatalf("expected [5, 10] with reversed args, got %d", n)
	}
}

func TestFloat64(t *testing.T) {
	f, err := Float64()
	if err != nil {
		t.Fatal(err)
	}
	if f < 0.0 || f >= 1.0 {
		t.Fatalf("expected [0.0, 1.0), got %f", f)
	}
}

func TestShuffle(t *testing.T) {
	original := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	s := make([]int, len(original))
	copy(s, original)

	Shuffle(s)

	same := true
	for i := range s {
		if s[i] != original[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("shuffle should change order")
	}
}

func TestShuffle_PreservesElements(t *testing.T) {
	s := []string{"a", "b", "c", "d", "e"}
	Shuffle(s)

	counts := make(map[string]int)
	for _, v := range s {
		counts[v]++
	}
	for _, v := range []string{"a", "b", "c", "d", "e"} {
		if counts[v] != 1 {
			t.Fatalf("shuffle lost element '%s'", v)
		}
	}
}

func TestChoice(t *testing.T) {
	items := []string{"apple", "banana", "cherry"}
	chosen, err := Choice(items)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, item := range items {
		if item == chosen {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("unexpected choice: '%s'", chosen)
	}
}

func TestChoice_Empty(t *testing.T) {
	_, err := Choice([]int{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestToken(t *testing.T) {
	tok := Token(32)
	if len(tok) == 0 {
		t.Fatal("expected non-empty token")
	}
}

func TestOTP(t *testing.T) {
	otp := OTP(6)
	if len(otp) != 6 {
		t.Fatalf("expected 6 digits, got %d", len(otp))
	}
	for _, c := range otp {
		if c < '0' || c > '9' {
			t.Fatalf("expected digit, got '%c'", c)
		}
	}
}

func TestOTP_Default(t *testing.T) {
	otp := OTP(0)
	if len(otp) != 6 {
		t.Fatalf("expected default 6 digits, got %d", len(otp))
	}
}

func BenchmarkUUID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		UUID()
	}
}

func BenchmarkNanoID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NanoID(21)
	}
}

func BenchmarkRandomString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		String(32)
	}
}

func BenchmarkHex(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Hex(32)
	}
}

func BenchmarkBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Bytes(32)
	}
}
