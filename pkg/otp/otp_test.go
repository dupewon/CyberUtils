package otp

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestTOTPGenerate(t *testing.T) {
	secret := make([]byte, 20)
	rand.Read(secret)

	totp := NewTOTP(secret)
	code := totp.Generate()

	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got '%s' (len=%d)", code, len(code))
	}
}

func TestTOTPValidate(t *testing.T) {
	secret := make([]byte, 20)
	rand.Read(secret)

	totp := NewTOTP(secret)
	code := totp.Generate()

	if !totp.Validate(code) {
		t.Fatal("should validate its own code")
	}
}

func TestTOTPValidate_WrongCode(t *testing.T) {
	secret := make([]byte, 20)
	rand.Read(secret)

	totp := NewTOTP(secret)
	if totp.Validate("000000") {
		t.Fatal("should not validate wrong code")
	}
}

func TestTOTPWithWindow(t *testing.T) {
	secret := make([]byte, 20)
	rand.Read(secret)

	totp := NewTOTP(secret)
	code := totp.Generate()

	// Test with a time 30 seconds in the past — should still be valid with window=1
	pastTime := time.Now().Add(-30 * time.Second)
	if !totp.ValidateAt(code, pastTime, 1) {
		t.Fatal("code should be valid within window of 1 interval")
	}
}

func TestTOTPDifferentSecrets(t *testing.T) {
	secret1 := make([]byte, 20)
	secret2 := make([]byte, 20)
	rand.Read(secret1)
	rand.Read(secret2)

	if string(secret1) == string(secret2) {
		t.Skip("secrets happened to be equal, skipping")
	}

	totp1 := NewTOTP(secret1)
	totp2 := NewTOTP(secret2)

	code1 := totp1.Generate()
	code2 := totp2.Generate()

	if code1 == code2 {
		// This can happen rarely, but let's generate more
		code1 = totp1.Generate()
		// Wait a sec to get different time step
		time.Sleep(100 * time.Millisecond)
		code2 = totp2.Generate()
	}

	if totp2.Validate(code1) {
		t.Fatal("different secrets should produce different codes normally")
	}
}

func TestTOTP8Digits(t *testing.T) {
	secret := make([]byte, 20)
	rand.Read(secret)

	totp := NewTOTP(secret).WithDigits(8)
	code := totp.Generate()

	if len(code) != 8 {
		t.Fatalf("expected 8-digit code, got '%s'", code)
	}
}

func TestTOTPWithInterval(t *testing.T) {
	secret := make([]byte, 20)
	rand.Read(secret)

	totp := NewTOTP(secret).WithInterval(60)
	code := totp.Generate()

	if !totp.Validate(code) {
		t.Fatal("should validate with custom interval")
	}
}

func TestTOTPSecretToString(t *testing.T) {
	secret := make([]byte, 20)
	rand.Read(secret)

	str := TOTPSecretToString(secret)
	decoded, err := TOTPSecretFromString(str)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if string(secret) != string(decoded) {
		t.Fatal("secret round-trip failed")
	}
}

func TestGenerateTOTPSecret(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(secret))
	}
}

func TestGenerateTOTPURI(t *testing.T) {
	secret := make([]byte, 20)
	rand.Read(secret)

	uri := GenerateTOTPURI(secret, "CyberUtils", "user@example.com")
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatal("expected otpauth URI")
	}
	if !strings.Contains(uri, "CyberUtils") {
		t.Fatal("URI should contain issuer")
	}
}

func TestHOTP(t *testing.T) {
	secret := make([]byte, 20)
	rand.Read(secret)

	hotp := NewHOTP(secret, 0)
	code1 := hotp.Generate()
	code2 := hotp.Generate()

	if code1 == code2 {
		t.Fatal("successive HOTP codes should differ")
	}

	if len(code1) != 6 {
		t.Fatalf("expected 6 digits, got %d", len(code1))
	}
}

func TestHOTPValidate(t *testing.T) {
	secret := make([]byte, 20)
	rand.Read(secret)

	hotp := NewHOTP(secret, 42)
	code := hotp.generateCode(42)

	if !hotp.Validate(code) {
		t.Fatal("should validate at current counter")
	}
}

func TestHOTP8Digits(t *testing.T) {
	secret := make([]byte, 20)
	rand.Read(secret)

	hotp := NewHOTP(secret, 0).WithDigits(8)
	code := hotp.Generate()

	if len(code) != 8 {
		t.Fatalf("expected 8 digits, got '%s'", code)
	}
}

func TestBackupCodes(t *testing.T) {
	codes, err := GenerateBackupCodes(10, 8)
	if err != nil {
		t.Fatal(err)
	}

	if len(codes) != 10 {
		t.Fatalf("expected 10 codes, got %d", len(codes))
	}

	for _, code := range codes {
		if len(code) < 8 {
			t.Fatalf("code too short: '%s'", code)
		}
	}
}

func TestBackupCodes_Unique(t *testing.T) {
	codes, err := GenerateBackupCodes(10, 12)
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[string]bool)
	for _, code := range codes {
		if seen[code] {
			t.Fatalf("duplicate code: %s", code)
		}
		seen[code] = true
	}
}

func TestValidateRecoveryCode(t *testing.T) {
	codes, err := GenerateBackupCodes(5, 8)
	if err != nil {
		t.Fatal(err)
	}

	found, remaining := ValidateRecoveryCode(codes, codes[0])
	if !found {
		t.Fatal("should find the first code")
	}
	if len(remaining) != 4 {
		t.Fatalf("expected 4 remaining codes, got %d", len(remaining))
	}
}

func TestRecoveryCode_NotFound(t *testing.T) {
	codes := []string{"CODE1-ABCD", "CODE2-EFGH"}
	found, _ := ValidateRecoveryCode(codes, "WRONG-CODE")
	if found {
		t.Fatal("should not find wrong code")
	}
}

func TestGenerateHexRecoveryCode(t *testing.T) {
	code, err := GenerateHexRecoveryCode(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 32 {
		t.Fatalf("expected 32 hex chars, got %d", len(code))
	}
}

func TestFormatBackupCodes(t *testing.T) {
	codes := []string{"CODE1", "CODE2"}
	formatted := FormatBackupCodes(codes)
	if !strings.Contains(formatted, "CODE1") {
		t.Fatal("formatted output should contain codes")
	}
}

func BenchmarkTOTPGenerate(b *testing.B) {
	secret := make([]byte, 20)
	rand.Read(secret)
	totp := NewTOTP(secret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		totp.Generate()
	}
}
