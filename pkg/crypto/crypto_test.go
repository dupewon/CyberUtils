package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptGCM(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("hello world this is a test message")

	ciphertext, err := EncryptGCM(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptGCM failed: %v", err)
	}

	decrypted, err := DecryptGCM(key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptGCM failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted text does not match original")
	}
}

func TestEncryptDecryptGCM_InvalidKey(t *testing.T) {
	_, err := EncryptGCM([]byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestEncryptDecryptGCM_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("sensitive data")

	ciphertext, err := EncryptGCM(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	_, err = DecryptGCM(wrongKey, ciphertext)
	if err != ErrAuthenticationFailed {
		t.Fatalf("expected ErrAuthenticationFailed, got %v", err)
	}
}

func TestEncryptDecryptCBC(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"AES-128", make([]byte, 16)},
		{"AES-192", make([]byte, 24)},
		{"AES-256", make([]byte, 32)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rand.Read(tt.key)
			plaintext := []byte("CBC mode test with padding")

			ciphertext, err := EncryptCBC(tt.key, plaintext)
			if err != nil {
				t.Fatalf("EncryptCBC failed: %v", err)
			}

			decrypted, err := DecryptCBC(tt.key, ciphertext)
			if err != nil {
				t.Fatalf("DecryptCBC failed: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Fatal("CBC decrypted text does not match original")
			}
		})
	}
}

func TestCBC_PaddingEdgeCases(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte("a")},
		{"exact block", bytes.Repeat([]byte("A"), 16)},
		{"block minus one", bytes.Repeat([]byte("B"), 15)},
		{"multiple blocks", bytes.Repeat([]byte("C"), 48)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := EncryptCBC(key, tt.data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := DecryptCBC(key, ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(tt.data, decrypted) {
				t.Fatal("mismatch")
			}
		})
	}
}

func TestRSAEncryptDecryptOAEP(t *testing.T) {
	priv, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("RSA-OAEP test")

	ciphertext, err := RSAEncryptOAEP(&priv.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("RSAEncryptOAEP failed: %v", err)
	}

	decrypted, err := RSADecryptOAEP(priv, ciphertext)
	if err != nil {
		t.Fatalf("RSADecryptOAEP failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("RSA decrypted text does not match original")
	}
}

func TestRSASignVerify(t *testing.T) {
	priv, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("message to sign")

	sig, err := RSASign(priv, data)
	if err != nil {
		t.Fatalf("RSASign failed: %v", err)
	}

	if err := RSAVerify(&priv.PublicKey, data, sig); err != nil {
		t.Fatalf("RSAVerify failed: %v", err)
	}
}

func TestRSAKeySizes(t *testing.T) {
	_, err := GenerateRSAKey(1024)
	if err == nil {
		t.Fatal("expected error for 1024-bit key")
	}

	_, err = GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("2048-bit key should be valid: %v", err)
	}
}

func TestRSAPEMRoundTrip(t *testing.T) {
	priv, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	privPEM, err := RSAPrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("RSAPrivateKeyToPEM failed: %v", err)
	}

	pubPEM, err := RSAPublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("RSAPublicKeyToPEM failed: %v", err)
	}

	decodedPriv, err := RSAPrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("RSAPrivateKeyFromPEM failed: %v", err)
	}

	decodedPub, err := RSAPublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("RSAPublicKeyFromPEM failed: %v", err)
	}

	if !decodedPriv.Equal(priv) {
		t.Fatal("private key mismatch after PEM round-trip")
	}

	if !decodedPub.Equal(&priv.PublicKey) {
		t.Fatal("public key mismatch after PEM round-trip")
	}
}

func TestEd25519SignVerify(t *testing.T) {
	priv, pub, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("Ed25519 test message")
	sig := Ed25519Sign(priv, data)

	if !Ed25519Verify(pub, data, sig) {
		t.Fatal("Ed25519 signature verification failed")
	}
}

func TestEd25519PEMRoundTrip(t *testing.T) {
	priv, pub, err := GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}

	privPEM, err := Ed25519PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}

	pubPEM, err := Ed25519PublicKeyToPEM(pub)
	if err != nil {
		t.Fatal(err)
	}

	decodedPriv, err := Ed25519PrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}

	decodedPub, err := Ed25519PublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	if !decodedPriv.Equal(priv) {
		t.Fatal("Ed25519 private key mismatch")
	}

	if !bytes.Equal(decodedPub, pub) {
		t.Fatal("Ed25519 public key mismatch")
	}
}

func TestECDSA(t *testing.T) {
	curves := []string{CurveP256, CurveP384, CurveP521}
	for _, curve := range curves {
		t.Run(curve, func(t *testing.T) {
			priv, err := GenerateECDSAKey(curve)
			if err != nil {
				t.Fatal(err)
			}

			data := []byte("ECDSA test")
			r, s, err := ECDSASign(priv, data)
			if err != nil {
				t.Fatal(err)
			}

			if !ECDSAVerify(&priv.PublicKey, data, r, s) {
				t.Fatal("ECDSA verification failed")
			}
		})
	}
}

func TestPEM(t *testing.T) {
	raw := []byte("some binary data")

	encoded := PEMEncode("TEST DATA", raw)
	blockType, decoded, err := PEMDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if blockType != "TEST DATA" {
		t.Fatalf("expected TEST DATA, got %s", blockType)
	}

	if !bytes.Equal(raw, decoded) {
		t.Fatal("PEM decode mismatch")
	}
}

func TestGenerateSymmetricKey(t *testing.T) {
	tests := []struct {
		name string
		n    int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateSymmetricKey(tt.n)
			if err != nil {
				t.Fatal(err)
			}
			if len(key) != tt.n {
				t.Fatalf("expected %d bytes, got %d", tt.n, len(key))
			}
		})
	}
}

func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name string
		kt   KeyType
	}{
		{"RSA 2048", KeyRSA2048},
		{"RSA 4096", KeyRSA4096},
		{"ECDSA P256", KeyECDSA256},
		{"ECDSA P384", KeyECDSA384},
		{"ECDSA P521", KeyECDSA521},
		{"Ed25519", KeyEd25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, pub, err := GenerateKeyPair(tt.kt)
			if err != nil {
				t.Fatal(err)
			}
			if priv == nil || pub == nil {
				t.Fatal("expected non-nil keys")
			}
		})
	}
}

func TestAESGCM_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	ciphertext, err := EncryptGCM(key, nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptGCM(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if len(decrypted) != 0 {
		t.Fatal("expected empty result")
	}
}

func TestDecryptGCM_ShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_, err := DecryptGCM(key, []byte("short"))
	if err != ErrCiphertextTooShort {
		t.Fatalf("expected ErrCiphertextTooShort, got %v", err)
	}
}

func BenchmarkAESGCMEncrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := make([]byte, 1024)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptGCM(key, plaintext)
	}
}

func BenchmarkRSASign(b *testing.B) {
	priv, _ := GenerateRSAKey(2048)
	data := []byte("benchmark data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RSASign(priv, data)
	}
}

func FuzzAESGCMRoundtrip(f *testing.F) {
	f.Add([]byte("key-123456789012"), []byte("plaintext data"))
	f.Fuzz(func(t *testing.T, key, plaintext []byte) {
		if len(key) != 16 && len(key) != 24 && len(key) != 32 || len(key) == 0 {
			t.Skip()
		}
		ciphertext, err := EncryptGCM(key, plaintext)
		if err != nil {
			t.Skip()
		}
		decrypted, err := DecryptGCM(key, ciphertext)
		if err != nil {
			t.Fatalf("roundtrip failed: %v", err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Fatal("mismatch")
		}
	})
}
