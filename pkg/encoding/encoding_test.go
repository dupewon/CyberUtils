package encoding

import (
	"bytes"
	"testing"
)

func TestBase64RoundTrip(t *testing.T) {
	original := []byte("hello world")
	encoded := Base64Encode(original)
	decoded, err := Base64Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, decoded) {
		t.Fatal("base64 round trip failed")
	}
}

func TestBase64Decode_Padding(t *testing.T) {
	// Without padding
	encoded := "aGVsbG8gd29ybGQ"
	decoded, err := Base64Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "hello world" {
		t.Fatalf("expected 'hello world', got '%s'", decoded)
	}
}

func TestBase64URLRoundTrip(t *testing.T) {
	original := []byte("test data with +/ and =")
	encoded := Base64URLEncode(original)
	decoded, err := Base64URLDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, decoded) {
		t.Fatal("base64url round trip failed")
	}
}

func TestHexRoundTrip(t *testing.T) {
	original := []byte{0xde, 0xad, 0xbe, 0xef}
	encoded := HexEncode(original)
	decoded, err := HexDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, decoded) {
		t.Fatal("hex round trip failed")
	}
}

func TestBase32RoundTrip(t *testing.T) {
	original := []byte("base32 test")
	encoded := Base32Encode(original)
	decoded, err := Base32Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, decoded) {
		t.Fatal("base32 round trip failed")
	}
}

func TestURLEncodeDecode(t *testing.T) {
	original := "hello world & special chars=yes"
	encoded := URLEncode(original)
	decoded, err := URLDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if original != decoded {
		t.Fatalf("expected '%s', got '%s'", original, decoded)
	}
}

func TestURLEncodeAll(t *testing.T) {
	encoded := URLEncodeAll("hello")
	if encoded != "%68%65%6C%6C%6F" {
		t.Fatalf("expected %%68%%65%%6C%%6C%%6F, got '%s'", encoded)
	}
}

func TestUnicodeRoundTrip(t *testing.T) {
	original := "héllo wörld"
	encoded := UnicodeEncode(original)
	decoded, err := UnicodeDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if original != decoded {
		t.Fatalf("expected '%s', got '%s'", original, decoded)
	}
}

func TestBinaryRoundTrip(t *testing.T) {
	original := []byte{0x48, 0x65, 0x6C, 0x6C, 0x6F}
	encoded := BinaryEncode(original)
	decoded, err := BinaryDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, decoded) {
		t.Fatal("binary round trip failed")
	}
}

func TestEmptyInputs(t *testing.T) {
	tests := []struct {
		name string
		fn   func() (interface{}, error)
	}{
		{"Base64Decode empty", func() (interface{}, error) { return Base64Decode("") }},
		{"HexDecode empty", func() (interface{}, error) { return HexDecode("") }},
		{"Base32Decode empty", func() (interface{}, error) { return Base32Decode("") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fn()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBase64Encode(t *testing.T) {
	encoded := Base64Encode([]byte("f"))
	if encoded != "Zg==" {
		t.Fatalf("expected 'Zg==', got '%s'", encoded)
	}
}

func BenchmarkBase64Encode(b *testing.B) {
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		Base64Encode(data)
	}
}

func BenchmarkHexEncode(b *testing.B) {
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		HexEncode(data)
	}
}
