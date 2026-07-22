package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTimingSafeCompare(t *testing.T) {
	tests := []struct {
		a, b []byte
		want bool
	}{
		{[]byte("abc"), []byte("abc"), true},
		{[]byte("abc"), []byte("xyz"), false},
		{[]byte{}, []byte{}, true},
	}

	for _, tt := range tests {
		if got := TimingSafeCompare(tt.a, tt.b); got != tt.want {
			t.Fatalf("TimingSafeCompare(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestChecksum(t *testing.T) {
	c1 := Checksum([]byte("hello"))
	c2 := Checksum([]byte("hello"))
	c3 := Checksum([]byte("world"))

	if c1 != c2 {
		t.Fatal("checksums of same data should match")
	}
	if c1 == c3 {
		t.Fatal("checksums of different data should differ")
	}
	if len(c1) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(c1))
	}
}

func TestFileHash(t *testing.T) {
	f, err := os.CreateTemp("", "test-hash")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	f.WriteString("test content")
	f.Close()

	hash, err := FileHash(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(hash))
	}
}

func TestFileHash_Nonexistent(t *testing.T) {
	_, err := FileHash("/nonexistent/file")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestDirectoryHash(t *testing.T) {
	dir, err := os.MkdirTemp("", "test-dirhash")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	f1, _ := os.Create(filepath.Join(dir, "a.txt"))
	f1.WriteString("content a")
	f1.Close()

	f2, _ := os.Create(filepath.Join(dir, "b.txt"))
	f2.WriteString("content b")
	f2.Close()

	hash, err := DirectoryHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(hash))
	}
}

func TestDetectFileType(t *testing.T) {
	f, err := os.CreateTemp("", "test-filetype")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	f.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52})
	f.Close()

	ft, err := DetectFileType(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if ft != "PNG" {
		t.Fatalf("expected PNG, got '%s'", ft)
	}
}

func TestMatchSignature(t *testing.T) {
	tests := []struct {
		magic []byte
		want  string
	}{
		{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "PNG"},
		{[]byte{0xFF, 0xD8, 0xFF, 0xE0}, "JPEG"},
		{[]byte{0x25, 0x50, 0x44, 0x46}, "PDF"},
		{[]byte{0x50, 0x4B, 0x03, 0x04}, "ZIP"},
		{[]byte{0x4D, 0x5A}, "PE"},
		{[]byte{0x00, 0x00, 0x00, 0x00}, "unknown"},
	}

	for _, tt := range tests {
		if got := MatchSignature(tt.magic); got != tt.want {
			t.Fatalf("MatchSignature(%v) = '%s', want '%s'", tt.magic, got, tt.want)
		}
	}
}

func TestSecureTempFile(t *testing.T) {
	f, err := SecureTempFile("", "test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if f.Name() == "" {
		t.Fatal("expected non-empty file name")
	}
}

func TestEnvOrDefault(t *testing.T) {
	os.Setenv("TEST_ENV_KEY", "custom")
	defer os.Unsetenv("TEST_ENV_KEY")

	if got := EnvOrDefault("TEST_ENV_KEY", "default"); got != "custom" {
		t.Fatalf("expected 'custom', got '%s'", got)
	}
	if got := EnvOrDefault("NONEXISTENT_KEY", "default"); got != "default" {
		t.Fatalf("expected 'default', got '%s'", got)
	}
}

func TestEnvIsSet(t *testing.T) {
	os.Setenv("TEST_SET_KEY", "value")
	defer os.Unsetenv("TEST_SET_KEY")

	if !EnvIsSet("TEST_SET_KEY") {
		t.Fatal("should be set")
	}
	if EnvIsSet("NONEXISTENT_KEY") {
		t.Fatal("should not be set")
	}
}

func TestListEnvWithPrefix(t *testing.T) {
	os.Setenv("TEST_PREFIX_KEY", "value")
	defer os.Unsetenv("TEST_PREFIX_KEY")

	envs := ListEnvWithPrefix("TEST_PREFIX")
	if len(envs) == 0 {
		t.Fatal("expected at least one env var")
	}
}

func TestIsFileAndIsDir(t *testing.T) {
	f, err := os.CreateTemp("", "test-exists")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	if !IsFile(f.Name()) {
		t.Fatal("should be a file")
	}

	dir, _ := os.MkdirTemp("", "test-dir")
	defer os.RemoveAll(dir)

	if !IsDir(dir) {
		t.Fatal("should be a directory")
	}

	if IsFile("/nonexistent") {
		t.Fatal("should be false for nonexistent")
	}
}

func TestFileSize(t *testing.T) {
	f, err := os.CreateTemp("", "test-size")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("12345")
	f.Close()

	size, err := FileSize(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if size != 5 {
		t.Fatalf("expected 5 bytes, got %d", size)
	}
}

func BenchmarkChecksum(b *testing.B) {
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		Checksum(data)
	}
}
