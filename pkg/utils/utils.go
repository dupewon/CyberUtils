package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func TimingSafeCompare(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func FileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Checksum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func DirectoryHash(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return "", err
		}
		fh, err := FileHash(filepath.Join(dir, info.Name()))
		if err != nil {
			return "", err
		}
		h.Write([]byte(info.Name()))
		h.Write([]byte(fh))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func SecureDelete(path string, passes int) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	size := info.Size()
	if passes <= 0 {
		passes = 3
	}
	for i := 0; i < passes; i++ {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		buf := make([]byte, 4096)
		remaining := size
		for remaining > 0 {
			rand.Read(buf)
			writeSize := int64(len(buf))
			if writeSize > remaining {
				writeSize = remaining
			}
			if _, err := f.Write(buf[:writeSize]); err != nil {
				f.Close()
				return err
			}
			remaining -= writeSize
		}
		f.Close()
	}
	return os.Remove(path)
}

func DetectFileType(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	magic := make([]byte, 16)
	n, err := io.ReadFull(f, magic)
	if err != nil && err != io.ErrUnexpectedEOF {
		return "", err
	}
	return MatchSignature(magic[:n]), nil
}

func MatchSignature(magic []byte) string {
	sigs := []struct {
		magic []byte
		ext   string
	}{
		{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "PNG"},
		{[]byte{0xFF, 0xD8, 0xFF, 0xE0}, "JPEG"},
		{[]byte{0xFF, 0xD8, 0xFF, 0xE1}, "JPEG"},
		{[]byte{0xFF, 0xD8, 0xFF, 0xE2}, "JPEG"},
		{[]byte{0x47, 0x49, 0x46, 0x38}, "GIF"},
		{[]byte{0x25, 0x50, 0x44, 0x46}, "PDF"},
		{[]byte{0x50, 0x4B, 0x03, 0x04}, "ZIP"},
		{[]byte{0x7F, 0x45, 0x4C, 0x46}, "ELF"},
		{[]byte{0x4D, 0x5A}, "PE"},
		{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, "CLASS"},
		{[]byte{0x1F, 0x8B}, "GZIP"},
	}
	for _, sig := range sigs {
		if len(magic) >= len(sig.magic) {
			match := true
			for i, b := range sig.magic {
				if magic[i] != b {
					match = false
					break
				}
			}
			if match {
				return sig.ext
			}
		}
	}
	return "unknown"
}

func SecureTempFile(dir, prefix string) (*os.File, error) {
	return os.CreateTemp(dir, prefix)
}

func EnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func EnvIsSet(key string) bool {
	return os.Getenv(key) != ""
}

func ListEnvWithPrefix(prefix string) map[string]string {
	result := make(map[string]string)
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, prefix) {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				result[parts[0]] = parts[1]
			}
		}
	}
	return result
}

func MustEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		panic("utils: required env " + key + " not set")
	}
	return val
}

func IsFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func IsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func FileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
