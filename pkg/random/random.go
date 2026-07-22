package random

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
)

const (
	alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	nanoIDChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)

func UUID() string {
	u := make([]byte, 16)
	rand.Read(u)
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return formatUUID(u)
}

func UUIDHex() string {
	u := make([]byte, 16)
	rand.Read(u)
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return hex.EncodeToString(u)
}

func NanoID(length int) string {
	if length <= 0 {
		length = 21
	}
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(nanoIDChars))))
		result[i] = nanoIDChars[n.Int64()]
	}
	return string(result)
}

func Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func String(length int) (string, error) {
	if length <= 0 {
		length = 16
	}
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumeric))))
		if err != nil {
			return "", err
		}
		result[i] = alphanumeric[n.Int64()]
	}
	return string(result), nil
}

func Hex(n int) string {
	b, err := Bytes(n)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func Base64(n int) string {
	b, err := Bytes(n)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func Int(max int64) (int64, error) {
	if max <= 0 {
		return 0, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}
	return n.Int64(), nil
}

func IntRange(min, max int64) (int64, error) {
	if min > max {
		min, max = max, min
	}
	n, err := Int(max - min + 1)
	if err != nil {
		return 0, err
	}
	return n + min, nil
}

func Float64() (float64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<53))
	if err != nil {
		return 0, err
	}
	return float64(n.Int64()) / float64(1<<53), nil
}

func Shuffle[T any](slice []T) {
	for i := len(slice) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return
		}
		j := n.Int64()
		slice[i], slice[j] = slice[j], slice[i]
	}
}

func Choice[T any](slice []T) (T, error) {
	var zero T
	if len(slice) == 0 {
		return zero, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(slice))))
	if err != nil {
		return zero, err
	}
	return slice[n.Int64()], nil
}

func Token(bytes int) string {
	return Base64(bytes)
}

func OTP(digits int) string {
	if digits <= 0 {
		digits = 6
	}
	var sb strings.Builder
	for i := 0; i < digits; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(10))
		sb.WriteByte(byte('0' + n.Int64()))
	}
	return sb.String()
}

func formatUUID(u []byte) string {
	return hex.EncodeToString(u[:4]) + "-" +
		hex.EncodeToString(u[4:6]) + "-" +
		hex.EncodeToString(u[6:8]) + "-" +
		hex.EncodeToString(u[8:10]) + "-" +
		hex.EncodeToString(u[10:])
}
