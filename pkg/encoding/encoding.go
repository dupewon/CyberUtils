package encoding

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.StdEncoding.DecodeString(s)
}

func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func Base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

func HexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func Base32Encode(data []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

func Base32Decode(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

func URLEncode(s string) string {
	return url.QueryEscape(s)
}

func URLDecode(s string) (string, error) {
	return url.QueryUnescape(s)
}

func URLEncodeAll(s string) string {
	var result strings.Builder
	for _, c := range s {
		if c > unicode.MaxASCII {
			result.WriteRune(c)
			continue
		}
		result.WriteString(fmt.Sprintf("%%%02X", c))
	}
	return result.String()
}

func UnicodeEncode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r > 127 {
			result.WriteString(fmt.Sprintf("\\u%04X", r))
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func UnicodeDecode(s string) (string, error) {
	var result strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+5 < len(s) && s[i+1] == 'u' {
			code := s[i+2 : i+6]
			var r rune
			_, err := fmt.Sscanf(code, "%04x", &r)
			if err != nil {
				return "", err
			}
			result.WriteRune(r)
			i += 6
		} else {
			result.WriteByte(s[i])
			i++
		}
	}
	return result.String(), nil
}

func BinaryEncode(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%08b", b)
	}
	return strings.Join(parts, " ")
}

func BinaryDecode(s string) ([]byte, error) {
	parts := strings.Fields(s)
	result := make([]byte, len(parts))
	for i, p := range parts {
		if len(p) != 8 {
			return nil, fmt.Errorf("encoding: invalid binary string: %s", p)
		}
		var b byte
		_, err := fmt.Sscanf(p, "%08b", &b)
		if err != nil {
			return nil, err
		}
		result[i] = b
	}
	return result, nil
}
