package validator

import (
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	emailRegex     = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	uuidRegex      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	uuidHexRegex   = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	base64Regex    = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	base64URLRegex = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	hexRegex       = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	macRegex       = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
)

func IPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func IPv6(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To16() != nil && ip.To4() == nil
}

func IP(s string) bool {
	return net.ParseIP(s) != nil
}

func CIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func MAC(s string) bool {
	return macRegex.MatchString(s)
}

func Domain(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) > 63 || len(label) == 0 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' {
				return false
			}
		}
	}
	return strings.Contains(s, ".")
}

func Hostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	return regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`).MatchString(s)
}

func Email(s string) bool {
	if len(s) > 254 {
		return false
	}
	_, err := mail.ParseAddress(s)
	return err == nil && emailRegex.MatchString(s)
}

func URL(s string) bool {
	u, err := url.ParseRequestURI(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func UUID(s string) bool {
	return uuidRegex.MatchString(s)
}

func UUIDHex(s string) bool {
	return uuidHexRegex.MatchString(s)
}

func JWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 {
			return false
		}
	}
	return true
}

func Hash(s string, byteLength int) bool {
	return len(s) == byteLength*2 && hexRegex.MatchString(s)
}

func SHA256Hash(s string) bool {
	return Hash(s, 32)
}

func SHA512Hash(s string) bool {
	return Hash(s, 64)
}

func Base64(s string) bool {
	return base64Regex.MatchString(s)
}

func Base64URL(s string) bool {
	return base64URLRegex.MatchString(s)
}

func Hex(s string) bool {
	if s == "" {
		return false
	}
	return hexRegex.MatchString(s)
}

func Port(n int) bool {
	return n >= 1 && n <= 65535
}

func PortString(s string) bool {
	n, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return Port(n)
}

func NotEmpty(s string) bool {
	return len(strings.TrimSpace(s)) > 0
}

func InRange[T int | int8 | int16 | int32 | int64 | float32 | float64](val, min, max T) bool {
	return val >= min && val <= max
}

func Length(s string, min, max int) bool {
	l := len(s)
	return l >= min && l <= max
}

func ASCII(s string) bool {
	for _, c := range s {
		if c > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func MIME(s string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return false
	}
	return NotEmpty(parts[0]) && NotEmpty(parts[1])
}

func FileExtension(s string) bool {
	if len(s) < 2 || s[0] != '.' {
		return false
	}
	for _, c := range s[1:] {
		if !unicode.IsLetter(c) {
			return false
		}
	}
	return true
}
