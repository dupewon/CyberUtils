package validator

import (
	"strconv"
	"testing"
)

func TestIPv4(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.1", true},
		{"8.8.8.8", true},
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"256.256.256.256", false},
		{"1.2.3", false},
		{"not-an-ip", false},
		{"", false},
		{"::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IPv4(tt.input); got != tt.want {
				t.Fatalf("IPv4(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIPv6(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"::1", true},
		{"2001:db8::1", true},
		{"fe80::1", true},
		{"192.168.1.1", false},
		{"not-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IPv6(tt.input); got != tt.want {
				t.Fatalf("IPv6(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIP(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.1", true},
		{"::1", true},
		{"not-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IP(tt.input); got != tt.want {
				t.Fatalf("IP(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCIDR(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.0/24", true},
		{"10.0.0.0/8", true},
		{"::1/128", true},
		{"2001:db8::/32", true},
		{"192.168.1.0", false},
		{"not-cidr", false},
		{"0.0.0.0/33", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := CIDR(tt.input); got != tt.want {
				t.Fatalf("CIDR(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestMAC(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"00:1A:2B:3C:4D:5E", true},
		{"00-1A-2B-3C-4D-5E", true},
		{"001A2B3C4D5E", false},
		{"not-a-mac", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := MAC(tt.input); got != tt.want {
				t.Fatalf("MAC(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDomain(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"example.com", true},
		{"sub.domain.example.com", true},
		{"localhost", false},
		{"not_a_domain", false},
		{"-invalid.com", false},
		{"invalid-.com", false},
		{"a..b.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := Domain(tt.input); got != tt.want {
				t.Fatalf("Domain(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestHostname(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"example.com", true},
		{"localhost", true},
		{"my-host", true},
		{"-invalid", false},
		{"invalid-", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := Hostname(tt.input); got != tt.want {
				t.Fatalf("Hostname(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestEmail(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"test@example.com", true},
		{"user.name+tag@example.co.uk", true},
		{"x@y.com", true},
		{"not-an-email", false},
		{"@example.com", false},
		{"test@", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := Email(tt.input); got != tt.want {
				t.Fatalf("Email(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://example.com", true},
		{"http://localhost:8080/path", true},
		{"ftp://files.example.com", true},
		{"not-a-url", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := URL(tt.input); got != tt.want {
				t.Fatalf("URL(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestUUID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"550e8400-e29b-41d4-a716-446655440000", true},
		{"550E8400-E29B-41D4-A716-446655440000", true},
		{"not-a-uuid", false},
		{"550e8400e29b41d4a716446655440000", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := UUID(tt.input); got != tt.want {
				t.Fatalf("UUID(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestJWT(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"header.payload.signature", true},
		{"a.b.c", true},
		{"not-jwt", false},
		{"a.b", false},
		{"a.b.c.d", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := JWT(tt.input); got != tt.want {
				t.Fatalf("JWT(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestHash(t *testing.T) {
	tests := []struct {
		name  string
		input string
		fn    func(string) bool
		want  bool
	}{
		{"SHA256 valid", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", SHA256Hash, true},
		{"SHA256 short", "abc", SHA256Hash, false},
		{"SHA256 invalid hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", SHA256Hash, false},
		{"SHA512 valid", "abcd" + "ef01" + "2345" + "6789" + "abcd" + "ef01" + "2345" + "6789" + "abcd" + "ef01" + "2345" + "6789" + "abcd" + "ef01" + "2345" + "6789" + "abcd" + "ef01" + "2345" + "6789" + "abcd" + "ef01" + "2345" + "6789" + "abcd" + "ef01" + "2345" + "6789" + "abcd" + "ef01" + "2345" + "6789", SHA512Hash, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fn(tt.input); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBase64(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"dGVzdA==", true},
		{"dGVzdA", true},
		{"invalid!!!", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := Base64(tt.input); got != tt.want {
				t.Fatalf("Base64(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestHex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"abcdef0123456789", true},
		{"ABCDEF", true},
		{"xyz", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := Hex(tt.input); got != tt.want {
				t.Fatalf("Hex(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestPort(t *testing.T) {
	tests := []struct {
		input int
		want  bool
	}{
		{80, true},
		{443, true},
		{65535, true},
		{0, false},
		{-1, false},
		{65536, false},
	}

	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.input), func(t *testing.T) {
			if got := Port(tt.input); got != tt.want {
				t.Fatalf("Port(%d) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNotEmpty(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello", true},
		{"", false},
		{"   ", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := NotEmpty(tt.input); got != tt.want {
				t.Fatalf("NotEmpty(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestASCII(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello", true},
		{"héllo", false},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ASCII(tt.input); got != tt.want {
				t.Fatalf("ASCII(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestLength(t *testing.T) {
	if !Length("hello", 1, 10) {
		t.Fatal("expected true")
	}
	if Length("hello", 10, 20) {
		t.Fatal("expected false")
	}
}

func TestPortString(t *testing.T) {
	if !PortString("443") {
		t.Fatal("expected true for '443'")
	}
	if PortString("0") {
		t.Fatal("expected false for '0'")
	}
	if PortString("not-a-port") {
		t.Fatal("expected false for non-numeric")
	}
}

func TestFileExtension(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{".txt", true},
		{".go", true},
		{"txt", false},
		{"", false},
		{".", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := FileExtension(tt.input); got != tt.want {
				t.Fatalf("FileExtension(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestMIME(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"text/plain", true},
		{"application/json", true},
		{"invalid", false},
		{"/plain", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := MIME(tt.input); got != tt.want {
				t.Fatalf("MIME(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func BenchmarkEmail(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Email("test.user+tag@example.co.uk")
	}
}

func BenchmarkIPv4(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IPv4("192.168.1.1")
	}
}

func BenchmarkURL(b *testing.B) {
	for i := 0; i < b.N; i++ {
		URL("https://example.com/path/to/resource?query=value")
	}
}
