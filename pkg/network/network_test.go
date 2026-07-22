package network

import (
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := IsPrivateIP(ip); got != tt.want {
				t.Fatalf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"192.168.1.1", false},
		{"127.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := IsPublicIP(ip); got != tt.want {
				t.Fatalf("IsPublicIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsReservedIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"0.0.0.1", true},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := IsReservedIP(ip); got != tt.want {
				t.Fatalf("IsReservedIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsLoopbackIP(t *testing.T) {
	if !IsLoopbackIP(net.ParseIP("127.0.0.1")) {
		t.Fatal("127.0.0.1 should be loopback")
	}
	if IsLoopbackIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("8.8.8.8 should not be loopback")
	}
}

func TestLookupIP(t *testing.T) {
	ips, err := LookupIP("localhost")
	if err != nil {
		t.Fatalf("LookupIP failed: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one IP for localhost")
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"443", 443, false},
		{"80", 80, false},
		{"0", 0, true},
		{"65536", 0, true},
		{"not-a-port", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			port, err := ParsePort(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if port != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, port)
			}
		})
	}
}

func TestSubnetSize(t *testing.T) {
	tests := []struct {
		cidr string
		want int64
	}{
		{"192.168.1.0/24", 256},
		{"10.0.0.0/8", 16777216},
		{"::1/128", 1},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			size, err := SubnetSize(tt.cidr)
			if err != nil {
				t.Fatal(err)
			}
			if size != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, size)
			}
		})
	}
}

func TestContainsCIDR(t *testing.T) {
	ok, err := ContainsCIDR("10.0.0.0/8", "10.0.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("10.0.0.0/8 should contain 10.0.1.0/24")
	}

	ok, err = ContainsCIDR("192.168.1.0/24", "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("192.168.1.0/24 should not contain 10.0.0.0/8")
	}
}

func TestNetworkAddress(t *testing.T) {
	ip, err := NetworkAddress("192.168.1.100/24")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "192.168.1.0" {
		t.Fatalf("expected 192.168.1.0, got %s", ip.String())
	}
}

func TestBroadcastAddress(t *testing.T) {
	ip, err := BroadcastAddress("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "192.168.1.255" {
		t.Fatalf("expected 192.168.1.255, got %s", ip.String())
	}
}

func TestIncrementIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	next := IncrementIP(ip)
	if next.String() != "192.168.1.2" {
		t.Fatalf("expected 192.168.1.2, got %s", next.String())
	}
}

func TestIPVersion(t *testing.T) {
	if IPVersion(net.ParseIP("192.168.1.1")) != 4 {
		t.Fatal("expected IPv4")
	}
	if IPVersion(net.ParseIP("::1")) != 6 {
		t.Fatal("expected IPv6")
	}
	if IPVersion(net.IP{}) != 0 {
		t.Fatal("expected 0 for invalid IP")
	}
}
