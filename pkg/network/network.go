package network

import (
	"net"
	"strconv"
	"strings"
)

var (
	privateCIDRs = []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	}
	reservedCIDRs = []string{
		"0.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	}
	privateNets  []*net.IPNet
	reservedNets []*net.IPNet
)

func init() {
	for _, c := range privateCIDRs {
		_, n, _ := net.ParseCIDR(c)
		if n != nil {
			privateNets = append(privateNets, n)
		}
	}
	for _, c := range reservedCIDRs {
		_, n, _ := net.ParseCIDR(c)
		if n != nil {
			reservedNets = append(reservedNets, n)
		}
	}
}

func IsPrivateIP(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func IsPublicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !IsPrivateIP(ip) && !IsReservedIP(ip)
}

func IsReservedIP(ip net.IP) bool {
	for _, n := range reservedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func IsLoopbackIP(ip net.IP) bool {
	return ip.IsLoopback()
}

func LookupIP(hostname string) ([]net.IP, error) {
	return net.LookupIP(hostname)
}

func ReverseDNS(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return "", err
	}
	if len(names) > 0 {
		return strings.TrimRight(names[0], "."), nil
	}
	return "", nil
}

func ParsePort(s string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if port < 1 || port > 65535 {
		return 0, ErrInvalidPort
	}
	return port, nil
}

var ErrInvalidPort = &errInvalidPort{}

type errInvalidPort struct{}

func (*errInvalidPort) Error() string { return "network: invalid port number" }

func SubnetSize(cidr string) (int64, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	ones, bits := n.Mask.Size()
	return 1 << (bits - ones), nil
}

func ContainsCIDR(parent, child string) (bool, error) {
	_, pNet, err := net.ParseCIDR(parent)
	if err != nil {
		return false, err
	}
	_, cNet, err := net.ParseCIDR(child)
	if err != nil {
		return false, err
	}
	return pNet.Contains(cNet.IP), nil
}

func NetworkAddress(cidr string) (net.IP, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return n.IP, nil
}

func BroadcastAddress(cidr string) (net.IP, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ip := n.IP.To4()
	if ip == nil {
		return nil, ErrInvalidPort
	}
	broadcast := make(net.IP, 4)
	copy(broadcast, ip)
	for i := range broadcast {
		broadcast[i] = ip[i] | ^n.Mask[i]
	}
	return broadcast, nil
}

func IncrementIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func IPVersion(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	if ip.To16() != nil {
		return 6
	}
	return 0
}
