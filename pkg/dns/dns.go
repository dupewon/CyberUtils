package dns

import (
	"context"
	"net"
	"time"
)

var DefaultResolver = &net.Resolver{}

func LookupA(hostname string) ([]net.IP, error) {
	addrs, err := DefaultResolver.LookupIPAddr(context.Background(), hostname)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP
	}
	return ips, nil
}

func LookupAAAA(hostname string) ([]net.IP, error) {
	addrs, err := DefaultResolver.LookupIPAddr(context.Background(), hostname)
	if err != nil {
		return nil, err
	}
	var v6 []net.IP
	for _, a := range addrs {
		if a.IP.To4() == nil {
			v6 = append(v6, a.IP)
		}
	}
	return v6, nil
}

func LookupTXT(hostname string) ([]string, error) {
	return DefaultResolver.LookupTXT(context.Background(), hostname)
}

func LookupMX(hostname string) ([]*net.MX, error) {
	return DefaultResolver.LookupMX(context.Background(), hostname)
}

func LookupNS(hostname string) ([]*net.NS, error) {
	return DefaultResolver.LookupNS(context.Background(), hostname)
}

func LookupPTR(ip string) ([]string, error) {
	return DefaultResolver.LookupAddr(context.Background(), ip)
}

func LookupSRV(service, proto, name string) (string, []*net.SRV, error) {
	return DefaultResolver.LookupSRV(context.Background(), service, proto, name)
}

func LookupCNAME(hostname string) (string, error) {
	return DefaultResolver.LookupCNAME(context.Background(), hostname)
}

type DNSResult struct {
	Hostname string
	A        []net.IP
	AAAA     []net.IP
	TXT      []string
	MX       []*net.MX
	NS       []*net.NS
	CNAME    string
}

func LookupAll(hostname string) (*DNSResult, error) {
	result := &DNSResult{Hostname: hostname}
	result.A, _ = LookupA(hostname)
	result.AAAA, _ = LookupAAAA(hostname)
	result.TXT, _ = LookupTXT(hostname)
	result.MX, _ = LookupMX(hostname)
	result.NS, _ = LookupNS(hostname)
	result.CNAME, _ = LookupCNAME(hostname)
	if len(result.A) == 0 && len(result.AAAA) == 0 {
		return result, &net.DNSError{Err: "no records", Name: hostname, IsNotFound: true}
	}
	return result, nil
}

func WithTimeout(timeout time.Duration) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, address)
		},
	}
}

func LookupWithContext(ctx context.Context, hostname string) ([]net.IPAddr, error) {
	return DefaultResolver.LookupIPAddr(ctx, hostname)
}
