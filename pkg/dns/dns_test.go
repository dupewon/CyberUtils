package dns

import (
	"context"
	"testing"
)

func TestLookupA(t *testing.T) {
	ips, err := LookupA("localhost")
	if err != nil {
		t.Fatalf("LookupA failed: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one IP for localhost")
	}
}

func TestLookupTXT(t *testing.T) {
	records, err := LookupTXT("localhost")
	if err != nil {
		t.Logf("TXT lookup for localhost: %v (non-fatal)", err)
	}
	if records != nil {
		t.Logf("TXT records: %v", records)
	}
}

func TestLookupMX(t *testing.T) {
	records, err := LookupMX("localhost")
	if err != nil {
		t.Logf("MX lookup for localhost: %v (non-fatal)", err)
	}
	_ = records
}

func TestLookupCNAME(t *testing.T) {
	cname, err := LookupCNAME("localhost")
	if err != nil {
		t.Logf("CNAME lookup for localhost: %v (non-fatal)", err)
	}
	_ = cname
}

func TestLookupAll(t *testing.T) {
	result, err := LookupAll("localhost")
	if err != nil && len(result.A) == 0 && len(result.AAAA) == 0 {
		t.Logf("LookupAll: no records found (expected on some systems)")
	}
	if result.Hostname != "localhost" {
		t.Fatalf("expected hostname 'localhost', got '%s'", result.Hostname)
	}
}

func TestLookupWithContext(t *testing.T) {
	ctx := context.Background()
	ips, err := LookupWithContext(ctx, "localhost")
	if err != nil {
		t.Fatalf("LookupWithContext failed: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one IP")
	}
}

func TestWithTimeout(t *testing.T) {
	resolver := WithTimeout(5)
	if resolver == nil {
		t.Fatal("expected non-nil resolver")
	}
}
