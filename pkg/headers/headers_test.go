package headers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultSecurityHeaders(t *testing.T) {
	h := DefaultSecurityHeaders()
	if h.ContentSecurityPolicy == "" {
		t.Fatal("expected non-empty CSP")
	}
	if h.HSTSMaxAge == 0 {
		t.Fatal("expected non-zero HSTS max age")
	}
}

func TestApply(t *testing.T) {
	rec := httptest.NewRecorder()
	h := DefaultSecurityHeaders()
	h.Apply(rec)

	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("expected CSP header")
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("expected HSTS header")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("expected X-Frame-Options: DENY")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("expected X-Content-Type-Options: nosniff")
	}
}

func TestMiddleware(t *testing.T) {
	h := DefaultSecurityHeaders()
	handler := h.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("middleware should set CSP header")
	}
}

func TestGenerateCSP(t *testing.T) {
	csp := GenerateCSP(map[string][]string{
		"default-src": {"'self'"},
		"script-src":  {"'self'", "https://cdn.example.com"},
	})

	if !strings.Contains(csp, "default-src 'self'") {
		t.Fatal("expected default-src directive")
	}
	if !strings.Contains(csp, "script-src") {
		t.Fatal("expected script-src directive")
	}
}

func TestGenerateHSTS(t *testing.T) {
	hsts := GenerateHSTS(31536000, true, false)
	if !strings.Contains(hsts, "max-age=31536000") {
		t.Fatal("expected max-age")
	}
	if !strings.Contains(hsts, "includeSubDomains") {
		t.Fatal("expected includeSubDomains")
	}
	if strings.Contains(hsts, "preload") {
		t.Fatal("should not include preload")
	}
}

func TestGeneratePermissionsPolicy(t *testing.T) {
	pp := GeneratePermissionsPolicy(map[string][]string{
		"geolocation": {},
		"camera":      {"'self'"},
	})

	if !strings.Contains(pp, "geolocation=()") {
		t.Fatal("expected empty origins for geolocation")
	}
	if !strings.Contains(pp, "camera=(") {
		t.Fatal("expected camera origins")
	}
}

func TestCustomSecurityHeaders(t *testing.T) {
	h := SecurityHeaders{
		ContentSecurityPolicy: "default-src 'none'; img-src 'self'",
		FrameOptions:          "SAMEORIGIN",
	}
	rec := httptest.NewRecorder()
	h.Apply(rec)

	if rec.Header().Get("Content-Security-Policy") != "default-src 'none'; img-src 'self'" {
		t.Fatal("custom CSP not set")
	}
	if rec.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Fatal("custom frame options not set")
	}
}

func TestEmptyHeaders(t *testing.T) {
	h := SecurityHeaders{}
	rec := httptest.NewRecorder()
	h.Apply(rec)
	// Should not panic and should not set empty headers
}
