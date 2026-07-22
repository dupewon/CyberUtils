package headers

import (
	"fmt"
	"net/http"
	"strings"
)

type SecurityHeaders struct {
	ContentSecurityPolicy     string
	HSTSMaxAge                int
	HSTSIncludeSubdomains     bool
	HSTSPreload               bool
	PermissionsPolicy         string
	ReferrerPolicy            string
	FrameOptions              string
	ContentTypeOptions        string
	CrossOriginOpenerPolicy   string
	CrossOriginEmbedderPolicy string
	CrossOriginResourcePolicy string
}

func DefaultSecurityHeaders() SecurityHeaders {
	return SecurityHeaders{
		ContentSecurityPolicy:     "default-src 'self'",
		HSTSMaxAge:                31536000,
		HSTSIncludeSubdomains:     true,
		PermissionsPolicy:         "geolocation=(), microphone=(), camera=()",
		ReferrerPolicy:            "strict-origin-when-cross-origin",
		FrameOptions:              "DENY",
		ContentTypeOptions:        "nosniff",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginEmbedderPolicy: "require-corp",
		CrossOriginResourcePolicy: "same-origin",
	}
}

func (h SecurityHeaders) Apply(w http.ResponseWriter) {
	set := func(k, v string) {
		if v != "" {
			w.Header().Set(k, v)
		}
	}
	set("Content-Security-Policy", h.ContentSecurityPolicy)
	if h.HSTSMaxAge > 0 {
		v := fmt.Sprintf("max-age=%d", h.HSTSMaxAge)
		if h.HSTSIncludeSubdomains {
			v += "; includeSubDomains"
		}
		if h.HSTSPreload {
			v += "; preload"
		}
		w.Header().Set("Strict-Transport-Security", v)
	}
	set("Permissions-Policy", h.PermissionsPolicy)
	set("Referrer-Policy", h.ReferrerPolicy)
	set("X-Frame-Options", h.FrameOptions)
	set("X-Content-Type-Options", h.ContentTypeOptions)
	set("Cross-Origin-Opener-Policy", h.CrossOriginOpenerPolicy)
	set("Cross-Origin-Embedder-Policy", h.CrossOriginEmbedderPolicy)
	set("Cross-Origin-Resource-Policy", h.CrossOriginResourcePolicy)
}

func (h SecurityHeaders) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.Apply(w)
		next.ServeHTTP(w, r)
	})
}

func GenerateCSP(directives map[string][]string) string {
	var parts []string
	for key, values := range directives {
		if len(values) == 0 {
			parts = append(parts, key)
			continue
		}
		parts = append(parts, key+" "+strings.Join(values, " "))
	}
	return strings.Join(parts, "; ")
}

func GeneratePermissionsPolicy(directives map[string][]string) string {
	var parts []string
	for feature, origins := range directives {
		var originsStr string
		if len(origins) == 0 {
			originsStr = "()"
		} else {
			originsStr = "(" + strings.Join(origins, " ") + ")"
		}
		parts = append(parts, feature+"="+originsStr)
	}
	return strings.Join(parts, ", ")
}

func GenerateHSTS(maxAge int, includeSubdomains, preload bool) string {
	v := fmt.Sprintf("max-age=%d", maxAge)
	if includeSubdomains {
		v += "; includeSubDomains"
	}
	if preload {
		v += "; preload"
	}
	return v
}
