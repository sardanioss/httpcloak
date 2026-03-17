package fingerprint

import (
	"testing"
)

func TestNavigationContext(t *testing.T) {
	ctx := NavigationContext()
	if ctx.Mode != FetchModeNavigate {
		t.Fatalf("expected navigate, got %s", ctx.Mode)
	}
	if ctx.Dest != FetchDestDocument {
		t.Fatalf("expected document, got %s", ctx.Dest)
	}
	if ctx.Site != FetchSiteNone {
		t.Fatalf("expected none, got %s", ctx.Site)
	}
	if !ctx.IsUserTriggered {
		t.Fatal("expected user triggered")
	}
}

func TestXHRContext(t *testing.T) {
	ctx := XHRContext("https://example.com", "https://example.com/api")
	if ctx.Mode != FetchModeCORS {
		t.Fatalf("expected cors, got %s", ctx.Mode)
	}
	if ctx.Dest != FetchDestXHR {
		t.Fatalf("expected empty, got %s", ctx.Dest)
	}
	if ctx.Site != FetchSiteSameOrigin {
		t.Fatalf("expected same-origin, got %s", ctx.Site)
	}
}

func TestImageContext(t *testing.T) {
	ctx := ImageContext("https://example.com", "https://cdn.example.com/img.png")
	if ctx.Mode != FetchModeNoCORS {
		t.Fatalf("expected no-cors, got %s", ctx.Mode)
	}
	if ctx.Dest != FetchDestImage {
		t.Fatalf("expected image, got %s", ctx.Dest)
	}
	if ctx.Site != FetchSiteSameSite {
		t.Fatalf("expected same-site, got %s", ctx.Site)
	}
}

func TestScriptContext(t *testing.T) {
	ctx := ScriptContext("https://example.com", "https://other.com/script.js")
	if ctx.Mode != FetchModeNoCORS {
		t.Fatalf("expected no-cors, got %s", ctx.Mode)
	}
	if ctx.Dest != FetchDestScript {
		t.Fatalf("expected script, got %s", ctx.Dest)
	}
	if ctx.Site != FetchSiteCrossSite {
		t.Fatalf("expected cross-site, got %s", ctx.Site)
	}
}

func TestStyleContext(t *testing.T) {
	ctx := StyleContext("https://example.com", "https://example.com/style.css")
	if ctx.Dest != FetchDestStyle {
		t.Fatalf("expected style, got %s", ctx.Dest)
	}
}

func TestFontContext(t *testing.T) {
	ctx := FontContext("https://example.com", "https://fonts.gstatic.com/font.woff2")
	if ctx.Mode != FetchModeCORS {
		t.Fatalf("expected cors, got %s", ctx.Mode)
	}
	if ctx.Dest != FetchDestFont {
		t.Fatalf("expected font, got %s", ctx.Dest)
	}
	if ctx.Site != FetchSiteCrossSite {
		t.Fatalf("expected cross-site, got %s", ctx.Site)
	}
}

func TestCalculateFetchSite(t *testing.T) {
	tests := []struct {
		name     string
		referrer string
		target   string
		want     FetchSite
	}{
		{"no referrer", "", "https://example.com", FetchSiteNone},
		{"same origin", "https://example.com/page", "https://example.com/api", FetchSiteSameOrigin},
		{"same site different subdomain", "https://www.example.com", "https://api.example.com", FetchSiteSameSite},
		{"cross site", "https://example.com", "https://other.com", FetchSiteCrossSite},
		{"different scheme same host", "http://example.com", "https://example.com", FetchSiteCrossSite},
		{"invalid referrer", "://invalid", "https://example.com", FetchSiteCrossSite},
		{"invalid target", "https://example.com", "://invalid", FetchSiteCrossSite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateFetchSite(tt.referrer, tt.target)
			if got != tt.want {
				t.Fatalf("calculateFetchSite(%q, %q) = %q, want %q", tt.referrer, tt.target, got, tt.want)
			}
		})
	}
}

func TestGetRegistrableDomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"www.example.com", "example.com"},
		{"api.cdn.example.com", "example.com"},
		{"example.com", "example.com"},
		{"localhost", "localhost"},
		{"example.com:8080", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := getRegistrableDomain(tt.host)
			if got != tt.want {
				t.Fatalf("getRegistrableDomain(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestGenerateSecFetchHeaders(t *testing.T) {
	// Navigation context — should include User
	navHeaders := GenerateSecFetchHeaders(NavigationContext())
	if navHeaders.User != "?1" {
		t.Fatal("expected '?1' for navigation")
	}
	if navHeaders.Mode != "navigate" {
		t.Fatalf("expected 'navigate', got %q", navHeaders.Mode)
	}

	// XHR context — should NOT include User
	xhrHeaders := GenerateSecFetchHeaders(XHRContext("https://example.com", "https://example.com/api"))
	if xhrHeaders.User != "" {
		t.Fatalf("expected empty user for XHR, got %q", xhrHeaders.User)
	}
}

func TestGenerateClientHints(t *testing.T) {
	platform := PlatformInfo{Platform: "Windows", Arch: "x86_64", PlatformVersion: "15.0.0"}

	// Low entropy only
	hints := GenerateClientHints("146", platform, false)
	if hints.UA == "" {
		t.Fatal("expected UA to be set")
	}
	if hints.UAMobile != "?0" {
		t.Fatalf("expected '?0', got %q", hints.UAMobile)
	}
	if hints.UAArch != "" {
		t.Fatal("expected empty UAArch for low entropy")
	}

	// High entropy
	hintsHigh := GenerateClientHints("146", platform, true)
	if hintsHigh.UAArch == "" {
		t.Fatal("expected UAArch for high entropy")
	}
	if hintsHigh.UAFullVersionList == "" {
		t.Fatal("expected UAFullVersionList for high entropy")
	}
}

func TestNewHeaderCoherence(t *testing.T) {
	p := Chrome146()
	hc := NewHeaderCoherence(p)
	if hc.preset != p {
		t.Fatal("expected preset to be set")
	}
}

func TestApplyToHeaders(t *testing.T) {
	p := Chrome146()
	hc := NewHeaderCoherence(p)
	headers := make(map[string]string)

	// Navigation
	hc.ApplyToHeaders(headers, NavigationContext())
	if headers["Sec-Fetch-Mode"] != "navigate" {
		t.Fatalf("expected 'navigate', got %q", headers["Sec-Fetch-Mode"])
	}
	if headers["Sec-Fetch-User"] != "?1" {
		t.Fatalf("expected '?1', got %q", headers["Sec-Fetch-User"])
	}
	if headers["Upgrade-Insecure-Requests"] != "1" {
		t.Fatal("expected Upgrade-Insecure-Requests for navigation")
	}

	// CORS (should remove user, UIR)
	hc.ApplyToHeaders(headers, XHRContext("https://example.com", "https://example.com/api"))
	if headers["Sec-Fetch-Mode"] != "cors" {
		t.Fatalf("expected 'cors', got %q", headers["Sec-Fetch-Mode"])
	}
	if _, ok := headers["Sec-Fetch-User"]; ok {
		t.Fatal("expected no Sec-Fetch-User for CORS")
	}
	if _, ok := headers["Upgrade-Insecure-Requests"]; ok {
		t.Fatal("expected no UIR for CORS")
	}

	// NoCORS image
	hc.ApplyToHeaders(headers, ImageContext("https://example.com", "https://cdn.example.com/img.png"))
	if headers["Accept"] != "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8" {
		t.Fatalf("expected image accept, got %q", headers["Accept"])
	}

	// NoCORS style
	hc.ApplyToHeaders(headers, StyleContext("https://example.com", "https://example.com/style.css"))
	if headers["Accept"] != "text/css,*/*;q=0.1" {
		t.Fatalf("expected style accept, got %q", headers["Accept"])
	}

	// NoCORS script
	hc.ApplyToHeaders(headers, ScriptContext("https://example.com", "https://example.com/script.js"))
	if headers["Accept"] != "*/*" {
		t.Fatalf("expected script accept, got %q", headers["Accept"])
	}

	// Referrer
	ctx := XHRContext("https://example.com/page", "https://example.com/api")
	hc.ApplyToHeaders(headers, ctx)
	if headers["Referer"] != "https://example.com/page" {
		t.Fatalf("expected referrer, got %q", headers["Referer"])
	}
}

func TestGenerateNavigationHeaders(t *testing.T) {
	p := Chrome146()
	hc := NewHeaderCoherence(p)
	headers := hc.GenerateNavigationHeaders()
	if headers["Sec-Fetch-Mode"] != "navigate" {
		t.Fatalf("expected 'navigate', got %q", headers["Sec-Fetch-Mode"])
	}
	if headers["Sec-Fetch-Dest"] != "document" {
		t.Fatalf("expected 'document', got %q", headers["Sec-Fetch-Dest"])
	}
}

func TestGenerateXHRHeaders(t *testing.T) {
	p := Chrome146()
	hc := NewHeaderCoherence(p)
	headers := hc.GenerateXHRHeaders("https://example.com/page", "https://example.com/api")
	if headers["Sec-Fetch-Mode"] != "cors" {
		t.Fatalf("expected 'cors', got %q", headers["Sec-Fetch-Mode"])
	}
	if headers["Accept"] != "*/*" {
		t.Fatalf("expected '*/*', got %q", headers["Accept"])
	}
	if headers["User-Agent"] != p.UserAgent {
		t.Fatal("expected preset user agent")
	}
}
