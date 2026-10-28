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

// Chrome on Windows sends the UniversalApiContract version, which is 19.0.0 on
// current Windows 11 (24H2 and 25H2), measured against Chrome 156. The default
// was 15.0.0, which is 22H2 and 23H2.
func TestResolveClientHintsWindowsPlatformVersion(t *testing.T) {
	checked := 0
	for _, name := range Available() {
		p := Get(name)
		if p.Headers["sec-ch-ua-platform"] != `"Windows"` || p.ClientHints.PlatformVersion != "" {
			continue
		}
		checked++
		if got := p.ResolveClientHints().UAPlatformVersion; got != `"19.0.0"` {
			t.Errorf("%s: sec-ch-ua-platform-version %s, want \"19.0.0\"", name, got)
		}
	}
	if checked == 0 {
		t.Fatal("no built-in Windows preset to check")
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

// sec-ch-ua-full-version is the browser's own full version, the one its brand
// carries in the full version list: Chrome 156 sent "156.0.8078.48" in both,
// measured against Cloudflare's challenge, which asks for it by name. A pinned
// list reaches it, a derived one gives the matching N.0.0.0, and a preset can
// pin it on its own.
func TestResolveClientHintsFullVersion(t *testing.T) {
	for _, c := range []struct{ preset, want string }{
		{"chrome-155-windows", `"155.0.8059.39"`},
		{"chrome-latest", `"158.0.8127.18"`},
		{"android-chrome-latest", `"158.0.0.0"`},
		{"chrome-146", `"146.0.0.0"`},
	} {
		if got := Get(c.preset).ResolveClientHints().UAFullVersion; got != c.want {
			t.Errorf("%s: sec-ch-ua-full-version %s, want %s", c.preset, got, c.want)
		}
	}
	for _, name := range []string{"firefox-latest", "safari-latest", "safari-latest-ios", "chrome-latest-ios"} {
		if got := Get(name).ResolveClientHints().UAFullVersion; got != "" {
			t.Errorf("%s sends no client hints, but resolves sec-ch-ua-full-version %s", name, got)
		}
	}

	p := clonePreset(Get("chrome-155-windows"))
	p.ClientHints.FullVersion = `"155.0.8059.40"`
	if got := p.ResolveClientHints().UAFullVersion; got != `"155.0.8059.40"` {
		t.Errorf("a pinned full version resolves to %s", got)
	}
	// Inherited by a preset that moved to another major, the pin would put the
	// old build beside the new sec-ch-ua, so the list's version wins instead.
	p.Headers = map[string]string{"sec-ch-ua": `"Google Chrome";v="200", "Chromium";v="200", "Not(A:Brand";v="24"`}
	if got := p.ResolveClientHints().UAFullVersion; got != `"200.0.0.0"` {
		t.Errorf("a pinned 155 full version under a 200 sec-ch-ua resolves to %s, want \"200.0.0.0\"", got)
	}
}

// A JSON preset writes full_version bare, like the spec's other string hints,
// and the header goes out quoted, the way Chrome sends it.
func TestClientHintsSpecFullVersion(t *testing.T) {
	for _, v := range []string{`"155.0.8059.40"`, `"\"155.0.8059.40\""`} {
		p, err := LoadAndBuildPresetFromJSON([]byte(`{"version": 1, "preset": {
			"name": "full-version-test", "based_on": "chrome-155-windows",
			"client_hints": {"full_version": ` + v + `}}}`))
		if err != nil {
			t.Fatalf("full_version %s: %v", v, err)
		}
		if got := p.ResolveClientHints().UAFullVersion; got != `"155.0.8059.40"` {
			t.Errorf("full_version %s: sec-ch-ua-full-version %s, want \"155.0.8059.40\"", v, got)
		}
	}
}

// The version is the browser brand's, wherever the list puts it: Chromium's
// own entry is the fallback and the GREASE brand never counts.
func TestBrowserFullVersion(t *testing.T) {
	for _, c := range []struct{ list, want string }{
		{`"Not(A:Brand";v="24.0.0.0", "Google Chrome";v="156.0.8078.48", "Chromium";v="156.0.8078.48"`, `"156.0.8078.48"`},
		{`"Chromium";v="130.0.6723.92", "Microsoft Edge";v="130.0.2849.68", "Not?A_Brand";v="99.0.0.0"`, `"130.0.2849.68"`},
		{`"Chromium";v="150.0.1.2", "Not;A=Brand";v="8.0.0.0"`, `"150.0.1.2"`},
		{`" Not A;Brand";v="99.0.0.0", "Chromium";v="96.0.4664.45"`, `"96.0.4664.45"`},
		{``, ``},
	} {
		if got := browserFullVersion(c.list); got != c.want {
			t.Errorf("browserFullVersion(%s) = %s, want %s", c.list, got, c.want)
		}
	}
}
