package fingerprint

import (
	"fmt"
	"net/url"
	"strings"
)

// FetchMode represents the Sec-Fetch-Mode header value
type FetchMode string

const (
	// FetchModeNavigate is for document navigation (clicking links, typing URLs)
	FetchModeNavigate FetchMode = "navigate"
	// FetchModeCORS is for cross-origin requests (fetch API with CORS)
	FetchModeCORS FetchMode = "cors"
	// FetchModeNoCORS is for simple requests that don't trigger CORS
	FetchModeNoCORS FetchMode = "no-cors"
	// FetchModeSameOrigin is for same-origin requests
	FetchModeSameOrigin FetchMode = "same-origin"
	// FetchModeWebSocket is for WebSocket connections
	FetchModeWebSocket FetchMode = "websocket"
)

// FetchDest represents the Sec-Fetch-Dest header value
type FetchDest string

const (
	FetchDestDocument      FetchDest = "document"
	FetchDestEmbed         FetchDest = "embed"
	FetchDestFont          FetchDest = "font"
	FetchDestImage         FetchDest = "image"
	FetchDestManifest      FetchDest = "manifest"
	FetchDestMedia         FetchDest = "media"
	FetchDestObject        FetchDest = "object"
	FetchDestReport        FetchDest = "report"
	FetchDestScript        FetchDest = "script"
	FetchDestServiceWorker FetchDest = "serviceworker"
	FetchDestSharedWorker  FetchDest = "sharedworker"
	FetchDestStyle         FetchDest = "style"
	FetchDestWorker        FetchDest = "worker"
	FetchDestXHR           FetchDest = "empty" // XHR/fetch uses "empty"
)

// FetchSite represents the Sec-Fetch-Site header value
type FetchSite string

const (
	FetchSiteNone       FetchSite = "none"        // Direct navigation (typing URL)
	FetchSiteSameOrigin FetchSite = "same-origin" // Same origin request
	FetchSiteSameSite   FetchSite = "same-site"   // Same site but different subdomain
	FetchSiteCrossSite  FetchSite = "cross-site"  // Different site entirely
)

// RequestContext contains information about the request context for header generation
type RequestContext struct {
	// Mode is the fetch mode (navigate, cors, no-cors, same-origin)
	Mode FetchMode
	// Dest is the resource destination type
	Dest FetchDest
	// Site is the relationship between request origin and target
	Site FetchSite
	// IsUserTriggered indicates if the request was user-initiated (affects Sec-Fetch-User)
	IsUserTriggered bool
	// Referrer is the page that initiated the request (for Sec-Fetch-Site calculation)
	Referrer string
	// TargetURL is the URL being requested
	TargetURL string
}

// NavigationContext returns a RequestContext for page navigation
func NavigationContext() RequestContext {
	return RequestContext{
		Mode:            FetchModeNavigate,
		Dest:            FetchDestDocument,
		Site:            FetchSiteNone,
		IsUserTriggered: true,
	}
}

// XHRContext returns a RequestContext for XHR/fetch API requests
func XHRContext(referrer, targetURL string) RequestContext {
	site := calculateFetchSite(referrer, targetURL)
	return RequestContext{
		Mode:            FetchModeCORS,
		Dest:            FetchDestXHR,
		Site:            site,
		IsUserTriggered: false,
		Referrer:        referrer,
		TargetURL:       targetURL,
	}
}

// ImageContext returns a RequestContext for image loads
func ImageContext(referrer, targetURL string) RequestContext {
	site := calculateFetchSite(referrer, targetURL)
	return RequestContext{
		Mode:            FetchModeNoCORS,
		Dest:            FetchDestImage,
		Site:            site,
		IsUserTriggered: false,
		Referrer:        referrer,
		TargetURL:       targetURL,
	}
}

// ScriptContext returns a RequestContext for script loads
func ScriptContext(referrer, targetURL string) RequestContext {
	site := calculateFetchSite(referrer, targetURL)
	return RequestContext{
		Mode:            FetchModeNoCORS,
		Dest:            FetchDestScript,
		Site:            site,
		IsUserTriggered: false,
		Referrer:        referrer,
		TargetURL:       targetURL,
	}
}

// StyleContext returns a RequestContext for stylesheet loads
func StyleContext(referrer, targetURL string) RequestContext {
	site := calculateFetchSite(referrer, targetURL)
	return RequestContext{
		Mode:            FetchModeNoCORS,
		Dest:            FetchDestStyle,
		Site:            site,
		IsUserTriggered: false,
		Referrer:        referrer,
		TargetURL:       targetURL,
	}
}

// FontContext returns a RequestContext for font loads
func FontContext(referrer, targetURL string) RequestContext {
	site := calculateFetchSite(referrer, targetURL)
	return RequestContext{
		Mode:            FetchModeCORS,
		Dest:            FetchDestFont,
		Site:            site,
		IsUserTriggered: false,
		Referrer:        referrer,
		TargetURL:       targetURL,
	}
}

// calculateFetchSite determines the Sec-Fetch-Site value based on referrer and target
func calculateFetchSite(referrer, targetURL string) FetchSite {
	if referrer == "" {
		return FetchSiteNone
	}

	refURL, err := url.Parse(referrer)
	if err != nil {
		return FetchSiteCrossSite
	}

	targURL, err := url.Parse(targetURL)
	if err != nil {
		return FetchSiteCrossSite
	}

	// Same origin: same scheme, host, and port
	if refURL.Scheme == targURL.Scheme && refURL.Host == targURL.Host {
		return FetchSiteSameOrigin
	}

	// Same site: same registrable domain (simplified check)
	refDomain := getRegistrableDomain(refURL.Host)
	targDomain := getRegistrableDomain(targURL.Host)
	if refDomain == targDomain && refURL.Scheme == targURL.Scheme {
		return FetchSiteSameSite
	}

	return FetchSiteCrossSite
}

// getRegistrableDomain extracts the registrable domain (simplified)
func getRegistrableDomain(host string) string {
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		// Simple heuristic: use last two parts
		// This doesn't handle all public suffix cases but works for most
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// SecFetchHeaders generates coherent Sec-Fetch-* headers based on context
type SecFetchHeaders struct {
	Site string
	Mode string
	Dest string
	User string // "?1" for user-triggered, empty otherwise
}

// GenerateSecFetchHeaders generates Sec-Fetch-* headers for the given context
func GenerateSecFetchHeaders(ctx RequestContext) SecFetchHeaders {
	headers := SecFetchHeaders{
		Site: string(ctx.Site),
		Mode: string(ctx.Mode),
		Dest: string(ctx.Dest),
	}

	// Sec-Fetch-User is only sent for user-triggered navigation requests
	if ctx.IsUserTriggered && ctx.Mode == FetchModeNavigate {
		headers.User = "?1"
	}

	return headers
}

// ClientHints contains browser client hint headers
type ClientHints struct {
	// Low-entropy hints (always sent by Chrome)
	UA         string // Sec-Ch-Ua
	UAMobile   string // Sec-Ch-Ua-Mobile
	UAPlatform string // Sec-Ch-Ua-Platform

	// High-entropy hints (only sent after Accept-CH)
	UAArch            string // Sec-Ch-Ua-Arch
	UABitness         string // Sec-Ch-Ua-Bitness
	UAFullVersionList string // Sec-Ch-Ua-Full-Version-List
	UAModel           string // Sec-Ch-Ua-Model
	UAPlatformVersion string // Sec-Ch-Ua-Platform-Version
	UAWow64           string // Sec-Ch-Ua-Wow64
}

// GenerateClientHints generates client hint headers for Chrome.
//
// Deprecated: this builds the hints from a bare version + platform and so cannot
// keep the GREASE brand token / order in sync with a preset's sec-ch-ua. It is no
// longer used in production. Use Preset.ResolveClientHints, which derives coherent
// hints from the preset itself.
func GenerateClientHints(chromeVersion string, platform PlatformInfo, includeHighEntropy bool) ClientHints {
	hints := ClientHints{
		// Low-entropy hints (always sent)
		UA:         fmt.Sprintf(`"Google Chrome";v="%s", "Chromium";v="%s", "Not_A Brand";v="24"`, chromeVersion, chromeVersion),
		UAMobile:   "?0",
		UAPlatform: fmt.Sprintf(`"%s"`, platform.Platform),
	}

	if includeHighEntropy {
		hints.UAArch = fmt.Sprintf(`"%s"`, platform.Arch)
		hints.UABitness = `"64"`
		hints.UAFullVersionList = fmt.Sprintf(`"Google Chrome";v="%s.0.0.0", "Chromium";v="%s.0.0.0", "Not_A Brand";v="24.0.0.0"`, chromeVersion, chromeVersion)
		hints.UAPlatformVersion = fmt.Sprintf(`"%s"`, platform.PlatformVersion)
	}

	return hints
}

// ResolveClientHints returns the fully-resolved UA client hints for this preset.
// The low-entropy trio is taken verbatim from the preset headers; the high-entropy
// hints come from the preset's ClientHints overrides where set, and are otherwise
// DERIVED from the trio so they can never drift out of sync. Specifically, an
// unset full-version-list is built from sec-ch-ua by preserving the exact brand
// names, order and GREASE token and expanding each major version to "<major>.0.0.0".
// This is the single coherent source the session layer reads to emit high-entropy
// hints after a host advertises Accept-CH.
func (p *Preset) ResolveClientHints() ClientHints {
	secChUa := p.Headers["sec-ch-ua"]
	platformName := unquote(p.Headers["sec-ch-ua-platform"]) // e.g. "Windows", "macOS", "Linux", "Android"
	isMobile := p.Headers["sec-ch-ua-mobile"] == "?1"

	ch := ClientHints{
		UA:         secChUa,
		UAMobile:   firstNonEmpty(p.Headers["sec-ch-ua-mobile"], "?0"),
		UAPlatform: p.Headers["sec-ch-ua-platform"],
	}

	if p.ClientHints.FullVersionList != "" {
		ch.UAFullVersionList = p.ClientHints.FullVersionList
	} else {
		ch.UAFullVersionList = expandSecChUaVersions(secChUa)
	}

	ch.UAArch = firstNonEmpty(p.ClientHints.Arch, defaultClientHintArch(platformName, isMobile))
	ch.UABitness = firstNonEmpty(p.ClientHints.Bitness, defaultClientHintBitness(isMobile))
	// Desktop Chrome answers sec-ch-ua-model with an empty quoted string; mobile
	// presets carry a device model via ClientHints.Model.
	ch.UAModel = firstNonEmpty(p.ClientHints.Model, `""`)
	ch.UAWow64 = firstNonEmpty(p.ClientHints.Wow64, `?0`)
	// PlatformVersion: explicit override wins; otherwise the platform default,
	// which is "" for Linux (real Chrome sends an empty platform version there).
	if p.ClientHints.PlatformVersion != "" {
		ch.UAPlatformVersion = p.ClientHints.PlatformVersion
	} else {
		ch.UAPlatformVersion = defaultClientHintPlatformVersion(platformName)
	}

	return ch
}

// expandSecChUaVersions turns a low-entropy sec-ch-ua value into a coherent
// sec-ch-ua-full-version-list by expanding each brand's major version to a
// 4-part version. Brand names, ordering and the GREASE token are preserved
// exactly, so the derived list always matches the trio. For example:
//
//	"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"
//
// becomes
//
//	"Google Chrome";v="149.0.0.0", "Chromium";v="149.0.0.0", "Not)A;Brand";v="24.0.0.0"
//
// A real capture (set as ClientHints.FullVersionList) carries the exact build
// number; this derivation is the coherent fallback when none is provided.
func expandSecChUaVersions(secChUa string) string {
	if secChUa == "" {
		return ""
	}
	parts := splitBrandList(secChUa)
	for i, part := range parts {
		parts[i] = expandBrandVersion(part)
	}
	return strings.Join(parts, ", ")
}

// splitBrandList splits a brand list on the comma+space separators that sit
// BETWEEN brand entries, without breaking inside a quoted brand name (GREASE
// tokens such as "Not)A;Brand" never contain a comma, but stay defensive).
func splitBrandList(s string) []string {
	var parts []string
	depth := 0 // inside double quotes when odd
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			depth ^= 1
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(s[start:]))
	return parts
}

// expandBrandVersion expands the v="N" inside a single brand entry to
// v="N.0.0.0", leaving an already-multipart version untouched.
func expandBrandVersion(entry string) string {
	const marker = `;v="`
	idx := strings.Index(entry, marker)
	if idx == -1 {
		return entry
	}
	vStart := idx + len(marker)
	vEnd := strings.IndexByte(entry[vStart:], '"')
	if vEnd == -1 {
		return entry
	}
	vEnd += vStart
	ver := entry[vStart:vEnd]
	if ver == "" || strings.Contains(ver, ".") {
		return entry // already a full version (or empty) — leave as-is
	}
	return entry[:vStart] + ver + ".0.0.0" + entry[vEnd:]
}

// defaultClientHintArch returns the sec-ch-ua-arch default for a platform.
// Chrome on mobile sends an empty arch; desktop sends "x86" except Apple
// Silicon macs which report "arm".
func defaultClientHintArch(platformName string, isMobile bool) string {
	if isMobile {
		return `""`
	}
	if platformName == "macOS" {
		return `"arm"`
	}
	return `"x86"`
}

// defaultClientHintBitness returns the sec-ch-ua-bitness default. Mobile reports
// an empty bitness; desktop reports "64".
func defaultClientHintBitness(isMobile bool) string {
	if isMobile {
		return `""`
	}
	return `"64"`
}

// defaultClientHintPlatformVersion returns the sec-ch-ua-platform-version default
// for a platform. Linux is "" (real Chrome behavior). Windows/macOS values are
// best-effort defaults; a preset should pin the exact value via ClientHints from a
// real capture.
func defaultClientHintPlatformVersion(platformName string) string {
	switch platformName {
	case "Windows":
		return `"15.0.0"`
	case "macOS":
		return `"14.5.0"`
	case "Android":
		return `"14.0.0"`
	default: // Linux and others
		return `""`
	}
}

// unquote strips a single pair of surrounding double quotes if present.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// firstNonEmpty returns a if non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// HeaderCoherence provides methods for generating coherent request headers
type HeaderCoherence struct {
	preset   *Preset
	platform PlatformInfo
}

// NewHeaderCoherence creates a new HeaderCoherence helper
func NewHeaderCoherence(preset *Preset) *HeaderCoherence {
	return &HeaderCoherence{
		preset:   preset,
		platform: GetPlatformInfo(),
	}
}

// ApplyToHeaders applies coherent headers to the given header map
func (h *HeaderCoherence) ApplyToHeaders(headers map[string]string, ctx RequestContext) {
	// Apply Sec-Fetch-* headers
	secFetch := GenerateSecFetchHeaders(ctx)
	headers["Sec-Fetch-Site"] = secFetch.Site
	headers["Sec-Fetch-Mode"] = secFetch.Mode
	headers["Sec-Fetch-Dest"] = secFetch.Dest
	if secFetch.User != "" {
		headers["Sec-Fetch-User"] = secFetch.User
	} else {
		delete(headers, "Sec-Fetch-User")
	}

	// Apply context-specific headers
	switch ctx.Mode {
	case FetchModeNavigate:
		headers["Upgrade-Insecure-Requests"] = "1"
		// Note: Cache-Control is NOT sent on normal navigation, only on hard refresh (Ctrl+F5)
		headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	case FetchModeCORS, FetchModeSameOrigin:
		headers["Accept"] = "*/*"
		delete(headers, "Upgrade-Insecure-Requests")
		delete(headers, "Cache-Control")
	case FetchModeNoCORS:
		// Set Accept based on destination
		switch ctx.Dest {
		case FetchDestImage:
			headers["Accept"] = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
		case FetchDestStyle:
			headers["Accept"] = "text/css,*/*;q=0.1"
		case FetchDestScript:
			headers["Accept"] = "*/*"
		default:
			headers["Accept"] = "*/*"
		}
		delete(headers, "Upgrade-Insecure-Requests")
		delete(headers, "Cache-Control")
	}

	// Set referrer if available
	if ctx.Referrer != "" {
		headers["Referer"] = ctx.Referrer
	}
}

// GenerateNavigationHeaders returns complete headers for page navigation
func (h *HeaderCoherence) GenerateNavigationHeaders() map[string]string {
	headers := make(map[string]string)

	// Copy preset headers
	for k, v := range h.preset.Headers {
		headers[k] = v
	}

	// Apply navigation context
	h.ApplyToHeaders(headers, NavigationContext())

	return headers
}

// GenerateXHRHeaders returns complete headers for XHR/fetch requests
func (h *HeaderCoherence) GenerateXHRHeaders(referrer, targetURL string) map[string]string {
	headers := make(map[string]string)

	// Start with basic headers
	headers["User-Agent"] = h.preset.UserAgent
	headers["Accept"] = "*/*"
	headers["Accept-Encoding"] = "gzip, deflate, br, zstd"
	headers["Accept-Language"] = "en-US,en;q=0.9"

	// Copy client hints from preset (low-entropy only for XHR)
	if ua, ok := h.preset.Headers["sec-ch-ua"]; ok {
		headers["sec-ch-ua"] = ua
	}
	if uaMobile, ok := h.preset.Headers["sec-ch-ua-mobile"]; ok {
		headers["sec-ch-ua-mobile"] = uaMobile
	}
	if uaPlatform, ok := h.preset.Headers["sec-ch-ua-platform"]; ok {
		headers["sec-ch-ua-platform"] = uaPlatform
	}

	// Apply XHR context
	h.ApplyToHeaders(headers, XHRContext(referrer, targetURL))

	return headers
}
