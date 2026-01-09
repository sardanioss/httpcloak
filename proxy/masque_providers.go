package proxy

import (
	"net/url"
	"strings"
)

// knownMASQUEProviders contains hostnames of known MASQUE proxy providers.
// These providers support HTTP/3 MASQUE (CONNECT-UDP) protocol for proxying
// QUIC/UDP traffic, which is needed for HTTP/3 through a proxy.
var knownMASQUEProviders = []string{
	// Bright Data (formerly Luminati)
	"brd.superproxy.io",
	"zproxy.lum-superproxy.io",
	"lum-superproxy.io",
	// Oxylabs
	"pr.oxylabs.io",
	"residential-eu.oxylabs.io",
	// Smartproxy
	"gate.smartproxy.com",
	// SOAX
	"proxy.soax.com",
}

// IsMASQUEProvider checks if the given hostname belongs to a known MASQUE provider.
// This allows auto-detection of MASQUE proxies when using https:// scheme.
func IsMASQUEProvider(host string) bool {
	host = strings.ToLower(host)
	for _, provider := range knownMASQUEProviders {
		if strings.Contains(host, provider) || strings.HasSuffix(host, provider) {
			return true
		}
	}
	return false
}

// IsMASQUEProxyURL checks if a proxy URL should use MASQUE protocol.
// Returns true if:
// - URL scheme is "masque://"
// - URL scheme is "https://" and host is a known MASQUE provider
func IsMASQUEProxyURL(proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}

	// Explicit masque:// scheme
	if parsed.Scheme == "masque" {
		return true
	}

	// Auto-detect known providers with https:// scheme
	if parsed.Scheme == "https" && IsMASQUEProvider(parsed.Host) {
		return true
	}

	return false
}

// NormalizeMASQUEURL normalizes a MASQUE proxy URL to https:// scheme.
// MASQUE uses HTTP/3 over HTTPS, so masque:// is just a hint.
func NormalizeMASQUEURL(proxyURL string) (string, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return "", err
	}

	// Convert masque:// to https://
	if parsed.Scheme == "masque" {
		parsed.Scheme = "https"
	}

	return parsed.String(), nil
}

// AddMASQUEProvider adds a custom MASQUE provider hostname to the known list.
// This allows users to add their own MASQUE-compatible proxy providers.
func AddMASQUEProvider(hostname string) {
	hostname = strings.ToLower(hostname)
	// Check if already exists
	for _, p := range knownMASQUEProviders {
		if p == hostname {
			return
		}
	}
	knownMASQUEProviders = append(knownMASQUEProviders, hostname)
}
