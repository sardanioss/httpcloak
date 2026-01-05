package fingerprint

import (
	"runtime"

	tls "github.com/sardanioss/utls"
)

// PlatformInfo contains platform-specific header values
type PlatformInfo struct {
	UserAgentOS        string // e.g., "(Windows NT 10.0; Win64; x64)" or "(X11; Linux x86_64)"
	Platform           string // e.g., "Windows", "Linux", "macOS"
	Arch               string // e.g., "x86", "arm"
	PlatformVersion    string // e.g., "10.0.0", "6.12.0", "14.7.0"
	FirefoxUserAgentOS string // Firefox has slightly different format
}

// GetPlatformInfo returns platform-specific info based on runtime OS
func GetPlatformInfo() PlatformInfo {
	switch runtime.GOOS {
	case "windows":
		return PlatformInfo{
			UserAgentOS:        "(Windows NT 10.0; Win64; x64)",
			Platform:           "Windows",
			Arch:               "x86",
			PlatformVersion:    "10.0.0",
			FirefoxUserAgentOS: "(Windows NT 10.0; Win64; x64; rv:133.0)",
		}
	case "darwin":
		return PlatformInfo{
			UserAgentOS:        "(Macintosh; Intel Mac OS X 10_15_7)",
			Platform:           "macOS",
			Arch:               "arm",
			PlatformVersion:    "14.7.0",
			FirefoxUserAgentOS: "(Macintosh; Intel Mac OS X 10.15; rv:133.0)",
		}
	default: // linux and others
		return PlatformInfo{
			UserAgentOS:        "(X11; Linux x86_64)",
			Platform:           "Linux",
			Arch:               "x86",
			PlatformVersion:    "6.12.0",
			FirefoxUserAgentOS: "(X11; Linux x86_64; rv:133.0)",
		}
	}
}

// Preset represents a browser fingerprint configuration
type Preset struct {
	Name              string
	ClientHelloID     tls.ClientHelloID // For TCP/TLS (HTTP/1.1, HTTP/2)
	QUICClientHelloID tls.ClientHelloID // For QUIC/HTTP/3 (different TLS extensions)
	UserAgent         string
	Headers           map[string]string
	HTTP2Settings     HTTP2Settings
	SupportHTTP3      bool
}

// HTTP2Settings contains HTTP/2 connection settings
type HTTP2Settings struct {
	HeaderTableSize      uint32
	EnablePush           bool
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
	// Window update and stream settings
	ConnectionWindowUpdate uint32
	StreamWeight           uint16 // Chrome uses 256
	StreamExclusive        bool
}

// Chrome131 returns the Chrome 131 fingerprint preset
func Chrome131() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:          "chrome-131",
		ClientHelloID: tls.HelloChrome_131, // Chrome 131 with X25519MLKEM768 (correct post-quantum)
		UserAgent:     "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY (Chrome sends these by default)
			// High-entropy hints (arch, bitness, full-version-list, model, platform-version)
			// are ONLY sent after server requests them via Accept-CH header
			// Sending them without Accept-CH is a bot fingerprint!
			"sec-ch-ua":          `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"` + p.Platform + `"`,
			// Standard navigation headers (human clicked link)
			"Cache-Control":             "max-age=0", // Browser sends this on fresh navigation
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0, // No limit from client
			InitialWindowSize:      6291456,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256, // Chrome uses 256, not 255
			StreamExclusive:        true,
		},
		SupportHTTP3: true,
	}
}

// Chrome133 returns the Chrome 133 fingerprint preset
func Chrome133() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:          "chrome-133",
		ClientHelloID: tls.HelloChrome_133, // Chrome 133 with X25519MLKEM768 (correct post-quantum)
		UserAgent:     "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="133", "Chromium";v="133", "Not_A Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"` + p.Platform + `"`,
			// Standard navigation headers (human clicked link)
			"Cache-Control":             "max-age=0",
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		SupportHTTP3: true,
	}
}

// Chrome141 returns the Chrome 141 fingerprint preset (latest)
func Chrome141() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:          "chrome-141",
		ClientHelloID: tls.HelloChrome_133, // Chrome 133 TLS fingerprint with X25519MLKEM768
		UserAgent:     "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"` + p.Platform + `"`,
			// Standard navigation headers (human clicked link)
			"Cache-Control":             "max-age=0",
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		SupportHTTP3: true,
	}
}

// Firefox133 returns the Firefox 133 fingerprint preset
func Firefox133() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:          "firefox-133",
		ClientHelloID: tls.HelloFirefox_120,
		UserAgent:     "Mozilla/5.0 " + p.FirefoxUserAgentOS + " Gecko/20100101 Firefox/133.0",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             true,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      131072,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 12517377,
			StreamWeight:           42,
			StreamExclusive:        false,
		},
		SupportHTTP3: true,
	}
}

// Chrome143 returns the Chrome 143 fingerprint preset with platform-specific TLS fingerprint
func Chrome143() *Preset {
	p := GetPlatformInfo()
	// Use platform-specific TLS fingerprint with fixed extension order
	var clientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_143_Windows
	case "macOS":
		clientHelloID = tls.HelloChrome_143_macOS
	default: // Linux and others
		clientHelloID = tls.HelloChrome_143_Linux
	}
	return &Preset{
		Name:              "chrome-143",
		ClientHelloID:     clientHelloID,
		QUICClientHelloID: tls.HelloChrome_143_QUIC, // QUIC-specific preset for HTTP/3
		UserAgent:         "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"` + p.Platform + `"`,
			// Standard navigation headers (human clicked link)
			"Cache-Control":             "max-age=0",
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		SupportHTTP3: true,
	}
}

// Chrome143Windows returns Chrome 143 with Windows platform and fixed TLS extension order
func Chrome143Windows() *Preset {
	return &Preset{
		Name:              "chrome-143-windows",
		ClientHelloID:     tls.HelloChrome_143_Windows, // Chrome 143 Windows with fixed extension order
		QUICClientHelloID: tls.HelloChrome_143_QUIC,    // QUIC-specific preset for HTTP/3
		UserAgent:         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"Windows"`,
			// Standard navigation headers (human clicked link)
			"Cache-Control":             "max-age=0",
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		SupportHTTP3: true,
	}
}

// Chrome143Linux returns Chrome 143 with Linux platform and fixed TLS extension order
func Chrome143Linux() *Preset {
	return &Preset{
		Name:              "chrome-143-linux",
		ClientHelloID:     tls.HelloChrome_143_Linux, // Chrome 143 Linux with fixed extension order
		QUICClientHelloID: tls.HelloChrome_143_QUIC,  // QUIC-specific preset for HTTP/3
		UserAgent:         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"Linux"`,
			// Standard navigation headers (human clicked link)
			"Cache-Control":             "max-age=0",
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		SupportHTTP3: true,
	}
}

// Chrome143macOS returns Chrome 143 with macOS platform and fixed TLS extension order
func Chrome143macOS() *Preset {
	return &Preset{
		Name:              "chrome-143-macos",
		ClientHelloID:     tls.HelloChrome_143_macOS, // Chrome 143 macOS with fixed extension order
		QUICClientHelloID: tls.HelloChrome_143_QUIC,  // QUIC-specific preset for HTTP/3
		UserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"macOS"`,
			// Standard navigation headers (human clicked link)
			"Cache-Control":             "max-age=0",
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		SupportHTTP3: true,
	}
}

// Safari18 returns the Safari 18 fingerprint preset
// Note: Safari is macOS-only, so no platform detection needed
func Safari18() *Preset {
	return &Preset{
		Name:          "safari-18",
		ClientHelloID: tls.HelloSafari_16_0,
		UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             true,
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
		},
		SupportHTTP3: false, // Safari HTTP/3 support is limited
	}
}

// presets is a map of all available presets
var presets = map[string]func() *Preset{
	"chrome-131":         Chrome131,
	"chrome-133":         Chrome133,
	"chrome-141":         Chrome141,
	"chrome-143":         Chrome143,
	"chrome-143-windows": Chrome143Windows,
	"chrome-143-linux":   Chrome143Linux,
	"chrome-143-macos":   Chrome143macOS,
	"firefox-133":        Firefox133,
	"safari-18":          Safari18,
}

// Get returns a preset by name, or Chrome143 as default
func Get(name string) *Preset {
	if fn, ok := presets[name]; ok {
		return fn()
	}
	return Chrome143()
}

// Available returns a list of available preset names
func Available() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	return names
}
