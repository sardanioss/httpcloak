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

// HeaderPair represents a single header key-value pair for ordered headers
type HeaderPair struct {
	Key   string
	Value string
}

// Preset represents a browser fingerprint configuration
type Preset struct {
	Name              string
	ClientHelloID     tls.ClientHelloID // For TCP/TLS (HTTP/1.1, HTTP/2)
	PSKClientHelloID  tls.ClientHelloID // For TCP/TLS with PSK (session resumption)
	QUICClientHelloID tls.ClientHelloID // For QUIC/HTTP/3 (different TLS extensions)
	QUICPSKClientHelloID tls.ClientHelloID // For QUIC/HTTP/3 with PSK (session resumption)
	UserAgent         string
	Headers           map[string]string // For backward compatibility
	HeaderOrder       []HeaderPair      // Ordered headers for HTTP/2 and HTTP/3
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
	StreamWeight           uint16 // Chrome sends 255 on wire (set to 256, code does -1)
	StreamExclusive        bool
	// RFC 9218 - disables RFC 7540 stream priorities
	NoRFC7540Priorities bool
}

// Chrome133 returns the Chrome 133 fingerprint preset
func Chrome133() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:             "chrome-133",
		ClientHelloID:    tls.HelloChrome_133,     // Chrome 133 with X25519MLKEM768 (correct post-quantum)
		PSKClientHelloID: tls.HelloChrome_133_PSK, // PSK for session resumption
		UserAgent:        "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="133", "Chromium";v="133", "Not_A Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"` + p.Platform + `"`,
			// Standard navigation headers (human clicked link)
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
		// Chrome header order for HTTP/2 and HTTP/3 (order matters!)
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="133", "Chromium";v="133", "Not_A Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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
		SupportHTTP3: false, // Legacy preset, no proper QUIC fingerprint
	}
}

// Chrome141 returns the Chrome 141 fingerprint preset (latest)
func Chrome141() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:             "chrome-141",
		ClientHelloID:    tls.HelloChrome_133,     // Chrome 133 TLS fingerprint with X25519MLKEM768
		PSKClientHelloID: tls.HelloChrome_133_PSK, // PSK for session resumption
		UserAgent:        "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"` + p.Platform + `"`,
			// Standard navigation headers (human clicked link)
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
		// Chrome header order for HTTP/2 and HTTP/3 (order matters!)
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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
		SupportHTTP3: false, // Legacy preset, no proper QUIC fingerprint
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
		// Firefox header order for HTTP/2 (different from Chrome)
		HeaderOrder: []HeaderPair{
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
			{"accept-language", "en-US,en;q=0.5"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
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
		SupportHTTP3: false, // No Firefox QUIC fingerprint in utls
	}
}

// Chrome143 returns the Chrome 143 fingerprint preset with platform-specific TLS fingerprint
func Chrome143() *Preset {
	p := GetPlatformInfo()
	// Use platform-specific TLS fingerprint with fixed extension order
	var clientHelloID, pskClientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_143_Windows
		pskClientHelloID = tls.HelloChrome_143_Windows_PSK
	case "macOS":
		clientHelloID = tls.HelloChrome_143_macOS
		pskClientHelloID = tls.HelloChrome_143_macOS_PSK
	default: // Linux and others
		clientHelloID = tls.HelloChrome_143_Linux
		pskClientHelloID = tls.HelloChrome_143_Linux_PSK
	}
	return &Preset{
		Name:                 "chrome-143",
		ClientHelloID:        clientHelloID,
		PSKClientHelloID:     pskClientHelloID,
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,     // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK, // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"` + p.Platform + `"`,
			// Standard navigation headers (human clicked link)
			// Note: Cache-Control is NOT sent on normal navigation, only on hard refresh (Ctrl+F5)
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
		// Chrome 143 header order for HTTP/2 and HTTP/3 (order matters!)
		// Verified against real Chrome 143 on Linux via tls.peet.ws
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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
		Name:                 "chrome-143-windows",
		ClientHelloID:        tls.HelloChrome_143_Windows,     // Chrome 143 Windows with fixed extension order
		PSKClientHelloID:     tls.HelloChrome_143_Windows_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,        // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,    // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"Windows"`,
			// Standard navigation headers (human clicked link)
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
		// Chrome 143 header order for HTTP/2 and HTTP/3 (order matters!)
		// Verified against real Chrome 143 on Windows via tls.peet.ws
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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
		Name:                 "chrome-143-linux",
		ClientHelloID:        tls.HelloChrome_143_Linux,     // Chrome 143 Linux with fixed extension order
		PSKClientHelloID:     tls.HelloChrome_143_Linux_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,      // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,  // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"Linux"`,
			// Standard navigation headers (human clicked link)
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
		// Chrome 143 header order for HTTP/2 and HTTP/3 (order matters!)
		// Verified against real Chrome 143 on Linux via tls.peet.ws
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Linux"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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
		Name:                 "chrome-143-macos",
		ClientHelloID:        tls.HelloChrome_143_macOS,     // Chrome 143 macOS with fixed extension order
		PSKClientHelloID:     tls.HelloChrome_143_macOS_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,      // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,  // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints ONLY
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": `"macOS"`,
			// Standard navigation headers (human clicked link)
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
		// Chrome 143 header order for HTTP/2 and HTTP/3 (order matters!)
		// Verified against real Chrome 143 on macOS via tls.peet.ws
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"macOS"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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

// Chrome144 returns the Chrome 144 fingerprint preset with platform-specific TLS fingerprint
func Chrome144() *Preset {
	p := GetPlatformInfo()
	// Chrome 144 uses same TLS fingerprint as Chrome 143
	var clientHelloID, pskClientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_144_Windows
		pskClientHelloID = tls.HelloChrome_144_Windows_PSK
	case "macOS":
		clientHelloID = tls.HelloChrome_144_macOS
		pskClientHelloID = tls.HelloChrome_144_macOS_PSK
	default: // Linux and others
		clientHelloID = tls.HelloChrome_144_Linux
		pskClientHelloID = tls.HelloChrome_144_Linux_PSK
	}
	return &Preset{
		Name:                 "chrome-144",
		ClientHelloID:        clientHelloID,
		PSKClientHelloID:     pskClientHelloID,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"` + p.Platform + `"`,
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
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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

// Chrome144Windows returns Chrome 144 with Windows platform
func Chrome144Windows() *Preset {
	return &Preset{
		Name:                 "chrome-144-windows",
		ClientHelloID:        tls.HelloChrome_144_Windows,
		PSKClientHelloID:     tls.HelloChrome_144_Windows_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Windows"`,
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
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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

// Chrome144Linux returns Chrome 144 with Linux platform
func Chrome144Linux() *Preset {
	return &Preset{
		Name:                 "chrome-144-linux",
		ClientHelloID:        tls.HelloChrome_144_Linux,
		PSKClientHelloID:     tls.HelloChrome_144_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Linux"`,
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
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Linux"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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

// Chrome144macOS returns Chrome 144 with macOS platform
func Chrome144macOS() *Preset {
	return &Preset{
		Name:                 "chrome-144-macos",
		ClientHelloID:        tls.HelloChrome_144_macOS,
		PSKClientHelloID:     tls.HelloChrome_144_macOS_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-GB,en-US;q=0.9,en;q=0.8",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"macOS"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-GB,en-US;q=0.9,en;q=0.8"},
			{"priority", "u=0, i"},
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

// Chrome145 returns the Chrome 145 fingerprint preset with platform-specific TLS fingerprint
func Chrome145() *Preset {
	p := GetPlatformInfo()
	// Chrome 145 uses same TLS fingerprint as Chrome 144/143
	var clientHelloID, pskClientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_145_Windows
		pskClientHelloID = tls.HelloChrome_145_Windows_PSK
	case "macOS":
		clientHelloID = tls.HelloChrome_145_macOS
		pskClientHelloID = tls.HelloChrome_145_macOS_PSK
	default: // Linux and others
		clientHelloID = tls.HelloChrome_145_Linux
		pskClientHelloID = tls.HelloChrome_145_Linux_PSK
	}
	return &Preset{
		Name:                 "chrome-145",
		ClientHelloID:        clientHelloID,
		PSKClientHelloID:     pskClientHelloID,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"` + p.Platform + `"`,
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
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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

// Chrome145Windows returns Chrome 145 with Windows platform
func Chrome145Windows() *Preset {
	return &Preset{
		Name:                 "chrome-145-windows",
		ClientHelloID:        tls.HelloChrome_145_Windows,
		PSKClientHelloID:     tls.HelloChrome_145_Windows_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Windows"`,
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
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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

// Chrome145Linux returns Chrome 145 with Linux platform
func Chrome145Linux() *Preset {
	return &Preset{
		Name:                 "chrome-145-linux",
		ClientHelloID:        tls.HelloChrome_145_Linux,
		PSKClientHelloID:     tls.HelloChrome_145_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Linux"`,
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
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Linux"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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

// Chrome145macOS returns Chrome 145 with macOS platform
func Chrome145macOS() *Preset {
	return &Preset{
		Name:                 "chrome-145-macos",
		ClientHelloID:        tls.HelloChrome_145_macOS,
		PSKClientHelloID:     tls.HelloChrome_145_macOS_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
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
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"macOS"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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
		Name:              "safari-18",
		ClientHelloID:     tls.HelloSafari_18,
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // Safari uses same QUIC as iOS
		UserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		// Safari header order for HTTP/2 (different from Chrome)
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
			{"accept-language", "en-US,en;q=0.9"},
			{"accept-encoding", "gzip, deflate, br"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
		},
		// Safari HTTP/2 settings (WebKit)
		// Similar to iOS but may have ENABLE_PUSH=1 on macOS
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // Match iOS behavior
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // Safari sends NO_RFC7540_PRIORITIES=1
		},
		SupportHTTP3: true,
	}
}

// IOSChrome143 returns Chrome 143 on iOS fingerprint preset
// Note: iOS Chrome uses WebKit (Apple requirement), so it has Safari's TLS AND HTTP/2 fingerprint
// WebKit doesn't support Client Hints, so no sec-ch-ua headers
func IOSChrome143() *Preset {
	return &Preset{
		Name:              "chrome-143-ios",
		ClientHelloID:     tls.HelloIOS_18,      // iOS Chrome uses Safari's TLS (WebKit requirement)
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Chrome uses Safari's QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/143.0.6917.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			// WebKit doesn't support Client Hints - no sec-ch-ua headers
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Mode":  "navigate",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-User":  "?1",
		},
		// Safari/WebKit header order
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-mode", "navigate"},
			{"user-agent", ""},
			{"accept-language", "en-US,en;q=0.9"},
			{"sec-fetch-user", "?1"},
		},
		// Safari/WebKit HTTP/2 settings
		// Akamai fingerprint: 2:0;4:2097152;3:100;9:1|10485760|0|m,s,p,a
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // iOS sends ENABLE_PUSH=0
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // iOS sends NO_RFC7540_PRIORITIES=1
		},
		SupportHTTP3: true,
	}
}

// IOSChrome144 returns Chrome 144 on iOS fingerprint preset
// Note: iOS Chrome uses WebKit (Apple requirement), so it has Safari's TLS AND HTTP/2 fingerprint
// WebKit doesn't support Client Hints, so no sec-ch-ua headers
func IOSChrome144() *Preset {
	return &Preset{
		Name:              "chrome-144-ios",
		ClientHelloID:     tls.HelloIOS_18,      // iOS Chrome uses Safari's TLS (WebKit requirement)
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Chrome uses Safari's QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/144.0.6917.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			// WebKit doesn't support Client Hints - no sec-ch-ua headers
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Mode":  "navigate",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-User":  "?1",
		},
		// Safari/WebKit header order (from real iOS Chrome capture)
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-mode", "navigate"},
			{"user-agent", ""},
			{"accept-language", "en-US,en;q=0.9"},
			{"sec-fetch-user", "?1"},
		},
		// Safari/WebKit HTTP/2 settings (from real iOS Chrome capture)
		// Akamai fingerprint: 2:0;4:2097152;3:100;9:1|10485760|0|m,s,p,a
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // iOS sends ENABLE_PUSH=0
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // iOS sends NO_RFC7540_PRIORITIES=1
		},
		SupportHTTP3: true,
	}
}

// IOSChrome145 returns Chrome 145 on iOS fingerprint preset
// Note: iOS Chrome uses WebKit (Apple requirement), so it has Safari's TLS AND HTTP/2 fingerprint
// WebKit doesn't support Client Hints, so no sec-ch-ua headers
func IOSChrome145() *Preset {
	return &Preset{
		Name:              "chrome-145-ios",
		ClientHelloID:     tls.HelloIOS_18,      // iOS Chrome uses Safari's TLS (WebKit requirement)
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Chrome uses Safari's QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/145.0.6917.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			// WebKit doesn't support Client Hints - no sec-ch-ua headers
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Mode":  "navigate",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-User":  "?1",
		},
		// Safari/WebKit header order (from real iOS Chrome capture)
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-mode", "navigate"},
			{"user-agent", ""},
			{"accept-language", "en-US,en;q=0.9"},
			{"sec-fetch-user", "?1"},
		},
		// Safari/WebKit HTTP/2 settings (from real iOS Chrome capture)
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false,
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true,
		},
		SupportHTTP3: true,
	}
}

// IOSSafari17 returns Safari 17 on iOS fingerprint preset
func IOSSafari17() *Preset {
	return &Preset{
		Name:          "safari-17-ios",
		ClientHelloID: tls.HelloIOS_14,
		UserAgent:     "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.7 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			// Safari doesn't send Client Hints
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		// iOS Safari header order for HTTP/2 (same as macOS Safari)
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
			{"accept-language", "en-US,en;q=0.9"},
			{"accept-encoding", "gzip, deflate, br"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
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
			NoRFC7540Priorities:    true, // Safari uses m,s,p,a pseudo header order
		},
		SupportHTTP3: false, // iOS Safari 17 doesn't have proper H3 TLS spec
	}
}

// IOSSafari18 returns Safari 18 on iOS fingerprint preset
func IOSSafari18() *Preset {
	return &Preset{
		Name:              "safari-18-ios",
		ClientHelloID:     tls.HelloIOS_18,
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Safari QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			// Safari doesn't send Client Hints
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		// iOS Safari header order for HTTP/2 (same as macOS Safari)
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
			{"accept-language", "en-US,en;q=0.9"},
			{"accept-encoding", "gzip, deflate, br"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
		},
		// iOS Safari HTTP/2 settings
		// Akamai fingerprint: 2:0;4:2097152;3:100;9:1|10485760|0|m,s,p,a
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // iOS 18 sends ENABLE_PUSH=0
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // iOS sends NO_RFC7540_PRIORITIES=1
		},
		SupportHTTP3: true,
	}
}

// AndroidChrome143 returns Chrome 143 on Android fingerprint preset
// Note: Chrome on Android uses Chrome's TLS fingerprint (not WebKit restricted like iOS)
func AndroidChrome143() *Preset {
	return &Preset{
		Name:                 "chrome-143-android",
		ClientHelloID:        tls.HelloChrome_143_Linux,     // Android Chrome uses Chrome's TLS
		PSKClientHelloID:     tls.HelloChrome_143_Linux_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,      // QUIC for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,  // QUIC PSK for session resumption
		UserAgent:        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Mobile Safari/537.36",
		Headers: map[string]string{
			// Low-entropy Client Hints for mobile
			"sec-ch-ua":          `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":   "?1",
			"sec-ch-ua-platform": `"Android"`,
			// Standard navigation headers
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
		// Chrome 143 header order for HTTP/2 and HTTP/3 (order matters!)
		// Same as desktop Chrome but with mobile flag
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?1"},
			{"sec-ch-ua-platform", `"Android"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			// Android Chrome uses same HTTP/2 settings as desktop Chrome
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

// AndroidChrome144 returns Chrome 144 on Android fingerprint preset
func AndroidChrome144() *Preset {
	return &Preset{
		Name:                 "chrome-144-android",
		ClientHelloID:        tls.HelloChrome_144_Linux,
		PSKClientHelloID:     tls.HelloChrome_144_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?1",
			"sec-ch-ua-platform":        `"Android"`,
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
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?1"},
			{"sec-ch-ua-platform", `"Android"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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

// AndroidChrome145 returns Chrome 145 on Android fingerprint preset
func AndroidChrome145() *Preset {
	return &Preset{
		Name:                 "chrome-145-android",
		ClientHelloID:        tls.HelloChrome_145_Linux,
		PSKClientHelloID:     tls.HelloChrome_145_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?1",
			"sec-ch-ua-platform":        `"Android"`,
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
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?1"},
			{"sec-ch-ua-platform", `"Android"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
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

// presets is a map of all available presets
var presets = map[string]func() *Preset{
	"chrome-133":         Chrome133,
	"chrome-141":         Chrome141,
	"chrome-143":         Chrome143,
	"chrome-143-windows": Chrome143Windows,
	"chrome-143-linux":   Chrome143Linux,
	"chrome-143-macos":   Chrome143macOS,
	"chrome-144":         Chrome144,
	"chrome-144-windows": Chrome144Windows,
	"chrome-144-linux":   Chrome144Linux,
	"chrome-144-macos":   Chrome144macOS,
	"chrome-145":         Chrome145,
	"chrome-145-windows": Chrome145Windows,
	"chrome-145-linux":   Chrome145Linux,
	"chrome-145-macos":   Chrome145macOS,
	"firefox-133":        Firefox133,
	"safari-18":          Safari18,
	"chrome-143-ios":     IOSChrome143,
	"chrome-144-ios":     IOSChrome144,
	"chrome-145-ios":     IOSChrome145,
	"safari-17-ios":      IOSSafari17,
	"safari-18-ios":      IOSSafari18,
	"chrome-143-android": AndroidChrome143,
	"chrome-144-android": AndroidChrome144,
	"chrome-145-android": AndroidChrome145,

	// -latest aliases (always point to the newest version)
	"chrome-latest":         Chrome145,
	"chrome-latest-windows": Chrome145Windows,
	"chrome-latest-linux":   Chrome145Linux,
	"chrome-latest-macos":   Chrome145macOS,
	"firefox-latest":        Firefox133,
	"safari-latest":         Safari18,
	"chrome-latest-ios":     IOSChrome145,
	"safari-latest-ios":     IOSSafari18,
	"chrome-latest-android": AndroidChrome145,

	// Backwards compatibility aliases (old naming convention)
	"ios-chrome-143":        IOSChrome143,
	"ios-chrome-144":        IOSChrome144,
	"ios-chrome-145":        IOSChrome145,
	"ios-safari-17":         IOSSafari17,
	"ios-safari-18":         IOSSafari18,
	"android-chrome-143":    AndroidChrome143,
	"android-chrome-144":    AndroidChrome144,
	"android-chrome-145":    AndroidChrome145,
	"ios-chrome-latest":     IOSChrome145,
	"ios-safari-latest":     IOSSafari18,
	"android-chrome-latest": AndroidChrome145,
}

// Get returns a preset by name, or chrome-latest as default
func Get(name string) *Preset {
	if fn, ok := presets[name]; ok {
		return fn()
	}
	return Chrome145()
}

// Available returns a list of available preset names
func Available() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	return names
}

// PresetInfo contains metadata about a preset's protocol support.
type PresetInfo struct {
	Protocols []string `json:"protocols"`
}

// AvailableWithInfo returns a map of preset names to their supported protocols.
func AvailableWithInfo() map[string]PresetInfo {
	result := make(map[string]PresetInfo, len(presets))
	for name, presetFn := range presets {
		p := presetFn()
		protocols := []string{"h1", "h2"}
		if p.SupportHTTP3 {
			protocols = append(protocols, "h3")
		}
		result[name] = PresetInfo{Protocols: protocols}
	}
	return result
}
