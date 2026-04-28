package fingerprint

import (
	"fmt"
	"strings"
	"sync"

	tls "github.com/sardanioss/utls"
)

// clientHelloIDs maps lowercase-hyphenated names to utls ClientHelloID constants.
// Naming convention: browser-version[-platform][-variant]
// Examples: "chrome-146-windows", "chrome-146-windows-psk", "chrome-146-quic", "firefox-120"
var clientHelloIDs = map[string]tls.ClientHelloID{
	// Special types
	"golang":           tls.HelloGolang,
	"custom":           tls.HelloCustom,
	"randomized":       tls.HelloRandomized,
	"randomized-alpn":  tls.HelloRandomizedALPN,
	"randomized-noalpn": tls.HelloRandomizedNoALPN,

	// Firefox
	"firefox-auto": tls.HelloFirefox_Auto,
	"firefox-55":   tls.HelloFirefox_55,
	"firefox-56":   tls.HelloFirefox_56,
	"firefox-63":   tls.HelloFirefox_63,
	"firefox-65":   tls.HelloFirefox_65,
	"firefox-99":   tls.HelloFirefox_99,
	"firefox-102":  tls.HelloFirefox_102,
	"firefox-105":  tls.HelloFirefox_105,
	"firefox-120":  tls.HelloFirefox_120,

	// Chrome (legacy, no platform split)
	"chrome-auto":        tls.HelloChrome_Auto,
	"chrome-58":          tls.HelloChrome_58,
	"chrome-62":          tls.HelloChrome_62,
	"chrome-70":          tls.HelloChrome_70,
	"chrome-72":          tls.HelloChrome_72,
	"chrome-83":          tls.HelloChrome_83,
	"chrome-87":          tls.HelloChrome_87,
	"chrome-96":          tls.HelloChrome_96,
	"chrome-100":         tls.HelloChrome_100,
	"chrome-102":         tls.HelloChrome_102,
	"chrome-106-shuffle": tls.HelloChrome_106_Shuffle,
	"chrome-120":         tls.HelloChrome_120,
	"chrome-120-pq":      tls.HelloChrome_120_PQ,
	"chrome-131":         tls.HelloChrome_131,
	"chrome-133":         tls.HelloChrome_133,

	// Chrome PSK (legacy, no platform split)
	"chrome-100-psk":     tls.HelloChrome_100_PSK,
	"chrome-112-psk":     tls.HelloChrome_112_PSK_Shuf,
	"chrome-114-psk":     tls.HelloChrome_114_Padding_PSK_Shuf,
	"chrome-115-pq":      tls.HelloChrome_115_PQ,
	"chrome-115-pq-psk":  tls.HelloChrome_115_PQ_PSK,
	"chrome-133-psk":     tls.HelloChrome_133_PSK,

	// Chrome 143 (per-platform)
	"chrome-143-windows":     tls.HelloChrome_143_Windows,
	"chrome-143-linux":       tls.HelloChrome_143_Linux,
	"chrome-143-macos":       tls.HelloChrome_143_macOS,
	"chrome-143-quic":        tls.HelloChrome_143_QUIC,
	"chrome-143-windows-psk": tls.HelloChrome_143_Windows_PSK,
	"chrome-143-linux-psk":   tls.HelloChrome_143_Linux_PSK,
	"chrome-143-macos-psk":   tls.HelloChrome_143_macOS_PSK,
	"chrome-143-quic-psk":    tls.HelloChrome_143_QUIC_PSK,

	// Chrome 144 (per-platform)
	"chrome-144-windows":     tls.HelloChrome_144_Windows,
	"chrome-144-linux":       tls.HelloChrome_144_Linux,
	"chrome-144-macos":       tls.HelloChrome_144_macOS,
	"chrome-144-quic":        tls.HelloChrome_144_QUIC,
	"chrome-144-windows-psk": tls.HelloChrome_144_Windows_PSK,
	"chrome-144-linux-psk":   tls.HelloChrome_144_Linux_PSK,
	"chrome-144-macos-psk":   tls.HelloChrome_144_macOS_PSK,
	"chrome-144-quic-psk":    tls.HelloChrome_144_QUIC_PSK,

	// Chrome 145 (per-platform)
	"chrome-145-windows":     tls.HelloChrome_145_Windows,
	"chrome-145-linux":       tls.HelloChrome_145_Linux,
	"chrome-145-macos":       tls.HelloChrome_145_macOS,
	"chrome-145-quic":        tls.HelloChrome_145_QUIC,
	"chrome-145-windows-psk": tls.HelloChrome_145_Windows_PSK,
	"chrome-145-linux-psk":   tls.HelloChrome_145_Linux_PSK,
	"chrome-145-macos-psk":   tls.HelloChrome_145_macOS_PSK,
	"chrome-145-quic-psk":    tls.HelloChrome_145_QUIC_PSK,

	// Chrome 146 (per-platform)
	"chrome-146-windows":     tls.HelloChrome_146_Windows,
	"chrome-146-linux":       tls.HelloChrome_146_Linux,
	"chrome-146-macos":       tls.HelloChrome_146_macOS,
	"chrome-146-quic":        tls.HelloChrome_146_QUIC,
	"chrome-146-windows-psk": tls.HelloChrome_146_Windows_PSK,
	"chrome-146-linux-psk":   tls.HelloChrome_146_Linux_PSK,
	"chrome-146-macos-psk":   tls.HelloChrome_146_macOS_PSK,
	"chrome-146-quic-psk":    tls.HelloChrome_146_QUIC_PSK,

	// iOS
	"ios-auto":     tls.HelloIOS_Auto,
	"ios-11-1":     tls.HelloIOS_11_1,
	"ios-12-1":     tls.HelloIOS_12_1,
	"ios-13":       tls.HelloIOS_13,
	"ios-14":       tls.HelloIOS_14,
	"ios-18":       tls.HelloIOS_18,
	"ios-18-quic":  tls.HelloIOS_18_QUIC,

	// Android
	"android-11-okhttp": tls.HelloAndroid_11_OkHttp,

	// Edge
	"edge-auto": tls.HelloEdge_Auto,
	"edge-85":   tls.HelloEdge_85,
	"edge-106":  tls.HelloEdge_106,

	// Safari
	"safari-auto": tls.HelloSafari_Auto,
	"safari-16":   tls.HelloSafari_16_0,
	"safari-18":   tls.HelloSafari_18,

	// 360 Browser
	"360-auto": tls.Hello360_Auto,
	"360-7-5":  tls.Hello360_7_5,
	"360-11":   tls.Hello360_11_0,

	// QQ Browser
	"qq-auto": tls.HelloQQ_Auto,
	"qq-11-1": tls.HelloQQ_11_1,
}

// ResolveClientHelloID resolves a string name to a utls ClientHelloID.
// Names use lowercase-hyphenated convention (e.g., "chrome-146-windows").
func ResolveClientHelloID(name string) (tls.ClientHelloID, error) {
	if id, ok := clientHelloIDs[name]; ok {
		return id, nil
	}
	return tls.ClientHelloID{}, fmt.Errorf("unknown client hello ID: %q", name)
}

// clientHelloIDKey is the (Client, Version) tuple used as the inverse-lookup key.
// Two utls ClientHelloIDs are considered equivalent when both fields match;
// Auto aliases share their key with the concrete target they resolve to.
type clientHelloIDKey struct{ Client, Version string }

var (
	clientHelloIDNamesOnce sync.Once
	clientHelloIDNames     map[clientHelloIDKey]string
)

func buildInverseClientHelloIDMap() {
	m := make(map[clientHelloIDKey]string, len(clientHelloIDs))
	// First pass: concrete names take priority. They're the unambiguous
	// canonical identifiers and the form Describe should round-trip into.
	for name, id := range clientHelloIDs {
		if strings.HasSuffix(name, "-auto") {
			continue
		}
		k := clientHelloIDKey{id.Client, id.Version}
		// Skip empty keys (e.g., HelloGolang/HelloCustom have empty Client/Version).
		if k.Client == "" && k.Version == "" {
			continue
		}
		// Last write wins among concretes; clientHelloIDs has no duplicates by
		// construction so this is effectively a single assignment per key.
		m[k] = name
	}
	// Second pass: -auto aliases fill any keys not claimed by a concrete.
	// This handles e.g. HelloChrome_Auto when no concrete shares its key,
	// or families where only the -auto entry exists.
	for name, id := range clientHelloIDs {
		if !strings.HasSuffix(name, "-auto") {
			continue
		}
		k := clientHelloIDKey{id.Client, id.Version}
		if k.Client == "" && k.Version == "" {
			continue
		}
		if _, exists := m[k]; !exists {
			m[k] = name
		}
	}
	clientHelloIDNames = m
}

// ClientHelloIDName returns the canonical string name for a utls ClientHelloID.
// Suitable for round-trip JSON via Describe. Concrete names are preferred over
// "-auto" aliases that resolve to the same (Client, Version) pair.
//
// Returns ("", false) for the zero-value ID and for IDs not registered in
// clientHelloIDs (e.g., randomized variants or hand-built IDs).
func ClientHelloIDName(id tls.ClientHelloID) (string, bool) {
	if id.Client == "" && id.Version == "" {
		return "", false
	}
	clientHelloIDNamesOnce.Do(buildInverseClientHelloIDMap)
	name, ok := clientHelloIDNames[clientHelloIDKey{id.Client, id.Version}]
	return name, ok
}
