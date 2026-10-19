package fingerprint

import (
	"strings"
	"testing"
)

func TestIOSSafari26LatestAliasesAndLegacyProfiles(t *testing.T) {
	for _, name := range []string{"safari-26-ios", "ios-safari-26", "safari-latest-ios", "ios-safari-latest"} {
		p := GetStrict(name)
		if p == nil || p.Name != "safari-26-ios" {
			t.Fatalf("%s does not select Safari 26 iOS", name)
		}
		if !strings.Contains(p.UserAgent, "Version/26.6.1") {
			t.Errorf("%s UA=%s", name, p.UserAgent)
		}
		if p.SupportHTTP3 {
			t.Errorf("%s claims HTTP/3 without a QUIC capture", name)
		}
	}
	for _, name := range []string{"safari-18-ios", "ios-safari-18", "safari-18", "safari-latest"} {
		p := GetStrict(name)
		if !strings.Contains(p.UserAgent, "Version/18.0") || p.HTTP2Settings.ConnectionWindowUpdate != 10485760 {
			t.Errorf("%s changed with the new iOS preset", name)
		}
	}
}
