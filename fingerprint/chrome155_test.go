package fingerprint

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// Chrome 154 is a headers-only bump over 153, the same shape as 153 was over
// 152. Chrome 155 moves a third header: Accept gained image/jxl, on document
// loads and on image loads. Measured on 155.0.8059.39 against 154.0.8037.92
// with one page that loads a document, an iframe, an image, a stylesheet, a
// script, a font and two fetch() calls; only the document, iframe and image
// Accept changed. The document Accept and the sec-ch-ua of both versions were
// also checked against real Windows Chrome 154 and 155 captures.
const (
	chrome154SecCHUA = `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`
	chrome155SecCHUA = `"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"`

	chrome155NavigationAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	chrome155ImageAccept      = "image/jxl,image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
)

func TestChrome154And155Presets(t *testing.T) {
	for _, tc := range []struct {
		major   int
		secCHUA string
	}{{154, chrome154SecCHUA}, {155, chrome155SecCHUA}} {
		for _, suffix := range []string{"", "-windows", "-linux", "-macos", "-android"} {
			name := fmt.Sprintf("chrome-%d%s", tc.major, suffix)
			p := GetStrict(name)
			if p == nil {
				t.Errorf("%s not registered", name)
				continue
			}
			if want := fmt.Sprintf("Chrome/%d.0.0.0", tc.major); !strings.Contains(p.UserAgent, want) {
				t.Errorf("%s: UA = %q, want %s; the based_on chain may have dropped the override",
					name, p.UserAgent, want)
			}
			if got := chrome152SecCHUA(p); got != tc.secCHUA {
				t.Errorf("%s: sec-ch-ua = %q, want %q", name, got, tc.secCHUA)
			}
		}
	}
}

// Neither release touched the cipher suites, extensions or signature
// algorithms, so those reach 154 and 155 through based_on unchanged, and only
// the expected header values may differ from the version before. The one TLS
// change is the trust_anchors list order, which 154 sorts.
func TestChrome154And155InheritTheClientHello(t *testing.T) {
	for _, plat := range []string{"windows", "linux", "macos", "android"} {
		for _, step := range []struct {
			from, to, wantDiff int
		}{{153, 154, 2}, {154, 155, 3}} {
			old := Get(fmt.Sprintf("chrome-%d-%s", step.from, plat))
			new := Get(fmt.Sprintf("chrome-%d-%s", step.to, plat))
			label := fmt.Sprintf("chrome-%d-%s", step.to, plat)
			if new.ClientHelloID != old.ClientHelloID || new.QUICClientHelloID != old.QUICClientHelloID {
				t.Errorf("%s: ClientHello ids differ from %d", label, step.from)
			}
			if fmt.Sprint(new.SignatureAlgorithms) != fmt.Sprint(old.SignatureAlgorithms) {
				t.Errorf("%s: signature algorithms differ from %d", label, step.from)
			}
			// Same anchor set throughout. 154 changes only the order, to
			// sorted; see trust_anchors_order_test.go.
			if fmt.Sprint(sortedHex(new)) != fmt.Sprint(sortedHex(old)) {
				t.Errorf("%s: trust anchor set differs from %d", label, step.from)
			}
			if diff := headerValueDiff(old, new); len(diff) != step.wantDiff {
				t.Errorf("%s: %d header values differ from %d, want %d: %v",
					label, len(diff), step.from, step.wantDiff, diff)
			}
		}
	}
}

// The Accept change has to reach every path that builds a request, not just the
// header order the transport reads. Before 155 the helper paths hardcoded
// Chrome's Accept, so a 155 preset would have sent image/jxl from one path and
// not from another.
func TestChrome155AcceptAddsJXL(t *testing.T) {
	for _, plat := range []string{"windows", "linux", "macos", "android"} {
		p155 := Get("chrome-155-" + plat)
		if got := p155.ResolveNavigationAccept(); got != chrome155NavigationAccept {
			t.Errorf("chrome-155-%s: navigation Accept = %q, want %q", plat, got, chrome155NavigationAccept)
		}
		if got := p155.ResolveImageAccept(); got != chrome155ImageAccept {
			t.Errorf("chrome-155-%s: image Accept = %q, want %q", plat, got, chrome155ImageAccept)
		}

		nav := NewHeaderCoherence(p155).GenerateNavigationHeaders()
		if nav["Accept"] != chrome155NavigationAccept {
			t.Errorf("chrome-155-%s: GenerateNavigationHeaders Accept = %q", plat, nav["Accept"])
		}
		img := map[string]string{}
		NewHeaderCoherence(p155).ApplyToHeaders(img, ImageContext("https://a.example/", "https://a.example/x.png"))
		if img["Accept"] != chrome155ImageAccept {
			t.Errorf("chrome-155-%s: image-context Accept = %q", plat, img["Accept"])
		}

		// 154 must still send exactly what it sent before.
		p154 := Get("chrome-154-" + plat)
		if p154.ResolveNavigationAccept() != legacyNavigationAccept || p154.ResolveImageAccept() != legacyImageAccept {
			t.Errorf("chrome-154-%s: Accept moved, but image/jxl only arrived in 155", plat)
		}
	}
}

// Replays Chromium's greased brand list over every desktop preset in the tree.
// 153 was derived before a 153 binary existed; 154 and 155 were derived first
// and then matched real captures, so the derivation has now been checked
// against three releases on the wire.
func TestChromeBrandListFollowsChromiumThrough155(t *testing.T) {
	for major := 146; major <= 155; major++ {
		p := GetStrict(fmt.Sprintf("chrome-%d-windows", major))
		if p == nil {
			continue
		}
		if got, want := greasedBrandList(major), chrome152SecCHUA(p); got != want {
			t.Errorf("chrome-%d: derivation gives %q, tree has %q", major, got, want)
		}
	}
}

// No iOS preset for 154, for the reason given under
// TestChrome153HasNoIOSPresetYet. 155 has one, from a capture.
func TestChrome154HasNoIOSPresetYet(t *testing.T) {
	for _, name := range []string{"chrome-154-ios"} {
		if p := GetStrict(name); p != nil {
			t.Errorf("%s is registered with UA %q; only add it from a capture", name, p.UserAgent)
		}
	}
}

func sortedHex(p *Preset) []string {
	out := anchorHex(p)
	sort.Strings(out)
	return out
}

// The Headers map is what a preset falls back on without an order list, and
// what Describe exports as its values. It drifted from the order list when a
// version changed a header there alone: the 155 presets sent the new Accept
// with image/jxl while the map kept 154's, and the iOS presets from 148 on
// sent zstd in Accept-Encoding while the map did not. Nothing on the wire was
// wrong, but a described preset carried two different values for one header.
func TestHeaderMapAgreesWithHeaderOrder(t *testing.T) {
	for _, name := range Available() {
		p := Get(name)
		for _, hp := range p.HeaderOrder {
			if hp.Value == "" {
				continue
			}
			for k, v := range p.Headers {
				if strings.EqualFold(k, hp.Key) && v != hp.Value {
					t.Errorf("%s: Headers[%q] = %q, but the order list sends %q", name, k, v, hp.Value)
				}
			}
		}
	}
}
