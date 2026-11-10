package transport

import (
	"testing"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/fingerprint"
)

// TestPresetSendsSecFetch checks the gate that keeps the Sec-Fetch-* coercion
// off presets describing clients that send no Sec-Fetch-* at all. Every built-in
// must pass the gate, or applyPresetHeaders stops correcting browser headers on
// API calls and the behavior issue #53 asked for regresses.
func TestPresetSendsSecFetch(t *testing.T) {
	var checked int
	for _, name := range fingerprint.Available() {
		p := fingerprint.GetStrict(name)
		if p == nil {
			continue
		}
		checked++
		if !presetSendsSecFetch(p) {
			t.Errorf("presetSendsSecFetch(%s) = false, want true for a built-in browser preset", name)
		}
	}
	if checked == 0 {
		t.Fatal("no built-in presets were checked, so this proves nothing")
	}
	t.Logf("checked %d built-in presets", checked)
}

// A preset whose HPACK position table declares no sec-fetch headers describes a
// non-browser client (okhttp, curl, a native SDK). Coercing Sec-Fetch-* onto one
// does not fix an incoherence, it invents headers the client never sends.
func TestPresetSendsSecFetchNonBrowser(t *testing.T) {
	secFetchPair := []fingerprint.HeaderPair{
		{Key: "user-agent", Value: "x"},
		{Key: "sec-fetch-mode", Value: "navigate"},
		{Key: "accept-encoding", Value: "gzip"},
	}
	plainPair := []fingerprint.HeaderPair{
		{Key: "authorization", Value: "x"},
		{Key: "user-agent", Value: "okhttp/5.1.0"},
		{Key: "accept-encoding", Value: "gzip"},
	}

	tests := []struct {
		name   string
		emit   []fingerprint.HeaderPair
		hdrMap map[string]string
		table  []string
		want   bool
	}{
		{
			name:  "emit set carries sec-fetch",
			emit:  secFetchPair,
			table: []string{"user-agent", "sec-fetch-mode"},
			want:  true,
		},
		{
			name:  "non-browser emit set",
			emit:  plainPair,
			table: []string{"authorization", "user-agent", "accept-encoding"},
			want:  false,
		},
		{
			// The hole the original gate left open. A custom preset that drops
			// Sec-Fetch-* from what it SENDS while inheriting a browser's HPACK
			// position table used to be coerced anyway, so the opt-out silently
			// failed for exactly the preset that asked for it.
			name:  "emit set opts out while inheriting a browser table",
			emit:  plainPair,
			table: []string{"user-agent", "sec-fetch-mode", "sec-fetch-dest"},
			want:  false,
		},
		{
			// Casing is the preset author's choice; the wire is lowercase but a
			// hand-written preset need not be.
			name: "canonical casing still matches",
			emit: []fingerprint.HeaderPair{
				{Key: "User-Agent", Value: "x"},
				{Key: "Sec-Fetch-Site", Value: "none"},
			},
			want: true,
		},
		{
			// The based_on case: a custom preset drops Sec-Fetch-* from its own
			// emit set but inherits the base preset's Headers map. The emit set
			// must win, or the opt-out silently fails for exactly the preset
			// that asked for it.
			name:   "based_on preset opts out while inheriting a base Headers map",
			emit:   plainPair,
			hdrMap: map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none"},
			want:   false,
		},
		{
			name:   "map-only preset with sec-fetch",
			hdrMap: map[string]string{"Sec-Fetch-Mode": "navigate"},
			want:   true,
		},
		{
			name:   "map-only preset without",
			hdrMap: map[string]string{"User-Agent": "curl/8.5.0"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &fingerprint.Preset{HeaderOrder: tt.emit, Headers: tt.hdrMap}
			if tt.table != nil {
				p.H2Config = &fingerprint.H2FingerprintConfig{HPACKHeaderOrder: tt.table}
			}
			if got := presetSendsSecFetch(p); got != tt.want {
				t.Errorf("presetSendsSecFetch() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The gate has to hold where it is actually used: applyPresetHeaders must leave
// a non-browser preset's headers alone on an API-shaped request, while still
// coercing a browser preset's.
func TestApplyPresetHeadersSkipsSecFetchForNonBrowserPreset(t *testing.T) {
	injected := []string{"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-Site", "Accept"}

	tests := []struct {
		name       string
		preset     *fingerprint.Preset
		wantAbsent bool
	}{
		{
			name: "non-browser preset",
			preset: &fingerprint.Preset{
				UserAgent: "okhttp/5.1.0",
				H2Config: &fingerprint.H2FingerprintConfig{
					HPACKHeaderOrder: []string{"user-agent", "content-type", "accept-encoding"},
				},
			},
			wantAbsent: true,
		},
		{
			name:       "browser preset",
			preset:     fingerprint.GetStrict("chrome-146-windows"),
			wantAbsent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.preset == nil {
				t.Skip("preset not registered")
			}
			req, err := http.NewRequest("POST", "https://example.com/api", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			// An API-shaped POST, which is what sniffXHRMode classifies as XHR.
			userHeaders := map[string][]string{"Content-Type": {"application/json"}}

			applyPresetHeaders(req, newPresetWireHeaders(tt.preset), nil, nil, false, "h2", userHeaders, false, nil)

			for _, key := range injected {
				_, present := req.Header[key]
				if tt.wantAbsent && present {
					t.Errorf("%s = %q was set, want it absent for a preset that does not declare it", key, req.Header.Get(key))
				}
				if !tt.wantAbsent && !present {
					t.Errorf("%s is absent, want the XHR coercion to still apply to a browser preset", key)
				}
			}
		})
	}
}

// A fetch() or subresource load takes its Sec-Fetch-Site and Origin from the
// page that made it, which the Referer names, and its Accept from its
// destination, as Chrome's do. Before, every such request said cross-site and
// carried no Origin, so a same-origin JSON POST read as no browser's.
func TestApplyPresetHeadersDerivesSubresourceContext(t *testing.T) {
	preset := fingerprint.GetStrict("chrome-latest")
	tests := []struct {
		name                 string
		method, url          string
		user                 map[string][]string
		site, origin, accept string
	}{
		{
			name:   "same-origin POST",
			method: "POST", url: "https://shop.example.com/api/graphql",
			user: map[string][]string{"Content-Type": {"application/json"}, "Referer": {"https://shop.example.com/products/x"}},
			site: "same-origin", origin: "https://shop.example.com", accept: "*/*",
		},
		{
			name:   "same-origin GET carries no Origin",
			method: "GET", url: "https://shop.example.com/cart.js",
			user: map[string][]string{"Sec-Fetch-Mode": {"cors"}, "Referer": {"https://shop.example.com/"}},
			site: "same-origin", origin: "", accept: "*/*",
		},
		{
			name:   "same-site, by the public suffix list",
			method: "POST", url: "https://api.shop.com.au/basket",
			user: map[string][]string{"Content-Type": {"application/json"}, "Referer": {"https://www.shop.com.au/"}},
			site: "same-site", origin: "https://www.shop.com.au", accept: "*/*",
		},
		{
			name:   "two sites under one public suffix are cross-site",
			method: "POST", url: "https://b.myshopify.com/api",
			user: map[string][]string{"Content-Type": {"application/json"}, "Referer": {"https://a.myshopify.com/"}},
			site: "cross-site", origin: "https://a.myshopify.com", accept: "*/*",
		},
		{
			name:   "cross-site GET",
			method: "GET", url: "https://api.example.net/v1",
			user: map[string][]string{"Sec-Fetch-Mode": {"cors"}, "Referer": {"https://shop.example.com/page"}},
			site: "cross-site", origin: "https://shop.example.com", accept: "*/*",
		},
		{
			name:   "no referer: page unknown, nothing invented",
			method: "POST", url: "https://shop.example.com/api",
			user: map[string][]string{"Content-Type": {"application/json"}},
			site: "cross-site", origin: "", accept: "*/*",
		},
		{
			name:   "an image takes the preset's image Accept and no Origin",
			method: "GET", url: "https://cdn.example.net/a.png",
			user: map[string][]string{"Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"image"}, "Referer": {"https://shop.example.com/"}},
			site: "cross-site", origin: "", accept: preset.ResolveImageAccept(),
		},
		{
			name:   "a stylesheet takes the CSS Accept",
			method: "GET", url: "https://shop.example.com/a.css",
			user: map[string][]string{"Sec-Fetch-Mode": {"no-cors"}, "Sec-Fetch-Dest": {"style"}, "Referer": {"https://shop.example.com/"}},
			site: "same-origin", origin: "", accept: "text/css,*/*;q=0.1",
		},
		{
			name:   "the caller's own values win",
			method: "POST", url: "https://shop.example.com/api",
			user: map[string][]string{"Content-Type": {"application/json"}, "Referer": {"https://shop.example.com/"}, "Sec-Fetch-Site": {"none"}, "Accept": {"application/json"}},
			site: "none", origin: "https://shop.example.com", accept: "application/json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			applyPresetHeaders(req, newPresetWireHeaders(preset), nil, nil, false, "h2", tt.user, false, nil)
			mergeCallerHeaders(req, &Request{Method: tt.method, URL: tt.url, Headers: tt.user})
			if got := req.Header.Get("Sec-Fetch-Site"); got != tt.site {
				t.Errorf("Sec-Fetch-Site = %q, want %q", got, tt.site)
			}
			if got := req.Header.Get("Origin"); got != tt.origin {
				t.Errorf("Origin = %q, want %q", got, tt.origin)
			}
			if got := req.Header.Get("Accept"); got != tt.accept {
				t.Errorf("Accept = %q, want %q", got, tt.accept)
			}
		})
	}
}

// A navigation started on a page (a link followed, a form submitted) takes its
// Sec-Fetch-Site from the page its Referer names, and a form POST carries the
// page's Origin, as Chrome's do. One without a Referer was typed and says none.
func TestApplyPresetHeadersDerivesNavigationSite(t *testing.T) {
	preset := fingerprint.GetStrict("chrome-latest")
	tests := []struct {
		name                         string
		method, url                  string
		user                         map[string][]string
		site, origin, userActivation string
	}{
		{
			name:   "typed navigation",
			method: "GET", url: "https://shop.example.com/checkout",
			user: map[string][]string{"Sec-Fetch-Mode": {"navigate"}},
			site: "none", origin: "", userActivation: "?1",
		},
		{
			name:   "link followed on the same site",
			method: "GET", url: "https://shop.example.com/checkout",
			user: map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Referer": {"https://shop.example.com/cart"}},
			site: "same-origin", origin: "", userActivation: "?1",
		},
		{
			name:   "form posted on the same origin",
			method: "POST", url: "https://shop.example.com/checkpoint",
			user: map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Content-Type": {"application/x-www-form-urlencoded"}, "Referer": {"https://shop.example.com/checkpoint?return_to=x"}},
			site: "same-origin", origin: "https://shop.example.com", userActivation: "?1",
		},
		{
			name:   "link followed from another site",
			method: "GET", url: "https://shop.example.com/products/x",
			user: map[string][]string{"Sec-Fetch-Mode": {"navigate"}, "Referer": {"https://www.google.com/"}},
			site: "cross-site", origin: "", userActivation: "?1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			applyPresetHeaders(req, newPresetWireHeaders(preset), nil, nil, false, "h2", tt.user, false, nil)
			mergeCallerHeaders(req, &Request{Method: tt.method, URL: tt.url, Headers: tt.user})
			if got := req.Header.Get("Sec-Fetch-Site"); got != tt.site {
				t.Errorf("Sec-Fetch-Site = %q, want %q", got, tt.site)
			}
			if got := req.Header.Get("Origin"); got != tt.origin {
				t.Errorf("Origin = %q, want %q", got, tt.origin)
			}
			if got := req.Header.Get("Sec-Fetch-User"); got != tt.userActivation {
				t.Errorf("Sec-Fetch-User = %q, want %q", got, tt.userActivation)
			}
			if got := req.Header.Get("Sec-Fetch-Mode"); got != "navigate" {
				t.Errorf("Sec-Fetch-Mode = %q, want navigate", got)
			}
		})
	}
}
