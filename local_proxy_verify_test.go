package httpcloak

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A LocalProxy (and so .NET's HttpCloakHandler) had no way to skip
// certificate verification, so a site with a self-signed certificate could not
// be reached through it at all, where a Session takes WithInsecureSkipVerify
// (#149). Verification stays on by default; the option turns it off.
func TestLocalProxyInsecureSkipVerify(t *testing.T) {
	origin := newTLSOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	for _, tc := range []struct {
		name string
		opts []LocalProxyOption
		want int
	}{
		{"verified by default", nil, http.StatusBadGateway},
		{"verification off", []LocalProxyOption{WithProxyInsecureSkipVerify()}, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]LocalProxyOption{WithProxyPreset("chrome-latest"), WithProxyTimeout(10 * time.Second)}, tc.opts...)
			proxy, err := StartLocalProxy(0, opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Stop()
			proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxy.Port()))
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 15 * time.Second}

			// The fingerprinted path: plain http:// to the proxy, with the
			// real scheme in X-HTTPCloak-Scheme, as HttpCloakHandler sends it.
			req, _ := http.NewRequest("POST", "http://"+origin+"/x", strings.NewReader("body"))
			req.Header.Set("X-HTTPCloak-Scheme", "https")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}
