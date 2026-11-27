package transport

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
)

// Chrome derives a stream's HTTP/2 weight and its priority header from one
// request priority. In net/spdy/spdy_session.cc the weight is
// Spdy3PriorityToHttp2Weight(HIGHEST - priority), and in spdy_http_utils.cc the
// header's urgency is the same HIGHEST - priority, so the weight on the wire is
// always a function of the u= in the header: 256 - 73*u/2, which is what
// quiche's float formula gives for every u from 0 to 7.
//
// The dest cannot stand in for the request priority. A favicon is dest image
// like an <img>, and Chrome sends it at u=1, weight 220, where the <img> goes at
// u=2, weight 183. So when a request carries its own priority header, the
// weight has to come from that header, or the frame and the header disagree in
// a way no Chrome build produces. A request that carries none is at u=3, the
// one urgency Chrome sends no header for, whatever its dest.
//
// Two shapes were broken. With ordinary headers the caller's priority went out
// unchanged but the weight came from the dest. With exact headers the names
// stay lowercase, Header.Get missed sec-fetch-dest, and every request went out
// at the static 256 whatever its dest.
func TestStreamWeightFollowsTheRequestsPriorityHeader(t *testing.T) {
	cases := []struct {
		name     string
		exact    bool
		dest     string
		priority string // "" sends none
		want     int    // effective weight
	}{
		{"favicon", false, "image", "u=1, i", 220},
		{"img", false, "image", "u=2, i", 183},
		{"favicon exact", true, "image", "u=1, i", 220},
		{"img exact", true, "image", "u=2, i", 183},
		// No header of its own is the default urgency; the dest does not
		// decide.
		{"dest only exact", true, "image", "", 147},
		{"style exact", true, "style", "", 147},
		// An RFC 9218 value with no u= is urgency 3.
		{"incremental only", false, "image", "i", 147},
		// A dest the table does not know still follows the header, and with
		// none it is at the default urgency too.
		{"unknown dest", false, "made-up-dest", "u=4, i", 110},
		{"unknown dest exact", true, "made-up-dest", "", 147},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startH2CaptureServer(t)
			tr := NewTransport("chrome-155-windows")
			tr.SetProtocol(ProtocolHTTP2)
			tr.SetInsecureSkipVerify(true)
			defer tr.Close()

			req := &Request{Method: "GET", URL: "https://" + srv.addr + "/r"}
			if tc.exact {
				req.ExactHeaders = []fingerprint.HeaderPair{{Key: "sec-fetch-dest", Value: tc.dest}}
				if tc.priority != "" {
					req.ExactHeaders = append(req.ExactHeaders, fingerprint.HeaderPair{Key: "priority", Value: tc.priority})
				}
			} else {
				req.Headers = map[string][]string{"Sec-Fetch-Dest": {tc.dest}}
				if tc.priority != "" {
					req.Headers["Priority"] = []string{tc.priority}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			resp, err := tr.Do(ctx, req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			select {
			case c := <-srv.captures:
				if tc.priority != "" && c.Headers["priority"] != tc.priority {
					t.Fatalf("priority header = %q, want the caller's %q", c.Headers["priority"], tc.priority)
				}
				if !c.HasPriority {
					t.Fatal("HEADERS carried no priority")
				}
				if got := int(c.Priority.Weight) + 1; got != tc.want {
					t.Errorf("dest %q, priority %q: weight %d, want %d",
						tc.dest, c.Headers["priority"], got, tc.want)
				}
				if !c.Priority.Exclusive {
					t.Error("exclusive = false; Chrome sets it on every stream")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no capture within 3s")
			}
		})
	}
}

// The header rule is Chromium's. Firefox's weight is not a function of the
// urgency (it sends 22 at u=2 and at u=4), so a Firefox request that carries
// its own priority header keeps the weight its dest has.
func TestFirefoxWeightIgnoresThePriorityHeader(t *testing.T) {
	srv := startH2CaptureServer(t)
	tr := NewTransport("firefox-148-windows")
	tr.SetProtocol(ProtocolHTTP2)
	tr.SetInsecureSkipVerify(true)
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := tr.Do(ctx, &Request{Method: "GET", URL: "https://" + srv.addr + "/r",
		Headers: map[string][]string{"Sec-Fetch-Dest": {"image"}, "Priority": {"u=1, i"}}})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	c := <-srv.captures
	if got := int(c.Priority.Weight) + 1; got != 12 || c.Priority.Exclusive {
		t.Errorf("firefox image with priority %q: weight %d exclusive %v, want 12 false",
			c.Headers["priority"], got, c.Priority.Exclusive)
	}
}
