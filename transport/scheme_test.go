package transport

import (
	"context"
	"strings"
	"testing"
	"time"

	http "github.com/sardanioss/http"
)

// A URL that is not http or https used to go out as plain HTTP, since the
// dispatch only asks whether the scheme is "https": ftps:// was sent
// unencrypted.
func TestOnlyHTTPAndHTTPSAreSent(t *testing.T) {
	tr := NewTransport("chrome-146")
	t.Cleanup(tr.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, u := range []string{"ftp://127.0.0.1:1/", "ftps://127.0.0.1:1/", "ws://127.0.0.1:1/", "localhost/x", "//127.0.0.1:1/"} {
		_, err := tr.Do(ctx, &Request{Method: http.MethodGet, URL: u})
		if err == nil || !strings.Contains(err.Error(), "unsupported protocol scheme") {
			t.Errorf("Do(%q) = %v, want an unsupported scheme error", u, err)
		}
		_, err = tr.DoStream(ctx, &Request{Method: http.MethodGet, URL: u})
		if err == nil || !strings.Contains(err.Error(), "unsupported protocol scheme") {
			t.Errorf("DoStream(%q) = %v, want an unsupported scheme error", u, err)
		}
	}
}
