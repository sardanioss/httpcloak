package transport

import (
	"context"
	shttp "github.com/sardanioss/http"
	"sync"
	"testing"
	"time"
)

// A bodiless POST is sent with "content-length: 0", as Chrome sends it; some
// servers answer 411 Length Required without it. Over HTTP/3 the empty body
// went out as http.NoBody, which quic-go's request writer reads as a body of
// unknown length, so it left the header out.
func TestHTTP3EmptyBodySendsZeroContentLength(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	url := startH3Origin(t, shttp.HandlerFunc(func(w shttp.ResponseWriter, r *shttp.Request) {
		mu.Lock()
		seen[r.Method] = r.Header.Get("Content-Length")
		mu.Unlock()
		w.WriteHeader(200)
	}))

	tr := NewTransport("chrome-latest")
	defer tr.Close()
	tr.SetInsecureSkipVerify(true)
	tr.SetProtocol(ProtocolHTTP3)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, stream := range []bool{false, true} {
		for _, method := range []string{"POST", "PUT", "PATCH", "GET"} {
			if stream {
				resp, err := tr.DoStream(ctx, &Request{Method: method, URL: url})
				if err != nil {
					t.Fatalf("DoStream %s: %v", method, err)
				}
				resp.ReadAll()
			} else if _, err := tr.Do(ctx, &Request{Method: method, URL: url}); err != nil {
				t.Fatalf("Do %s: %v", method, err)
			}
			mu.Lock()
			got := seen[method]
			mu.Unlock()
			want := "0"
			if method == "GET" {
				want = ""
			}
			if got != want {
				t.Errorf("stream=%v %s: content-length %q, want %q", stream, method, got, want)
			}
		}
	}
}
