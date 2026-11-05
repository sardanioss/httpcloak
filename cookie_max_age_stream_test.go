package httpcloak_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak"
)

func TestCookieMaxAgeStream(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("protocol = %s, want HTTP/2", r.Proto)
		}
		switch r.URL.Path {
		case "/set":
			w.Header().Add("Set-Cookie", "token=root; Path=/; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
			w.Header().Add("Set-Cookie", "token=scoped; Path=/account; Max-Age=3600")
		case "/delete":
			w.Header().Add("Set-Cookie", "token=deleted; Path=/; Max-Age=0; Expires=Fri, 31 Dec 9999 23:59:59 GMT")
		}
		io.WriteString(w, r.Header.Get("Cookie"))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := httpcloak.NewSession("chrome-latest-windows", httpcloak.WithForceHTTP2(), httpcloak.WithInsecureSkipVerify())
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	get := func(path string) string {
		t.Helper()
		response, err := client.DoStream(ctx, &httpcloak.Request{Method: "GET", URL: server.URL + path})
		if err != nil {
			t.Fatalf("DoStream(%s): %v", path, err)
		}
		body, err := io.ReadAll(response)
		closeErr := response.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("read/close %s: %v / %v", path, err, closeErr)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", response.StatusCode)
		}
		return string(body)
	}
	get("/set")
	if got := get("/account/check"); got != "token=scoped; token=root" {
		t.Fatalf("positive Max-Age did not override Expires or preserve path order: %q", got)
	}
	get("/delete")
	if got := get("/account/check"); got != "token=scoped" {
		t.Fatalf("Max-Age=0 did not delete only the root cookie: %q", got)
	}
	if got := get("/check"); got != "" {
		t.Fatalf("deleted cookie was sent again: %q", got)
	}
}
