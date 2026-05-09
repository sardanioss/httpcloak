---
title: Go
sidebar_position: 1
---

# Go

Go is the native API. Every other binding (Python, Node, .NET) calls into the cgo wrapper that wraps this exact code, so the Go surface is the most direct way to use the lib and usually the fastest. If your project is already in Go, use this. No FFI hops, no JSON marshalling between two languages, no native binary to ship.

## Install

```bash
go get github.com/sardanioss/httpcloak
```

The module path is `github.com/sardanioss/httpcloak` and the public package name is `httpcloak`.

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/sardanioss/httpcloak"
)

func main() {
	s := httpcloak.NewSession("chrome-latest",
		httpcloak.WithSessionTimeout(20*time.Second),
	)
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := s.Get(ctx, "https://tls.peet.ws/api/all")
	if err != nil {
		panic(err)
	}
	defer resp.Close()

	body, _ := resp.Text()
	fmt.Println("status:", resp.StatusCode)
	fmt.Println("proto:", resp.Protocol)
	fmt.Println("len:", len(body))
}
```

Three things to notice:

- `NewSession` takes a preset name string and a variadic list of `SessionOption` values. See the full preset catalog at [Presets](/fingerprinting/presets).
- The `ctx context.Context` argument is always first. This is idiomatic Go and gives you cancellation and deadline plumbing for free.
- `defer s.Close()` and `defer resp.Close()`. The session owns connections and a cookie jar. The response body is an `io.ReadCloser` that must be drained or closed.

## Two API levels

httpcloak ships two levels of API. Most users want the session level.

### `Session` (recommended)

Persistent. Holds cookies, TLS resumption tickets, ECH configs, the connection pool. Use this when you're hitting the same host multiple times, when you care about cookies, or when you want browser-style refresh / warmup behaviour.

```go
s := httpcloak.NewSession("chrome-latest")
defer s.Close()
```

### `Client` (lower level)

Stateless wrapper for one-off requests. No cookie jar. Each `Do()` builds a fresh request through the same transport stack. Use this when you genuinely don't need state between requests.

```go
c := httpcloak.New("chrome-latest", httpcloak.WithTimeout(15*time.Second))
defer c.Close()

resp, err := c.Get(ctx, "https://example.com")
```

The two surfaces are intentionally similar but have different option types: `Option` for `Client`, `SessionOption` for `Session`. Don't mix them.

## Session methods

Full method list on `*httpcloak.Session`. Read top to bottom.

### Construction

```go
func NewSession(preset string, opts ...SessionOption) *Session
func LoadSession(path string) (*Session, error)
func UnmarshalSession(data []byte) (*Session, error)
```

`NewSession` is the normal entry point. `LoadSession` and `UnmarshalSession` rebuild a session from a file or JSON blob saved earlier, see [Session save & restore](/connection-lifecycle/session-save-restore).

### Core request

```go
func (s *Session) Do(ctx context.Context, req *Request) (*Response, error)
func (s *Session) DoWithBody(ctx context.Context, req *Request, bodyReader io.Reader) (*Response, error)
func (s *Session) Get(ctx context.Context, url string) (*Response, error)
```

The Go session API is more sparse than the Python/Node ones on purpose. `Get` is the only one-call shortcut. For `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, build a `Request` struct and call `Do`:

```go
req := &httpcloak.Request{
	Method:  "POST",
	URL:     "https://httpbin.org/post",
	Headers: map[string][]string{"Content-Type": {"application/json"}},
	Body:    bytes.NewReader([]byte(`{"hello":"world"}`)),
}
resp, err := s.Do(ctx, req)
```

`DoWithBody` takes the body separately as an `io.Reader`. Use it for streaming uploads where you don't want to buffer the body upfront.

### Streaming responses

```go
func (s *Session) DoStream(ctx context.Context, req *Request) (*StreamResponse, error)
func (s *Session) GetStream(ctx context.Context, url string) (*StreamResponse, error)
func (s *Session) GetStreamWithHeaders(ctx context.Context, url string, headers map[string][]string) (*StreamResponse, error)
```

`StreamResponse` exposes `Read(p []byte) (int, error)`, `ReadChunk(size int) ([]byte, error)`, `ReadAll() ([]byte, error)`, and `Close() error`. Use `DoStream` for downloads where buffering the whole body in memory is a bad idea (videos, large JSON dumps, archives).

Streaming does not auto-follow redirects. If the response is a 3xx, you handle it manually.

### Lifecycle

```go
func (s *Session) Close()
func (s *Session) Refresh()
func (s *Session) RefreshWithProtocol(protocol string) error
func (s *Session) Warmup(ctx context.Context, url string) error
func (s *Session) Fork(n int) []*Session
```

- `Close()` releases the connection pool and the cookie jar. Always defer this.
- `Refresh()` closes connections but keeps cookies and TLS tickets. Simulates a browser hitting F5.
- `RefreshWithProtocol("h1" | "h2" | "h3" | "auto")` does a refresh and switches the wire protocol for next requests. Useful for warming TLS on H3 then serving H2 with resumption.
- `Warmup(ctx, url)` does a real-browser-style page load: HTML first, then subresources with proper priorities, headers, and timing. Great before hitting an antibot endpoint.
- `Fork(n)` makes `n` child sessions that share cookies and TLS resumption with the parent but have independent connections. Same browser, multiple tabs.

### Persistence

```go
func (s *Session) Save(path string) error
func (s *Session) Marshal() ([]byte, error)
```

`Save` writes a JSON blob containing cookies, TLS session tickets, and ECH configs to disk. `Marshal` returns the same blob as bytes for stuffing into Redis or a database. Round-trip with `LoadSession` / `UnmarshalSession`.

### Cookie management

```go
func (s *Session) GetCookies() []CookieInfo
func (s *Session) GetCookiesDetailed() []CookieInfo
func (s *Session) SetCookie(cookie CookieInfo)
func (s *Session) DeleteCookie(name, domain string)
func (s *Session) ClearCookies()
```

`CookieInfo` is a type alias for `session.CookieState` and carries the full `name`, `value`, `domain`, `path`, `expires`, `maxAge`, `secure`, `httpOnly`, `sameSite` set.

### Proxy management

```go
func (s *Session) SetProxy(proxyURL string)
func (s *Session) SetTCPProxy(proxyURL string)
func (s *Session) SetUDPProxy(proxyURL string)
func (s *Session) GetProxy() string
func (s *Session) GetTCPProxy() string
func (s *Session) GetUDPProxy() string
```

`SetProxy("")` switches the session back to direct. The split TCP/UDP proxies exist for cases where you want H1/H2 over an HTTP proxy and H3 over MASQUE. See [Proxies overview](/proxies/overview).

### Header order

```go
func (s *Session) SetHeaderOrder(order []string)
func (s *Session) GetHeaderOrder() []string
```

Override the preset's header order. Pass lowercase names. Empty slice resets to the preset default.

### Other

```go
func (s *Session) SetSessionIdentifier(sessionId string)
```

Tags this session for distributed TLS cache key isolation when used behind a `LocalProxy`. Most users won't touch this.

## Client methods

`*httpcloak.Client` for one-off requests:

```go
func New(preset string, opts ...Option) *Client
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error)
func (c *Client) Get(ctx context.Context, url string) (*Response, error)
func (c *Client) GetWithHeaders(ctx context.Context, url string, headers map[string][]string) (*Response, error)
func (c *Client) Post(ctx context.Context, url string, body io.Reader, contentType string) (*Response, error)
func (c *Client) PostJSON(ctx context.Context, url string, body []byte) (*Response, error)
func (c *Client) PostForm(ctx context.Context, url string, body []byte) (*Response, error)
func (c *Client) PostMultipart(ctx context.Context, url string, fields []MultipartField) (*Response, error)
func (c *Client) Close()
```

`Client` only takes `WithTimeout` and `WithProxy` as options. If you need more knobs, switch to `Session`.

## Request struct

```go
type Request struct {
	Method  string
	URL     string
	Headers map[string][]string // matches http.Header
	Body    io.Reader
	Timeout time.Duration
	TLSOnly *bool // per-request override
}
```

`Headers` is `map[string][]string` to match the stdlib `http.Header` shape and let you send the same header multiple times. Lowercase the keys to match the preset's order.

`TLSOnly` set to `&true` skips the preset's HTTP headers for this single request (TLS fingerprint still applied). `nil` means use the session's setting.

## Response struct

```go
type Response struct {
	StatusCode int
	Headers    map[string][]string
	Body       io.ReadCloser
	FinalURL   string
	Protocol   string             // "http/1.1", "h2", "h3"
	History    []*RedirectInfo
}
```

Methods:

```go
func (r *Response) Close() error
func (r *Response) Bytes() ([]byte, error)
func (r *Response) Text() (string, error)
func (r *Response) JSON(v interface{}) error
func (r *Response) GetHeader(key string) string
func (r *Response) GetHeaders(key string) []string
```

`Bytes`, `Text`, `JSON` cache the body after the first read. `GetHeader` / `GetHeaders` look up case-insensitively against the lowercase keys.

`History` is the list of intermediate redirects you went through. Each entry has `StatusCode`, `URL`, and `Headers`.

## Idiomatic patterns

### Always defer Close

```go
s := httpcloak.NewSession("chrome-latest")
defer s.Close()
// ...
resp, err := s.Get(ctx, url)
if err != nil { return err }
defer resp.Close()
```

The session owns network resources. The response body is an `io.ReadCloser` you must close.

### Pass context

Always thread a `context.Context` through. It's how cancellation, deadlines, and request-scoped values move around in Go. httpcloak honours `ctx.Done()` everywhere, at dial, at TLS handshake, at body reads.

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
resp, err := s.Get(ctx, url)
```

### Decode JSON straight into a struct

```go
var payload struct {
	UserAgent string `json:"user_agent"`
	IP        string `json:"ip"`
}
if err := resp.JSON(&payload); err != nil {
	return err
}
```

`Response.JSON` reads the body once, caches the bytes, then runs `encoding/json` on them.

### Errors

httpcloak returns plain `error` values. Use `errors.Is` against `context.DeadlineExceeded` or `context.Canceled` to tell timeout errors apart from anything else.

## Concurrency

The session is safe for concurrent use. Internally it holds a `sync.RWMutex` around mutable state (cookies, header order, proxy switches), and the underlying transport pool handles concurrent dials.

What that means in practice:

- One `*Session`, many goroutines making requests at once. Fine.
- One `*Session`, one goroutine calling `SetProxy()` while another calls `Get()`. Also fine: the lock orders them.
- Reading the `Response.Body` from multiple goroutines simultaneously. Don't. Each response is single-reader.

If you want true parallelism with shared cookie state, use `Fork(n)` to get sibling sessions. Each fork has its own connection pool but inherits the parent's cookies and TLS tickets. That's the closest to "browser tabs" behaviour.

## Custom fingerprints

```go
s := httpcloak.NewSession("chrome-latest",
	httpcloak.WithCustomFingerprint(httpcloak.CustomFingerprint{
		JA3:    "771,4865-4866-4867-...,0-23-65281-...,29-23-24,0",
		Akamai: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
	}),
)
```

Setting `JA3` automatically flips the session into TLS-only mode (HTTP headers from the preset get skipped). See [Custom JA3](/fingerprinting/custom-ja3) and [Akamai shorthand](/fingerprinting/akamai-shorthand).

## What about HTTP/3?

The same `Session.Get`, `Session.Do`, etc. The transport picks the protocol via Alt-Svc, ALPN, and a small race between H3 and H2 dials. Force a specific protocol with `WithForceHTTP1`, `WithForceHTTP2`, `WithForceHTTP3`. The `Response.Protocol` field tells you what was actually used.

## See also

- [Options reference](/reference/options): every `SessionOption` flag with a one-line description.
- [Connection lifecycle](/connection-lifecycle): refresh, warmup, fork, save, load.
- [Cookies and state](/cookies-and-state): jar internals and per-request overrides.
- [Proxies](/proxies): HTTP, SOCKS5, MASQUE, source-IP binding.
