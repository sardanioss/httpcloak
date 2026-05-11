---
title: Go
sidebar_position: 1
---

# Go

The Go API is the native implementation. Every other binding (Python, Node, .NET) calls into a cgo wrapper around this same code, which makes the Go surface the most direct entry point and usually the fastest. For a project already written in Go, this is the right path. There's no FFI hop, no cross-language JSON marshalling, no native binary to ship alongside the code.

## Install

```bash
go get github.com/sardanioss/httpcloak
```

Module path is `github.com/sardanioss/httpcloak`. Public package name is `httpcloak`.

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

Three things worth flagging:

- `NewSession` takes a preset name string and a variadic list of `SessionOption` values. Full preset catalog at [Presets](/fingerprinting/presets).
- `ctx context.Context` is always the first arg. Cancellation and deadlines come for free that way.
- `defer s.Close()` and `defer resp.Close()`. The session owns connections and a cookie jar. The response body is an `io.ReadCloser` that has to be drained or closed.

## Two API levels

httpcloak exposes two API levels. The session level is the one most callers want.

### `Session` (recommended)

A `Session` is persistent. It holds cookies, TLS resumption tickets, ECH configs, and the connection pool. Use it when the same host gets hit more than once, when cookies matter, or when browser-style refresh and warmup behaviour is needed.

```go
s := httpcloak.NewSession("chrome-latest")
defer s.Close()
```

### `Client` (lower level)

A `Client` is a stateless wrapper for one-off requests. There's no cookie jar. Each `Do()` builds a fresh request through the same transport stack. Reach for this when no state should carry between requests.

```go
c := httpcloak.New("chrome-latest", httpcloak.WithTimeout(15*time.Second))
defer c.Close()

resp, err := c.Get(ctx, "https://example.com")
```

The two surfaces look similar on purpose, but the option types are different: `Option` for `Client`, `SessionOption` for `Session`. They don't mix.

## Session methods

Full method list on `*httpcloak.Session`, top to bottom.

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

The Go session API is intentionally sparser than Python's or Node's. `Get` is the only one-call shortcut. For `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, build a `Request` struct and call `Do`:

```go
req := &httpcloak.Request{
	Method:  "POST",
	URL:     "https://httpbin.org/post",
	Headers: map[string][]string{"Content-Type": {"application/json"}},
	Body:    bytes.NewReader([]byte(`{"hello":"world"}`)),
}
resp, err := s.Do(ctx, req)
```

`DoWithBody` takes the body separately as an `io.Reader`. Use it for streaming uploads where buffering the body upfront isn't an option.

### Streaming responses

```go
func (s *Session) DoStream(ctx context.Context, req *Request) (*StreamResponse, error)
func (s *Session) GetStream(ctx context.Context, url string) (*StreamResponse, error)
func (s *Session) GetStreamWithHeaders(ctx context.Context, url string, headers map[string][]string) (*StreamResponse, error)
```

`StreamResponse` exposes `Read(p []byte) (int, error)`, `ReadChunk(size int) ([]byte, error)`, `ReadAll() ([]byte, error)`, and `Close() error`. `DoStream` is the right call for downloads where buffering the whole body in memory is a bad idea: videos, big JSON dumps, archives.

Streaming won't auto-follow redirects. A 3xx on a stream response has to be handled manually.

### Lifecycle

```go
func (s *Session) Close()
func (s *Session) Refresh()
func (s *Session) RefreshWithProtocol(protocol string) error
func (s *Session) Warmup(ctx context.Context, url string) error
func (s *Session) Fork(n int) []*Session
```

- `Close()` releases the connection pool and the cookie jar. Always defer it.
- `Refresh()` drops connections but keeps cookies and TLS tickets, mirroring a browser F5.
- `RefreshWithProtocol("h1" | "h2" | "h3" | "auto")` does a refresh and switches the wire protocol for following requests. Useful for warming TLS on H3 and then serving H2 with resumption.
- `Warmup(ctx, url)` runs a browser-style page load: HTML first, then subresources with proper priorities, headers, and timing. Pop it before hitting an antibot endpoint.
- `Fork(n)` returns `n` child sessions that share cookies and TLS resumption with the parent but get their own connections. Same browser, multiple tabs.

### Persistence

```go
func (s *Session) Save(path string) error
func (s *Session) Marshal() ([]byte, error)
```

`Save` writes a JSON blob (cookies, TLS session tickets, ECH configs) to disk. `Marshal` returns the same blob as bytes for storage in Redis, a database, or any other byte-shaped backend. Round-trip with `LoadSession` / `UnmarshalSession`.

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

`SetProxy("")` flips the session back to direct. The split TCP/UDP proxy methods exist for the case where H1/H2 needs to go through an HTTP proxy while H3 goes through MASQUE. See [Proxies overview](/proxies/overview).

### Header order

```go
func (s *Session) SetHeaderOrder(order []string)
func (s *Session) GetHeaderOrder() []string
```

Override the preset's header order. Pass lowercase names. Empty slice resets to the preset default.

### Other

```go
func (s *Session) SetSessionIdentifier(sessionId string)
func (s *Session) Stats() session.SessionStats
func (s *Session) IdleTime() time.Duration
func (s *Session) IsActive() bool
func (s *Session) Touch()
func (s *Session) ClearCache()
func (s *Session) GetTransport() *transport.Transport
```

`SetSessionIdentifier` tags this session for distributed TLS cache key isolation when running behind a `LocalProxy`. The other methods are observability and lifecycle helpers covered fully in [Observability](/connection-lifecycle/observability) and [Session Manager](/connection-lifecycle/session-manager).

### Conditional cache and redirect runtime control

```go
func (s *Session) SetConditionalCacheEnabled(enabled bool)
func (s *Session) ConditionalCacheEnabled() bool
func (s *Session) SetFollowRedirects(enabled bool)
func (s *Session) FollowRedirects() bool
func (s *Session) SetMaxRedirects(max int)
func (s *Session) MaxRedirects() int
```

Flip the session's redirect-following policy or its ETag / If-Modified-Since handling at runtime; pair with `ClearCache()` when wiping cached validators too. The `WithoutConditionalCache()` SessionOption disables conditional caching for the whole session at construction time. For per-request control, set `Request.FollowRedirects *bool` and / or `Request.DisableConditionalCache bool` before calling `Do`. See [Conditional Cache](/connection-lifecycle/conditional-cache) for the full design.

### Top-level helpers

```go
func New(preset string, opts ...Option) *Client
func NewSession(preset string, opts ...SessionOption) *Session
func NewManager() *Manager                              // session.Manager re-export
func LoadSession(path string) (*Session, error)
func UnmarshalSession(data []byte) (*Session, error)
func ValidateSessionFile(path string) error             // pre-flight load check
func SetKeyLogWriter(w io.Writer)                       // process-wide TLS keylog sink
func Presets() []string                                 // all registered preset names
```

`Manager` is a type alias for `session.Manager` so callers can declare `var m *httpcloak.Manager` without reaching into the subpackage. See [Session Manager](/connection-lifecycle/session-manager) for the full registry surface.

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

`Client` only takes `WithTimeout` and `WithProxy`. Anything else means switching to `Session`.

### `client.Client` runtime mutators

Both `*httpcloak.Client` and `*httpcloak.Session` are thin wrappers around the lower-level `*client.Client` from the `httpcloak/client` subpackage. That lower client carries a handful of runtime mutators the wrappers don't always re-export. Reach for them when you need to flip something mid-flight without rebuilding the session:

```go
import "github.com/sardanioss/httpcloak/client"

c := client.NewSession("chrome-latest")   // or NewClient for stateless
defer c.Close()

c.SetPreset("firefox-148")                // swap the fingerprint
c.SetTimeout(15 * time.Second)
c.SetForceProtocol(client.ProtocolHTTP3)  // pin to H3 from now on
c.EnableCookies()                         // turn the jar on after the fact
c.DisableCookies()                        // or back off
c.CloseQUICConnections()                  // tear down H3 only, keep H1/H2 pools
c.SetBasicAuth("user", "pass")
c.SetBearerAuth("eyJ...")
c.ClearCookies()                          // wipe the jar
```

`SetForceProtocol` takes a `client.Protocol` value (`ProtocolAuto`, `ProtocolHTTP1`, `ProtocolHTTP2`, `ProtocolHTTP3`). `CloseQUICConnections` is the precise tool for "drop H3 because the network just blocked UDP" without touching the H1/H2 connection pool that's still serving live requests.

`*httpcloak.Session.GetTransport()` returns the lower transport (different from `*client.Client`), and the transport carries its own runtime escape hatches; see [Observability](../connection-lifecycle/observability) for that surface. The `client.Client` ones above are higher in the stack and are the right fit when you want runtime control without dropping into the transport.

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

`Headers` is `map[string][]string` to match the stdlib `http.Header` shape and to allow repeating the same header. Lowercase the keys so they line up with the preset's order.

`TLSOnly` set to `&true` skips the preset's HTTP headers for this single request, while the TLS fingerprint still applies. `nil` falls back to the session's setting.

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

`History` is the list of intermediate redirects the request went through. Each entry has `StatusCode`, `URL`, and `Headers`.

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

The session owns network resources. The response body is an `io.ReadCloser`, so it has to be closed.

### Pass context

Always thread a `context.Context` through. That's how cancellation, deadlines, and request-scoped values move around in Go. httpcloak honours `ctx.Done()` at dial, at TLS handshake, and at body reads.

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

httpcloak returns plain `error` values. `errors.Is` against `context.DeadlineExceeded` or `context.Canceled` separates timeout errors from anything else.

## Concurrency

The session is safe for concurrent use. It holds a `sync.RWMutex` around mutable state (cookies, header order, proxy switches), and the underlying transport pool handles concurrent dials.

In practice:

- One `*Session`, many goroutines making requests at once. Fine.
- One `*Session`, one goroutine calling `SetProxy()` while another calls `Get()`. Also fine, the lock orders them.
- Reading the same `Response.Body` from multiple goroutines at once. Don't. Each response is single-reader.

For true parallelism with shared cookie state, `Fork(n)` returns sibling sessions. Each fork has its own connection pool while inheriting the parent's cookies and TLS tickets. That's the closest equivalent to browser-tab behaviour.

## Custom fingerprints

```go
s := httpcloak.NewSession("chrome-latest",
	httpcloak.WithCustomFingerprint(httpcloak.CustomFingerprint{
		JA3:    "771,4865-4866-4867-...,0-23-65281-...,29-23-24,0",
		Akamai: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
	}),
)
```

Setting `JA3` automatically flips the session into TLS-only mode, so the preset's HTTP headers get skipped. See [Custom JA3](/fingerprinting/custom-ja3) and [Akamai shorthand](/fingerprinting/akamai-shorthand).

## What about HTTP/3?

Same `Session.Get`, `Session.Do`, etc. The transport picks the protocol via Alt-Svc, ALPN, and a small race between H3 and H2 dials. `WithForceHTTP1`, `WithForceHTTP2`, and `WithForceHTTP3` pin a specific one. The `Response.Protocol` field reports what went on the wire.

## See also

- [Options reference](/reference/options): every `SessionOption` flag with a one-line description.
- [Connection lifecycle](/connection-lifecycle): refresh, warmup, fork, save, load.
- [Cookies and state](/cookies-and-state): jar internals and per-request overrides.
- [Proxies](/proxies): HTTP, SOCKS5, MASQUE, source-IP binding.
