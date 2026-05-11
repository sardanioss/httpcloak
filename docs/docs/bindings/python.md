---
title: Python
sidebar_position: 2
---

# Python

The Python binding is a Pythonic wrapper around the cgo shared library. The C ABI underneath is the same one the Node and .NET bindings ride on, but the surface follows the `requests` lib: `Session`, `.get()`, `.post()`, `.json()`, kwargs everywhere, `with`-statements for cleanup. Anyone fluent in `requests` will land in familiar territory.

## Install

```bash
pip install httpcloak
```

The wheel ships the prebuilt shared library for your platform. Linux x86_64 / arm64, macOS x86_64 / arm64, Windows x86_64 are all covered. Python 3.8 and up.

When pip's resolver picks the right wheel, install is one command. On an unusual platform, building from source is the fallback, see the GitHub README for the steps.

## Quick start

```python
import httpcloak

with httpcloak.Session(preset="chrome-146") as s:
    r = s.get("https://tls.peet.ws/api/all")
    print(r.status_code)
    print(r.json()["user_agent"])
```

The `with` block guarantees the session closes cleanly even when an exception fires. Same shape as a `requests.Session()`, with the TLS fingerprint baked in.

## Module-level shortcuts

For one-off requests, top-level functions mirror `requests`:

```python
import httpcloak

r = httpcloak.get("https://tls.peet.ws/api/all")
r = httpcloak.post("https://httpbin.org/post", json={"hello": "world"})
r = httpcloak.put(...)
r = httpcloak.delete(...)
r = httpcloak.patch(...)
r = httpcloak.head(...)
r = httpcloak.options(...)
r = httpcloak.request("GET", url)
```

These all share a hidden default `Session`. To configure that default (preset, headers, proxy, retry, etc.):

```python
httpcloak.configure(
    preset="chrome-146",
    headers={"Authorization": "Bearer xxx"},
    proxy="http://user:pass@proxy:8080",
    retry=3,
)
r = httpcloak.get("https://example.com")  # uses the configured defaults
```

For anything beyond a few requests, use an explicit `Session`. The default-session path is there to make porting `requests`-style scripts quick.

## `Session`

The main class. Constructor signature (kwargs, all optional):

```python
httpcloak.Session(
    preset: str = "chrome-146",
    proxy: Optional[str] = None,
    tcp_proxy: Optional[str] = None,
    udp_proxy: Optional[str] = None,
    timeout: int = 30,
    http_version: str = "auto",       # "auto", "h1", "h2", "h3"
    verify: bool = True,
    allow_redirects: bool = True,
    max_redirects: int = 10,
    retry: int = 0,                    # 0 = retries off
    retry_on_status: Optional[List[int]] = None,
    retry_wait_min: int = 500,
    retry_wait_max: int = 10000,
    prefer_ipv4: bool = False,
    auth: Optional[Tuple[str, str]] = None,
    connect_to: Optional[Dict[str, str]] = None,
    ech_config_domain: Optional[str] = None,
    tls_only: bool = False,
    quic_idle_timeout: int = 0,
    local_address: Optional[str] = None,
    key_log_file: Optional[str] = None,
    enable_speculative_tls: bool = False,
    switch_protocol: Optional[str] = None,
    without_cookie_jar: bool = False,
    ja3: Optional[str] = None,
    akamai: Optional[str] = None,
    extra_fp: Optional[Dict[str, Any]] = None,
    tcp_ttl: Optional[int] = None,
    tcp_mss: Optional[int] = None,
    tcp_window_size: Optional[int] = None,
    tcp_window_scale: Optional[int] = None,
    tcp_df: Optional[bool] = None,
)
```

Full description for each kwarg: [Options reference](/reference/options).

`retry` defaults to `0`. The previous `3` default silently retried POST/PUT/PATCH on 5xx, which broke idempotency expectations. Set it to a positive integer to opt in.

### Request methods

```python
session.get(url, params=None, headers=None, cookies=None, auth=None,
            timeout=None, stream=False, fetch_mode=None) -> Response
session.post(url, data=None, json=None, files=None, params=None,
             headers=None, cookies=None, auth=None, timeout=None,
             stream=False, fetch_mode=None) -> Response
session.put(url, data=None, json=None, ...) -> Response
session.patch(url, data=None, json=None, ...) -> Response
session.delete(url, ...) -> Response
session.head(url, ...) -> Response
session.options(url, ...) -> Response
session.request(method, url, data=None, json=None, ...) -> Response
```

`stream=True` returns a `StreamResponse` instead of a buffered `Response`. `json={...}` JSON-encodes the body and sets `Content-Type: application/json`. `data={...}` does form encoding. `files={...}` does multipart uploads.

### Streaming methods

```python
session.get_stream(url, ...) -> StreamResponse
session.post_stream(url, ...) -> StreamResponse
session.put_stream(url, ...) -> StreamResponse
session.patch_stream(url, ...) -> StreamResponse
session.delete_stream(url, ...) -> StreamResponse
session.request_stream(method, url, ...) -> StreamResponse
```

`StreamResponse` supports `iter_content(chunk_size=8192)`, `iter_lines()`, `content`, `text`, `json()`, and the `with`-block protocol. A 1:1 match for the `requests` streaming API.

```python
with session.get("https://example.com/big.zip", stream=True) as r:
    with open("big.zip", "wb") as f:
        for chunk in r.iter_content(chunk_size=64 * 1024):
            f.write(chunk)
```

### Fast methods

```python
session.get_fast(url, ...) -> FastResponse
session.post_fast(url, ...) -> FastResponse
session.request_fast(method, url, ...) -> FastResponse
session.put_fast(...) / delete_fast(...) / patch_fast(...) -> FastResponse
```

`FastResponse` skips a few allocations and exposes `.content` as a `memoryview` instead of `bytes`. Use it for large bodies that benefit from zero-copy access. Read the docstring before relying on the buffer; it can be reused on later requests, so copy with `bytes(r.content)` to hold onto it past the next call.

### Lifecycle

```python
session.close()
session.refresh(switch_protocol: Optional[str] = None)
session.warmup(url: str, timeout: Optional[int] = None)
session.fork(n: int = 1) -> List[Session]
```

`refresh()` mirrors a browser F5: cookies and TLS tickets stay, connections drop. `switch_protocol="h2"` flips the wire protocol at the same time. `warmup()` simulates a real page load. `fork(n)` returns `n` sibling sessions that share cookies and TLS state while getting their own connection pools.

### Persistence

```python
session.save(path: str)
session.marshal() -> str
Session.load(path: str) -> Session
Session.unmarshal(data: str) -> Session
```

`save` writes a JSON file with cookies, TLS tickets, and ECH configs. `marshal` returns the same blob as a string, ready to drop into Redis or a database. `Session.load` and `Session.unmarshal` are classmethods.

### Cookie management

```python
session.cookies                                # property -> List[Cookie] (delegates to get_cookies)
session.get_cookies() -> List[Cookie]          # full Cookie objects
session.get_cookies_detailed() -> List[Cookie] # alias of get_cookies
session.get_cookie(name) -> Optional[Cookie]   # full Cookie object or None
session.get_cookie_detailed(name) -> Optional[Cookie]  # alias of get_cookie
session.set_cookie(name, value, domain="", path="/", secure=False,
                   http_only=False, same_site="", max_age=0, expires=None)
session.delete_cookie(name, domain="")
session.clear_cookies()
```

`get_cookies` and `get_cookies_detailed` both return the same `List[Cookie]`; same with `get_cookie` and `get_cookie_detailed`. The `session.cookies` property delegates to `get_cookies()` and returns the same `List[Cookie]` value despite the older `Dict[str, str]` type annotation it still carries (the annotation is queued to flip in a future release; the runtime already returns the list). Build the flat name-to-value dict yourself when you need it: `{c.name: c.value for c in session.cookies}`. Each `Cookie` carries `name`, `value`, `domain`, `path`, `expires`, `max_age`, `secure`, `http_only`, `same_site`.

### Proxy management

```python
session.set_proxy(proxy_url: str)
session.set_tcp_proxy(proxy_url: str)
session.set_udp_proxy(proxy_url: str)
session.get_proxy() -> str
session.get_tcp_proxy() -> str
session.get_udp_proxy() -> str
```

Empty string flips back to direct.

### Header order

```python
session.set_header_order(order: List[str])  # lowercase names
session.get_header_order() -> List[str]
```

### Misc

```python
session.set_session_identifier(session_id: str)
session.headers              # dict for default headers, mutate freely
session.auth                 # tuple for default basic auth
```

## Pythonic conventions

- snake_case names everywhere. `get_cookies`, `set_proxy`, `clear_cookies`, never `getCookies`.
- Kwargs over positional past the `url` arg. `session.get("...", headers=..., timeout=...)` reads cleaner than the positional form.
- Context managers. `with httpcloak.Session(...) as s:` and `with session.get(url, stream=True) as r:` both work.
- Exceptions. Errors raise `httpcloak.HTTPCloakError`. `r.raise_for_status()` raises on `>= 400`, same as `requests`.
- `r.json()` parses, `r.text` returns a `str`, `r.content` (and `r.body`) returns `bytes`.

## `Response`

```python
r.status_code: int
r.ok: bool                          # True if status_code < 400
r.reason: str                        # "OK", "Not Found", etc.
r.headers: Dict[str, str]
r.body: bytes
r.content: bytes                     # alias of body
r.text: str
r.encoding: Optional[str]
r.url: str                           # final URL after redirects
r.final_url: str                     # alias
r.protocol: str                      # "http/1.1", "h2", "h3"
r.elapsed: float                     # seconds
r.cookies: List[Cookie]
r.history: List[RedirectInfo]
r.json(**kwargs) -> Any
r.raise_for_status()
```

`raise_for_status()` raises `HTTPCloakError` on 4xx/5xx.

## Concurrency

The session is thread-safe for concurrent requests. The Go transport pool underneath handles parallel dials, and the Python wrapper holds the GIL only briefly when entering the C call.

### Native asyncio

Every sync request method has a `*_async` sibling that returns a coroutine and runs the underlying cgo call through the lib's async callback manager (no thread-pool round-trip). Available on every `Session`:

```python
async def get_async(url, *, params=None, headers=None, cookies=None,
                    auth=None, fetch_mode=None) -> Response: ...
async def post_async(url, *, data=None, json_data=None, files=None,
                     params=None, headers=None, cookies=None,
                     auth=None, fetch_mode=None) -> Response: ...
async def put_async(url, **kw) -> Response: ...
async def delete_async(url, **kw) -> Response: ...
async def patch_async(url, **kw) -> Response: ...
async def head_async(url, **kw) -> Response: ...
async def options_async(url, **kw) -> Response: ...
async def request_async(method: str, url: str, **kw) -> Response: ...
```

`post_async` takes `json_data=` (not `json=`) to avoid shadowing the `json` module. The `*_async` family doesn't accept a per-call `timeout=`; the session-level setting applies to every async call. Per-request `allow_redirects=` and `disable_conditional_cache=` ARE accepted on every `*_async` method (and every sync method); see the section below. The `**kw` in the trailing async methods (`put_async` and friends) forwards to `request_async`, which accepts the same kwarg surface as `post_async`.

### Per-request redirect and cache overrides

Every request method (sync and async, every verb) accepts two extra kwargs:

```python
allow_redirects: Optional[bool] = None        # True/False overrides session default; None defers
disable_conditional_cache: bool = False       # True skips ETag / If-Modified-Since for this call
```

```python
r = s.get(url, allow_redirects=False)                # don't follow 3xx
r = s.post(url, json_data={"x": 1}, disable_conditional_cache=True)
r = await s.put_async(url, allow_redirects=False, disable_conditional_cache=True)
```

Available on `get`, `post`, `put`, `delete`, `patch`, `head`, `options`, `request` and every `*_async` sibling. The session-wide settings stay untouched; the override applies only to that one call.

### Session-level toggles

```python
s = httpcloak.Session(preset="chrome-latest",
                      without_conditional_cache=True)   # ctor: ETag handling off for life

s.set_conditional_cache(False)        # runtime toggle
s.set_conditional_cache(True)
on = s.get_conditional_cache()

s.set_follow_redirects(False)         # runtime redirect policy
s.set_max_redirects(3)
n = s.get_max_redirects()

s.clear_cache()                       # wipe stored ETag / Last-Modified entries
```

See [Conditional Cache](../connection-lifecycle/conditional-cache) for the full design.

Use them directly inside an asyncio event loop:

```python
import asyncio
import httpcloak

async def main():
    with httpcloak.Session(preset="chrome-146") as s:
        results = await asyncio.gather(
            s.get_async("https://example.com"),
            s.get_async("https://example.org"),
            s.get_async("https://httpbin.org/get"),
        )
        for r in results:
            print(r.status_code)

asyncio.run(main())
```

## Custom fingerprints

Pass `ja3=` and / or `akamai=` to the `Session` constructor:

```python
with httpcloak.Session(
    preset="chrome-146",
    ja3="771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    akamai="1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
) as s:
    r = s.get("https://tls.peet.ws/api/all")
```

Setting `ja3` flips the session into TLS-only mode automatically. See [Custom JA3](/fingerprinting/custom-ja3).

## Other building blocks

```python
httpcloak.LocalProxy(...)            # local HTTP proxy that fingerprints any client
httpcloak.PresetPool(path)           # rotate through a JSON-defined preset pool
httpcloak.SessionCacheBackend(...)   # plug a Redis-style backend for distributed TLS resumption
httpcloak.load_preset(path)          # register a JSON preset file
httpcloak.load_preset_from_json(...) # register a JSON preset string
httpcloak.unregister_preset(name)
httpcloak.describe_preset(name)
httpcloak.available_presets()
httpcloak.version()
httpcloak.set_ech_dns_servers([...])
httpcloak.get_ech_dns_servers()
```

`LocalProxy` runs an HTTP proxy server that applies the fingerprint to any HTTP client pointed at it. `PresetPool` and the JSON loaders are covered in [JSON preset builder](/fingerprinting/json-preset-builder). `SessionCacheBackend` plugs into [Session save and restore](/connection-lifecycle/session-save-restore).

## See also

- [Options reference](/reference/options): every kwarg with one line each.
- [Cookies and state](/cookies-and-state).
- [Proxies](/proxies).
