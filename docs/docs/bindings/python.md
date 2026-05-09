---
title: Python
sidebar_position: 2
---

# Python

The Python binding is a Pythonic wrapper around the cgo shared library. Same C ABI as the Node and .NET bindings underneath, but the surface area looks like the `requests` library: `Session`, `.get()`, `.post()`, `.json()`, kwargs everywhere, `with`-statements for cleanup.

If you've used `requests`, you'll be at home in five minutes.

## Install

```bash
pip install httpcloak
```

The wheel ships the prebuilt shared library for your platform. Linux x86_64 / arm64, macOS x86_64 / arm64, Windows x86_64 are covered. Python 3.8 and up.

If pip's resolver picks the right wheel you're done. If you're on something unusual you'll need to build from source, see the GitHub README for that.

## Quick start

```python
import httpcloak

with httpcloak.Session(preset="chrome-146") as s:
    r = s.get("https://tls.peet.ws/api/all")
    print(r.status_code)
    print(r.json()["user_agent"])
```

The `with` block makes sure the session closes cleanly even if you raise. Same as a `requests.Session()` but with the TLS fingerprint baked in.

## Module-level shortcuts

For one-off requests there are top-level functions that mirror `requests`:

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

For anything beyond a few requests, use an explicit `Session`. The default-session path exists mainly for porting `requests`-style scripts quickly.

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

`retry` defaults to `0`. The previous `3` default silently retried POST/PUT/PATCH on 5xx, which broke idempotency expectations. Set it explicitly to a positive integer if you want retries.

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

Pass `stream=True` to get a `StreamResponse` instead. Pass `json={...}` and the body is JSON-encoded with `Content-Type: application/json`. Pass `data={...}` for form encoding. Pass `files={...}` for multipart uploads.

### Streaming methods

```python
session.get_stream(url, ...) -> StreamResponse
session.post_stream(url, ...) -> StreamResponse
session.put_stream(url, ...) -> StreamResponse
session.patch_stream(url, ...) -> StreamResponse
session.delete_stream(url, ...) -> StreamResponse
session.request_stream(method, url, ...) -> StreamResponse
```

`StreamResponse` supports `iter_content(chunk_size=8192)`, `iter_lines()`, `content`, `text`, `json()`, and the `with`-block protocol. It's a 1:1 match for `requests`'s streaming API.

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

`FastResponse` skips a few allocations and exposes `.content` as a `memoryview` instead of `bytes`. Use this when you're downloading huge bodies and want zero-copy access. Read the docstring before relying on the buffer, it can be reused on later requests, so copy with `bytes(r.content)` if you need to keep it around.

### Lifecycle

```python
session.close()
session.refresh(switch_protocol: Optional[str] = None)
session.warmup(url: str, timeout: Optional[int] = None)
session.fork(n: int = 1) -> List[Session]
```

`refresh()` mirrors a browser F5, keeps cookies and TLS tickets, drops connections. Pass `switch_protocol="h2"` to also flip to a different wire protocol. `warmup()` simulates a real page load. `fork(n)` returns `n` sibling sessions that share cookies and TLS state but have their own connection pools.

### Persistence

```python
session.save(path: str)
session.marshal() -> str
Session.load(path: str) -> Session
Session.unmarshal(data: str) -> Session
```

`save` writes a JSON file with cookies, TLS tickets, and ECH configs. `marshal` gives you the same blob as a string for storing in Redis or a database. `Session.load` and `Session.unmarshal` are classmethods.

### Cookie management

```python
session.cookies                           # dict (deprecated flat shape)
session.get_cookies() -> Dict[str, str]   # deprecated
session.get_cookies_detailed() -> List[Cookie]
session.get_cookie(name) -> Optional[str]      # deprecated
session.get_cookie_detailed(name) -> Optional[Cookie]
session.set_cookie(name, value, domain="", path="/", secure=False,
                   http_only=False, same_site="", max_age=0, expires=None)
session.delete_cookie(name, domain="")
session.clear_cookies()
```

The `_detailed` variants return full `Cookie` objects with `domain`, `path`, `expires`, `max_age`, `secure`, `http_only`, `same_site`. The flat-dict variants will eventually return the detailed shape too, that's why they're marked deprecated. Migrate when you can.

### Proxy management

```python
session.set_proxy(proxy_url: str)
session.set_tcp_proxy(proxy_url: str)
session.set_udp_proxy(proxy_url: str)
session.get_proxy() -> str
session.get_tcp_proxy() -> str
session.get_udp_proxy() -> str
```

Empty string switches back to direct.

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

- Snake_case names everywhere. `get_cookies`, `set_proxy`, `clear_cookies`, never `getCookies`.
- Kwargs over positional args once you're past `url`. `session.get("...", headers=..., timeout=...)` reads better than positional params.
- Context managers. `with httpcloak.Session(...) as s:` and `with session.get(url, stream=True) as r:` both work.
- Exceptions. Errors raise `httpcloak.HTTPCloakError`. `r.raise_for_status()` raises on `>= 400` status codes, same as `requests`.
- `r.json()` parses, `r.text` gives a `str`, `r.content` (and `r.body`) gives `bytes`.

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

For asyncio: there isn't a native async surface yet on the public API. The library does have an internal async callback manager, but most users run httpcloak in a `concurrent.futures.ThreadPoolExecutor` or `asyncio.to_thread` and that performs fine because the request is mostly waiting on cgo, releasing the GIL.

```python
import asyncio

async def fetch(s, url):
    return await asyncio.to_thread(s.get, url)

async def main():
    with httpcloak.Session(preset="chrome-146") as s:
        results = await asyncio.gather(
            fetch(s, "https://example.com"),
            fetch(s, "https://example.org"),
            fetch(s, "https://httpbin.org/get"),
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

`LocalProxy` runs an HTTP proxy server that applies the fingerprint to any HTTP client pointing at it. `PresetPool` and the JSON loaders are covered in [JSON preset builder](/fingerprinting/json-preset-builder). `SessionCacheBackend` plugs into [Session save and restore](/connection-lifecycle/session-save-restore).

## See also

- [Options reference](/reference/options): every kwarg with one line each.
- [Cookies and state](/cookies-and-state).
- [Proxies](/proxies).
