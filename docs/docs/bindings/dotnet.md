---
title: .NET
sidebar_position: 4
---

# .NET

The .NET binding wraps the cgo shared library through P/Invoke. The C ABI underneath is the same one Node and Python ride on, while the surface follows .NET conventions: PascalCase names, `Async` suffixes on `Task<T>` returns, `IDisposable` for resource cleanup, `using` declarations for scope-bound disposal.

## Install

```bash
dotnet add package HttpCloak
```

The NuGet package ships native binaries for `linux-x64`, `linux-arm64`, `osx-x64`, `osx-arm64`, `win-x64` under the standard `runtimes/` layout. .NET picks the right one based on RID at build time, with no extra configuration needed.

Target frameworks: `net6.0`, `net7.0`, `net8.0`, `net9.0`, `net10.0`. The latest LTS (`net8.0` at the time of writing) is the default choice unless something specific blocks it.

## Quick start

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-146");
var r = await s.GetAsync("https://tls.peet.ws/api/all");
Console.WriteLine($"Status: {r.StatusCode}");
Console.WriteLine($"Protocol: {r.Protocol}");
Console.WriteLine($"Body length: {r.Text.Length}");
```

The `using` declaration disposes the session when the enclosing scope ends. `Session` implements `IDisposable`, so every `new Session(...)` should pair with a `using`.

## `Session`

Constructor signature (named arguments are the way):

```csharp
public Session(
    string preset = "chrome-146",
    string? proxy = null,
    string? tcpProxy = null,
    string? udpProxy = null,
    int timeout = 30,
    string httpVersion = "auto",
    bool verify = true,
    bool allowRedirects = true,
    int maxRedirects = 10,
    int retry = 0,
    int[]? retryOnStatus = null,
    int retryWaitMin = 500,
    int retryWaitMax = 10000,
    bool preferIpv4 = false,
    (string Username, string Password)? auth = null,
    Dictionary<string, string>? connectTo = null,
    string? echConfigDomain = null,
    bool tlsOnly = false,
    int quicIdleTimeout = 0,
    string? localAddress = null,
    string? keyLogFile = null,
    bool enableSpeculativeTls = false,
    string? switchProtocol = null,
    bool withoutCookieJar = false,
    string? ja3 = null,
    string? akamai = null,
    Dictionary<string, object>? extraFp = null,
    int? tcpTtl = null,
    int? tcpMss = null,
    int? tcpWindowSize = null,
    int? tcpWindowScale = null,
    bool? tcpDf = null
)
```

Use named arguments at call sites. Positional form gets messy fast with this many parameters.

Full description per option: [Options reference](/reference/options).

### Async request methods (recommended)

All return `Task<Response>` and accept `CancellationToken`:

```csharp
Task<Response> GetAsync(string url, ..., CancellationToken cancellationToken = default, ...);
Task<Response> PostAsync(string url, string? body = null, ...);
Task<Response> PostJsonAsync<T>(string url, T data, ...);
Task<Response> PostFormAsync(string url, Dictionary<string, string> formData, ...);
Task<Response> PutAsync(string url, string? body = null, ...);
Task<Response> PutJsonAsync<T>(string url, T data, ...);
Task<Response> PatchAsync(string url, string? body = null, ...);
Task<Response> PatchJsonAsync<T>(string url, T data, ...);
Task<Response> DeleteAsync(string url, ...);
Task<Response> HeadAsync(string url, ...);
Task<Response> OptionsAsync(string url, ...);
Task<Response> RequestAsync(string method, string url, string? body = null, ...);
```

Common kwargs across all of them: `headers`, `parameters`, `cookies`, `auth`, `timeout`, `cancellationToken`, `fetchMode`. The JSON variants serialise `data` to JSON and add `Content-Type: application/json`.

```csharp
var r = await s.PostJsonAsync("https://httpbin.org/post", new { hello = "world" });
```

### Sync variants

```csharp
Response Get(string url, ...);
Response Post(string url, string? body = null, ...);
Response PostJson<T>(string url, T data, ...);
Response PostForm(string url, Dictionary<string, string> formData, ...);
Response PostMultipart(string url, ...);
Response Put(string url, string? body = null, ...);
Response PutJson<T>(string url, T data, ...);
Response Patch(string url, string? body = null, ...);
Response PatchJson<T>(string url, T data, ...);
Response Delete(string url, ...);
Response Head(string url, ...);
Response Options(string url, ...);
Response Request(string method, string url, string? body = null, ...);
```

There are also overloads that take `byte[]` and `Stream` for the body:

```csharp
Response Post(string url, byte[] body, ...);
Response Post(string url, Stream bodyStream, ...);
// Same for Put / Patch
Response RequestBinary(string method, string url, byte[] body, ...);
Response RequestStream(string method, string url, Stream bodyStream, ...);
```

The `Stream` overloads cover streaming uploads where the body shouldn't get materialised in memory. The common case is uploading a big file from disk.

### Streaming responses

```csharp
StreamResponse GetStream(string url, ...);
StreamResponse PostStream(string url, string? body = null, ...);
StreamResponse RequestStream(string method, string url, string? body = null, ...);
```

`StreamResponse` exposes a `Stream`-like API and implements `IDisposable`. Wrap it in a `using` block at the consumption site.

### Fast path

```csharp
FastResponse GetFast(string url, Dictionary<string, string>? headers = null);
FastResponse PostFast(string url, byte[]? body = null, Dictionary<string, string>? headers = null, string? contentType = null);
FastResponse RequestFast(string method, string url, byte[]? body = null, Dictionary<string, string>? headers = null, string? contentType = null, int? timeout = null);
FastResponse PutFast(string url, byte[]? body = null, Dictionary<string, string>? headers = null, string? contentType = null, int? timeout = null);
FastResponse DeleteFast(string url, Dictionary<string, string>? headers = null, int? timeout = null);
FastResponse PatchFast(string url, byte[]? body = null, Dictionary<string, string>? headers = null, string? contentType = null, int? timeout = null);
```

`GetFast` and `PostFast` don't accept a `timeout` parameter; they use the session-level default. `RequestFast`, `PutFast`, `DeleteFast`, and `PatchFast` do take an optional per-call `timeout` (seconds).

`FastResponse` skips a few allocations and exposes `Content` as a `byte[]` that's already been copied out of the pooled native buffer at the C boundary. There's no `Release()` method and no `IDisposable` to pair with `using`; the `byte[]` is GC-managed like any other .NET array. The class is a value-shaped record you read and let the garbage collector recycle.

### Lifecycle

```csharp
void Dispose();                            // also via using
void Refresh(string? switchProtocol = null);
void Warmup(string url, long timeoutMs = 0);
Session[] Fork(int n = 1);
```

`Refresh` keeps cookies and TLS tickets while dropping connections. `Warmup` runs a browser-style page load. `Fork(n)` returns sibling sessions sharing cookies and TLS state.

### Per-request redirect and cache overrides

Every `Get/Post/Put/Delete/Patch/Head/Options/Request` (and the binary / Stream / Json variants) and every `*Async` sibling takes two optional kwargs:

```csharp
bool? allowRedirects = null;            // true/false overrides session default; null defers
bool disableConditionalCache = false;   // true skips ETag / If-Modified-Since for this call
```

```csharp
var r = session.Get(url, allowRedirects: false);
var r2 = session.PostJson(url, new { x = 1 }, disableConditionalCache: true);
var r3 = await session.PutAsync(url, body, allowRedirects: false, disableConditionalCache: true);
```

The session-wide settings stay untouched; the override applies only to that one call.

### Session-level toggles

```csharp
using var s = new Session(preset: "chrome-latest", withoutConditionalCache: true);

s.SetConditionalCache(false);
s.SetConditionalCache(true);
bool on = s.GetConditionalCache();

s.SetFollowRedirects(false);
s.SetMaxRedirects(3);
int n = s.GetMaxRedirects();

s.ClearCache();
```

See [Conditional Cache](../connection-lifecycle/conditional-cache) for the full design.

### Persistence

```csharp
void Save(string path);
string Marshal();
static Session Load(string path);
static Session Unmarshal(string data);
```

`Marshal` returns a JSON string. Save it to Redis, a database, or any string-shaped store, then call `Unmarshal` to rebuild.

### Cookies

```csharp
List<Cookie> GetCookies();                        // full Cookie objects
List<Cookie> GetCookiesDetailed();                // alias of GetCookies
Cookie? GetCookie(string name);                   // full Cookie or null
Cookie? GetCookieDetailed(string name);           // alias of GetCookie
void SetCookie(string name, string value,
               string? domain = null, string? path = null,
               bool secure = false, bool httpOnly = false,
               string? sameSite = null,
               long maxAge = 0, string? expires = null);
void DeleteCookie(string name, string domain = "");
void ClearCookies();
```

`GetCookies` and `GetCookiesDetailed` both return the same `List<Cookie>`; same with `GetCookie` and `GetCookieDetailed`. The `expires` parameter on `SetCookie` is the cookie's `Expires` attribute serialized as an RFC 1123 string (e.g. `"Wed, 21 Oct 2026 07:28:00 GMT"`), not a `DateTime`.

### Proxy management

```csharp
void SetProxy(string? proxyUrl);
void SetTcpProxy(string? proxyUrl);
void SetUdpProxy(string? proxyUrl);
string GetProxy();
string GetTcpProxy();
string GetUdpProxy();

string Proxy { get; set; }   // also a property
```

Pass `null` or empty string to disable.

### Header order

```csharp
void SetHeaderOrder(string[]? order);   // null/empty resets to preset default
string[] GetHeaderOrder();
```

Lowercase names.

### Misc

```csharp
void SetSessionIdentifier(string? sessionId);
public (string Username, string Password)? Auth { get; set; }   // default for all requests
```

## `Response`

```csharp
public sealed class Response
{
    public int StatusCode { get; }
    public Dictionary<string, string[]> Headers { get; }   // multi-value, matches HTTP wire shape
    public byte[] Content { get; }
    public string Text { get; }
    public string Url { get; }
    public string Protocol { get; }       // "http/1.1", "h2", "h3"
    public TimeSpan Elapsed { get; }
    public List<Cookie> Cookies { get; }
    public List<RedirectInfo> History { get; }
    public bool Ok { get; }               // true if StatusCode < 400
    public string Reason { get; }
    public string? Encoding { get; }

    public string? GetHeader(string name);          // first value, case-insensitive
    public string[] GetHeaders(string name);        // all values, case-insensitive
    public T? Json<T>();
    public void RaiseForStatus();
}
```

`Content` holds the raw response bytes; `Text` is the decoded string. `Elapsed` is a `TimeSpan` (use `.TotalMilliseconds` if you need a `double` in ms). `Json<T>()` parses `Text` with `System.Text.Json` default options and throws `JsonException` on malformed input or empty body; wrap it in a `try/catch` if you want to treat parse failures as `null` instead of an exception. `RaiseForStatus()` throws `HttpCloakException` on `>= 400`. `FastResponse` exposes the same property surface plus a smaller fast-path constructor and is documented as a separate type in [Reference: FastResponse](#fast-path).

## Conventions

- PascalCase everywhere. `GetCookies`, `SetProxy`, `ClearCookies`.
- `Async` suffix on `Task<T>` returns.
- `CancellationToken` parameter on all `*Async` methods. Wire it up at the call site.
- `IDisposable` on `Session`, `StreamResponse`, `LocalProxy`, and `PresetPool`. Pair every `new` with `using`. `FastResponse` does NOT implement `IDisposable` (its content is a copied `byte[]`, no native handle to release).
- Errors throw `HttpCloakException`.
- Nullable annotations are on. `string?` allows null, `string` doesn't.

## Concurrency

`Session` is safe for concurrent use. Multiple `Task`s can call request methods on the same session at once, and the underlying transport handles parallel dials.

```csharp
using var s = new Session(preset: "chrome-146");
var tasks = urls.Select(u => s.GetAsync(u));
var responses = await Task.WhenAll(tasks);
```

For browser-tab-style parallelism with shared cookies, use `Fork(n)`. Each fork gets its own connection pool while inheriting cookies and TLS resumption tickets from the parent.

## Custom fingerprints

```csharp
using var s = new Session(
    preset: "chrome-146",
    ja3: "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    akamai: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
);
```

Setting `ja3` auto-enables TLS-only mode. See [Custom JA3](/fingerprinting/custom-ja3).

## `HttpCloakHandler`: drop into `HttpClient`

For codebases already wired around `HttpClient`, `HttpCloakHandler` is the .NET-idiomatic way to graft httpcloak's TLS fingerprinting onto the existing pipeline. It's a `DelegatingHandler` subclass that runs an internal `LocalProxy` and routes outbound requests through it, so the surrounding code keeps using `HttpClient`, redirects, cookies, and decompression as normal:

```csharp
using HttpCloak;

using var handler = new HttpCloakHandler(preset: "chrome-latest");
using var client = new HttpClient(handler);

var response = await client.GetAsync("https://example.com");
var body = await response.Content.ReadAsStringAsync();
```

Constructor signatures:

```csharp
new HttpCloakHandler(
    string preset = "chrome-146",
    string? proxy = null,
    string? tcpProxy = null,
    string? udpProxy = null,
    int timeout = 30,
    int maxConnections = 1000);

new HttpCloakHandler(LocalProxy existingProxy);
```

The first form spins up its own `LocalProxy` and disposes it with the handler. The second form takes an existing `LocalProxy` and leaves disposal to the caller (so multiple handlers can share one proxy). `handler.Proxy`, `handler.ProxyUrl`, and `handler.GetStats()` reach the underlying proxy for diagnostics.

For a `LocalProxy` you already own (configured with custom registered sessions, etc.), the same proxy hands out a `WebProxy` directly:

```csharp
using var proxy = new LocalProxy(port: 0, preset: "chrome-latest");
using var client = new HttpClient(new HttpClientHandler {
    Proxy = proxy.CreateWebProxy(),
    UseProxy = true,
});
```

`LocalProxy.CreateWebProxy()` returns a `System.Net.WebProxy`, and `LocalProxy.CreateHandler()` returns a fully-wired `HttpClientHandler` (proxy plus `UseProxy = true`). Pick whichever fits the call site you're integrating with.

## ECH DNS server overrides

```csharp
HttpCloak.HttpCloakInfo.SetEchDnsServers(new[] { "1.1.1.1:53", "8.8.8.8:53" });
string[] current = HttpCloak.HttpCloakInfo.GetEchDnsServers();
HttpCloak.HttpCloakInfo.SetEchDnsServers(null);   // reset to defaults
```

Process-wide setting; affects every session and every ECH HTTPS RR query the binary makes. Use it when the system resolver doesn't return ECH HTTPS RR (corporate DNS, captive portals).

## Other types

```csharp
HttpCloak.LocalProxy
HttpCloak.PresetPool
HttpCloak.HttpCloakException
HttpCloak.MultipartFile     // for PostMultipart
HttpCloak.Cookie
HttpCloak.RedirectInfo
HttpCloak.StreamResponse
HttpCloak.FastResponse
HttpCloak.HttpCloakHandler  // DelegatingHandler for HttpClient integration
HttpCloak.HttpCloakInfo     // version, AvailablePresets, SetEchDnsServers, GetEchDnsServers
HttpCloak.CustomPresets     // Describe / LoadFromJson / LoadFromFile / Unregister
HttpCloak.Presets           // PascalCase string constants (Presets.Chrome146, Presets.Firefox133, ...)
```

The `Presets` static class lags the registry by a release or two; the constants currently top out at `Presets.Chrome146` and the family of older PascalCase names. Newer presets land as plain string literals first (`new Session(preset: "chrome-148-windows")`) and get a typed constant in a follow-up. `HttpCloakInfo.AvailablePresets()` returns a `Dictionary<string, PresetInfo>` keyed by the canonical preset name (use `.ContainsKey("chrome-148")` to probe).

`SessionCacheBackend` is Python and Node only; the .NET binding doesn't ship a managed wrapper today. The C entry points exist in `libhttpcloak`, so a future binding update can fold it in. Until then, the in-memory per-session ticket cache works as expected and only the cross-process distributed-cache use case isn't reachable from .NET.

`LocalProxy` runs a local HTTP proxy server that applies the fingerprint to any HTTP client pointed at it. `PresetPool` and JSON loading are covered in [JSON preset builder](/fingerprinting/json-preset-builder). `SessionCacheBackend` plugs into [Session save and restore](/connection-lifecycle/session-save-restore).

## P/Invoke pitfalls

The native lib is a cgo shared library. A few things to keep in mind:

- The lib loads once per process. Loading it from multiple `AppDomain`s isn't supported.
- The lib calls back into managed code for the distributed session cache. Pin the delegates the way `SessionCacheBackend` already does, instead of rolling a custom version without reading that source.
- `Native.cs` exposes the raw P/Invoke surface but is internal. App code should never need to touch it; the `Session` / `LocalProxy` / `PresetPool` classes wrap everything.

## See also

- [Options reference](/reference/options).
- [Cookies and state](/cookies-and-state).
- [Proxies](/proxies).
