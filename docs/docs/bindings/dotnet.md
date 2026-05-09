---
title: .NET
sidebar_position: 4
---

# .NET

The .NET binding wraps the cgo shared library through P/Invoke. Same C ABI as the Node and Python bindings underneath, surface area styled like .NET: PascalCase, `Async` suffixes for `Task<T>` returns, `IDisposable` for resource cleanup, `using` declarations.

## Install

```bash
dotnet add package HttpCloak
```

The NuGet package ships native binaries for `linux-x64`, `linux-arm64`, `osx-x64`, `osx-arm64`, `win-x64` under the standard `runtimes/` layout. .NET picks the right one based on RID at build time, no extra configuration.

Target frameworks supported: `net6.0`, `net7.0`, `net8.0`, `net9.0`, `net10.0`. Use the latest LTS (`net8.0` at the time of writing) unless you have a reason not to.

## Quick start

```csharp
using HttpCloak;

using var s = new Session(preset: "chrome-146");
var r = await s.GetAsync("https://tls.peet.ws/api/all");
Console.WriteLine($"Status: {r.StatusCode}");
Console.WriteLine($"Protocol: {r.Protocol}");
Console.WriteLine($"Body length: {r.Text.Length}");
```

The `using` declaration disposes the session at the end of the enclosing scope. The session implements `IDisposable` and you should always pair `new Session(...)` with `using`.

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

Use named arguments at call sites. Positional gets messy fast with this many parameters.

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

Common kwargs across all of them: `headers`, `parameters`, `cookies`, `auth`, `timeout`, `cancellationToken`, `fetchMode`. The JSON variants serialize `data` to JSON and add `Content-Type: application/json`.

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

There are also overloads that accept `byte[]` and `Stream` for the body:

```csharp
Response Post(string url, byte[] body, ...);
Response Post(string url, Stream bodyStream, ...);
// Same for Put / Patch
Response RequestBinary(string method, string url, byte[] body, ...);
Response RequestStream(string method, string url, Stream bodyStream, ...);
```

The `Stream` overloads are for streaming uploads where you don't want to materialise the body in memory. Common use: uploading a large file from disk.

### Streaming responses

```csharp
StreamResponse GetStream(string url, ...);
StreamResponse PostStream(string url, string? body = null, ...);
StreamResponse RequestStream(string method, string url, string? body = null, ...);
```

`StreamResponse` exposes a `Stream`-like API and `IDisposable`. Use a `using` block when consuming it.

### Fast path

```csharp
FastResponse GetFast(string url, ...);
FastResponse PostFast(string url, byte[]? body = null, ...);
FastResponse RequestFast(string method, string url, byte[]? body = null, ...);
FastResponse PutFast(string url, byte[]? body = null, ...);
FastResponse DeleteFast(string url, ...);
FastResponse PatchFast(string url, byte[]? body = null, ...);
```

`FastResponse` skips a few allocations and exposes `Body` as a `byte[]` from a pooled buffer. Dispose it (or call `Release()`) when you're done so the buffer returns to the pool.

### Lifecycle

```csharp
void Dispose();                            // also via using
void Refresh(string? switchProtocol = null);
void Warmup(string url, long timeoutMs = 0);
Session[] Fork(int n = 1);
```

`Refresh` keeps cookies and TLS tickets while dropping connections. `Warmup` does a real-browser-style page load. `Fork(n)` returns sibling sessions sharing cookies and TLS state.

### Persistence

```csharp
void Save(string path);
string Marshal();
static Session Load(string path);
static Session Unmarshal(string data);
```

`Marshal` returns a JSON string. Save it to Redis, a database, wherever, then `Unmarshal` to rebuild.

### Cookies

```csharp
List<Cookie> GetCookies();                       // deprecated flat shape
List<Cookie> GetCookiesDetailed();
Cookie? GetCookie(string name);                   // deprecated
Cookie? GetCookieDetailed(string name);
void SetCookie(string name, string value,
               string? domain = null, string? path = null,
               bool secure = false, bool httpOnly = false,
               string? sameSite = null,
               int maxAge = 0, DateTime? expires = null);
void DeleteCookie(string name, string domain = "");
void ClearCookies();
```

The deprecated variants currently return shape-compatible data; they'll switch to the detailed shape in a future major. Migrate to `*Detailed` when convenient.

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
    public Dictionary<string, string> Headers { get; }
    public byte[] Body { get; }
    public string Text { get; }
    public string FinalUrl { get; }
    public string Url { get; }            // alias of FinalUrl
    public string Protocol { get; }       // "http/1.1", "h2", "h3"
    public double Elapsed { get; }        // ms
    public List<Cookie> Cookies { get; }
    public List<RedirectInfo> History { get; }
    public bool Ok { get; }               // true if StatusCode < 400
    public string Reason { get; }
    public string? Encoding { get; }

    public T Json<T>();
    public void RaiseForStatus();
}
```

`Json<T>()` parses the body using `System.Text.Json` with relaxed escaping. `RaiseForStatus()` throws `HttpCloakException` on `>= 400`.

## Conventions

- PascalCase everywhere. `GetCookies`, `SetProxy`, `ClearCookies`.
- `Async` suffix for `Task<T>` returns.
- `CancellationToken` parameter on all `*Async` methods. Use it.
- `IDisposable` on `Session`, `StreamResponse`, `FastResponse`, `LocalProxy`. Pair every `new` with `using`.
- Errors throw `HttpCloakException`.
- Nullable annotations are turned on. `string?` means it can be null, `string` means it can't.

## Concurrency

`Session` is safe for concurrent use. Multiple `Task`s can call request methods on the same session at once, the underlying transport handles parallel dials.

```csharp
using var s = new Session(preset: "chrome-146");
var tasks = urls.Select(u => s.GetAsync(u));
var responses = await Task.WhenAll(tasks);
```

For browser-tab style parallelism with shared cookies, use `Fork(n)`. Each fork has its own connection pool but inherits cookies and TLS resumption tickets from the parent.

## Custom fingerprints

```csharp
using var s = new Session(
    preset: "chrome-146",
    ja3: "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    akamai: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
);
```

Setting `ja3` auto-enables TLS-only mode. See [Custom JA3](/fingerprinting/custom-ja3).

## Other types

```csharp
HttpCloak.LocalProxy
HttpCloak.PresetPool
HttpCloak.SessionCacheBackend
HttpCloak.HttpCloakException
HttpCloak.MultipartFile     // for PostMultipart
HttpCloak.Cookie
HttpCloak.RedirectInfo
HttpCloak.StreamResponse
HttpCloak.FastResponse
```

`LocalProxy` runs a local HTTP proxy server that applies the fingerprint to any HTTP client pointing at it. `PresetPool` and JSON loading are covered in [JSON preset builder](/fingerprinting/json-preset-builder). `SessionCacheBackend` plugs into [Session save and restore](/connection-lifecycle/session-save-restore).

## P/Invoke pitfalls

The native lib is a cgo shared library. A few things to keep in mind:

- The lib is loaded once per process. Loading it from multiple `AppDomain`s is not supported.
- The lib calls back into managed code for the distributed session cache. Pin the delegates as the `SessionCacheBackend` class already does: don't roll your own without reading that source.
- `Native.cs` exposes the raw P/Invoke surface but is internal. You should never need to touch it from app code; the `Session` / `LocalProxy` / `PresetPool` classes wrap everything.

## See also

- [Options reference](/reference/options).
- [Cookies and state](/cookies-and-state).
- [Proxies](/proxies).
