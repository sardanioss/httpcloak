# HTTPCloak C# / .NET

Browser fingerprint emulation HTTP client with HTTP/1.1, HTTP/2, and HTTP/3 support.

## Installation

```bash
dotnet add package HttpCloak
```

Or via NuGet Package Manager:
```
Install-Package HttpCloak
```

## Quick Start

### Basic Usage with Session

```csharp
using HttpCloak;

// Create a session with Chrome fingerprint
using var session = new Session(preset: "chrome-143");

// GET request
var response = session.Get("https://www.cloudflare.com/cdn-cgi/trace");
Console.WriteLine(response.StatusCode);  // 200
Console.WriteLine(response.Text);        // Response body
Console.WriteLine(response.Protocol);    // h2 or h3

// POST request with JSON
var postResponse = session.PostJson("https://api.example.com/data", new { key = "value" });

// Custom headers
var customResponse = session.Get("https://example.com",
    headers: new Dictionary<string, string> { ["X-Custom"] = "value" });
```

### HttpClient Integration (Recommended)

Use `HttpCloakHandler` for seamless integration with existing `HttpClient` code:

```csharp
using HttpCloak;

// Create handler with Chrome fingerprint
using var handler = new HttpCloakHandler(preset: "chrome-143");
using var client = new HttpClient(handler);

// All HttpClient requests now go through httpcloak with TLS fingerprinting
var response = await client.GetAsync("https://example.com");
var content = await response.Content.ReadAsStringAsync();
Console.WriteLine(content);

// POST with JSON
var jsonContent = new StringContent(
    "{\"key\": \"value\"}",
    Encoding.UTF8,
    "application/json");
var postResponse = await client.PostAsync("https://api.example.com/data", jsonContent);

// Works with all HttpClient features
await client.PutAsync(url, content);
await client.DeleteAsync(url);
```

### Streaming Downloads

For large downloads, use streaming to avoid loading entire response into memory:

```csharp
using HttpCloak;

// HttpCloakHandler streams by default (UseStreaming = true)
using var handler = new HttpCloakHandler(preset: "chrome-143");
using var client = new HttpClient(handler);

var response = await client.GetAsync("https://example.com/large-file.zip");

// Read as stream - data is fetched on-demand
using var stream = await response.Content.ReadAsStreamAsync();
using var fileStream = File.Create("downloaded-file.zip");

byte[] buffer = new byte[65536];
int bytesRead;
while ((bytesRead = await stream.ReadAsync(buffer)) > 0)
{
    await fileStream.WriteAsync(buffer, 0, bytesRead);
}

// Or disable streaming for small responses
handler.UseStreaming = false;
var smallResponse = await client.GetAsync("https://api.example.com/data");
var bytes = await smallResponse.Content.ReadAsByteArrayAsync();
```

### Direct Streaming with Session

```csharp
using HttpCloak;

using var session = new Session(preset: "chrome-143");

// Stream response in chunks
using var streamResponse = session.GetStream("https://example.com/large-file");
Console.WriteLine($"Status: {streamResponse.StatusCode}");
Console.WriteLine($"Content-Length: {streamResponse.ContentLength}");

// Option 1: Read chunks directly
foreach (var chunk in streamResponse.ReadChunks(65536))
{
    // Process each chunk
    Console.WriteLine($"Received {chunk.Length} bytes");
}

// Option 2: Use as System.IO.Stream
using var contentStream = streamResponse.GetContentStream();
using var fileStream = File.Create("output.bin");
contentStream.CopyTo(fileStream);
```

### Async Requests

```csharp
using HttpCloak;

using var session = new Session(preset: "chrome-143");

// Async GET
var response = await session.GetAsync("https://example.com");
Console.WriteLine(response.Text);

// Async POST
var postResponse = await session.PostAsync("https://api.example.com/data", "{\"key\":\"value\"}");

// Multiple concurrent requests
var tasks = new[]
{
    session.GetAsync("https://example.com/1"),
    session.GetAsync("https://example.com/2"),
    session.GetAsync("https://example.com/3"),
};
var responses = await Task.WhenAll(tasks);
```

## Proxy Support

HTTPCloak supports HTTP, SOCKS5, and HTTP/3 (MASQUE) proxies with full fingerprint preservation.

### HTTP Proxy

```csharp
using HttpCloak;

// Basic HTTP proxy
using var session = new Session(preset: "chrome-143", proxy: "http://host:port");

// With authentication
using var sessionAuth = new Session(preset: "chrome-143", proxy: "http://user:pass@host:port");

// HTTPS proxy
using var sessionHttps = new Session(preset: "chrome-143", proxy: "https://user:pass@host:port");

// With HttpCloakHandler
using var handler = new HttpCloakHandler(preset: "chrome-143", proxy: "http://user:pass@host:port");
using var client = new HttpClient(handler);
```

### SOCKS5 Proxy

```csharp
using HttpCloak;

// SOCKS5 proxy (with DNS resolution on proxy)
using var session = new Session(preset: "chrome-143", proxy: "socks5h://host:port");

// With authentication
using var sessionAuth = new Session(preset: "chrome-143", proxy: "socks5h://user:pass@host:port");

var response = session.Get("https://www.cloudflare.com/cdn-cgi/trace");
Console.WriteLine(response.Protocol);  // h3 (HTTP/3 through SOCKS5!)
```

### HTTP/3 MASQUE Proxy

MASQUE (RFC 9484) enables HTTP/3 connections through compatible proxies:

```csharp
using HttpCloak;

// MASQUE proxy (auto-detected for known providers like Bright Data)
using var session = new Session(
    preset: "chrome-143",
    proxy: "https://user:pass@brd.superproxy.io:10001"
);

var response = session.Get("https://www.cloudflare.com/cdn-cgi/trace");
Console.WriteLine(response.Protocol);  // h3
```

### Split Proxy Configuration

Use different proxies for TCP (HTTP/1.1, HTTP/2) and UDP (HTTP/3) traffic:

```csharp
using HttpCloak;

using var session = new Session(
    preset: "chrome-143",
    tcpProxy: "http://tcp-proxy:port",      // For HTTP/1.1, HTTP/2
    udpProxy: "https://masque-proxy:port"   // For HTTP/3
);
```

## Advanced Features

### Encrypted Client Hello (ECH)

ECH encrypts the SNI (Server Name Indication) to prevent traffic analysis:

```csharp
using HttpCloak;

// Enable ECH for Cloudflare domains
using var session = new Session(
    preset: "chrome-143",
    echConfigDomain: "cloudflare-ech.com"
);

var response = session.Get("https://www.cloudflare.com/cdn-cgi/trace");
Console.WriteLine(response.Text);
// Output includes: sni=encrypted, http=http/3

// With HttpCloakHandler
using var handler = new HttpCloakHandler(
    preset: "chrome-143",
    echConfigDomain: "cloudflare-ech.com"
);
```

### Domain Fronting (Connect-To)

Connect to one server while requesting a different domain:

```csharp
using HttpCloak;

using var session = new Session(
    preset: "chrome-143",
    connectTo: new Dictionary<string, string>
    {
        ["www.cloudflare.com"] = "example.com"
    }
);

var response = session.Get("https://www.cloudflare.com/cdn-cgi/trace");
```

### Combined: SOCKS5 + ECH

Get HTTP/3 with encrypted SNI through a SOCKS5 proxy:

```csharp
using HttpCloak;

using var session = new Session(
    preset: "chrome-143",
    proxy: "socks5h://user:pass@host:port",
    echConfigDomain: "cloudflare-ech.com"
);

var response = session.Get("https://www.cloudflare.com/cdn-cgi/trace");
// Response shows: http=http/3, sni=encrypted
```

## Cookie Management

```csharp
using HttpCloak;

using var session = new Session();

// Set a cookie
session.SetCookie("session_id", "abc123");

// Get all cookies
var cookies = session.GetCookies();
foreach (var cookie in cookies)
{
    Console.WriteLine($"{cookie.Name}={cookie.Value}");
}

// Delete a cookie
session.DeleteCookie("session_id");

// Clear all cookies
session.ClearCookies();

// Access cookies via HttpCloakHandler
using var handler = new HttpCloakHandler(preset: "chrome-143");
handler.Session.SetCookie("auth_token", "xyz789");
```

## Response Object

### Standard Response

```csharp
var response = session.Get("https://example.com");

response.StatusCode    // int: HTTP status code (200, 404, etc.)
response.Headers       // Dictionary<string, string[]>: Response headers (multi-value)
response.Text          // string: Response body as text
response.Content       // byte[]: Response body as bytes
response.Url           // string: Final URL after redirects
response.Protocol      // string: Protocol used (h2, h3)
response.Ok            // bool: True if status < 400
response.Elapsed       // TimeSpan: Request duration
response.Cookies       // List<Cookie>: Cookies from response
response.History       // List<RedirectInfo>: Redirect history
response.Reason        // string: Status reason phrase

// Get specific header
string? contentType = response.GetHeader("Content-Type");
string[] allCookies = response.GetHeaders("Set-Cookie");

// Deserialize JSON
var data = response.Json<MyClass>();
```

### Streaming Response

```csharp
using var streamResponse = session.GetStream("https://example.com");

streamResponse.StatusCode      // int: HTTP status code
streamResponse.Headers         // Dictionary<string, string[]>: Response headers
streamResponse.ContentLength   // long: Content length (-1 if unknown)
streamResponse.FinalUrl        // string: Final URL after redirects
streamResponse.Protocol        // string: Protocol used

// Read all bytes
byte[] data = streamResponse.ReadAll();

// Read in chunks
foreach (var chunk in streamResponse.ReadChunks(65536))
{
    // Process chunk
}

// Get as Stream
using var stream = streamResponse.GetContentStream();
```

## HttpCloakHandler Options

```csharp
var handler = new HttpCloakHandler(
    preset: "chrome-143",           // Browser fingerprint preset
    proxy: "http://host:port",      // Proxy URL
    tcpProxy: null,                 // Separate TCP proxy
    udpProxy: null,                 // Separate UDP proxy (MASQUE)
    timeout: 30,                    // Request timeout in seconds
    httpVersion: "auto",            // "auto", "h1", "h2", "h3"
    verify: true,                   // SSL certificate verification
    allowRedirects: true,           // Follow redirects
    maxRedirects: 10,               // Maximum redirect count
    retry: 0,                       // Retry count on failure
    preferIpv4: false,              // Prefer IPv4 over IPv6
    echConfigDomain: null           // ECH config domain
);

// Streaming control
handler.UseStreaming = true;  // Default: true (memory efficient for large downloads)

// Access underlying Session
handler.Session.SetCookie("name", "value");
```

## Available Presets

```csharp
using HttpCloak;

var presets = HttpCloakInfo.AvailablePresets();
foreach (var preset in presets)
{
    Console.WriteLine(preset);
}
// chrome-143, chrome-143-windows, chrome-143-linux, chrome-143-macos,
// chrome-131, firefox-133, safari-18, ...
```

## Error Handling

```csharp
using HttpCloak;

try
{
    using var session = new Session();
    var response = session.Get("https://example.com");
}
catch (HttpCloakException ex)
{
    Console.WriteLine($"Request failed: {ex.Message}");
}

// With HttpClient
using var handler = new HttpCloakHandler();
using var client = new HttpClient(handler);

try
{
    var response = await client.GetAsync("https://example.com");
}
catch (HttpRequestException ex)
{
    // HttpCloakException is wrapped in HttpRequestException
    Console.WriteLine($"Request failed: {ex.Message}");
}
```

## Local Proxy

Use `LocalProxy` to apply TLS fingerprinting to any HTTP client transparently.

### HTTPS with True Streaming (Recommended)

For HTTPS requests with full fingerprinting AND true streaming (request/response bodies not materialized into memory), use the `X-HTTPCloak-Scheme` header:

```csharp
using HttpCloak;

// Start local proxy with Chrome fingerprint
using var proxy = new LocalProxy(preset: "chrome-143");
Console.WriteLine($"Proxy running on {proxy.ProxyUrl}");

// Configure HttpClient to use the proxy
var handler = new HttpClientHandler
{
    Proxy = proxy.CreateWebProxy()
};
using var client = new HttpClient(handler);

// Use X-HTTPCloak-Scheme header to get HTTPS with fingerprinting + streaming
var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com/api"); // Note: http://
request.Headers.Add("X-HTTPCloak-Scheme", "https"); // Upgrades to HTTPS with fingerprinting
var response = await client.SendAsync(request);

// This provides:
// - Full TLS fingerprinting (Chrome/Firefox JA3/JA4)
// - HTTP/3 support
// - True streaming (request body NOT materialized into memory)
// - Header modification capabilities
```

**Why use `X-HTTPCloak-Scheme`?**

Standard HTTP proxy clients (like .NET HttpClient) use CONNECT tunneling for HTTPS, which means the proxy can't inspect or modify the request. The `X-HTTPCloak-Scheme: https` header tells LocalProxy to:
1. Accept the request as plain HTTP
2. Upgrade it to HTTPS internally
3. Apply full TLS fingerprinting
4. Stream request/response bodies without memory materialization

### Basic Usage

```csharp
using HttpCloak;

// Start local proxy with Chrome fingerprint
using var proxy = new LocalProxy(preset: "chrome-143");

var handler = new HttpClientHandler
{
    Proxy = proxy.CreateWebProxy()
};
using var client = new HttpClient(handler);

// Standard HTTPS (uses CONNECT tunnel - fingerprinting via upstream proxy only)
var response = await client.GetAsync("https://example.com");

// Per-request upstream proxy rotation via header
var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com");
request.Headers.Add("X-Upstream-Proxy", "http://user:pass@rotating-proxy.com:8080");
var rotatedResponse = await client.SendAsync(request);
```

### TLS-Only Mode

When your client already provides authentic browser headers, use TLS-only mode:

```csharp
using HttpCloak;

// Only apply TLS fingerprint, pass headers through
using var proxy = new LocalProxy(preset: "chrome-143", tlsOnly: true);

var handler = new HttpClientHandler
{
    Proxy = proxy.CreateWebProxy()
};
using var client = new HttpClient(handler);

// Your client's headers are preserved
client.DefaultRequestHeaders.Add("User-Agent", "My Custom UA");
var response = await client.GetAsync("https://example.com");
```

### Session Registry

Route different requests through different browser fingerprints:

```csharp
using HttpCloak;

using var proxy = new LocalProxy(preset: "chrome-143");

// Create sessions with different fingerprints
using var chromeSession = new Session(preset: "chrome-143");
using var firefoxSession = new Session(preset: "firefox-133");

// Register sessions with the proxy
proxy.RegisterSession("chrome-user", chromeSession);
proxy.RegisterSession("firefox-user", firefoxSession);

// Route requests using X-HTTPCloak-Session header
var handler = new HttpClientHandler { Proxy = proxy.CreateWebProxy() };
using var client = new HttpClient(handler);

var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com");
request.Headers.Add("X-HTTPCloak-Session", "firefox-user"); // Uses firefox fingerprint
var response = await client.SendAsync(request);

// Unregister when done
proxy.UnregisterSession("chrome-user");
proxy.UnregisterSession("firefox-user");
```

### LocalProxy Options

```csharp
var proxy = new LocalProxy(
    port: 0,               // Port (0 = auto-select)
    preset: "chrome-143",  // Browser fingerprint
    timeout: 30,           // Request timeout in seconds
    maxConnections: 1000,  // Max concurrent connections
    tcpProxy: null,        // Default upstream TCP proxy
    udpProxy: null,        // Default upstream UDP proxy
    tlsOnly: false         // TLS-only mode
);

proxy.Port;           // Actual port number
proxy.ProxyUrl;       // Full proxy URL (http://localhost:port)
proxy.IsRunning;      // True if proxy is active
proxy.GetStats();     // Returns LocalProxyStats with request/connection counts
proxy.CreateWebProxy();   // Creates System.Net.WebProxy instance
proxy.CreateHandler();    // Creates HttpClientHandler with proxy configured
proxy.Dispose();      // Stop the proxy
```

## Platform Support

- Linux (x64, arm64)
- macOS (x64, arm64)
- Windows (x64, arm64)
- .NET 6.0, 7.0, 8.0, 9.0, 10.0+

## License

MIT
