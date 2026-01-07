# HttpCloak for .NET

Browser fingerprint emulation HTTP client with HTTP/1.1, HTTP/2, and HTTP/3 support. Bypass bot detection with accurate TLS fingerprints.

## Installation

```bash
dotnet add package HttpCloak
```

## Usage

```csharp
using HttpCloak;

// Create a session with Chrome 143 fingerprint
using var session = new Session(preset: Presets.Chrome143Windows);

// Simple GET request
var response = session.Get("https://example.com");
Console.WriteLine($"Status: {response.StatusCode}");
Console.WriteLine($"Protocol: {response.Protocol}");
Console.WriteLine(response.Text);

// POST with JSON
var data = new { name = "test", value = 123 };
var postResponse = session.PostJson("https://api.example.com/data", data);
Console.WriteLine(postResponse.Json<MyResponseType>());

// Custom headers
var headers = new Dictionary<string, string>
{
    ["Authorization"] = "Bearer token123"
};
var authResponse = session.Get("https://api.example.com/protected", headers);

// Check for errors
response.RaiseForStatus(); // Throws if status >= 400
```

## Configuration Options

```csharp
using var session = new Session(
    preset: Presets.Chrome143Windows,  // Browser fingerprint
    proxy: "http://user:pass@host:8080",  // Optional proxy
    timeout: 30,  // Request timeout in seconds
    httpVersion: "auto",  // "auto", "h1", "h2", "h3"
    verify: true,  // SSL verification
    allowRedirects: true,  // Follow redirects
    maxRedirects: 10,  // Max redirect count
    retry: 3  // Retry on failure
);
```

## Available Presets

- `Presets.Chrome143` - Chrome 143 (auto-detect platform)
- `Presets.Chrome143Windows` - Chrome 143 on Windows
- `Presets.Chrome143Linux` - Chrome 143 on Linux
- `Presets.Chrome143MacOS` - Chrome 143 on macOS
- `Presets.Firefox133` - Firefox 133
- `Presets.Safari18` - Safari 18
- `Presets.IosChrome143` - Chrome on iOS
- `Presets.AndroidChrome143` - Chrome on Android

## Cookie Management

```csharp
// Set a cookie
session.SetCookie("session_id", "abc123");

// Get all cookies
var cookies = session.GetCookies();
foreach (var (name, value) in cookies)
{
    Console.WriteLine($"{name}: {value}");
}
```

## License

MIT
