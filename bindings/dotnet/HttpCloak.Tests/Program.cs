using HttpCloak;

Console.WriteLine("HttpCloak .NET Test");
Console.WriteLine("===================\n");

// Test version
Console.WriteLine($"Version: {HttpCloakInfo.Version()}");
Console.WriteLine($"Available presets: {string.Join(", ", HttpCloakInfo.AvailablePresets())}\n");

// Create session
Console.WriteLine("Creating session with chrome-143-windows preset...");
using var session = new Session(preset: Presets.Chrome143Windows);

// Test 1: Basic GET request
Console.WriteLine("\n=== Test 1: GET https://httpbin.org/headers ===");
var resp1 = session.Get("https://httpbin.org/headers");
Console.WriteLine($"Status: {resp1.StatusCode} | Protocol: {resp1.Protocol}");

// Parse the headers to check Cache-Control is NOT sent
var headersResponse = resp1.Json<HeadersResponse>();
Console.WriteLine("\nHeaders sent:");
foreach (var (key, value) in headersResponse?.Headers ?? new())
{
    Console.WriteLine($"  {key}: {value}");
}

// Check Cache-Control
if (headersResponse?.Headers?.ContainsKey("Cache-Control") == true)
{
    Console.WriteLine("\n❌ ERROR: Cache-Control header IS being sent!");
}
else
{
    Console.WriteLine("\n✓ SUCCESS: Cache-Control header is NOT sent");
}

// Test 2: Cloudflare trace
Console.WriteLine("\n=== Test 2: GET https://www.cloudflare.com/cdn-cgi/trace ===");
var resp2 = session.Get("https://www.cloudflare.com/cdn-cgi/trace");
Console.WriteLine($"Status: {resp2.StatusCode} | Protocol: {resp2.Protocol}");
Console.WriteLine($"Response preview: {resp2.Text[..Math.Min(200, resp2.Text.Length)]}...");

// Test 3: POST request
Console.WriteLine("\n=== Test 3: POST https://httpbin.org/post ===");
var resp3 = session.Post("https://httpbin.org/post", "test data", new Dictionary<string, string>
{
    ["Content-Type"] = "text/plain"
});
Console.WriteLine($"Status: {resp3.StatusCode} | Protocol: {resp3.Protocol}");

// Test 4: Cookies
Console.WriteLine("\n=== Test 4: Cookie Management ===");
session.SetCookie("test_cookie", "test_value");
var cookies = session.GetCookies();
Console.WriteLine($"Cookies set: {cookies.Count}");

Console.WriteLine("\n=== All tests completed! ===");

// Response types for JSON parsing
record HeadersResponse(Dictionary<string, string>? Headers);
