/**
 * Local Proxy for Transparent HttpClient Integration
 *
 * This example shows how to use httpcloak's LocalProxy feature to enable
 * TLS fingerprinting with standard .NET HttpClient - no FFI limitations!
 *
 * What you'll learn:
 * - Starting a local proxy server
 * - Using HttpClient with the proxy
 * - True streaming uploads/downloads
 * - Working with third-party libraries
 * - Why a plain proxy handler is NOT enough for https:// URLs
 *
 * Why use LocalProxy?
 * - Works with ANY HttpClient-based code (including third-party libs)
 * - True streaming - request/response bodies are never buffered in memory
 * - High performance (~3GB/s throughput on localhost)
 * - Simple integration - one call to build the client
 *
 * READ THIS FIRST
 * Build your client with proxy.CreateClient(). Pointing a plain
 * HttpClientHandler at the proxy URL is not enough: for an https:// URI through
 * a proxy, HttpClient sends CONNECT and then does its OWN TLS handshake end to
 * end, so the target sees .NET's fingerprint and the proxy only forwards bytes
 * it cannot read. CreateClient rewrites https:// to http:// plus a scheme
 * header, which keeps the fingerprinted handshake on the proxy side.
 *
 * Requirements:
 *   dotnet add package HttpCloak
 *
 * Run:
 *   dotnet run
 */

using HttpCloak;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

class LocalProxyExamples
{
    static async Task Main(string[] args)
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("HttpCloak Local Proxy Examples");
        Console.WriteLine(new string('=', 60));

        await Example1_BasicUsage();
        await Example2_WithExistingHttpClient();
        await Example3_PostWithLargeBody();
        await Example4_ConcurrentRequests();
        await Example5_VerifyFingerprint();
        await Example6_ProxyWithConfiguration();
        await Example7_MonitoringStats();
        await Example8_ThirdPartyLibraryIntegration();

        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("All examples completed!");
        Console.WriteLine(new string('=', 60));
    }

    // ============================================================
    // Example 1: Basic Usage
    // ============================================================
    static async Task Example1_BasicUsage()
    {
        Console.WriteLine("\n[Example 1] Basic Usage");
        Console.WriteLine(new string('-', 50));

        // Start a local proxy with Chrome fingerprint
        using var proxy = new LocalProxy(preset: "chrome-latest");
        Console.WriteLine($"Proxy started on port: {proxy.Port}");

        // Build the client. CreateClient, NOT new HttpClient(CreateHandler()):
        // the latter tunnels https:// past the proxy and applies no fingerprint.
        using var client = proxy.CreateClient();

        // Make requests - they go through httpcloak with fingerprinting
        var response = await client.GetAsync("https://httpbin.org/get");
        Console.WriteLine($"Status: {response.StatusCode}");

        var body = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Response length: {body.Length} bytes");
    }

    // ============================================================
    // Example 2: Bringing Your Own Handler
    // ============================================================
    static async Task Example2_WithExistingHttpClient()
    {
        Console.WriteLine("\n[Example 2] Bringing Your Own Handler");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest");

        // Need cookies, credentials, or any other handler setting? Hand your
        // handler over and it gets wired to the proxy for you, with the https://
        // rewrite still in place.
        //
        // What NOT to do:
        //     new HttpClient(new HttpClientHandler {
        //         Proxy = new WebProxy(proxy.ProxyUrl), UseProxy = true })
        // That compiles, runs, and returns real responses, and every https://
        // request in it carries .NET's fingerprint rather than the preset's.
        using var client = proxy.CreateClient(new HttpClientHandler
        {
            UseCookies = true,
            AutomaticDecompression = DecompressionMethods.All
        });

        var response = await client.GetAsync("https://httpbin.org/headers");
        Console.WriteLine($"Status: {response.StatusCode}");
    }

    // ============================================================
    // Example 3: POST with Large Body (True Streaming)
    // ============================================================
    static async Task Example3_PostWithLargeBody()
    {
        Console.WriteLine("\n[Example 3] POST with Large Body (True Streaming)");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest");
        using var client = proxy.CreateClient();
        client.Timeout = TimeSpan.FromMinutes(5);

        // Create 1MB of data
        var data = new byte[1024 * 1024];
        Random.Shared.NextBytes(data);

        Console.WriteLine("Uploading 1MB of data...");
        var content = new ByteArrayContent(data);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        var response = await client.PostAsync("https://httpbin.org/post", content);
        Console.WriteLine($"Upload status: {response.StatusCode}");

        // The body streams through TCP - never buffered in memory by FFI
    }

    // ============================================================
    // Example 4: Concurrent Requests
    // ============================================================
    static async Task Example4_ConcurrentRequests()
    {
        Console.WriteLine("\n[Example 4] Concurrent Requests");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest", maxConnections: 100);
        using var client = proxy.CreateClient();

        // Fire 10 concurrent requests
        var tasks = Enumerable.Range(1, 10)
            .Select(i => client.GetAsync($"https://httpbin.org/get?id={i}"))
            .ToArray();

        var responses = await Task.WhenAll(tasks);
        var successCount = responses.Count(r => r.IsSuccessStatusCode);

        Console.WriteLine($"Completed: {successCount}/10 successful");

        // Check proxy stats
        var stats = proxy.GetStats();
        Console.WriteLine($"Total requests processed: {stats.TotalRequests}");
    }

    // ============================================================
    // Example 5: Proving the Fingerprint Is Actually Applied
    // ============================================================
    static async Task Example5_VerifyFingerprint()
    {
        Console.WriteLine("\n[Example 5] Proving the Fingerprint Is Actually Applied");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest");

        try
        {
            // The right way. The proxy performs the TLS handshake, so the target
            // sees the preset.
            using var good = proxy.CreateClient();
            var applied = await good.GetStringAsync("https://tls.peet.ws/api/clean");
            Console.WriteLine($"Through CreateClient : {Ja4Of(applied)}");

            // The trap. CONNECT means HttpClient does its own TLS end to end and
            // the proxy never sees the handshake, so the target reads .NET.
            using var bare = new HttpClient(proxy.CreateHandler());
            var bypassed = await bare.GetStringAsync("https://tls.peet.ws/api/clean");
            Console.WriteLine($"Through CreateHandler: {Ja4Of(bypassed)}");

            // Compare the cipher-list segment rather than the whole JA4. The
            // first hash is over the cipher suites, which do not move; the last
            // is over the extensions, and that one legitimately changes once the
            // connection starts resuming TLS sessions, as a real browser does.
            Console.WriteLine(CipherPartOf(applied) == CipherPartOf(bypassed)
                ? "Same cipher list - something is wrong, these should differ"
                : "Different cipher lists, as expected: only the first one is fingerprinted");
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine($"Could not reach the fingerprint reflector, skipping: {e.Message}");
        }
    }

    static string Ja4Of(string json)
    {
        var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty("ja4", out var v) ? v.GetString() ?? "?" : "?";
    }

    // JA4 is "<prefix>_<ciphers>_<extensions>"; take the middle field.
    static string CipherPartOf(string json)
    {
        var parts = Ja4Of(json).Split('_');
        return parts.Length > 1 ? parts[1] : "?";
    }

    // ============================================================
    // Example 6: Proxy with Configuration
    // ============================================================
    static async Task Example6_ProxyWithConfiguration()
    {
        Console.WriteLine("\n[Example 6] Proxy with Configuration");
        Console.WriteLine(new string('-', 50));

        // Full configuration options
        using var proxy = new LocalProxy(
            port: 0,              // 0 = auto-select available port
            preset: "chrome-latest", // Browser fingerprint
            timeout: 60,          // Request timeout in seconds
            maxConnections: 500   // Max concurrent connections
            // tcpProxy: "socks5://user:pass@proxy.example.com:1080"  // Optional upstream proxy
        );

        Console.WriteLine($"Proxy URL: {proxy.ProxyUrl}");
        Console.WriteLine($"Running: {proxy.IsRunning}");

        using var client = proxy.CreateClient();

        var response = await client.GetAsync("https://httpbin.org/ip");
        var ip = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Your IP: {ip.Trim()}");
    }

    // ============================================================
    // Example 7: Monitoring Stats
    // ============================================================
    static async Task Example7_MonitoringStats()
    {
        Console.WriteLine("\n[Example 7] Monitoring Stats");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest");
        using var client = proxy.CreateClient();

        // Make some requests
        for (int i = 0; i < 5; i++)
        {
            await client.GetAsync("https://httpbin.org/get");
        }

        // Check stats
        var stats = proxy.GetStats();
        Console.WriteLine($"Running: {stats.Running}");
        Console.WriteLine($"Port: {stats.Port}");
        Console.WriteLine($"Preset: {stats.Preset}");
        Console.WriteLine($"Active Connections: {stats.ActiveConnections}");
        Console.WriteLine($"Total Requests: {stats.TotalRequests}");
        Console.WriteLine($"Max Connections: {stats.MaxConnections}");
    }

    // ============================================================
    // Example 8: Third-Party Library Integration
    // ============================================================
    static async Task Example8_ThirdPartyLibraryIntegration()
    {
        Console.WriteLine("\n[Example 8] Third-Party Library Integration");
        Console.WriteLine(new string('-', 50));

        using var proxy = new LocalProxy(preset: "chrome-latest");

        // Many third-party libraries accept HttpClient or IHttpClientFactory
        // You can configure them to use your proxy-enabled client

        using var client = proxy.CreateClient();

        // If the library wants a handler rather than a client, hand it the
        // fingerprinting one:
        //     services.AddHttpClient("api")
        //         .ConfigurePrimaryHttpMessageHandler(() => proxy.CreateFingerprintHandler());

        // Example: Using with a REST API client
        client.BaseAddress = new Uri("https://httpbin.org");
        client.DefaultRequestHeaders.Accept.Add(
            new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

        var response = await client.GetAsync("/json");
        var json = await response.Content.ReadAsStringAsync();

        var doc = JsonDocument.Parse(json);
        Console.WriteLine($"Slideshow title: {doc.RootElement.GetProperty("slideshow").GetProperty("title").GetString()}");

        // This works with:
        // - RestSharp (pass HttpClient)
        // - Refit (pass HttpClient)
        // - Flurl (configure HttpClientFactory)
        // - Any library that uses HttpClient internally
        Console.WriteLine("Works with RestSharp, Refit, Flurl, and more!");
    }
}
