/**
 * TLS-Only Mode with HttpCloak for C#
 *
 * TLS-only mode lets you use the browser's TLS fingerprint (JA3/JA4, Peetprint,
 * Akamai) while having full control over HTTP headers.
 *
 * What you'll learn:
 * - What TLS-only mode does vs normal mode
 * - When to use TLS-only mode
 * - How to set custom headers in TLS-only mode
 *
 * Requirements:
 *   dotnet add package HttpCloak
 *
 * Run:
 *   dotnet run
 */

using HttpCloak;
using System.Text.Json;

class TlsOnlyModeExamples
{
    static async Task Main(string[] args)
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("TLS-Only Mode Examples");
        Console.WriteLine(new string('=', 60));

        await Example1_NormalMode();
        await Example2_TlsOnlyMode();
        await Example3_ApiClient();
        await Example4_CompareFingerprintss();

        PrintSummary();
    }

    // ============================================================
    // Example 1: Normal Mode (default behavior)
    // ============================================================
    static async Task Example1_NormalMode()
    {
        Console.WriteLine("\n[Example 1] Normal Mode (preset headers applied)");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: "chrome-latest");

        var response = await session.GetAsync("https://httpbin.org/headers");
        var json = JsonDocument.Parse(response.Text);
        var headers = json.RootElement.GetProperty("headers");

        Console.WriteLine("Headers sent to server:");
        foreach (var prop in headers.EnumerateObject().OrderBy(p => p.Name))
        {
            if (prop.Name.StartsWith("Sec-") || prop.Name.StartsWith("Accept") ||
                prop.Name == "User-Agent" || prop.Name == "Priority" ||
                prop.Name.StartsWith("Upgrade"))
            {
                var value = prop.Value.GetString() ?? "";
                if (value.Length > 60) value = value[..60] + "...";
                Console.WriteLine($"  {prop.Name}: {value}");
            }
        }

        var headerCount = headers.EnumerateObject().Count();
        Console.WriteLine($"\nTotal headers: {headerCount}");
        Console.WriteLine("Note: All Chrome preset headers are automatically included");
    }

    // ============================================================
    // Example 2: TLS-Only Mode (no preset headers)
    // ============================================================
    static async Task Example2_TlsOnlyMode()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("[Example 2] TLS-Only Mode (custom headers only)");
        Console.WriteLine(new string('-', 50));

        // Enable TLS-only mode - only TLS fingerprint, no preset HTTP headers
        using var session = new Session(preset: "chrome-latest", tlsOnly: true);

        // Only our custom headers will be sent
        var response = await session.GetAsync(
            "https://httpbin.org/headers",
            headers: new Dictionary<string, string>
            {
                ["User-Agent"] = "MyBot/1.0",
                ["X-Custom-Header"] = "my-value"
            }
        );

        var json = JsonDocument.Parse(response.Text);
        var headers = json.RootElement.GetProperty("headers");

        Console.WriteLine("Headers sent to server:");
        foreach (var prop in headers.EnumerateObject().OrderBy(p => p.Name))
        {
            Console.WriteLine($"  {prop.Name}: {prop.Value.GetString()}");
        }

        var headerCount = headers.EnumerateObject().Count();
        Console.WriteLine($"\nTotal headers: {headerCount}");
        Console.WriteLine("Note: Only our custom headers + minimal required headers");
    }

    // ============================================================
    // Example 3: TLS-Only for API Clients
    // ============================================================
    static async Task Example3_ApiClient()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("[Example 3] TLS-Only for API Clients");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: "chrome-latest", tlsOnly: true);

        // API-style request with custom headers
        var response = await session.GetAsync(
            "https://httpbin.org/headers",
            headers: new Dictionary<string, string>
            {
                ["Authorization"] = "Bearer my-api-token",
                ["X-API-Key"] = "secret-key-123",
                ["Content-Type"] = "application/json",
                ["Accept"] = "application/json"
            }
        );

        var json = JsonDocument.Parse(response.Text);
        var headers = json.RootElement.GetProperty("headers");

        Console.WriteLine("API request headers:");
        foreach (var prop in headers.EnumerateObject().OrderBy(p => p.Name))
        {
            if (!prop.Name.StartsWith("X-Amzn"))
            {
                Console.WriteLine($"  {prop.Name}: {prop.Value.GetString()}");
            }
        }

        Console.WriteLine("\nNo Sec-Ch-Ua or browser-specific headers leaked!");
    }

    // ============================================================
    // Example 4: Comparing Fingerprints
    // ============================================================
    static async Task Example4_CompareFingerprintss()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("[Example 4] TLS Fingerprint Comparison");
        Console.WriteLine(new string('-', 50));

        // Check TLS fingerprint in normal mode
        using (var session = new Session(preset: "chrome-latest"))
        {
            var response = await session.GetAsync("https://tls.peet.ws/api/all");
            var json = JsonDocument.Parse(response.Text);
            var ja4 = json.RootElement.GetProperty("tls").GetProperty("ja4").GetString();
            Console.WriteLine($"Normal mode JA4:   {ja4}");
        }

        // Check TLS fingerprint in TLS-only mode
        using (var session = new Session(preset: "chrome-latest", tlsOnly: true))
        {
            var response = await session.GetAsync("https://tls.peet.ws/api/all");
            var json = JsonDocument.Parse(response.Text);
            var ja4 = json.RootElement.GetProperty("tls").GetProperty("ja4").GetString();
            Console.WriteLine($"TLS-only mode JA4: {ja4}");
        }

        Console.WriteLine("\nBoth have identical TLS fingerprints!");
    }

    // ============================================================
    // Summary
    // ============================================================
    static void PrintSummary()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("Summary: When to use TLS-Only Mode");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine(@"
Use TLS-only mode when you need:

1. Full control over HTTP headers
   - API clients with specific header requirements
   - Custom User-Agent strings
   - No browser-specific headers (Sec-Ch-Ua, etc.)

2. TLS fingerprint without HTTP fingerprint
   - Pass TLS-based bot detection
   - But use your own HTTP header set

3. Minimal header footprint
   - Only send headers you explicitly set
   - Useful for testing or specific protocols

Normal mode is better when:
- You want to fully mimic a browser
- You need automatic browser headers
- You're accessing websites (not APIs)
");
    }
}
