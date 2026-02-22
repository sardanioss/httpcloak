/**
 * Custom JA3 & Akamai Fingerprinting with HttpCloak for C#
 *
 * Override the preset's TLS and HTTP/2 fingerprints with custom JA3 and Akamai
 * strings for fine-grained control over how your connections appear on the wire.
 *
 * What you'll learn:
 * - How to set a custom JA3 TLS fingerprint
 * - How to set a custom Akamai HTTP/2 fingerprint
 * - How to use extra fingerprint options (ALPN, signature algorithms, etc.)
 * - How to combine JA3 + Akamai for full fingerprint control
 * - How to verify your fingerprint against tls.peet.ws
 *
 * Requirements:
 *   dotnet add package HttpCloak
 *
 * Run:
 *   dotnet run
 */

using HttpCloak;
using System.Text.Json;

class CustomFingerprintExamples
{
    // A real Chrome 131 JA3 string (different from the default preset)
    const string Chrome131JA3 =
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172"
        + "-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037,29-23-24,0";

    // A real Chrome Akamai HTTP/2 fingerprint
    const string ChromeAkamai = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";

    static async Task Main(string[] args)
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Custom JA3 & Akamai Fingerprint Examples");
        Console.WriteLine(new string('=', 60));

        await Example1_CustomJA3();
        await Example2_CustomAkamai();
        await Example3_CombinedFingerprint();
        await Example4_ExtraOptions();
        await Example5_PermuteOnly();

        PrintSummary();
    }

    // ============================================================
    // Example 1: Custom JA3 Fingerprint
    // ============================================================
    static async Task Example1_CustomJA3()
    {
        Console.WriteLine("\n[Example 1] Custom JA3 Fingerprint");
        Console.WriteLine(new string('-', 50));

        // TLS-only mode is automatically enabled when JA3 is set
        using var session = new Session(preset: "chrome-145", ja3: Chrome131JA3);

        var response = await session.GetAsync("https://tls.peet.ws/api/tls");
        var json = JsonDocument.Parse(response.Text);

        var ja3Hash = json.RootElement.TryGetProperty("ja3_hash", out var h) ? h.GetString() : "N/A";
        var ja3Text = json.RootElement.TryGetProperty("ja3", out var t) ? t.GetString() : "N/A";
        Console.WriteLine($"JA3 hash: {ja3Hash}");
        Console.WriteLine($"JA3 text: {ja3Text?[..Math.Min(ja3Text.Length, 80)]}...");
        Console.WriteLine("\nThe TLS fingerprint now matches the custom JA3 string,");
        Console.WriteLine("not the chrome-145 preset.");
    }

    // ============================================================
    // Example 2: Custom Akamai HTTP/2 Fingerprint
    // ============================================================
    static async Task Example2_CustomAkamai()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("[Example 2] Custom Akamai HTTP/2 Fingerprint");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(preset: "chrome-145", akamai: ChromeAkamai);

        var response = await session.GetAsync("https://tls.peet.ws/api/all");
        var json = JsonDocument.Parse(response.Text);

        var akamiFp = json.RootElement.GetProperty("http2").TryGetProperty("akamai_fingerprint", out var a)
            ? a.GetString() : "N/A";
        Console.WriteLine($"Akamai fingerprint: {akamiFp}");
        Console.WriteLine($"Expected:           {ChromeAkamai}");
        Console.WriteLine($"Match: {akamiFp == ChromeAkamai}");
    }

    // ============================================================
    // Example 3: JA3 + Akamai Combined
    // ============================================================
    static async Task Example3_CombinedFingerprint()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("[Example 3] Combined JA3 + Akamai");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(
            preset: "chrome-145",
            ja3: Chrome131JA3,
            akamai: ChromeAkamai
        );

        var response = await session.GetAsync("https://tls.peet.ws/api/all");
        var json = JsonDocument.Parse(response.Text);

        var ja3Hash = json.RootElement.GetProperty("tls").TryGetProperty("ja3_hash", out var h)
            ? h.GetString() : "N/A";
        var akamiFp = json.RootElement.GetProperty("http2").TryGetProperty("akamai_fingerprint", out var a)
            ? a.GetString() : "N/A";
        Console.WriteLine($"JA3 hash:    {ja3Hash}");
        Console.WriteLine($"Akamai:      {akamiFp}");
        Console.WriteLine("\nBoth TLS and HTTP/2 fingerprints are fully custom.");
    }

    // ============================================================
    // Example 4: Extra Fingerprint Options
    // ============================================================
    static async Task Example4_ExtraOptions()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("[Example 4] Extra Fingerprint Options");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(
            preset: "chrome-145",
            ja3: Chrome131JA3,
            extraFp: new Dictionary<string, object>
            {
                ["tls_alpn"] = new[] { "h2", "http/1.1" },
                ["tls_cert_compression"] = new[] { "brotli" },
                ["tls_permute_extensions"] = true,
            }
        );

        var response = await session.GetAsync("https://tls.peet.ws/api/tls");
        var json = JsonDocument.Parse(response.Text);

        var ja3Hash = json.RootElement.TryGetProperty("ja3_hash", out var h) ? h.GetString() : "N/A";
        Console.WriteLine($"JA3 hash: {ja3Hash}");
        Console.WriteLine("Extensions are randomly permuted — JA3 hash will vary each run");
        Console.WriteLine("but cipher suites and curves remain the same.");
    }

    // ============================================================
    // Example 5: Permute Extensions Only (no custom JA3)
    // ============================================================
    static async Task Example5_PermuteOnly()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("[Example 5] Permute Extensions Only");
        Console.WriteLine(new string('-', 50));

        using var session = new Session(
            preset: "chrome-145",
            extraFp: new Dictionary<string, object>
            {
                ["tls_permute_extensions"] = true,
            }
        );

        var response = await session.GetAsync("https://tls.peet.ws/api/tls");
        var json = JsonDocument.Parse(response.Text);

        var extensions = json.RootElement.GetProperty("extensions");
        var count = extensions.GetArrayLength();
        Console.WriteLine($"Extension count: {count}");
        Console.WriteLine("Extension order is randomized for each connection.");
    }

    // ============================================================
    // Summary
    // ============================================================
    static void PrintSummary()
    {
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("Summary: Custom Fingerprinting Options");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine(@"
JA3 fingerprint (ja3):
  - Overrides the TLS ClientHello fingerprint
  - Format: TLSVersion,Ciphers,Extensions,Curves,PointFormats
  - Automatically enables TLS-only mode (no preset HTTP headers)

Akamai fingerprint (akamai):
  - Overrides HTTP/2 SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order
  - Format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
  - Works alongside the preset's TLS fingerprint

Extra options (extraFp):
  - tls_alpn: [""h2"", ""http/1.1""]
  - tls_signature_algorithms: [""ecdsa_secp256r1_sha256"", ...]
  - tls_cert_compression: [""brotli"", ""zlib"", ""zstd""]
  - tls_permute_extensions: true/false
  - Can be used standalone or combined with ja3/akamai
");
    }
}
