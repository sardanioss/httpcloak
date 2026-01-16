using System;
using System.IO;
using System.Text.Json;
using HttpCloak;

Console.WriteLine("=== ECH + PSK Session Resumption Tests (C#) ===");

bool allPass = true;

// Test 1: cloudflare.com (no ECH, auto)
Console.WriteLine("\n=== Testing cloudflare_cs (auto) ===");
try
{
    using var session1 = new Session(preset: "chrome-143", httpVersion: "auto");
    var resp1 = session1.Get("https://cloudflare.com/cdn-cgi/trace");
    Console.WriteLine($"Fresh request: Status={resp1.StatusCode}, Protocol={resp1.Protocol}");

    session1.Save("/tmp/session_cloudflare_cs.json");

    using var loaded1 = Session.Load("/tmp/session_cloudflare_cs.json");
    var resp1b = loaded1.Get("https://cloudflare.com/cdn-cgi/trace");
    Console.WriteLine($"Loaded request: Status={resp1b.StatusCode}, Protocol={resp1b.Protocol}");

    File.Delete("/tmp/session_cloudflare_cs.json");
    Console.WriteLine("cloudflare_auto: PASS");
}
catch (Exception e)
{
    Console.WriteLine($"Error: {e.Message}");
    Console.WriteLine("cloudflare_auto: FAIL");
    allPass = false;
}

// Test 2: crypto.cloudflare.com (ECH, H2)
Console.WriteLine("\n=== Testing crypto_cs (auto) ===");
try
{
    using var session2 = new Session(preset: "chrome-143", httpVersion: "auto");
    var resp2 = session2.Get("https://crypto.cloudflare.com/cdn-cgi/trace");
    Console.WriteLine($"Fresh request: Status={resp2.StatusCode}, Protocol={resp2.Protocol}");

    session2.Save("/tmp/session_crypto_cs.json");

    using var loaded2 = Session.Load("/tmp/session_crypto_cs.json");
    var resp2b = loaded2.Get("https://crypto.cloudflare.com/cdn-cgi/trace");
    Console.WriteLine($"Loaded request: Status={resp2b.StatusCode}, Protocol={resp2b.Protocol}");

    File.Delete("/tmp/session_crypto_cs.json");
    Console.WriteLine("crypto_ech_h2: PASS");
}
catch (Exception e)
{
    Console.WriteLine($"Error: {e.Message}");
    Console.WriteLine("crypto_ech_h2: FAIL");
    allPass = false;
}

// Test 3: quic.browserleaks.com (ECH + 0-RTT, H3 forced)
Console.WriteLine("\n=== Testing quic_cs (h3) with ECH + 0-RTT verification ===");
try
{
    var session3 = new Session(preset: "chrome-143", httpVersion: "h3");
    var resp3 = session3.Get("https://quic.browserleaks.com/?minify=1");
    var data3 = JsonDocument.Parse(resp3.Text);
    bool echFirst = data3.RootElement.GetProperty("tls").GetProperty("ech").GetProperty("ech_success").GetBoolean();
    bool zeroRttFirst = data3.RootElement.GetProperty("quic").GetProperty("0-rtt").GetBoolean();
    Console.WriteLine($"Fresh request: ECH={echFirst}, 0-RTT={zeroRttFirst}");

    // Wait for session ticket
    System.Threading.Thread.Sleep(1000);
    session3.Save("/tmp/session_quic_cs.json");
    session3.Dispose();

    // Wait before loading
    System.Threading.Thread.Sleep(500);

    using var loaded3 = Session.Load("/tmp/session_quic_cs.json");
    var resp3b = loaded3.Get("https://quic.browserleaks.com/?minify=1");
    var data3b = JsonDocument.Parse(resp3b.Text);
    bool echSecond = data3b.RootElement.GetProperty("tls").GetProperty("ech").GetProperty("ech_success").GetBoolean();
    bool zeroRttSecond = data3b.RootElement.GetProperty("quic").GetProperty("0-rtt").GetBoolean();
    Console.WriteLine($"Loaded request: ECH={echSecond}, 0-RTT={zeroRttSecond}");

    File.Delete("/tmp/session_quic_cs.json");

    if (echSecond && zeroRttSecond)
    {
        Console.WriteLine("quic_ech_h3_0rtt: PASS");
    }
    else
    {
        Console.WriteLine("quic_ech_h3_0rtt: FAIL (0-RTT not achieved)");
        allPass = false;
    }
}
catch (Exception e)
{
    Console.WriteLine($"Error: {e.Message}");
    Console.WriteLine("quic_ech_h3_0rtt: FAIL");
    allPass = false;
}

Console.WriteLine("\n=== Summary ===");
Console.WriteLine(allPass ? "ALL TESTS PASSED!" : "SOME TESTS FAILED!");
