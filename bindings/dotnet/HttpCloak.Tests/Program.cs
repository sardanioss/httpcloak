using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using HttpCloak;
using HttpCloak.Tests;

// Check command line args for which test to run
var cmdArgs = Environment.GetCommandLineArgs();
string testArg = cmdArgs.Length > 1 ? cmdArgs[1] : "";

if (testArg == "handler")
{
    await TestHttpCloakHandler.Run();
    return;
}

if (testArg == "proxy")
{
    await LocalProxyTest.RunAsync();
    return;
}

if (testArg == "headers")
{
    Environment.Exit(TestHeaderSpelling.Run() ? 0 : 1);
}

if (testArg == "cache")
{
    Environment.Exit(await TestSessionCache.RunAsync() ? 0 : 1);
}

if (testArg == "gcstress")
{
    Environment.Exit(await TestGcStress.RunAsync(cmdArgs) ? 0 : 1);
}

Console.WriteLine(new string('=', 70));
Console.WriteLine("C#: Comprehensive Session Test (H3 + 0-RTT)");
Console.WriteLine(new string('=', 70));

// H3 Config Persistence - using browserleaks.com for reliable session resumption
Console.WriteLine("\n--- H3 Session Config Persistence ---");
var sess1 = new Session(preset: "chrome-143", httpVersion: "h3", timeout: 30);
var resp1 = sess1.Get("https://quic.browserleaks.com/?minify=1");
var bl1 = JsonDocument.Parse(resp1.Text);
// Check if quic object exists (indicates H3 was used)
var hasQuic1 = bl1.RootElement.TryGetProperty("quic", out _);
Console.WriteLine($"Session 1: H3={hasQuic1}");

sess1.Save("/tmp/cs_h3.json");
sess1.Dispose();

var saved = JsonDocument.Parse(File.ReadAllText("/tmp/cs_h3.json"));
var version = saved.RootElement.GetProperty("version").GetInt32();
var forceHttp3 = saved.RootElement.GetProperty("config").GetProperty("forceHttp3").GetBoolean();
Console.WriteLine($"Saved: version={version}, forceHttp3={forceHttp3}");

Thread.Sleep(1000);

try
{
    var sess2 = Session.Load("/tmp/cs_h3.json");
    var resp2 = sess2.Get("https://quic.browserleaks.com/?minify=1");
    var bl2 = JsonDocument.Parse(resp2.Text);
    var hasQuic2 = bl2.RootElement.TryGetProperty("quic", out _);
    Console.WriteLine($"Session 2: H3={hasQuic2}");

    if (hasQuic2)
        Console.WriteLine("✓ H3 Config Persistence: PASS");
    else
        Console.WriteLine("✗ H3 Config Persistence: FAIL");
    sess2.Dispose();
}
catch (Exception e)
{
    Console.WriteLine($"Session 2 Error: {e.Message}");
    Console.WriteLine("✗ H3 Config Persistence: FAIL (timeout/connection issue)");
}

// 0-RTT Session Resumption
Console.WriteLine("\n--- 0-RTT Session Resumption ---");
var sess3 = new Session(preset: "chrome-143", httpVersion: "h3", timeout: 60);

Console.WriteLine("\nRequest 1 (Fresh):");
try
{
    var resp3 = sess3.Get("https://quic.browserleaks.com/?minify=1");
    var rtt1 = JsonDocument.Parse(resp3.Text);
    var zeroRtt1 = rtt1.RootElement.GetProperty("quic").GetProperty("0-rtt").GetBoolean();
    var ech1 = rtt1.RootElement.GetProperty("tls").GetProperty("ech").GetProperty("ech_success").GetBoolean();
    Console.WriteLine($"  0-RTT={zeroRtt1}, ECH={ech1}");

    Thread.Sleep(1000);
    sess3.Save("/tmp/cs_0rtt.json");
    sess3.Dispose();
    Thread.Sleep(500);

    Console.WriteLine("\nRequest 2 (Resumed):");
    var sess4 = Session.Load("/tmp/cs_0rtt.json");
    var resp4 = sess4.Get("https://quic.browserleaks.com/?minify=1");
    var rtt2 = JsonDocument.Parse(resp4.Text);
    var zeroRtt2 = rtt2.RootElement.GetProperty("quic").GetProperty("0-rtt").GetBoolean();
    var ech2 = rtt2.RootElement.GetProperty("tls").GetProperty("ech").GetProperty("ech_success").GetBoolean();
    Console.WriteLine($"  0-RTT={zeroRtt2}, ECH={ech2}");

    if (zeroRtt2)
        Console.WriteLine("✓ 0-RTT Session Resumption: PASS");
    else
        Console.WriteLine("✗ 0-RTT Session Resumption: FAIL");
    sess4.Dispose();
}
catch (Exception e)
{
    Console.WriteLine($"  Error: {e.Message}");
}

Console.WriteLine("\n" + new string('=', 70));
Console.WriteLine("C# Test Complete");
Console.WriteLine(new string('=', 70));

// Test fast methods
Console.WriteLine();
TestFastMethods.Run();
