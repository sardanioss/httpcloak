/**
 * Runtime Proxy Switching
 *
 * This example demonstrates:
 * - Switching proxies mid-session without creating new sessions
 * - Split proxy configuration (different proxies for TCP and UDP)
 * - Getting current proxy configuration
 * - H2 and H3 proxy switching
 */

using HttpCloak;

// Test URL that shows your IP
const string TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace";

Dictionary<string, string> ParseTrace(string body)
{
    var result = new Dictionary<string, string>();
    foreach (var line in body.Trim().Split('\n'))
    {
        var idx = line.IndexOf('=');
        if (idx != -1)
            result[line[..idx]] = line[(idx + 1)..];
    }
    return result;
}

// Basic proxy switching
Console.WriteLine(new string('=', 60));
Console.WriteLine("Example 1: Basic Proxy Switching");
Console.WriteLine(new string('-', 60));

// Create session without proxy (direct connection)
using (var session = new Session(preset: "chrome-latest"))
{
    // Make request with direct connection
    var r = await session.GetAsync(TEST_URL);
    var trace = ParseTrace(r.Text);
    Console.WriteLine("Direct connection:");
    Console.WriteLine($"  Protocol: {r.Protocol}, IP: {trace.GetValueOrDefault("ip", "N/A")}, Colo: {trace.GetValueOrDefault("colo", "N/A")}");

    // Switch to a proxy (replace with your actual proxy)
    // session.SetProxy("http://user:pass@proxy.example.com:8080");
    // r = await session.GetAsync(TEST_URL);
    // trace = ParseTrace(r.Text);
    // Console.WriteLine("\nAfter switching to HTTP proxy:");
    // Console.WriteLine($"  Protocol: {r.Protocol}, IP: {trace.GetValueOrDefault("ip", "N/A")}");

    // Switch back to direct connection
    // session.SetProxy("");
    // Console.WriteLine($"\nSwitched back to direct: {session.GetProxy()}");
}

// Getting current proxy
Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Example 2: Getting Current Proxy Configuration");
Console.WriteLine(new string('-', 60));

using (var session = new Session(preset: "chrome-latest"))
{
    Console.WriteLine($"Initial proxy: '{session.GetProxy()}' (empty = direct)");
    Console.WriteLine($"TCP proxy: '{session.GetTcpProxy()}'");
    Console.WriteLine($"UDP proxy: '{session.GetUdpProxy()}'");

    // Using property accessor
    Console.WriteLine($"Proxy (via property): '{session.Proxy}'");
}

// Split proxy configuration
Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Example 3: Split Proxy Configuration (TCP vs UDP)");
Console.WriteLine(new string('-', 60));

Console.WriteLine(@"
// Use different proxies for HTTP/1.1+HTTP/2 (TCP) and HTTP/3 (UDP):

using var session = new Session(preset: ""chrome-latest"");

// Set TCP proxy for HTTP/1.1 and HTTP/2
session.SetTcpProxy(""http://tcp-proxy.example.com:8080"");

// Set UDP proxy for HTTP/3 (requires SOCKS5 with UDP ASSOCIATE or MASQUE)
session.SetUdpProxy(""socks5://udp-proxy.example.com:1080"");

// Now HTTP/2 requests go through TCP proxy
// and HTTP/3 requests go through UDP proxy

Console.WriteLine($""TCP proxy: {session.GetTcpProxy()}"");
Console.WriteLine($""UDP proxy: {session.GetUdpProxy()}"");
");

// HTTP/3 proxy switching
Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Example 4: HTTP/3 Proxy Switching");
Console.WriteLine(new string('-', 60));

Console.WriteLine(@"
// HTTP/3 requires special proxy support:
// - SOCKS5 with UDP ASSOCIATE (most residential proxies)
// - MASQUE (CONNECT-UDP) - premium providers like Bright Data, Oxylabs

using var session = new Session(preset: ""chrome-latest"", httpVersion: ""h3"");

// Direct H3 connection
var r = await session.GetAsync(""https://example.com"");
Console.WriteLine($""Direct: {r.Protocol}"");

// Switch to SOCKS5 proxy with UDP support
session.SetUdpProxy(""socks5://user:pass@proxy.example.com:1080"");
r = await session.GetAsync(""https://example.com"");
Console.WriteLine($""Via SOCKS5: {r.Protocol}"");

// Switch to MASQUE proxy
session.SetUdpProxy(""https://user:pass@brd.superproxy.io:10001"");
r = await session.GetAsync(""https://example.com"");
Console.WriteLine($""Via MASQUE: {r.Protocol}"");
");

// Proxy rotation pattern
Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Example 5: Proxy Rotation Pattern");
Console.WriteLine(new string('-', 60));

Console.WriteLine(@"
// Rotate through multiple proxies without recreating sessions:

var proxies = new[]
{
    ""http://proxy1.example.com:8080"",
    ""http://proxy2.example.com:8080"",
    ""http://proxy3.example.com:8080"",
};

using var session = new Session(preset: ""chrome-latest"");

for (int i = 0; i < proxies.Length; i++)
{
    session.SetProxy(proxies[i]);
    var r = await session.GetAsync(""https://api.ipify.org"");
    Console.WriteLine($""Request {i + 1} via {proxies[i]}: IP = {r.Text}"");
}
");

// Speculative TLS
Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Example 6: Speculative TLS Optimization");
Console.WriteLine(new string('-', 60));

Console.WriteLine(@"
// Speculative TLS (enabled by default):
// Sends CONNECT + TLS ClientHello together, saving one round-trip (~25% faster).
// If you experience issues with certain proxies, disable it:

using var session = new Session(
    preset: ""chrome-latest"",
    proxy: ""http://user:pass@proxy.example.com:8080"",
    disableSpeculativeTls: true
);
");

Console.WriteLine("\n" + new string('=', 60));
Console.WriteLine("Proxy switching examples completed!");
Console.WriteLine(new string('=', 60));
