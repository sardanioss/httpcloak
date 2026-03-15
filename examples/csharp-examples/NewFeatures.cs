/**
 * New Features: Refresh, Local Address Binding, TLS Key Logging
 *
 * This example demonstrates:
 * - Refresh() - simulate browser page refresh (close connections, keep TLS cache)
 * - Local Address Binding - bind to specific local IP (IPv4 or IPv6)
 * - TLS Key Logging - write TLS keys for Wireshark decryption
 */

using System;
using System.IO;
using System.Collections.Generic;
using HttpCloak;

class NewFeatures
{
    const string TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace";

    static Dictionary<string, string> ParseTrace(string body)
    {
        var result = new Dictionary<string, string>();
        foreach (var line in body.Trim().Split('\n'))
        {
            var idx = line.IndexOf('=');
            if (idx != -1)
            {
                result[line.Substring(0, idx)] = line.Substring(idx + 1);
            }
        }
        return result;
    }

    static void Main()
    {
        // ==========================================================
        // Example 1: Refresh (Browser Page Refresh Simulation)
        // ==========================================================
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Example 1: Refresh (Browser Page Refresh)");
        Console.WriteLine(new string('-', 60));

        using (var session = new Session(preset: "chrome-latest", timeout: 30))
        {
            // Make initial request - establishes TLS session
            var resp = session.Get(TEST_URL);
            var trace = ParseTrace(resp.Text);
            trace.TryGetValue("ip", out var ip);
            Console.WriteLine($"First request: Protocol={resp.Protocol}, IP={ip ?? "N/A"}");

            // Simulate browser refresh (F5)
            // This closes TCP/QUIC connections but keeps TLS session cache
            session.Refresh();
            Console.WriteLine("Called Refresh() - connections closed, TLS cache kept");

            // Next request uses TLS resumption (faster handshake)
            resp = session.Get(TEST_URL);
            trace = ParseTrace(resp.Text);
            trace.TryGetValue("ip", out ip);
            Console.WriteLine($"After refresh: Protocol={resp.Protocol}, IP={ip ?? "N/A"} (TLS resumption)");
        }

        // ==========================================================
        // Example 2: TLS Key Logging
        // ==========================================================
        Console.WriteLine();
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Example 2: TLS Key Logging");
        Console.WriteLine(new string('-', 60));

        var keylogPath = "/tmp/csharp_keylog_example.txt";

        // Remove old keylog file
        if (File.Exists(keylogPath))
            File.Delete(keylogPath);

        // Create session with key logging enabled
        using (var session = new Session(
            preset: "chrome-latest",
            timeout: 30,
            keyLogFile: keylogPath))
        {
            // Make request - TLS keys written to file
            var resp = session.Get(TEST_URL);
            Console.WriteLine($"Request completed: Protocol={resp.Protocol}");
        }

        // Check if keylog file was created
        if (File.Exists(keylogPath))
        {
            var info = new FileInfo(keylogPath);
            Console.WriteLine($"Key log file created: {keylogPath} ({info.Length} bytes)");
            Console.WriteLine("Use in Wireshark: Edit -> Preferences -> Protocols -> TLS -> Pre-Master-Secret log filename");
        }
        else
        {
            Console.WriteLine("Key log file not found");
        }

        // ==========================================================
        // Example 3: Local Address Binding
        // ==========================================================
        Console.WriteLine();
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Example 3: Local Address Binding");
        Console.WriteLine(new string('-', 60));

        Console.WriteLine(@"
Local address binding allows you to specify which local IP to use
for outgoing connections. This is essential for IPv6 rotation scenarios.

Usage:

// Bind to specific IPv6 address
using var session = new Session(
    preset: ""chrome-latest"",
    localAddress: ""2001:db8::1""
);

// Bind to specific IPv4 address
using var session = new Session(
    preset: ""chrome-latest"",
    localAddress: ""192.168.1.100""
);

Note: When local address is set, target IPs are filtered to match
the address family (IPv6 local -> only connects to IPv6 targets).

Example with your machine's IPs:
");

        // This is a demonstration - replace with actual local IP
        // Uncomment to test with your real IPv6/IPv4:
        //
        // using var session3 = new Session(
        //     preset: "chrome-latest",
        //     localAddress: "YOUR_LOCAL_IP_HERE",
        //     timeout: 30
        // );
        //
        // var resp3 = session3.Get("https://api.ipify.org");
        // Console.WriteLine($"Server saw IP: {resp3.Text}");

        Console.WriteLine();
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("New features examples completed!");
        Console.WriteLine(new string('=', 60));
    }
}
