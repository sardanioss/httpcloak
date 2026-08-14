using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using HttpCloak;

namespace HttpCloak.Tests;

public static class LocalProxyTest
{
    public static async Task RunAsync()
    {
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("C#: Local Proxy Test");
        Console.WriteLine(new string('=', 70));

        // Test 1: Basic proxy startup
        Console.WriteLine("\n--- Test 1: Basic Proxy Startup ---");
        try
        {
            using var proxy = new LocalProxy(port: 0, preset: "chrome-143");
            Console.WriteLine($"Proxy started on port: {proxy.Port}");
            Console.WriteLine($"Proxy URL: {proxy.ProxyUrl}");
            Console.WriteLine($"IsRunning: {proxy.IsRunning}");

            var stats = proxy.GetStats();
            Console.WriteLine($"Stats: running={stats.Running}, preset={stats.Preset}");
            Console.WriteLine("PASS: Proxy started successfully");
        }
        catch (Exception e)
        {
            Console.WriteLine($"FAIL: {e.Message}");
        }

        // Test 2: HTTP request through proxy (plain HTTP)
        Console.WriteLine("\n--- Test 2: HTTP Request Through Proxy ---");
        try
        {
            using var proxy = new LocalProxy(port: 0, preset: "chrome-143");
            Console.WriteLine($"Proxy running on: {proxy.ProxyUrl}");

            using var client = proxy.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(30);

            var response = await client.GetAsync("http://httpbin.org/get");
            Console.WriteLine($"HTTP Status: {response.StatusCode}");

            if (response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Response length: {body.Length} bytes");
                Console.WriteLine("PASS: HTTP request through proxy succeeded");
            }
            else
            {
                Console.WriteLine($"FAIL: HTTP status {response.StatusCode}");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"FAIL: {e.Message}");
        }

        // Test 3: an https:// request must carry the preset, not .NET's own TLS
        Console.WriteLine("\n--- Test 3: HTTPS Keeps The Fingerprint ---");
        try
        {
            using var proxy = new LocalProxy(port: 0, preset: "chrome-143");
            Console.WriteLine($"Proxy running on: {proxy.ProxyUrl}");

            using var client = proxy.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(30);

            var response = await client.GetAsync("https://tls.peet.ws/api/clean");
            Console.WriteLine($"HTTPS Status: {response.StatusCode}");

            var body = await response.Content.ReadAsStringAsync();
            var ja4 = JsonDocument.Parse(body).RootElement.GetProperty("ja4").GetString() ?? "";

            // A .NET handshake reports TLS 1.3 with far fewer extensions and no
            // h2 marker; the preset's reports h2 in the prefix.
            if (response.IsSuccessStatusCode && ja4.Contains("h2"))
            {
                Console.WriteLine($"PASS: https:// carried the preset (ja4={ja4})");
            }
            else
            {
                Console.WriteLine($"FAIL: https:// did NOT carry the preset (ja4={ja4}); " +
                    "the request was probably CONNECT-tunnelled past the proxy");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"FAIL: {e.Message}");
        }

        // Test 4: Multiple concurrent requests
        Console.WriteLine("\n--- Test 4: Concurrent Requests ---");
        try
        {
            using var proxy = new LocalProxy(port: 0, preset: "chrome-143", maxConnections: 100);

            using var client = proxy.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(60);

            var tasks = new Task<HttpResponseMessage>[5];
            for (int i = 0; i < 5; i++)
            {
                tasks[i] = client.GetAsync("http://httpbin.org/get");
            }

            await Task.WhenAll(tasks);

            int successCount = 0;
            foreach (var task in tasks)
            {
                if (task.Result.IsSuccessStatusCode)
                    successCount++;
            }

            Console.WriteLine($"Successful requests: {successCount}/5");

            var stats = proxy.GetStats();
            Console.WriteLine($"Total requests: {stats.TotalRequests}");

            if (successCount == 5)
                Console.WriteLine("PASS: All concurrent requests succeeded");
            else
                Console.WriteLine($"FAIL: Only {successCount}/5 requests succeeded");
        }
        catch (Exception e)
        {
            Console.WriteLine($"FAIL: {e.Message}");
        }

        Console.WriteLine("\n" + new string('=', 70));
        Console.WriteLine("Local Proxy Test Complete");
        Console.WriteLine(new string('=', 70));
    }
}
