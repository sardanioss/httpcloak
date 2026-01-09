// Test ECH with C# bindings
using HttpCloak;

Console.WriteLine("Testing ECH with C# bindings (HTTP/3)...");
Console.WriteLine(new string('=', 50));

using var session = new Session(
    preset: "chrome-143",
    echConfigDomain: "cloudflare-ech.com",
    httpVersion: "h3",
    retry: 0
);

try
{
    var response = session.Get("https://www.cloudflare.com/cdn-cgi/trace");
    Console.WriteLine($"Status: {response.StatusCode}");
    Console.WriteLine($"Protocol: {response.Protocol}");
    Console.WriteLine();
    Console.WriteLine("Response:");
    Console.WriteLine(response.Text);

    // Check for key indicators
    var lines = response.Text.Trim().Split('\n');
    foreach (var line in lines)
    {
        if (line.StartsWith("http="))
        {
            Console.WriteLine($"\n>> HTTP Version: {line}");
        }
        if (line.StartsWith("sni="))
        {
            Console.WriteLine($">> SNI Status: {line}");
            if (line.Contains("encrypted"))
            {
                Console.WriteLine("   SUCCESS: ECH is working!");
            }
            else
            {
                Console.WriteLine("   WARNING: ECH may not be enabled");
            }
        }
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex.Message}");
}
