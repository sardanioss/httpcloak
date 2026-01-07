using HttpCloak;
using System.Text.Json;

Console.WriteLine("=== C# ===");
using var session = new Session(preset: Presets.Chrome143Windows, httpVersion: "h3");
var resp = session.Get("https://quic.browserleaks.com/?minify=1");
var data = JsonDocument.Parse(resp.Text).RootElement;
Console.WriteLine($"ja4: {data.GetProperty("ja4").GetString()}");
Console.WriteLine($"h3_hash: {data.GetProperty("h3_hash").GetString()}");
Console.WriteLine($"h3_text: {data.GetProperty("h3_text").GetString()}");
Console.WriteLine($"ECH: {data.GetProperty("tls").GetProperty("ech").GetProperty("ech_success").GetBoolean()}");
Console.WriteLine($"Protocol: {resp.Protocol}");
