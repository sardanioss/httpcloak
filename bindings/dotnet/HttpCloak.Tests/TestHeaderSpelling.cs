using System.Net;
using System.Text;
using System.Text.Json;

namespace HttpCloak.Tests;

// Lock for header spellings the caller chose. The transport sends one
// spelling of a header name and prefers the canonical one, so a default the
// binding adds beside a caller's lowercase spelling must not replace the
// caller's value. Local HttpListener only.
//
// Run: dotnet run -- headers
public static class TestHeaderSpelling
{
    public static bool Run()
    {
        var port = FreePort();
        var url = $"http://127.0.0.1:{port}/";
        using var listener = new HttpListener();
        listener.Prefixes.Add(url);
        listener.Start();
        var serving = Task.Run(() =>
        {
            while (listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = listener.GetContext(); } catch { return; }
                var body = JsonSerializer.Serialize(new
                {
                    cookie = ctx.Request.Headers.GetValues("Cookie") ?? Array.Empty<string>(),
                    contentType = ctx.Request.Headers.GetValues("Content-Type") ?? Array.Empty<string>(),
                    authorization = ctx.Request.Headers.GetValues("Authorization") ?? Array.Empty<string>(),
                });
                ctx.Response.Headers.Add("Set-Cookie", "jar=1; Path=/");
                var bytes = Encoding.UTF8.GetBytes(body);
                ctx.Response.ContentType = "application/json";
                ctx.Response.OutputStream.Write(bytes);
                ctx.Response.Close();
            }
        });

        var ok = true;
        static string Vals(Response r, string field) =>
            string.Join(" | ", JsonDocument.Parse(r.Text).RootElement.GetProperty(field).EnumerateArray().Select(e => e.GetString()));
        void Expect(bool cond, string what, string got)
        {
            if (!cond) { ok = false; Console.WriteLine($"FAIL {what}: {got}"); }
        }

        using (var s = new Session(preset: "chrome-latest", httpVersion: "h1"))
        {
            s.Get(url); // the jar now holds jar=1
            for (var i = 0; i < 5; i++)
            {
                var r = s.PostJson(url, new { a = 1 }, headers: new Dictionary<string, string> { { "content-type", "application/vnd.api+json" } });
                var ct = Vals(r, "contentType");
                Expect(ct == "application/vnd.api+json", "PostJson keeps a lowercase content-type", ct);

                r = s.Get(url, headers: new Dictionary<string, string> { { "cookie", "mine=1" } }, cookies: new Dictionary<string, string> { { "c", "3" } });
                var ck = Vals(r, "cookie");
                Expect(ck.Contains("mine=1") && ck.Contains("c=3") && ck.Contains("jar=1"), "lowercase cookie survives a full jar", ck);
            }
            var a = s.Get(url, auth: ("u", "p"), headers: new Dictionary<string, string> { { "authorization", "Bearer mine" } });
            var au = Vals(a, "authorization");
            Expect(au == "Basic dTpw", "auth replaces any authorization spelling", au);

            // auth=, cookies= and json= work on a copy: the caller's own
            // dictionary comes back as it went in.
            var mine = new Dictionary<string, string> { { "authorization", "Bearer mine" }, { "cookie", "mine=1" } };
            s.Get(url, auth: ("u", "p"), headers: mine, cookies: new Dictionary<string, string> { { "c", "3" } });
            s.PostJson(url, new { a = 1 }, headers: mine);
            var left = string.Join(", ", mine.Select(kv => $"{kv.Key}={kv.Value}"));
            Expect(left == "authorization=Bearer mine, cookie=mine=1", "the caller's headers are left alone", left);

            // cookies= joins the caller's lowercase cookie, after it.
            var c = s.Get(url, headers: new Dictionary<string, string> { { "cookie", "mine=1" } }, cookies: new Dictionary<string, string> { { "c", "3" } });
            var cv = Vals(c, "cookie");
            Expect(cv.StartsWith("mine=1; c=3"), "cookies= follows a lowercase cookie", cv);
        }

        listener.Stop();
        serving.Wait(TimeSpan.FromSeconds(5));
        Console.WriteLine(ok ? "headers: PASS" : "headers: FAIL");
        return ok;
    }

    static int FreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
