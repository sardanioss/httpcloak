using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace HttpCloak.Tests;

// Stress for #147. .NET suspends its threads for GC with special user APCs.
// When one landed on a .NET thread that was inside the library, running Go on
// a goroutine stack, Windows ended the process with 0xC000000D and no managed
// exception. This keeps many threads inside the library at once (synchronous
// GETs, session create/free, version) and the async path busy, while another
// thread forces garbage collections back to back.
//
// A build with the fix finishes and prints PASS. A build without it is
// expected to die partway, with the process exit code 0xC000000D
// (-1073741811) and nothing printed. Windows only shows the crash; elsewhere
// this just checks the calls stay correct under GC pressure.
//
// Run: dotnet run -c Release -- gcstress [seconds] [threads]
public static class TestGcStress
{
    public static async Task<bool> RunAsync(string[] args)
    {
        int seconds = args.Length > 2 && int.TryParse(args[2], out var s) ? s : 60;
        int threads = args.Length > 3 && int.TryParse(args[3], out var t) ? t : 16;

        var port = FreePort();
        var url = $"http://127.0.0.1:{port}/";
        using var listener = new HttpListener();
        listener.Prefixes.Add(url);
        listener.Start();
        var body = Encoding.ASCII.GetBytes("ok");
        _ = Task.Run(() =>
        {
            while (listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = listener.GetContext(); } catch { return; }
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    try
                    {
                        ctx.Response.ContentLength64 = body.Length;
                        ctx.Response.OutputStream.Write(body);
                        ctx.Response.Close();
                    }
                    catch { }
                });
            }
        });

        Console.WriteLine($"gcstress: {threads} threads for {seconds}s against {url}");
        var stop = DateTime.UtcNow.AddSeconds(seconds);
        long calls = 0, failures = 0, gcs = 0;

        var gcThread = new Thread(() =>
        {
            while (DateTime.UtcNow < stop)
            {
                GC.Collect(2, GCCollectionMode.Forced, blocking: true);
                GC.WaitForPendingFinalizers();
                Interlocked.Increment(ref gcs);
            }
        }) { IsBackground = true };
        gcThread.Start();

        var workers = new List<Thread>();
        for (int i = 0; i < threads; i++)
        {
            int id = i;
            var w = new Thread(() =>
            {
                using var shared = new Session(preset: "chrome-latest", httpVersion: "h1", timeout: 30);
                while (DateTime.UtcNow < stop)
                {
                    try
                    {
                        switch (id % 3)
                        {
                            case 0:
                                if (shared.Get(url).StatusCode != 200) Interlocked.Increment(ref failures);
                                break;
                            case 1:
                                using (var fresh = new Session(preset: "chrome-latest", httpVersion: "h1", timeout: 30))
                                {
                                    if (fresh.Get(url).StatusCode != 200) Interlocked.Increment(ref failures);
                                }
                                break;
                            default:
                                if (string.IsNullOrEmpty(HttpCloakInfo.Version())) Interlocked.Increment(ref failures);
                                _ = new byte[64 * 1024]; // keep the GC busy too
                                break;
                        }
                    }
                    catch (Exception e)
                    {
                        Interlocked.Increment(ref failures);
                        Console.WriteLine($"  thread {id}: {e.GetType().Name}: {e.Message}");
                    }
                    Interlocked.Increment(ref calls);
                }
            }) { IsBackground = true };
            workers.Add(w);
            w.Start();
        }

        // The async path at the same time: completions arrive on library threads.
        using (var asyncSession = new Session(preset: "chrome-latest", httpVersion: "h1", timeout: 30))
        {
            while (DateTime.UtcNow < stop)
            {
                var batch = Enumerable.Range(0, 8).Select(_ => asyncSession.GetAsync(url)).ToArray();
                try
                {
                    foreach (var r in await Task.WhenAll(batch))
                        if (r.StatusCode != 200) Interlocked.Increment(ref failures);
                }
                catch (Exception e)
                {
                    Interlocked.Increment(ref failures);
                    Console.WriteLine($"  async: {e.GetType().Name}: {e.Message}");
                }
                Interlocked.Add(ref calls, batch.Length);
            }
        }

        foreach (var w in workers) w.Join();
        gcThread.Join();
        listener.Stop();

        bool ok = failures == 0 && calls > 0;
        Console.WriteLine($"gcstress: {calls} calls, {gcs} forced GCs, {failures} failures");
        Console.WriteLine(ok ? "gcstress: PASS" : "gcstress: FAIL");
        return ok;
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}
