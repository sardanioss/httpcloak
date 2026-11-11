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
// To see the fix on Windows, compare two libraries from the same tree that
// differ only in the hop, chosen with HTTPCLOAK_LIB_PATH:
//
//   go build -buildmode=c-shared -o hop.dll .                      (as shipped)
//   CGO_CFLAGS=-DHC_NO_EXPORT_HOP go build -buildmode=c-shared -o nohop.dll .
//
// The hop build should finish and print PASS. The no-hop build is expected to
// die partway with exit code -1073741811 (0xC000000D) and nothing printed.
// Elsewhere this only checks the calls stay correct under GC pressure. The
// report was on .NET 9; add -p:TargetFramework=net9.0 to run on it.
//
// Run: dotnet run -c Release -- gcstress [seconds] [threads]
public static class TestGcStress
{
    public static async Task<bool> RunAsync(string[] args)
    {
        int seconds = args.Length > 2 && int.TryParse(args[2], out var s) ? s : 60;
        int threads = args.Length > 3 && int.TryParse(args[3], out var t) ? t : 16;

        // A bare TCP responder rather than HttpListener: HttpListener goes
        // through http.sys on Windows, which refuses a non-elevated process.
        var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        var port = ((IPEndPoint)server.LocalEndpoint).Port;
        var url = $"http://127.0.0.1:{port}/";
        var reply = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok");
        _ = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient c;
                try { c = await server.AcceptTcpClientAsync(); } catch { return; }
                _ = Task.Run(() => Serve(c, reply));
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
        server.Stop();

        bool ok = failures == 0 && calls > 0;
        Console.WriteLine($"gcstress: {calls} calls, {gcs} forced GCs, {failures} failures");
        Console.WriteLine(ok ? "gcstress: PASS" : "gcstress: FAIL");
        return ok;
    }

    // Answers every request on a keep-alive connection with "ok". Requests
    // from the stress loop are GETs with no body, so a request ends at the
    // first blank line.
    private static async Task Serve(TcpClient c, byte[] reply)
    {
        using (c)
        {
            var stream = c.GetStream();
            var buf = new byte[8192];
            int have = 0;
            try
            {
                while (true)
                {
                    int n = await stream.ReadAsync(buf.AsMemory(have));
                    if (n == 0) return;
                    have += n;
                    int end;
                    while ((end = IndexOfHeaderEnd(buf, have)) >= 0)
                    {
                        await stream.WriteAsync(reply);
                        Buffer.BlockCopy(buf, end, buf, 0, have - end);
                        have -= end;
                    }
                    if (have == buf.Length) return; // oversized head; not ours
                }
            }
            catch { }
        }
    }

    private static int IndexOfHeaderEnd(byte[] b, int len)
    {
        for (int i = 3; i < len; i++)
            if (b[i - 3] == '\r' && b[i - 2] == '\n' && b[i - 1] == '\r' && b[i] == '\n') return i + 1;
        return -1;
    }
}
