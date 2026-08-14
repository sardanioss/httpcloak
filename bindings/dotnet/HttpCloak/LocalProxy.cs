using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HttpCloak;

/// <summary>
/// A local HTTP proxy server that forwards requests through httpcloak with TLS fingerprinting.
/// Use this with C# HttpClient to transparently apply fingerprinting to all requests.
/// </summary>
/// <example>
/// <code>
/// // Start local proxy
/// using var proxy = new LocalProxy(preset: "chrome-latest");
///
/// // Build a client that routes through the proxy WITH fingerprinting.
/// var client = proxy.CreateClient();
///
/// var response = await client.GetAsync("https://example.com");
///
/// // Note: pointing a plain HttpClientHandler at the proxy is NOT enough for
/// // https:// URLs. See CreateHandler.
/// </code>
/// </example>
public sealed class LocalProxy : IDisposable
{
    private readonly long _handle;
    private bool _disposed;

    /// <summary>
    /// Creates and starts a local HTTP proxy with the specified configuration.
    /// </summary>
    /// <param name="port">Port to listen on (0 = auto-select)</param>
    /// <param name="preset">Browser fingerprint preset (default: chrome-146)</param>
    /// <param name="timeout">Request timeout in seconds (default: 30)</param>
    /// <param name="maxConnections">Maximum concurrent connections (default: 1000)</param>
    /// <param name="tcpProxy">Upstream TCP proxy URL (optional)</param>
    /// <param name="udpProxy">Upstream UDP proxy URL (optional)</param>
    /// <param name="tlsOnly">TLS-only mode: skip preset HTTP headers, only apply TLS fingerprint (default: false)</param>
    public LocalProxy(
        int port = 0,
        string preset = "chrome-146",
        int timeout = 30,
        int maxConnections = 1000,
        string? tcpProxy = null,
        string? udpProxy = null,
        bool tlsOnly = false)
    {
        var config = new LocalProxyConfig
        {
            Port = port,
            Preset = preset,
            Timeout = timeout,
            MaxConnections = maxConnections,
            TcpProxy = tcpProxy,
            UdpProxy = udpProxy,
            TlsOnly = tlsOnly
        };

        string configJson = JsonSerializer.Serialize(config, LocalProxyJsonContext.Default.LocalProxyConfig);
        _handle = Native.LocalProxyStart(configJson);

        if (_handle < 0)
        {
            throw new HttpCloakException("Failed to start local proxy");
        }
    }

    /// <summary>
    /// Gets the port the proxy is listening on.
    /// </summary>
    public int Port
    {
        get
        {
            ThrowIfDisposed();
            return Native.LocalProxyGetPort(_handle);
        }
    }

    /// <summary>
    /// Gets whether the proxy is currently running.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the proxy has been disposed.</exception>
    public bool IsRunning
    {
        get
        {
            ThrowIfDisposed();
            return Native.LocalProxyIsRunning(_handle) != 0;
        }
    }

    /// <summary>
    /// Gets the proxy URL for use with HttpClient.
    /// </summary>
    public string ProxyUrl
    {
        get
        {
            ThrowIfDisposed();
            return $"http://localhost:{Port}";
        }
    }

    /// <summary>
    /// Creates a WebProxy instance configured to use this local proxy.
    /// </summary>
    public WebProxy CreateWebProxy()
    {
        ThrowIfDisposed();
        return new WebProxy(ProxyUrl);
    }

    /// <summary>
    /// Creates an HttpClientHandler pointed at this local proxy.
    /// </summary>
    /// <remarks>
    /// This alone does NOT fingerprint https:// requests. For an https:// URI
    /// through a proxy, HttpClient issues CONNECT and then performs its own TLS
    /// handshake end to end, so the target sees .NET's TLS and header
    /// fingerprint rather than the browser preset - the proxy only forwards
    /// bytes it cannot see. That is the same trap as issue #79.
    ///
    /// Use <see cref="CreateClient"/> instead, which rewrites https:// to
    /// http:// plus a scheme header so the proxy performs the fingerprinted TLS
    /// itself. This method remains for callers who only send http:// URLs or who
    /// are wiring the rewrite themselves.
    /// </remarks>
    public HttpClientHandler CreateHandler()
    {
        ThrowIfDisposed();
        return new HttpClientHandler
        {
            Proxy = CreateWebProxy(),
            UseProxy = true
        };
    }

    /// <summary>
    /// Creates an HttpClient that routes through this proxy AND actually applies
    /// the browser fingerprint to https:// requests.
    /// </summary>
    /// <remarks>
    /// Prefer this over <see cref="CreateHandler"/>. See that method for why a
    /// bare proxy handler silently bypasses fingerprinting on https://.
    ///
    /// Pass your own handler if you need cookies, credentials, automatic
    /// decompression or any other HttpClientHandler setting; its proxy fields
    /// are pointed at this proxy for you.
    /// </remarks>
    public HttpClient CreateClient(HttpClientHandler? inner = null)
    {
        return new HttpClient(CreateFingerprintHandler(inner));
    }

    /// <summary>
    /// Wraps a handler so https:// requests through this proxy keep the browser
    /// fingerprint. Use this when something else owns the HttpClient, such as
    /// IHttpClientFactory or a library that takes a HttpMessageHandler.
    /// </summary>
    /// <param name="inner">
    /// Your handler, or null for a fresh one. Either way its Proxy and UseProxy
    /// are set to this proxy, so you do not have to wire those yourself.
    /// </param>
    public HttpMessageHandler CreateFingerprintHandler(HttpClientHandler? inner = null)
    {
        ThrowIfDisposed();

        var handler = inner ?? new HttpClientHandler();
        handler.Proxy = CreateWebProxy();
        handler.UseProxy = true;

        return new FingerprintRoutingHandler(handler);
    }

    /// <summary>
    /// Rewrites https:// to http:// plus a scheme header so the local proxy
    /// performs the TLS handshake with the browser fingerprint, instead of
    /// HttpClient CONNECT-tunnelling past it and doing its own.
    ///
    /// The localhost hop is plaintext; the fingerprinted TLS runs between the
    /// proxy and the target.
    /// </summary>
    private sealed class FingerprintRoutingHandler : DelegatingHandler
    {
        private const string SchemeHeader = "X-HTTPCloak-Scheme";

        public FingerprintRoutingHandler(HttpMessageHandler inner) : base(inner) { }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri;
            if (uri != null && uri.Scheme == Uri.UriSchemeHttps)
            {
                var builder = new UriBuilder(uri) { Scheme = Uri.UriSchemeHttp };
                // Drop the port when it was the https default so the proxy's
                // upgrade yields a clean https://host; keep an explicit one.
                if (uri.IsDefaultPort)
                    builder.Port = -1;
                request.RequestUri = builder.Uri;

                if (!request.Headers.Contains(SchemeHeader))
                    request.Headers.Add(SchemeHeader, "https");
            }
            return base.SendAsync(request, cancellationToken);
        }
    }

    /// <summary>
    /// Gets proxy statistics.
    /// </summary>
    public LocalProxyStats GetStats()
    {
        ThrowIfDisposed();

        IntPtr ptr = Native.LocalProxyGetStats(_handle);
        string? json = Native.PtrToStringAndFree(ptr);

        if (string.IsNullOrEmpty(json))
        {
            return new LocalProxyStats();
        }

        // Check for error
        if (json.Contains("\"error\""))
        {
            return new LocalProxyStats();
        }

        try
        {
            return JsonSerializer.Deserialize(json, LocalProxyJsonContext.Default.LocalProxyStats)
                ?? new LocalProxyStats();
        }
        catch
        {
            return new LocalProxyStats();
        }
    }

    /// <summary>
    /// Registers a session with the proxy for per-request routing.
    /// Clients can use the X-HTTPCloak-Session header to select which session to use.
    /// </summary>
    /// <param name="sessionId">Unique identifier for this session</param>
    /// <param name="session">The session to register</param>
    /// <exception cref="ArgumentNullException">If session is null</exception>
    /// <exception cref="HttpCloakException">If sessionId already exists</exception>
    /// <example>
    /// <code>
    /// var proxy = new LocalProxy(preset: "chrome-latest");
    /// var session1 = new Session(preset: "chrome-latest");
    /// var session2 = new Session(preset: "firefox-133");
    ///
    /// proxy.RegisterSession("user-1", session1);
    /// proxy.RegisterSession("user-2", session2);
    ///
    /// // Clients use: X-HTTPCloak-Session: user-1 to route to session1
    /// </code>
    /// </example>
    public void RegisterSession(string sessionId, Session session)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(session);

        if (string.IsNullOrEmpty(sessionId))
            throw new ArgumentException("Session ID cannot be null or empty", nameof(sessionId));

        IntPtr errorPtr = Native.LocalProxyRegisterSession(_handle, sessionId, session.Handle);
        string? error = Native.PtrToStringAndFree(errorPtr);

        if (!string.IsNullOrEmpty(error))
        {
            throw new HttpCloakException(error);
        }
    }

    /// <summary>
    /// Unregisters a session from the proxy.
    /// </summary>
    /// <param name="sessionId">The session ID to unregister</param>
    /// <returns>True if the session was found and removed, false otherwise</returns>
    /// <remarks>
    /// This does NOT close the session - you must dispose it separately.
    /// </remarks>
    public bool UnregisterSession(string sessionId)
    {
        ThrowIfDisposed();

        if (string.IsNullOrEmpty(sessionId))
            return false;

        int result = Native.LocalProxyUnregisterSession(_handle, sessionId);
        return result == 1;
    }

    /// <summary>
    /// Return the IDs of every session currently registered on this proxy.
    /// These are the same IDs the X-HTTPCloak-Session header accepts for
    /// per-request session routing.
    /// </summary>
    public List<string> ListSessions()
    {
        ThrowIfDisposed();

        IntPtr resultPtr = Native.LocalProxyListSessions(_handle);
        string? json = Native.PtrToStringAndFree(resultPtr);
        if (string.IsNullOrEmpty(json)) return new List<string>();

        try
        {
            return JsonSerializer.Deserialize(json, LocalProxyJsonContext.Default.ListString)
                ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }

    /// <summary>
    /// Return true if a session with the given ID is currently registered.
    /// Cheaper than calling <see cref="ListSessions"/> and scanning when
    /// callers only need an existence check.
    /// </summary>
    public bool HasSession(string sessionId)
    {
        ThrowIfDisposed();
        if (string.IsNullOrEmpty(sessionId)) return false;
        return Native.LocalProxyHasSession(_handle, sessionId) == 1;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(LocalProxy));
        }
    }

    /// <summary>
    /// Stops the local proxy server.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Native.LocalProxyStop(_handle);
        GC.SuppressFinalize(this);
    }

    ~LocalProxy()
    {
        Dispose();
    }
}

/// <summary>
/// Configuration for creating a local proxy.
/// </summary>
internal class LocalProxyConfig
{
    [JsonPropertyName("port")]
    public int Port { get; set; }

    [JsonPropertyName("preset")]
    public string Preset { get; set; } = "chrome-146";

    [JsonPropertyName("timeout")]
    public int Timeout { get; set; } = 30;

    [JsonPropertyName("max_connections")]
    public int MaxConnections { get; set; } = 1000;

    [JsonPropertyName("tcp_proxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TcpProxy { get; set; }

    [JsonPropertyName("udp_proxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UdpProxy { get; set; }

    [JsonPropertyName("tls_only")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool TlsOnly { get; set; }
}

/// <summary>
/// Statistics about the local proxy.
/// </summary>
public class LocalProxyStats
{
    [JsonPropertyName("running")]
    public bool Running { get; set; }

    [JsonPropertyName("port")]
    public int Port { get; set; }

    [JsonPropertyName("active_conns")]
    public long ActiveConnections { get; set; }

    [JsonPropertyName("total_requests")]
    public long TotalRequests { get; set; }

    [JsonPropertyName("preset")]
    public string? Preset { get; set; }

    [JsonPropertyName("max_connections")]
    public int MaxConnections { get; set; }
}

/// <summary>
/// JSON serialization context for LocalProxy types.
/// </summary>
[JsonSerializable(typeof(LocalProxyConfig))]
[JsonSerializable(typeof(LocalProxyStats))]
[JsonSerializable(typeof(List<string>))]
internal partial class LocalProxyJsonContext : JsonSerializerContext
{
}
