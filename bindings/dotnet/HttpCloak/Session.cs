using System.Collections.Concurrent;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HttpCloak;

/// <summary>
/// Manages native async callbacks from Go goroutines.
/// Each async request gets a unique callback ID from Go.
/// </summary>
internal sealed class AsyncCallbackManager
{
    private static readonly Lazy<AsyncCallbackManager> _instance = new(() => new AsyncCallbackManager());
    public static AsyncCallbackManager Instance => _instance.Value;

    private readonly ConcurrentDictionary<long, TaskCompletionSource<Response>> _pendingRequests = new();
    private readonly Native.AsyncCallback _callback;
    private readonly object _lock = new();

    private AsyncCallbackManager()
    {
        // Create callback delegate - must keep reference to prevent GC
        _callback = OnCallback;
    }

    private void OnCallback(long callbackId, IntPtr responseJsonPtr, IntPtr errorPtr)
    {
        if (!_pendingRequests.TryRemove(callbackId, out var tcs))
            return;

        try
        {
            string? error = Native.PtrToString(errorPtr);
            string? responseJson = Native.PtrToString(responseJsonPtr);

            if (!string.IsNullOrEmpty(error))
            {
                string errorMsg = error;
                try
                {
                    var errorData = JsonSerializer.Deserialize(error, JsonContext.Default.ErrorResponse);
                    if (errorData?.Error != null)
                        errorMsg = errorData.Error;
                }
                catch { }

                tcs.TrySetException(new HttpCloakException(errorMsg));
            }
            else if (!string.IsNullOrEmpty(responseJson))
            {
                try
                {
                    if (responseJson.Contains("\"error\""))
                    {
                        var errorResponse = JsonSerializer.Deserialize(responseJson, JsonContext.Default.ErrorResponse);
                        if (errorResponse?.Error != null)
                        {
                            tcs.TrySetException(new HttpCloakException(errorResponse.Error));
                            return;
                        }
                    }

                    var responseData = JsonSerializer.Deserialize(responseJson, JsonContext.Default.ResponseData);
                    if (responseData == null)
                    {
                        tcs.TrySetException(new HttpCloakException("Failed to parse response"));
                        return;
                    }

                    tcs.TrySetResult(new Response(responseData));
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(new HttpCloakException($"Failed to parse response: {ex.Message}"));
                }
            }
            else
            {
                tcs.TrySetException(new HttpCloakException("No response received"));
            }
        }
        catch (Exception ex)
        {
            tcs.TrySetException(ex);
        }
    }

    /// <summary>
    /// Register a new async request. Returns (callbackId, Task).
    /// When a CancellationToken is provided, cancellation will cancel the Task
    /// (the Go goroutine continues but the caller is unblocked immediately).
    /// </summary>
    public (long CallbackId, Task<Response> Task) RegisterRequest(CancellationToken cancellationToken = default)
    {
        var tcs = new TaskCompletionSource<Response>(TaskCreationOptions.RunContinuationsAsynchronously);

        // Register callback with Go - each request gets unique ID
        long callbackId = Native.RegisterCallback(_callback);

        _pendingRequests[callbackId] = tcs;

        // Wire up cancellation: cancel the Go context and the TCS
        if (cancellationToken.CanBeCanceled)
        {
            var id = callbackId;
            cancellationToken.Register(() =>
            {
                // Cancel the in-flight Go request (cancels context.Context → aborts DNS/TCP/TLS/HTTP)
                Native.CancelRequest(id);
                // Cancel the C# Task so the caller is unblocked immediately
                if (_pendingRequests.TryRemove(id, out var removed))
                    removed.TrySetCanceled(cancellationToken);
            });
        }

        return (callbackId, tcs.Task);
    }
}

/// <summary>
/// HTTP Session with browser fingerprint emulation.
/// Maintains cookies and connection state across requests.
/// </summary>
public sealed class Session : IDisposable
{
    private long _handle;
    private bool _disposed;

    /// <summary>
    /// Relaxed JSON serializer options that preserves raw characters (&amp;, +, &lt;, &gt;) in payloads
    /// instead of escaping them as unicode (\u0026, \u002B, etc.).
    /// </summary>
    private static readonly JsonSerializerOptions _relaxedJsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// Internal handle for use by LocalProxy.RegisterSession.
    /// </summary>
    internal long Handle => _handle;

    /// <summary>
    /// Default auth (username, password) for all requests.
    /// Can be overridden per-request.
    /// </summary>
    public (string Username, string Password)? Auth { get; set; }

    /// <summary>
    /// Create a new session with the specified options.
    /// </summary>
    /// <param name="preset">Browser preset (default: "chrome-145")</param>
    /// <param name="proxy">Proxy URL (e.g., "http://user:pass@host:port" or "socks5://host:port")</param>
    /// <param name="tcpProxy">Proxy URL for TCP protocols (HTTP/1.1, HTTP/2) - use with udpProxy for split config</param>
    /// <param name="udpProxy">Proxy URL for UDP protocols (HTTP/3 via MASQUE) - use with tcpProxy for split config</param>
    /// <param name="timeout">Request timeout in seconds (default: 30)</param>
    /// <param name="httpVersion">HTTP version: "auto", "h1", "h2", "h3" (default: "auto")</param>
    /// <param name="verify">SSL certificate verification (default: true)</param>
    /// <param name="allowRedirects">Follow redirects (default: true)</param>
    /// <param name="maxRedirects">Maximum number of redirects (default: 10)</param>
    /// <param name="retry">Number of retries on failure (default: 0)</param>
    /// <param name="retryOnStatus">HTTP status codes to retry on (default: null, uses [429, 500, 502, 503, 504])</param>
    /// <param name="retryWaitMin">Minimum wait time between retries in milliseconds (default: 500)</param>
    /// <param name="retryWaitMax">Maximum wait time between retries in milliseconds (default: 10000)</param>
    /// <param name="preferIpv4">Prefer IPv4 addresses over IPv6 (default: false)</param>
    /// <param name="auth">Default auth (username, password) for all requests</param>
    /// <param name="connectTo">Domain fronting map (requestHost -> connectHost)</param>
    /// <param name="echConfigDomain">Domain to fetch ECH config from (e.g., "cloudflare-ech.com")</param>
    /// <param name="tlsOnly">TLS-only mode: use TLS fingerprint but skip preset HTTP headers (default: false)</param>
    /// <param name="quicIdleTimeout">QUIC idle timeout in seconds (default: 30). Set higher for long-lived HTTP/3 connections.</param>
    /// <param name="switchProtocol">Protocol to switch to after Refresh(): "h1", "h2", "h3" (default: null, no switch)</param>
    public Session(
        string preset = "chrome-145",
        string? proxy = null,
        string? tcpProxy = null,
        string? udpProxy = null,
        int timeout = 30,
        string httpVersion = "auto",
        bool verify = true,
        bool allowRedirects = true,
        int maxRedirects = 10,
        int retry = 0,
        int[]? retryOnStatus = null,
        int retryWaitMin = 500,
        int retryWaitMax = 10000,
        bool preferIpv4 = false,
        (string Username, string Password)? auth = null,
        Dictionary<string, string>? connectTo = null,
        string? echConfigDomain = null,
        bool tlsOnly = false,
        int quicIdleTimeout = 0,
        string? localAddress = null,
        string? keyLogFile = null,
        bool enableSpeculativeTls = false,
        string? switchProtocol = null,
        string? ja3 = null,
        string? akamai = null,
        Dictionary<string, object>? extraFp = null)
    {
        Auth = auth;

        var config = new SessionConfig
        {
            Preset = preset,
            Proxy = proxy,
            TcpProxy = tcpProxy,
            UdpProxy = udpProxy,
            Timeout = timeout,
            HttpVersion = httpVersion,
            Verify = verify,
            AllowRedirects = allowRedirects,
            MaxRedirects = maxRedirects,
            Retry = retry,
            RetryOnStatus = retryOnStatus,
            RetryWaitMin = retryWaitMin,
            RetryWaitMax = retryWaitMax,
            PreferIpv4 = preferIpv4,
            ConnectTo = connectTo,
            EchConfigDomain = echConfigDomain,
            TlsOnly = tlsOnly,
            QuicIdleTimeout = quicIdleTimeout,
            LocalAddress = localAddress,
            KeyLogFile = keyLogFile,
            EnableSpeculativeTls = enableSpeculativeTls,
            SwitchProtocol = switchProtocol,
            Ja3 = ja3,
            Akamai = akamai,
            ExtraFp = extraFp
        };

        string configJson = JsonSerializer.Serialize(config, JsonContext.Relaxed.SessionConfig);
        _handle = Native.SessionNew(configJson);

        if (_handle == 0)
            throw new HttpCloakException("Failed to create session");
    }

    /// <summary>
    /// Apply auth to headers.
    /// </summary>
    private Dictionary<string, string> ApplyAuth(Dictionary<string, string>? headers, (string Username, string Password)? auth)
    {
        var effectiveAuth = auth ?? Auth;
        headers ??= new Dictionary<string, string>();

        if (effectiveAuth != null)
        {
            var credentials = $"{effectiveAuth.Value.Username}:{effectiveAuth.Value.Password}";
            var base64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(credentials));
            headers["Authorization"] = $"Basic {base64}";
        }

        return headers;
    }

    /// <summary>
    /// Add query parameters to URL, preserving insertion order and using standard percent-encoding.
    /// </summary>
    private static string AddParamsToUrl(string url, Dictionary<string, string>? parameters)
    {
        if (parameters == null || parameters.Count == 0)
            return url;

        var sb = new System.Text.StringBuilder(url);
        sb.Append(url.Contains('?') ? '&' : '?');
        bool first = true;
        foreach (var param in parameters)
        {
            if (!first) sb.Append('&');
            sb.Append(Uri.EscapeDataString(param.Key));
            sb.Append('=');
            sb.Append(Uri.EscapeDataString(param.Value));
            first = false;
        }
        return sb.ToString();
    }

    /// <summary>
    /// Apply cookies to headers.
    /// </summary>
    private static Dictionary<string, string> ApplyCookies(Dictionary<string, string> headers, Dictionary<string, string>? cookies)
    {
        if (cookies == null || cookies.Count == 0)
            return headers;

        var cookieStr = string.Join("; ", cookies.Select(c => $"{c.Key}={c.Value}"));
        if (headers.TryGetValue("Cookie", out var existing) && !string.IsNullOrEmpty(existing))
        {
            headers["Cookie"] = $"{existing}; {cookieStr}";
        }
        else
        {
            headers["Cookie"] = cookieStr;
        }
        return headers;
    }

    /// <summary>
    /// Auto-detect Content-Type from body when not explicitly set.
    /// If body looks like JSON (starts with { or [), sets application/json.
    /// </summary>
    private static void InferContentType(string? body, Dictionary<string, string> headers)
    {
        if (string.IsNullOrEmpty(body))
            return;

        // Check if Content-Type is already set (case-insensitive)
        foreach (var key in headers.Keys)
        {
            if (key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                return;
        }

        // Detect JSON body
        var trimmed = body.AsSpan().TrimStart();
        if (trimmed.Length > 0 && (trimmed[0] == '{' || trimmed[0] == '['))
        {
            headers["Content-Type"] = "application/json";
        }
    }

    /// <summary>
    /// Perform a GET request.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Response Get(string url, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        if (timeout != null)
            return Request("GET", url, null, headers, timeout, auth);

        // Wrap headers in RequestOptions as expected by clib
        string? optionsJson = headers.Count > 0
            ? JsonSerializer.Serialize(new RequestOptions { Headers = headers }, JsonContext.Relaxed.RequestOptions)
            : null;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        IntPtr resultPtr = Native.Get(_handle, url, optionsJson);
        stopwatch.Stop();

        return ParseResponse(resultPtr, stopwatch.Elapsed);
    }

    /// <summary>
    /// Perform a POST request.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Response Post(string url, string? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        if (timeout != null)
            return Request("POST", url, body, headers, timeout, auth);

        // Wrap headers in RequestOptions as expected by clib
        string? optionsJson = headers.Count > 0
            ? JsonSerializer.Serialize(new RequestOptions { Headers = headers }, JsonContext.Relaxed.RequestOptions)
            : null;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        IntPtr resultPtr = Native.Post(_handle, url, body, optionsJson);
        stopwatch.Stop();

        return ParseResponse(resultPtr, stopwatch.Elapsed);
    }

    /// <summary>
    /// Perform a POST request with JSON body.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="data">Data to serialize as JSON</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Response PostJson<T>(string url, T data, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return Post(url, body, headers, parameters, cookies, auth, timeout);
    }

    /// <summary>
    /// Perform a POST request with form data.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="formData">Form data as key-value pairs</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Response PostForm(string url, Dictionary<string, string> formData, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/x-www-form-urlencoded";

        string body = string.Join("&", formData.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
        return Post(url, body, headers, parameters, cookies, auth, timeout);
    }

    /// <summary>
    /// Perform a custom HTTP request.
    /// </summary>
    /// <param name="method">HTTP method</param>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="timeout">Request timeout in seconds</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    public Response Request(string method, string url, string? body = null, Dictionary<string, string>? headers = null, int? timeout = null, (string, string)? auth = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Body = body,
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Relaxed.RequestConfig);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        IntPtr resultPtr = Native.Request(_handle, requestJson);
        stopwatch.Stop();

        return ParseResponse(resultPtr, stopwatch.Elapsed);
    }

    /// <summary>
    /// Perform a PUT request.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Response Put(string url, string? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => Request("PUT", url, body, headers, timeout, auth, parameters, cookies);

    /// <summary>
    /// Perform a PUT request with JSON body.
    /// </summary>
    public Response PutJson<T>(string url, T data, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return Put(url, body, headers, parameters, cookies, auth, timeout);
    }

    /// <summary>
    /// Perform a DELETE request.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Response Delete(string url, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => Request("DELETE", url, null, headers, timeout, auth, parameters, cookies);

    /// <summary>
    /// Perform a PATCH request.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Response Patch(string url, string? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => Request("PATCH", url, body, headers, timeout, auth, parameters, cookies);

    /// <summary>
    /// Perform a PATCH request with JSON body.
    /// </summary>
    public Response PatchJson<T>(string url, T data, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return Patch(url, body, headers, parameters, cookies, auth, timeout);
    }

    /// <summary>
    /// Perform a HEAD request.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Response Head(string url, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => Request("HEAD", url, null, headers, timeout, auth, parameters, cookies);

    /// <summary>
    /// Perform an OPTIONS request.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Response Options(string url, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => Request("OPTIONS", url, null, headers, timeout, auth, parameters, cookies);

    // =========================================================================
    // Binary Body Methods (for uploads)
    // =========================================================================

    /// <summary>
    /// Perform a POST request with binary body.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="body">Binary request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Response Post(string url, byte[] body, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => RequestBinary("POST", url, body, headers, timeout, auth, parameters, cookies);

    /// <summary>
    /// Perform a PUT request with binary body.
    /// </summary>
    public Response Put(string url, byte[] body, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => RequestBinary("PUT", url, body, headers, timeout, auth, parameters, cookies);

    /// <summary>
    /// Perform a PATCH request with binary body.
    /// </summary>
    public Response Patch(string url, byte[] body, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => RequestBinary("PATCH", url, body, headers, timeout, auth, parameters, cookies);

    /// <summary>
    /// Perform a POST request with Stream body.
    /// Note: The entire stream is read into memory before sending.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="bodyStream">Stream containing the request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Response Post(string url, Stream bodyStream, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => RequestStream("POST", url, bodyStream, headers, timeout, auth, parameters, cookies);

    /// <summary>
    /// Perform a PUT request with Stream body.
    /// Note: The entire stream is read into memory before sending.
    /// </summary>
    public Response Put(string url, Stream bodyStream, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => RequestStream("PUT", url, bodyStream, headers, timeout, auth, parameters, cookies);

    /// <summary>
    /// Perform a PATCH request with Stream body.
    /// Note: The entire stream is read into memory before sending.
    /// </summary>
    public Response Patch(string url, Stream bodyStream, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => RequestStream("PATCH", url, bodyStream, headers, timeout, auth, parameters, cookies);

    /// <summary>
    /// Perform a custom HTTP request with binary body.
    /// </summary>
    public Response RequestBinary(string method, string url, byte[] body, Dictionary<string, string>? headers = null, int? timeout = null, (string, string)? auth = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Body = Convert.ToBase64String(body),
            BodyEncoding = "base64",
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Relaxed.RequestConfig);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        IntPtr resultPtr = Native.Request(_handle, requestJson);
        stopwatch.Stop();

        return ParseResponse(resultPtr, stopwatch.Elapsed);
    }

    /// <summary>
    /// Perform a custom HTTP request with Stream body.
    /// Note: The entire stream is read into memory before sending.
    /// </summary>
    public Response RequestStream(string method, string url, Stream bodyStream, Dictionary<string, string>? headers = null, int? timeout = null, (string, string)? auth = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null)
    {
        using var ms = new MemoryStream();
        bodyStream.CopyTo(ms);
        return RequestBinary(method, url, ms.ToArray(), headers, timeout, auth, parameters, cookies);
    }

    // =========================================================================
    // Async Methods (Native - using Go goroutines)
    // =========================================================================

    /// <summary>
    /// Perform an async GET request using native Go goroutines.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Task<Response> GetAsync(string url, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        if (timeout != null)
            return RequestAsync("GET", url, null, headers, timeout, auth, parameters, cookies, cancellationToken);

        // Wrap headers in RequestOptions structure (Go expects {"headers": {...}, "timeout": ...})
        var options = new RequestOptions { Headers = headers.Count > 0 ? headers : null };
        string? optionsJson = (options.Headers != null)
            ? JsonSerializer.Serialize(options, JsonContext.Relaxed.RequestOptions)
            : null;

        var (callbackId, task) = AsyncCallbackManager.Instance.RegisterRequest(cancellationToken);
        Native.GetAsync(_handle, url, optionsJson, callbackId);

        return task;
    }

    /// <summary>
    /// Perform an async POST request using native Go goroutines.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public Task<Response> PostAsync(string url, string? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        if (timeout != null)
            return RequestAsync("POST", url, body, headers, timeout, auth, parameters, cookies, cancellationToken);

        // Wrap headers in RequestOptions structure (Go expects {"headers": {...}, "timeout": ...})
        var options = new RequestOptions { Headers = headers.Count > 0 ? headers : null };
        string? optionsJson = (options.Headers != null)
            ? JsonSerializer.Serialize(options, JsonContext.Relaxed.RequestOptions)
            : null;

        var (callbackId, task) = AsyncCallbackManager.Instance.RegisterRequest(cancellationToken);
        Native.PostAsync(_handle, url, body, optionsJson, callbackId);

        return task;
    }

    /// <summary>
    /// Perform an async POST request with JSON body using native Go goroutines.
    /// </summary>
    public Task<Response> PostJsonAsync<T>(string url, T data, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return PostAsync(url, body, headers, parameters, cookies, auth, timeout, cancellationToken);
    }

    /// <summary>
    /// Perform an async POST request with form data using native Go goroutines.
    /// </summary>
    public Task<Response> PostFormAsync(string url, Dictionary<string, string> formData, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/x-www-form-urlencoded";

        string body = string.Join("&", formData.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
        return PostAsync(url, body, headers, parameters, cookies, auth, timeout, cancellationToken);
    }

    /// <summary>
    /// Perform an async custom HTTP request using native Go goroutines.
    /// </summary>
    /// <param name="method">HTTP method</param>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="timeout">Request timeout in seconds</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    public Task<Response> RequestAsync(string method, string url, string? body = null, Dictionary<string, string>? headers = null, int? timeout = null, (string, string)? auth = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Body = body,
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Relaxed.RequestConfig);

        var (callbackId, task) = AsyncCallbackManager.Instance.RegisterRequest(cancellationToken);
        Native.RequestAsync(_handle, requestJson, callbackId);

        return task;
    }

    /// <summary>
    /// Perform an async PUT request using native Go goroutines.
    /// </summary>
    public Task<Response> PutAsync(string url, string? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default)
        => RequestAsync("PUT", url, body, headers, timeout, auth, parameters, cookies, cancellationToken);

    /// <summary>
    /// Perform an async PUT request with JSON body using native Go goroutines.
    /// </summary>
    public Task<Response> PutJsonAsync<T>(string url, T data, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return PutAsync(url, body, headers, parameters, cookies, auth, timeout, cancellationToken);
    }

    /// <summary>
    /// Perform an async DELETE request using native Go goroutines.
    /// </summary>
    public Task<Response> DeleteAsync(string url, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default)
        => RequestAsync("DELETE", url, null, headers, timeout, auth, parameters, cookies, cancellationToken);

    /// <summary>
    /// Perform an async PATCH request using native Go goroutines.
    /// </summary>
    public Task<Response> PatchAsync(string url, string? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default)
        => RequestAsync("PATCH", url, body, headers, timeout, auth, parameters, cookies, cancellationToken);

    /// <summary>
    /// Perform an async PATCH request with JSON body using native Go goroutines.
    /// </summary>
    public Task<Response> PatchJsonAsync<T>(string url, T data, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data, _relaxedJsonOptions);
        return PatchAsync(url, body, headers, parameters, cookies, auth, timeout, cancellationToken);
    }

    /// <summary>
    /// Perform an async HEAD request using native Go goroutines.
    /// </summary>
    public Task<Response> HeadAsync(string url, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default)
        => RequestAsync("HEAD", url, null, headers, timeout, auth, parameters, cookies, cancellationToken);

    /// <summary>
    /// Perform an async OPTIONS request using native Go goroutines.
    /// </summary>
    public Task<Response> OptionsAsync(string url, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null, CancellationToken cancellationToken = default)
        => RequestAsync("OPTIONS", url, null, headers, timeout, auth, parameters, cookies, cancellationToken);

    // =========================================================================
    // Cookie Management
    // =========================================================================

    /// <summary>
    /// Get all cookies from the session.
    /// </summary>
    public Dictionary<string, string> GetCookies()
    {
        ThrowIfDisposed();

        IntPtr resultPtr = Native.GetCookies(_handle);
        string? json = Native.PtrToStringAndFree(resultPtr);

        if (string.IsNullOrEmpty(json))
            return new Dictionary<string, string>();

        return JsonSerializer.Deserialize(json, JsonContext.Default.DictionaryStringString)
            ?? new Dictionary<string, string>();
    }

    /// <summary>
    /// Set a cookie in the session.
    /// </summary>
    public void SetCookie(string name, string value)
    {
        ThrowIfDisposed();
        Native.SetCookie(_handle, name, value);
    }

    /// <summary>
    /// Get a specific cookie by name.
    /// </summary>
    /// <param name="name">Cookie name</param>
    /// <returns>Cookie value, or null if not found</returns>
    public string? GetCookie(string name)
    {
        ThrowIfDisposed();
        var cookies = GetCookies();
        return cookies.TryGetValue(name, out var value) && !string.IsNullOrEmpty(value) ? value : null;
    }

    /// <summary>
    /// Delete a specific cookie by name.
    /// </summary>
    /// <param name="name">Cookie name to delete</param>
    public void DeleteCookie(string name)
    {
        ThrowIfDisposed();
        // Set cookie to empty string to delete it
        Native.SetCookie(_handle, name, "");
    }

    /// <summary>
    /// Clear all cookies from the session.
    /// </summary>
    public void ClearCookies()
    {
        ThrowIfDisposed();
        var cookies = GetCookies();
        foreach (var name in cookies.Keys)
        {
            Native.SetCookie(_handle, name, "");
        }
    }

    // =========================================================================
    // Proxy Management
    // =========================================================================

    /// <summary>
    /// Change both TCP and UDP proxies for the session.
    /// This closes all existing connections and creates new ones through the new proxy.
    /// Use this for runtime proxy switching (e.g., rotating proxies).
    /// </summary>
    /// <param name="proxyUrl">Proxy URL (e.g., "http://user:pass@host:port", "socks5://host:port"). Pass null or empty for direct connection.</param>
    /// <example>
    /// <code>
    /// using var session = new Session(proxy: "http://proxy1:8080");
    /// await session.GetAsync("https://example.com");  // Uses proxy1
    /// session.SetProxy("http://proxy2:8080");         // Switch to proxy2
    /// await session.GetAsync("https://example.com");  // Uses proxy2
    /// session.SetProxy("");                           // Switch to direct connection
    /// </code>
    /// </example>
    public void SetProxy(string? proxyUrl)
    {
        ThrowIfDisposed();
        Native.SessionSetProxy(_handle, proxyUrl ?? "");
    }

    /// <summary>
    /// Change only the TCP proxy (for HTTP/1.1 and HTTP/2).
    /// Use this with SetUdpProxy() for split proxy configuration.
    /// </summary>
    /// <param name="proxyUrl">Proxy URL for TCP traffic</param>
    public void SetTcpProxy(string? proxyUrl)
    {
        ThrowIfDisposed();
        Native.SessionSetTcpProxy(_handle, proxyUrl ?? "");
    }

    /// <summary>
    /// Change only the UDP proxy (for HTTP/3 via SOCKS5 or MASQUE).
    /// HTTP/3 requires either SOCKS5 (with UDP ASSOCIATE support) or MASQUE proxy.
    /// </summary>
    /// <param name="proxyUrl">Proxy URL for UDP traffic (e.g., "socks5://host:port" or MASQUE URL)</param>
    public void SetUdpProxy(string? proxyUrl)
    {
        ThrowIfDisposed();
        Native.SessionSetUdpProxy(_handle, proxyUrl ?? "");
    }

    /// <summary>
    /// Get the current proxy URL.
    /// </summary>
    /// <returns>Current proxy URL, or empty string if using direct connection</returns>
    public string GetProxy()
    {
        ThrowIfDisposed();
        IntPtr resultPtr = Native.SessionGetProxy(_handle);
        return Native.PtrToStringAndFree(resultPtr) ?? "";
    }

    /// <summary>
    /// Get the current TCP proxy URL.
    /// </summary>
    /// <returns>Current TCP proxy URL, or empty string if using direct connection</returns>
    public string GetTcpProxy()
    {
        ThrowIfDisposed();
        IntPtr resultPtr = Native.SessionGetTcpProxy(_handle);
        return Native.PtrToStringAndFree(resultPtr) ?? "";
    }

    /// <summary>
    /// Get the current UDP proxy URL.
    /// </summary>
    /// <returns>Current UDP proxy URL, or empty string if using direct connection</returns>
    public string GetUdpProxy()
    {
        ThrowIfDisposed();
        IntPtr resultPtr = Native.SessionGetUdpProxy(_handle);
        return Native.PtrToStringAndFree(resultPtr) ?? "";
    }

    /// <summary>
    /// Set a custom header order for all requests.
    /// </summary>
    /// <param name="order">Array of header names in desired order (lowercase). Pass null or empty array to reset to preset's default.</param>
    /// <example>
    /// <code>
    /// session.SetHeaderOrder(new[] { "accept-language", "sec-ch-ua", "accept", "sec-fetch-site" });
    /// </code>
    /// </example>
    public void SetHeaderOrder(string[]? order)
    {
        ThrowIfDisposed();
        var orderJson = order != null && order.Length > 0
            ? System.Text.Json.JsonSerializer.Serialize(order)
            : "[]";
        IntPtr resultPtr = Native.SessionSetHeaderOrder(_handle, orderJson);
        var result = Native.PtrToStringAndFree(resultPtr);
        if (!string.IsNullOrEmpty(result) && result.Contains("error"))
        {
            var data = System.Text.Json.JsonDocument.Parse(result);
            if (data.RootElement.TryGetProperty("error", out var errorElement))
            {
                throw new InvalidOperationException(errorElement.GetString());
            }
        }
    }

    /// <summary>
    /// Get the current header order.
    /// </summary>
    /// <returns>Array of header names in current order, or preset's default order</returns>
    public string[] GetHeaderOrder()
    {
        ThrowIfDisposed();
        IntPtr resultPtr = Native.SessionGetHeaderOrder(_handle);
        var result = Native.PtrToStringAndFree(resultPtr);
        if (!string.IsNullOrEmpty(result))
        {
            return System.Text.Json.JsonSerializer.Deserialize<string[]>(result) ?? Array.Empty<string>();
        }
        return Array.Empty<string>();
    }

    /// <summary>
    /// Set a session identifier for TLS cache key isolation.
    /// This is used when the session is registered with a LocalProxy to ensure
    /// TLS sessions are isolated per proxy/session configuration in distributed caches.
    /// </summary>
    /// <param name="sessionId">Unique identifier for this session. Pass null or empty to clear.</param>
    /// <example>
    /// <code>
    /// session.SetSessionIdentifier("user-123");
    /// </code>
    /// </example>
    public void SetSessionIdentifier(string? sessionId)
    {
        ThrowIfDisposed();
        Native.SessionSetIdentifier(_handle, sessionId);
    }

    /// <summary>
    /// Get or set the current proxy URL.
    /// </summary>
    public string Proxy
    {
        get => GetProxy();
        set => SetProxy(value);
    }

    // =========================================================================
    // Session Persistence
    // =========================================================================

    /// <summary>
    /// Save session state (cookies, TLS sessions) to a file.
    /// This allows you to persist session state across program runs.
    /// </summary>
    /// <param name="path">Path to save the session file</param>
    /// <example>
    /// <code>
    /// using var session = new Session(preset: "chrome-145");
    /// var r = session.Get("https://example.com");  // Acquire cookies
    /// session.Save("session.json");
    ///
    /// // Later, restore the session
    /// using var session2 = Session.Load("session.json");
    /// </code>
    /// </example>
    public void Save(string path)
    {
        ThrowIfDisposed();

        IntPtr resultPtr = Native.SessionSave(_handle, path);
        string? result = Native.PtrToStringAndFree(resultPtr);

        if (!string.IsNullOrEmpty(result))
        {
            if (result.Contains("\"error\""))
            {
                var error = JsonSerializer.Deserialize(result, JsonContext.Default.ErrorResponse);
                if (error?.Error != null)
                    throw new HttpCloakException(error.Error);
            }
        }
    }

    /// <summary>
    /// Export session state to JSON string.
    /// </summary>
    /// <returns>JSON string containing session state</returns>
    /// <example>
    /// <code>
    /// string sessionData = session.Marshal();
    /// // Store sessionData in database, cache, etc.
    ///
    /// // Later, restore the session
    /// var session = Session.Unmarshal(sessionData);
    /// </code>
    /// </example>
    public string Marshal()
    {
        ThrowIfDisposed();

        IntPtr resultPtr = Native.SessionMarshal(_handle);
        string? result = Native.PtrToStringAndFree(resultPtr);

        if (string.IsNullOrEmpty(result))
            throw new HttpCloakException("Failed to marshal session");

        // Check for error
        if (result.Contains("\"error\""))
        {
            var error = JsonSerializer.Deserialize(result, JsonContext.Default.ErrorResponse);
            if (error?.Error != null)
                throw new HttpCloakException(error.Error);
        }

        return result;
    }

    /// <summary>
    /// Load a session from a file.
    /// This restores session state including cookies and TLS session tickets.
    /// </summary>
    /// <param name="path">Path to the session file</param>
    /// <returns>Restored Session object</returns>
    /// <example>
    /// <code>
    /// using var session = Session.Load("session.json");
    /// var r = session.Get("https://example.com");  // Uses restored cookies
    /// </code>
    /// </example>
    public static Session Load(string path)
    {
        long handle = Native.SessionLoad(path);

        if (handle < 0 || handle == 0)
            throw new HttpCloakException($"Failed to load session from {path}");

        return new Session(handle);
    }

    /// <summary>
    /// Load a session from JSON string.
    /// </summary>
    /// <param name="data">JSON string containing session state</param>
    /// <returns>Restored Session object</returns>
    /// <example>
    /// <code>
    /// // Retrieve sessionData from database, cache, etc.
    /// var session = Session.Unmarshal(sessionData);
    /// </code>
    /// </example>
    public static Session Unmarshal(string data)
    {
        long handle = Native.SessionUnmarshal(data);

        if (handle < 0 || handle == 0)
            throw new HttpCloakException("Failed to unmarshal session");

        return new Session(handle);
    }

    /// <summary>
    /// Private constructor for creating a Session from an existing handle.
    /// Used by Load and Unmarshal static methods.
    /// </summary>
    private Session(long handle)
    {
        _handle = handle;
        Auth = null;
    }

    // =========================================================================
    // Streaming Methods
    // =========================================================================

    /// <summary>
    /// Perform a streaming GET request for downloading large files.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in milliseconds</param>
    /// <returns>StreamResponse for chunked reading</returns>
    /// <example>
    /// <code>
    /// using var stream = session.GetStream("https://example.com/large-file.zip");
    /// foreach (var chunk in stream.ReadChunks())
    /// {
    ///     file.Write(chunk);
    /// }
    /// </code>
    /// </example>
    public StreamResponse GetStream(string url, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        var options = new StreamOptions { Headers = headers.Count > 0 ? headers : null, Timeout = timeout };
        string? optionsJson = JsonSerializer.Serialize(options, JsonContext.Relaxed.StreamOptions);

        long streamHandle = Native.StreamGet(_handle, url, optionsJson);
        if (streamHandle < 0)
            throw new HttpCloakException("Failed to start streaming request");

        return CreateStreamResponse(streamHandle);
    }

    /// <summary>
    /// Perform a streaming POST request.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in milliseconds</param>
    /// <returns>StreamResponse for chunked reading</returns>
    public StreamResponse PostStream(string url, string? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        var options = new StreamOptions { Headers = headers.Count > 0 ? headers : null, Timeout = timeout };
        string? optionsJson = JsonSerializer.Serialize(options, JsonContext.Relaxed.StreamOptions);

        long streamHandle = Native.StreamPost(_handle, url, body, optionsJson);
        if (streamHandle < 0)
            throw new HttpCloakException("Failed to start streaming request");

        return CreateStreamResponse(streamHandle);
    }

    /// <summary>
    /// Perform a streaming request with any HTTP method.
    /// </summary>
    /// <param name="method">HTTP method</param>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    /// <returns>StreamResponse for chunked reading</returns>
    public StreamResponse RequestStream(string method, string url, string? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);
        InferContentType(body, headers);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Body = body,
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Relaxed.RequestConfig);

        long streamHandle = Native.StreamRequest(_handle, requestJson);
        if (streamHandle < 0)
            throw new HttpCloakException("Failed to start streaming request");

        return CreateStreamResponse(streamHandle);
    }

    private static StreamResponse CreateStreamResponse(long streamHandle)
    {
        IntPtr metadataPtr = Native.StreamGetMetadata(streamHandle);
        string? metadataJson = Native.PtrToStringAndFree(metadataPtr);

        if (string.IsNullOrEmpty(metadataJson))
        {
            Native.StreamClose(streamHandle);
            throw new HttpCloakException("Failed to get stream metadata");
        }

        if (metadataJson.Contains("\"error\""))
        {
            var error = JsonSerializer.Deserialize(metadataJson, JsonContext.Default.ErrorResponse);
            if (error?.Error != null)
            {
                Native.StreamClose(streamHandle);
                throw new HttpCloakException(error.Error);
            }
        }

        var metadata = JsonSerializer.Deserialize(metadataJson, JsonContext.Default.StreamMetadata);
        if (metadata == null)
        {
            Native.StreamClose(streamHandle);
            throw new HttpCloakException("Failed to parse stream metadata");
        }

        return new StreamResponse(streamHandle, metadata);
    }

    private static Response ParseResponse(IntPtr resultPtr, TimeSpan elapsed = default)
    {
        string? json = Native.PtrToStringAndFree(resultPtr);

        if (string.IsNullOrEmpty(json))
            throw new HttpCloakException("No response received");

        // Check for error response
        if (json.Contains("\"error\""))
        {
            var error = JsonSerializer.Deserialize(json, JsonContext.Default.ErrorResponse);
            if (error?.Error != null)
                throw new HttpCloakException(error.Error);
        }

        var response = JsonSerializer.Deserialize(json, JsonContext.Default.ResponseData);
        if (response == null)
            throw new HttpCloakException("Failed to parse response");

        return new Response(response, elapsed);
    }

    private static FastResponse ParseFastResponse(long responseHandle, TimeSpan elapsed = default)
    {
        try
        {
            // Get metadata
            IntPtr metaPtr = Native.ResponseGetMetadata(responseHandle);
            string? metaJson = Native.PtrToStringAndFree(metaPtr);

            if (string.IsNullOrEmpty(metaJson))
                throw new HttpCloakException("No response metadata received");

            // Check for error
            if (metaJson.Contains("\"error\""))
            {
                var error = JsonSerializer.Deserialize(metaJson, JsonContext.Default.ErrorResponse);
                if (error?.Error != null)
                    throw new HttpCloakException(error.Error);
            }

            var metadata = JsonSerializer.Deserialize(metaJson, JsonContext.Default.FastResponseMetadata);
            if (metadata == null)
                throw new HttpCloakException("Failed to parse response metadata");

            // Get body
            int bodyLen = Native.ResponseGetBodyLen(responseHandle);
            byte[] content;

            if (bodyLen > 0)
            {
                content = new byte[bodyLen];
                unsafe
                {
                    fixed (byte* bufPtr = content)
                    {
                        Native.ResponseCopyBodyTo(responseHandle, (IntPtr)bufPtr, bodyLen);
                    }
                }
            }
            else
            {
                content = Array.Empty<byte>();
            }

            return new FastResponse(metadata, content, elapsed);
        }
        finally
        {
            Native.ResponseFree(responseHandle);
        }
    }

    /// <summary>
    /// Perform a high-performance GET request with direct byte array response.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    public FastResponse GetFast(string url, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        var options = new RequestOptions { Headers = headers.Count > 0 ? headers : null };
        string? optionsJson = headers.Count > 0
            ? JsonSerializer.Serialize(options, JsonContext.Relaxed.RequestOptions)
            : null;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        long responseHandle = Native.GetRaw(_handle, url, optionsJson);
        stopwatch.Stop();

        if (responseHandle < 0)
            throw new HttpCloakException("Request failed");

        return ParseFastResponse(responseHandle, stopwatch.Elapsed);
    }

    /// <summary>
    /// Perform a high-performance POST request with direct byte array response.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body as bytes</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    public FastResponse PostFast(string url, byte[]? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        var options = new RequestOptions { Headers = headers.Count > 0 ? headers : null };
        string? optionsJson = headers.Count > 0
            ? JsonSerializer.Serialize(options, JsonContext.Relaxed.RequestOptions)
            : null;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        long responseHandle;

        if (body != null && body.Length > 0)
        {
            unsafe
            {
                fixed (byte* bodyPtr = body)
                {
                    responseHandle = Native.PostRaw(_handle, url, (IntPtr)bodyPtr, body.Length, optionsJson);
                }
            }
        }
        else
        {
            responseHandle = Native.PostRaw(_handle, url, IntPtr.Zero, 0, optionsJson);
        }
        stopwatch.Stop();

        if (responseHandle < 0)
            throw new HttpCloakException("Request failed");

        return ParseFastResponse(responseHandle, stopwatch.Elapsed);
    }

    /// <summary>
    /// Perform a high-performance custom HTTP request with direct byte array response.
    /// </summary>
    /// <param name="method">HTTP method</param>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body as bytes</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="parameters">Query parameters</param>
    /// <param name="cookies">Cookies to send with this request</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    /// <param name="timeout">Request timeout in seconds</param>
    public FastResponse RequestFast(string method, string url, byte[]? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
    {
        ThrowIfDisposed();

        url = AddParamsToUrl(url, parameters);
        headers = ApplyAuth(headers, auth);
        headers = ApplyCookies(headers, cookies);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Relaxed.RequestConfig);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        long responseHandle;

        if (body != null && body.Length > 0)
        {
            unsafe
            {
                fixed (byte* bodyPtr = body)
                {
                    responseHandle = Native.RequestRaw(_handle, requestJson, (IntPtr)bodyPtr, body.Length);
                }
            }
        }
        else
        {
            responseHandle = Native.RequestRaw(_handle, requestJson, IntPtr.Zero, 0);
        }
        stopwatch.Stop();

        if (responseHandle < 0)
            throw new HttpCloakException("Request failed");

        return ParseFastResponse(responseHandle, stopwatch.Elapsed);
    }

    /// <summary>
    /// Perform a high-performance PUT request with direct byte array response.
    /// </summary>
    public FastResponse PutFast(string url, byte[]? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => RequestFast("PUT", url, body, headers, parameters, cookies, auth, timeout);

    /// <summary>
    /// Perform a high-performance DELETE request with direct byte array response.
    /// </summary>
    public FastResponse DeleteFast(string url, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => RequestFast("DELETE", url, null, headers, parameters, cookies, auth, timeout);

    /// <summary>
    /// Perform a high-performance PATCH request with direct byte array response.
    /// </summary>
    public FastResponse PatchFast(string url, byte[]? body = null, Dictionary<string, string>? headers = null, Dictionary<string, string>? parameters = null, Dictionary<string, string>? cookies = null, (string, string)? auth = null, int? timeout = null)
        => RequestFast("PATCH", url, body, headers, parameters, cookies, auth, timeout);

    /// <summary>
    /// Simulate a real browser page load to warm TLS sessions, cookies, and cache.
    /// Fetches the HTML page and its subresources (CSS, JS, images) with
    /// realistic headers, priorities, and timing.
    /// </summary>
    /// <param name="url">The page URL to warm up.</param>
    /// <param name="timeoutMs">Timeout in milliseconds (default: 60000).</param>
    public void Warmup(string url, long timeoutMs = 0)
    {
        ThrowIfDisposed();
        IntPtr resultPtr = Native.SessionWarmup(_handle, url, timeoutMs);
        if (resultPtr != IntPtr.Zero)
        {
            string? result = Native.PtrToStringAndFree(resultPtr);
            if (!string.IsNullOrEmpty(result))
            {
                var error = JsonSerializer.Deserialize(result, JsonContext.Default.ErrorResponse);
                if (error?.Error != null)
                    throw new HttpCloakException(error.Error);
            }
        }
    }

    /// <summary>
    /// Create n forked sessions sharing cookies and TLS session caches.
    /// Forked sessions simulate multiple browser tabs from the same browser:
    /// same cookies, same TLS resumption tickets, same fingerprint, but
    /// independent connections for parallel requests.
    /// </summary>
    /// <param name="n">Number of sessions to create.</param>
    /// <returns>Array of new Session objects.</returns>
    public Session[] Fork(int n = 1)
    {
        ThrowIfDisposed();
        var forks = new Session[n];
        for (int i = 0; i < n; i++)
        {
            long handle = Native.SessionFork(_handle);
            if (handle < 0 || handle == 0)
                throw new HttpCloakException("Failed to fork session");
            forks[i] = new Session(handle);
        }
        return forks;
    }

    /// <summary>
    /// Refresh the session by closing all connections while keeping TLS session tickets.
    /// This simulates a browser page refresh - connections are severed but 0-RTT
    /// early data can be used on reconnection due to preserved session tickets.
    /// </summary>
    /// <param name="switchProtocol">Optional protocol to switch to ("h1", "h2", "h3").
    /// Overrides any switchProtocol set at construction time. Persists for future Refresh() calls.</param>
    public void Refresh(string? switchProtocol = null)
    {
        ThrowIfDisposed();
        if (switchProtocol != null)
        {
            IntPtr resultPtr = Native.SessionRefreshProtocol(_handle, switchProtocol);
            if (resultPtr != IntPtr.Zero)
            {
                string? result = Native.PtrToStringAndFree(resultPtr);
                if (!string.IsNullOrEmpty(result))
                {
                    var error = JsonSerializer.Deserialize(result, JsonContext.Default.ErrorResponse);
                    if (error?.Error != null)
                        throw new HttpCloakException(error.Error);
                }
            }
        }
        else
        {
            Native.SessionRefresh(_handle);
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(Session));
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_handle != 0)
            {
                Native.SessionFree(_handle);
                _handle = 0;
            }
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    ~Session()
    {
        Dispose();
    }
}

/// <summary>
/// Cookie from Set-Cookie header.
/// </summary>
public sealed class Cookie
{
    /// <summary>Cookie name.</summary>
    public string Name { get; }

    /// <summary>Cookie value.</summary>
    public string Value { get; }

    internal Cookie(string name, string value)
    {
        Name = name;
        Value = value;
    }

    public override string ToString() => $"Cookie(Name={Name}, Value={Value})";
}

/// <summary>
/// Information about a redirect response.
/// </summary>
public sealed class RedirectInfo
{
    /// <summary>HTTP status code of the redirect.</summary>
    public int StatusCode { get; }

    /// <summary>URL that was requested.</summary>
    public string Url { get; }

    /// <summary>Response headers from the redirect (multi-value).</summary>
    public Dictionary<string, string[]> Headers { get; }

    internal RedirectInfo(int statusCode, string url, Dictionary<string, string[]>? headers)
    {
        StatusCode = statusCode;
        Url = url;
        Headers = headers ?? new Dictionary<string, string[]>();
    }

    /// <summary>Get first value of a header (case-insensitive).</summary>
    public string? GetHeader(string name)
    {
        if (Headers.TryGetValue(name, out var values) && values.Length > 0)
            return values[0];
        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values) && values.Length > 0)
            return values[0];
        return null;
    }

    public override string ToString() => $"RedirectInfo(StatusCode={StatusCode}, Url={Url})";
}

/// <summary>
/// HTTP Response.
/// </summary>
public sealed class Response
{
    private static readonly Dictionary<int, string> HttpStatusPhrases = new()
    {
        { 100, "Continue" }, { 101, "Switching Protocols" }, { 102, "Processing" },
        { 200, "OK" }, { 201, "Created" }, { 202, "Accepted" }, { 203, "Non-Authoritative Information" },
        { 204, "No Content" }, { 205, "Reset Content" }, { 206, "Partial Content" }, { 207, "Multi-Status" },
        { 300, "Multiple Choices" }, { 301, "Moved Permanently" }, { 302, "Found" }, { 303, "See Other" },
        { 304, "Not Modified" }, { 305, "Use Proxy" }, { 307, "Temporary Redirect" }, { 308, "Permanent Redirect" },
        { 400, "Bad Request" }, { 401, "Unauthorized" }, { 402, "Payment Required" }, { 403, "Forbidden" },
        { 404, "Not Found" }, { 405, "Method Not Allowed" }, { 406, "Not Acceptable" },
        { 407, "Proxy Authentication Required" }, { 408, "Request Timeout" }, { 409, "Conflict" },
        { 410, "Gone" }, { 411, "Length Required" }, { 412, "Precondition Failed" },
        { 413, "Payload Too Large" }, { 414, "URI Too Long" }, { 415, "Unsupported Media Type" },
        { 416, "Range Not Satisfiable" }, { 417, "Expectation Failed" }, { 418, "I'm a teapot" },
        { 421, "Misdirected Request" }, { 422, "Unprocessable Entity" }, { 423, "Locked" },
        { 424, "Failed Dependency" }, { 425, "Too Early" }, { 426, "Upgrade Required" },
        { 428, "Precondition Required" }, { 429, "Too Many Requests" },
        { 431, "Request Header Fields Too Large" }, { 451, "Unavailable For Legal Reasons" },
        { 500, "Internal Server Error" }, { 501, "Not Implemented" }, { 502, "Bad Gateway" },
        { 503, "Service Unavailable" }, { 504, "Gateway Timeout" }, { 505, "HTTP Version Not Supported" },
        { 506, "Variant Also Negotiates" }, { 507, "Insufficient Storage" }, { 508, "Loop Detected" },
        { 510, "Not Extended" }, { 511, "Network Authentication Required" },
    };

    internal Response(ResponseData data, TimeSpan elapsed = default)
    {
        StatusCode = data.StatusCode;
        Headers = data.Headers ?? new Dictionary<string, string[]>();
        Text = data.Body ?? "";
        Url = data.FinalUrl ?? "";
        Protocol = data.Protocol ?? "";
        Elapsed = elapsed;

        // Parse cookies from response
        Cookies = data.Cookies?.Select(c => new Cookie(c.Name ?? "", c.Value ?? "")).ToList()
            ?? new List<Cookie>();

        // Parse redirect history
        History = data.History?.Select(h => new RedirectInfo(h.StatusCode, h.Url ?? "", h.Headers)).ToList()
            ?? new List<RedirectInfo>();
    }

    /// <summary>HTTP status code.</summary>
    public int StatusCode { get; }

    /// <summary>Response headers (multi-value). Use GetHeader() for single value access.</summary>
    public Dictionary<string, string[]> Headers { get; }

    /// <summary>Get first value of a header (case-insensitive).</summary>
    /// <param name="name">Header name</param>
    /// <returns>First header value, or null if not found</returns>
    public string? GetHeader(string name)
    {
        // Try exact match first
        if (Headers.TryGetValue(name, out var values) && values.Length > 0)
            return values[0];

        // Try case-insensitive
        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values) && values.Length > 0)
            return values[0];

        return null;
    }

    /// <summary>Get all values of a header (case-insensitive).</summary>
    /// <param name="name">Header name</param>
    /// <returns>All header values, or empty array if not found</returns>
    public string[] GetHeaders(string name)
    {
        // Try exact match first
        if (Headers.TryGetValue(name, out var values))
            return values;

        // Try case-insensitive
        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values))
            return values;

        return Array.Empty<string>();
    }

    /// <summary>Response body as string.</summary>
    public string Text { get; }

    /// <summary>Response body as bytes.</summary>
    public byte[] Content => System.Text.Encoding.UTF8.GetBytes(Text);

    /// <summary>Final URL after redirects.</summary>
    public string Url { get; }

    /// <summary>Protocol used (http/1.1, h2, h3).</summary>
    public string Protocol { get; }

    /// <summary>True if status code is less than 400.</summary>
    public bool Ok => StatusCode < 400;

    /// <summary>Time elapsed for the request.</summary>
    public TimeSpan Elapsed { get; }

    /// <summary>Cookies set by this response.</summary>
    public List<Cookie> Cookies { get; }

    /// <summary>Redirect history (list of RedirectInfo objects).</summary>
    public List<RedirectInfo> History { get; }

    /// <summary>HTTP status reason phrase (e.g., "OK", "Not Found").</summary>
    public string Reason => HttpStatusPhrases.TryGetValue(StatusCode, out var phrase) ? phrase : "Unknown";

    /// <summary>Response encoding from Content-Type header. Null if not specified.</summary>
    public string? Encoding
    {
        get
        {
            string? contentType = GetHeader("Content-Type");
            if (string.IsNullOrEmpty(contentType))
                return null;

            if (contentType.Contains("charset="))
            {
                foreach (var part in contentType.Split(';'))
                {
                    var trimmed = part.Trim();
                    if (trimmed.StartsWith("charset=", StringComparison.OrdinalIgnoreCase))
                    {
                        return trimmed.Substring(8).Trim().Trim('"', '\'');
                    }
                }
            }
            return null;
        }
    }

    /// <summary>Parse response body as JSON.</summary>
    public T? Json<T>() => JsonSerializer.Deserialize<T>(Text);

    /// <summary>Throw if status code indicates an error.</summary>
    public void RaiseForStatus()
    {
        if (!Ok)
            throw new HttpCloakException($"HTTP {StatusCode}: {Reason}");
    }
}

/// <summary>
/// High-performance HTTP Response with direct byte array access.
/// Provides better performance for large downloads by avoiding string conversion overhead.
/// </summary>
/// <example>
/// <code>
/// var response = session.GetFast("https://example.com/large-file.zip");
/// byte[] data = response.Content;  // Direct access to response bytes
/// </code>
/// </example>
public sealed class FastResponse
{
    private static readonly Dictionary<int, string> HttpStatusPhrases = new()
    {
        { 100, "Continue" }, { 101, "Switching Protocols" }, { 102, "Processing" },
        { 200, "OK" }, { 201, "Created" }, { 202, "Accepted" }, { 203, "Non-Authoritative Information" },
        { 204, "No Content" }, { 205, "Reset Content" }, { 206, "Partial Content" }, { 207, "Multi-Status" },
        { 300, "Multiple Choices" }, { 301, "Moved Permanently" }, { 302, "Found" }, { 303, "See Other" },
        { 304, "Not Modified" }, { 305, "Use Proxy" }, { 307, "Temporary Redirect" }, { 308, "Permanent Redirect" },
        { 400, "Bad Request" }, { 401, "Unauthorized" }, { 402, "Payment Required" }, { 403, "Forbidden" },
        { 404, "Not Found" }, { 405, "Method Not Allowed" }, { 406, "Not Acceptable" },
        { 407, "Proxy Authentication Required" }, { 408, "Request Timeout" }, { 409, "Conflict" },
        { 410, "Gone" }, { 411, "Length Required" }, { 412, "Precondition Failed" },
        { 413, "Payload Too Large" }, { 414, "URI Too Long" }, { 415, "Unsupported Media Type" },
        { 416, "Range Not Satisfiable" }, { 417, "Expectation Failed" }, { 418, "I'm a teapot" },
        { 421, "Misdirected Request" }, { 422, "Unprocessable Entity" }, { 423, "Locked" },
        { 424, "Failed Dependency" }, { 425, "Too Early" }, { 426, "Upgrade Required" },
        { 428, "Precondition Required" }, { 429, "Too Many Requests" },
        { 431, "Request Header Fields Too Large" }, { 451, "Unavailable For Legal Reasons" },
        { 500, "Internal Server Error" }, { 501, "Not Implemented" }, { 502, "Bad Gateway" },
        { 503, "Service Unavailable" }, { 504, "Gateway Timeout" }, { 505, "HTTP Version Not Supported" },
        { 506, "Variant Also Negotiates" }, { 507, "Insufficient Storage" }, { 508, "Loop Detected" },
        { 510, "Not Extended" }, { 511, "Network Authentication Required" },
    };

    internal FastResponse(FastResponseMetadata metadata, byte[] content, TimeSpan elapsed = default)
    {
        StatusCode = metadata.StatusCode;
        Headers = metadata.Headers ?? new Dictionary<string, string[]>();
        Content = content;
        Url = metadata.FinalUrl ?? "";
        Protocol = metadata.Protocol ?? "";
        Elapsed = elapsed;

        // Parse cookies from response
        Cookies = metadata.Cookies?.Select(c => new Cookie(c.Name ?? "", c.Value ?? "")).ToList()
            ?? new List<Cookie>();

        // Parse redirect history
        History = metadata.History?.Select(h => new RedirectInfo(h.StatusCode, h.Url ?? "", h.Headers)).ToList()
            ?? new List<RedirectInfo>();
    }

    /// <summary>HTTP status code.</summary>
    public int StatusCode { get; }

    /// <summary>Response headers (multi-value). Use GetHeader() for single value access.</summary>
    public Dictionary<string, string[]> Headers { get; }

    /// <summary>Get first value of a header (case-insensitive).</summary>
    public string? GetHeader(string name)
    {
        if (Headers.TryGetValue(name, out var values) && values.Length > 0)
            return values[0];

        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values) && values.Length > 0)
            return values[0];

        return null;
    }

    /// <summary>Get all values of a header (case-insensitive).</summary>
    public string[] GetHeaders(string name)
    {
        if (Headers.TryGetValue(name, out var values))
            return values;

        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values))
            return values;

        return Array.Empty<string>();
    }

    /// <summary>Response body as bytes (direct access, no copy).</summary>
    public byte[] Content { get; }

    /// <summary>Response body as string (creates a copy).</summary>
    public string Text => System.Text.Encoding.UTF8.GetString(Content);

    /// <summary>Final URL after redirects.</summary>
    public string Url { get; }

    /// <summary>Protocol used (http/1.1, h2, h3).</summary>
    public string Protocol { get; }

    /// <summary>True if status code is less than 400.</summary>
    public bool Ok => StatusCode < 400;

    /// <summary>Time elapsed for the request.</summary>
    public TimeSpan Elapsed { get; }

    /// <summary>Cookies set by this response.</summary>
    public List<Cookie> Cookies { get; }

    /// <summary>Redirect history (list of RedirectInfo objects).</summary>
    public List<RedirectInfo> History { get; }

    /// <summary>HTTP status reason phrase (e.g., "OK", "Not Found").</summary>
    public string Reason => HttpStatusPhrases.TryGetValue(StatusCode, out var phrase) ? phrase : "Unknown";

    /// <summary>Response encoding from Content-Type header. Null if not specified.</summary>
    public string? Encoding
    {
        get
        {
            string? contentType = GetHeader("Content-Type");
            if (string.IsNullOrEmpty(contentType))
                return null;

            if (contentType.Contains("charset="))
            {
                foreach (var part in contentType.Split(';'))
                {
                    var trimmed = part.Trim();
                    if (trimmed.StartsWith("charset=", StringComparison.OrdinalIgnoreCase))
                    {
                        return trimmed.Substring(8).Trim().Trim('"', '\'');
                    }
                }
            }
            return null;
        }
    }

    /// <summary>Parse response body as JSON.</summary>
    public T? Json<T>() => JsonSerializer.Deserialize<T>(Text);

    /// <summary>Throw if status code indicates an error.</summary>
    public void RaiseForStatus()
    {
        if (!Ok)
            throw new HttpCloakException($"HTTP {StatusCode}: {Reason}");
    }
}

/// <summary>
/// Exception thrown by HttpCloak operations.
/// </summary>
public class HttpCloakException : Exception
{
    public HttpCloakException(string message) : base(message) { }
}

/// <summary>
/// Streaming HTTP Response for downloading large files.
/// Implements IDisposable for proper resource cleanup.
/// </summary>
/// <example>
/// <code>
/// using var stream = session.GetStream("https://example.com/large-file.zip");
/// foreach (var chunk in stream.ReadChunks())
/// {
///     file.Write(chunk);
/// }
/// // Or use as a standard Stream:
/// using var contentStream = stream.GetContentStream();
/// await contentStream.CopyToAsync(fileStream);
/// </code>
/// </example>
public sealed class StreamResponse : IDisposable
{
    private static readonly Dictionary<int, string> HttpStatusPhrases = new()
    {
        { 100, "Continue" }, { 101, "Switching Protocols" }, { 102, "Processing" },
        { 200, "OK" }, { 201, "Created" }, { 202, "Accepted" },
        { 204, "No Content" }, { 206, "Partial Content" },
        { 301, "Moved Permanently" }, { 302, "Found" }, { 304, "Not Modified" },
        { 400, "Bad Request" }, { 401, "Unauthorized" }, { 403, "Forbidden" },
        { 404, "Not Found" }, { 405, "Method Not Allowed" }, { 408, "Request Timeout" },
        { 429, "Too Many Requests" },
        { 500, "Internal Server Error" }, { 502, "Bad Gateway" },
        { 503, "Service Unavailable" }, { 504, "Gateway Timeout" },
    };

    private readonly long _handle;
    private bool _disposed;
    private HttpCloakContentStream? _contentStream;

    internal StreamResponse(long handle, StreamMetadata metadata)
    {
        _handle = handle;
        StatusCode = metadata.StatusCode;
        Headers = metadata.Headers ?? new Dictionary<string, string[]>();
        Url = metadata.FinalUrl ?? "";
        Protocol = metadata.Protocol ?? "";
        ContentLength = metadata.ContentLength;
        Cookies = metadata.Cookies?.Select(c => new Cookie(c.Name ?? "", c.Value ?? "")).ToList()
            ?? new List<Cookie>();
    }

    /// <summary>HTTP status code.</summary>
    public int StatusCode { get; }

    /// <summary>Response headers (multi-value). Use GetHeader() for single value access.</summary>
    public Dictionary<string, string[]> Headers { get; }

    /// <summary>Final URL after redirects.</summary>
    public string Url { get; }

    /// <summary>Protocol used (h1, h2, h3).</summary>
    public string Protocol { get; }

    /// <summary>Expected content length, or -1 if unknown (chunked).</summary>
    public long ContentLength { get; }

    /// <summary>Cookies set by this response.</summary>
    public List<Cookie> Cookies { get; }

    /// <summary>True if status code is less than 400.</summary>
    public bool Ok => StatusCode < 400;

    /// <summary>HTTP status reason phrase.</summary>
    public string Reason => HttpStatusPhrases.TryGetValue(StatusCode, out var phrase) ? phrase : "Unknown";

    /// <summary>Get first value of a header (case-insensitive).</summary>
    /// <param name="name">Header name</param>
    /// <returns>First header value, or null if not found</returns>
    public string? GetHeader(string name)
    {
        if (Headers.TryGetValue(name, out var values) && values.Length > 0)
            return values[0];
        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values) && values.Length > 0)
            return values[0];
        return null;
    }

    /// <summary>Get all values of a header (case-insensitive).</summary>
    /// <param name="name">Header name</param>
    /// <returns>All header values, or empty array if not found</returns>
    public string[] GetHeaders(string name)
    {
        if (Headers.TryGetValue(name, out var values))
            return values;
        var key = Headers.Keys.FirstOrDefault(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (key != null && Headers.TryGetValue(key, out values))
            return values;
        return Array.Empty<string>();
    }

    /// <summary>
    /// Read a chunk of data from the stream.
    /// </summary>
    /// <param name="chunkSize">Maximum bytes to read (default: 8192)</param>
    /// <returns>Chunk of data, or null if EOF</returns>
    public byte[]? ReadChunk(int chunkSize = 8192)
    {
        ThrowIfDisposed();

        IntPtr resultPtr = Native.StreamRead(_handle, chunkSize);
        string? base64 = Native.PtrToStringAndFree(resultPtr);

        if (string.IsNullOrEmpty(base64))
            return null; // EOF

        return Convert.FromBase64String(base64);
    }

    /// <summary>
    /// Enumerate chunks from the response.
    /// </summary>
    /// <param name="chunkSize">Size of each chunk (default: 8192)</param>
    /// <returns>Enumerable of byte arrays</returns>
    public IEnumerable<byte[]> ReadChunks(int chunkSize = 8192)
    {
        while (true)
        {
            var chunk = ReadChunk(chunkSize);
            if (chunk == null)
                yield break;
            yield return chunk;
        }
    }

    /// <summary>
    /// Get a standard System.IO.Stream for the response body.
    /// Ideal for use with HttpClient, StreamContent, or CopyToAsync.
    /// Note: The stream will be disposed when the StreamResponse is disposed.
    /// </summary>
    /// <param name="bufferSize">Internal buffer size (default: 65536)</param>
    /// <returns>A readable Stream wrapping the response body</returns>
    /// <example>
    /// <code>
    /// using var streamResponse = session.GetStream("https://example.com/file");
    /// using var contentStream = streamResponse.GetContentStream();
    ///
    /// // Use with HttpResponseMessage
    /// var response = new HttpResponseMessage { Content = new StreamContent(contentStream) };
    ///
    /// // Or copy to file
    /// await contentStream.CopyToAsync(fileStream);
    /// </code>
    /// </example>
    public Stream GetContentStream(int bufferSize = 65536)
    {
        ThrowIfDisposed();
        if (_contentStream != null)
            throw new InvalidOperationException("GetContentStream can only be called once per StreamResponse");

        _contentStream = new HttpCloakContentStream(this, bufferSize);
        return _contentStream;
    }

    /// <summary>
    /// Read the entire response body as bytes.
    /// Warning: This defeats the purpose of streaming for large files.
    /// </summary>
    public byte[] ReadAll()
    {
        using var ms = new MemoryStream();
        foreach (var chunk in ReadChunks())
        {
            ms.Write(chunk, 0, chunk.Length);
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Read the entire response body as a string.
    /// </summary>
    public string Text => System.Text.Encoding.UTF8.GetString(ReadAll());

    /// <summary>
    /// Parse the response body as JSON.
    /// </summary>
    public T? Json<T>() => JsonSerializer.Deserialize<T>(Text);

    /// <summary>
    /// Throw if status code indicates an error.
    /// </summary>
    public void RaiseForStatus()
    {
        if (!Ok)
            throw new HttpCloakException($"HTTP {StatusCode}: {Reason}");
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(StreamResponse));
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _contentStream?.MarkParentDisposed();
            Native.StreamClose(_handle);
            _disposed = true;
        }
    }
}

/// <summary>
/// A Stream wrapper around StreamResponse for standard .NET streaming APIs.
/// Enables use with HttpClient, StreamContent, CopyToAsync, etc.
/// </summary>
public sealed class HttpCloakContentStream : Stream
{
    private readonly StreamResponse _parent;
    private readonly int _bufferSize;
    private byte[]? _buffer;
    private int _bufferPos;
    private int _bufferLen;
    private bool _eof;
    private bool _parentDisposed;
    private long _position;

    internal HttpCloakContentStream(StreamResponse parent, int bufferSize)
    {
        _parent = parent;
        _bufferSize = bufferSize;
    }

    internal void MarkParentDisposed() => _parentDisposed = true;

    public override bool CanRead => !_parentDisposed;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _parent.ContentLength;
    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException("Seeking is not supported");
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_parentDisposed)
            throw new ObjectDisposedException(nameof(HttpCloakContentStream));
        if (_eof)
            return 0;

        int totalRead = 0;

        while (count > 0)
        {
            // If buffer is empty, fetch more data
            if (_buffer == null || _bufferPos >= _bufferLen)
            {
                var chunk = _parent.ReadChunk(_bufferSize);
                if (chunk == null || chunk.Length == 0)
                {
                    _eof = true;
                    break;
                }
                _buffer = chunk;
                _bufferPos = 0;
                _bufferLen = chunk.Length;
            }

            // Copy from buffer to output
            int available = _bufferLen - _bufferPos;
            int toCopy = Math.Min(available, count);
            Array.Copy(_buffer, _bufferPos, buffer, offset, toCopy);
            _bufferPos += toCopy;
            offset += toCopy;
            count -= toCopy;
            totalRead += toCopy;
            _position += toCopy;
        }

        return totalRead;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        // The underlying native call is synchronous, so we just wrap it
        return await Task.Run(() => Read(buffer, offset, count), cancellationToken);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// Available browser presets.
/// </summary>
public static class Presets
{
    public const string Chrome145 = "chrome-145";
    public const string Chrome145Windows = "chrome-145-windows";
    public const string Chrome145Linux = "chrome-145-linux";
    public const string Chrome145MacOS = "chrome-145-macos";
    public const string Chrome144 = "chrome-144";
    public const string Chrome144Windows = "chrome-144-windows";
    public const string Chrome144Linux = "chrome-144-linux";
    public const string Chrome144MacOS = "chrome-144-macos";
    public const string Chrome143 = "chrome-143";
    public const string Chrome143Windows = "chrome-143-windows";
    public const string Chrome143Linux = "chrome-143-linux";
    public const string Chrome143MacOS = "chrome-143-macos";
    public const string Chrome141 = "chrome-141";
    public const string Chrome133 = "chrome-133";
    public const string Firefox133 = "firefox-133";
    public const string Safari18 = "safari-18";
    public const string Chrome143Ios = "chrome-143-ios";
    public const string Chrome144Ios = "chrome-144-ios";
    public const string Chrome145Ios = "chrome-145-ios";
    public const string Safari17Ios = "safari-17-ios";
    public const string Safari18Ios = "safari-18-ios";
    public const string Chrome143Android = "chrome-143-android";
    public const string Chrome144Android = "chrome-144-android";
    public const string Chrome145Android = "chrome-145-android";

    // Backwards compatibility aliases (old naming convention)
    public const string IosChrome143 = Chrome143Ios;
    public const string IosChrome144 = Chrome144Ios;
    public const string IosChrome145 = Chrome145Ios;
    public const string IosSafari17 = Safari17Ios;
    public const string IosSafari18 = Safari18Ios;
    public const string AndroidChrome143 = Chrome143Android;
    public const string AndroidChrome144 = Chrome144Android;
    public const string AndroidChrome145 = Chrome145Android;
}

/// <summary>
/// HttpCloak utility functions.
/// </summary>
public static class HttpCloakInfo
{
    /// <summary>Get the native library version.</summary>
    public static string Version()
    {
        IntPtr ptr = Native.Version();
        return Native.PtrToStringAndFree(ptr) ?? "unknown";
    }

    /// <summary>Get available presets with their supported protocols.</summary>
    /// <returns>Dictionary mapping preset names to their protocol support info.</returns>
    public static Dictionary<string, PresetInfo> AvailablePresets()
    {
        IntPtr ptr = Native.AvailablePresets();
        string? json = Native.PtrToStringAndFree(ptr);

        if (string.IsNullOrEmpty(json))
            return new Dictionary<string, PresetInfo>();

        return JsonSerializer.Deserialize(json, JsonContext.Default.DictionaryStringPresetInfo)
            ?? new Dictionary<string, PresetInfo>();
    }

    /// <summary>
    /// Configure the DNS servers used for ECH (Encrypted Client Hello) config queries.
    /// By default, ECH queries use Google (8.8.8.8), Cloudflare (1.1.1.1), and Quad9 (9.9.9.9).
    /// This is a global setting that affects all sessions.
    /// </summary>
    /// <param name="servers">
    /// Array of DNS server addresses in "host:port" format (e.g., "10.0.0.53:53").
    /// Pass null or empty array to reset to defaults.
    /// </param>
    /// <exception cref="HttpCloakException">Thrown if the servers list is invalid.</exception>
    public static void SetEchDnsServers(string[]? servers)
    {
        string? serversJson = null;
        if (servers != null && servers.Length > 0)
        {
            serversJson = JsonSerializer.Serialize(servers, JsonContext.Relaxed.StringArray);
        }

        IntPtr errorPtr = Native.SetEchDnsServers(serversJson);
        string? error = Native.PtrToStringAndFree(errorPtr);
        if (!string.IsNullOrEmpty(error))
        {
            throw new HttpCloakException($"Failed to set ECH DNS servers: {error}");
        }
    }

    /// <summary>
    /// Get the current DNS servers used for ECH (Encrypted Client Hello) config queries.
    /// </summary>
    /// <returns>Array of DNS server addresses in "host:port" format.</returns>
    public static string[] GetEchDnsServers()
    {
        IntPtr ptr = Native.GetEchDnsServers();
        string? json = Native.PtrToStringAndFree(ptr);

        if (string.IsNullOrEmpty(json))
            return Array.Empty<string>();

        return JsonSerializer.Deserialize(json, JsonContext.Default.StringArray) ?? Array.Empty<string>();
    }
}

// Internal types for JSON serialization
internal class SessionConfig
{
    [JsonPropertyName("preset")]
    public string Preset { get; set; } = "chrome-145";

    [JsonPropertyName("proxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Proxy { get; set; }

    [JsonPropertyName("tcp_proxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TcpProxy { get; set; }

    [JsonPropertyName("udp_proxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UdpProxy { get; set; }

    [JsonPropertyName("timeout")]
    public int Timeout { get; set; } = 30;

    [JsonPropertyName("http_version")]
    public string HttpVersion { get; set; } = "auto";

    [JsonPropertyName("verify")]
    public bool Verify { get; set; } = true;

    [JsonPropertyName("allow_redirects")]
    public bool AllowRedirects { get; set; } = true;

    [JsonPropertyName("max_redirects")]
    public int MaxRedirects { get; set; } = 10;

    [JsonPropertyName("retry")]
    public int Retry { get; set; }

    [JsonPropertyName("retry_on_status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int[]? RetryOnStatus { get; set; }

    [JsonPropertyName("retry_wait_min")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int RetryWaitMin { get; set; } = 500;

    [JsonPropertyName("retry_wait_max")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int RetryWaitMax { get; set; } = 10000;

    [JsonPropertyName("prefer_ipv4")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool PreferIpv4 { get; set; }

    [JsonPropertyName("connect_to")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? ConnectTo { get; set; }

    [JsonPropertyName("ech_config_domain")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EchConfigDomain { get; set; }

    [JsonPropertyName("tls_only")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool TlsOnly { get; set; }

    [JsonPropertyName("quic_idle_timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public int QuicIdleTimeout { get; set; }

    [JsonPropertyName("local_address")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LocalAddress { get; set; }

    [JsonPropertyName("key_log_file")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeyLogFile { get; set; }

    [JsonPropertyName("enable_speculative_tls")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool EnableSpeculativeTls { get; set; }

    [JsonPropertyName("switch_protocol")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SwitchProtocol { get; set; }

    [JsonPropertyName("ja3")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Ja3 { get; set; }

    [JsonPropertyName("akamai")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Akamai { get; set; }

    [JsonPropertyName("extra_fp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, object>? ExtraFp { get; set; }
}

internal class RequestConfig
{
    [JsonPropertyName("method")]
    public string Method { get; set; } = "GET";

    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    [JsonPropertyName("headers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Headers { get; set; }

    [JsonPropertyName("body")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Body { get; set; }

    [JsonPropertyName("body_encoding")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BodyEncoding { get; set; }

    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Timeout { get; set; }
}

internal class CookieData
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("value")]
    public string? Value { get; set; }
}

internal class RedirectInfoData
{
    [JsonPropertyName("status_code")]
    public int StatusCode { get; set; }

    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string[]>? Headers { get; set; }
}

internal class ResponseData
{
    [JsonPropertyName("status_code")]
    public int StatusCode { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string[]>? Headers { get; set; }

    [JsonPropertyName("body")]
    public string? Body { get; set; }

    [JsonPropertyName("final_url")]
    public string? FinalUrl { get; set; }

    [JsonPropertyName("protocol")]
    public string? Protocol { get; set; }

    [JsonPropertyName("cookies")]
    public List<CookieData>? Cookies { get; set; }

    [JsonPropertyName("history")]
    public List<RedirectInfoData>? History { get; set; }
}

/// <summary>
/// Metadata for fast/raw responses (excludes body which is handled separately).
/// </summary>
internal class FastResponseMetadata
{
    [JsonPropertyName("status_code")]
    public int StatusCode { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string[]>? Headers { get; set; }

    [JsonPropertyName("body_len")]
    public int BodyLen { get; set; }

    [JsonPropertyName("final_url")]
    public string? FinalUrl { get; set; }

    [JsonPropertyName("protocol")]
    public string? Protocol { get; set; }

    [JsonPropertyName("cookies")]
    public List<CookieData>? Cookies { get; set; }

    [JsonPropertyName("history")]
    public List<RedirectInfoData>? History { get; set; }
}

internal class ErrorResponse
{
    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

/// <summary>
/// Protocol support information for a browser preset.
/// </summary>
public class PresetInfo
{
    [JsonPropertyName("protocols")]
    public string[] Protocols { get; set; } = Array.Empty<string>();
}

/// <summary>
/// Request options for async requests (matches Go's RequestOptions struct).
/// </summary>
internal class RequestOptions
{
    [JsonPropertyName("headers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Headers { get; set; }

    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Timeout { get; set; }
}

internal class StreamOptions
{
    [JsonPropertyName("headers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Headers { get; set; }

    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Timeout { get; set; }
}

internal class StreamMetadata
{
    [JsonPropertyName("status_code")]
    public int StatusCode { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string[]>? Headers { get; set; }

    [JsonPropertyName("final_url")]
    public string? FinalUrl { get; set; }

    [JsonPropertyName("protocol")]
    public string? Protocol { get; set; }

    [JsonPropertyName("content_length")]
    public long ContentLength { get; set; }

    [JsonPropertyName("cookies")]
    public List<CookieData>? Cookies { get; set; }
}

/// <summary>
/// HttpMessageHandler implementation that routes all requests through httpcloak via LocalProxy.
/// Use this with HttpClient to get browser fingerprint impersonation for all requests.
///
/// This handler uses LocalProxy internally for TRUE streaming - request and response bodies
/// are streamed through TCP without being buffered in memory.
/// </summary>
/// <example>
/// <code>
/// // Create handler with browser fingerprint
/// using var handler = new HttpCloakHandler(preset: "chrome-145");
/// using var client = new HttpClient(handler);
///
/// // All requests now go through httpcloak with TLS fingerprinting
/// // TRUE streaming - no memory buffering!
/// var response = await client.GetAsync("https://example.com");
/// var content = await response.Content.ReadAsStringAsync();
/// </code>
/// </example>
public sealed class HttpCloakHandler : DelegatingHandler
{
    private readonly LocalProxy _proxy;
    private readonly bool _ownsProxy;
    private bool _disposed;

    /// <summary>
    /// Create a new HttpCloakHandler with the specified options.
    /// Uses LocalProxy internally for true streaming support.
    /// </summary>
    /// <param name="preset">Browser preset (default: "chrome-145")</param>
    /// <param name="proxy">Upstream proxy URL (e.g., "http://user:pass@host:port" or "socks5://host:port")</param>
    /// <param name="tcpProxy">Upstream proxy URL for TCP protocols (HTTP/1.1, HTTP/2)</param>
    /// <param name="udpProxy">Upstream proxy URL for UDP protocols (HTTP/3 via MASQUE)</param>
    /// <param name="timeout">Request timeout in seconds (default: 30)</param>
    /// <param name="maxConnections">Maximum concurrent connections (default: 1000)</param>
    public HttpCloakHandler(
        string preset = "chrome-145",
        string? proxy = null,
        string? tcpProxy = null,
        string? udpProxy = null,
        int timeout = 30,
        int maxConnections = 1000)
    {
        _proxy = new LocalProxy(
            port: 0,
            preset: preset,
            timeout: timeout,
            maxConnections: maxConnections,
            tcpProxy: tcpProxy ?? proxy,
            udpProxy: udpProxy ?? proxy);
        _ownsProxy = true;

        // Set up inner handler to use the local proxy
        InnerHandler = new HttpClientHandler
        {
            Proxy = _proxy.CreateWebProxy(),
            UseProxy = true
        };
    }

    /// <summary>
    /// Create a new HttpCloakHandler with an existing LocalProxy.
    /// The LocalProxy will NOT be disposed when the handler is disposed.
    /// </summary>
    /// <param name="proxy">Existing LocalProxy to use</param>
    public HttpCloakHandler(LocalProxy proxy)
    {
        _proxy = proxy ?? throw new ArgumentNullException(nameof(proxy));
        _ownsProxy = false;

        // Set up inner handler to use the local proxy
        InnerHandler = new HttpClientHandler
        {
            Proxy = _proxy.CreateWebProxy(),
            UseProxy = true
        };
    }

    /// <summary>
    /// Gets the underlying LocalProxy for advanced configuration.
    /// </summary>
    public LocalProxy Proxy => _proxy;

    /// <summary>
    /// Gets the proxy URL that requests are routed through.
    /// </summary>
    public string ProxyUrl => _proxy.ProxyUrl;

    /// <summary>
    /// Gets statistics about the proxy.
    /// </summary>
    public LocalProxyStats GetStats() => _proxy.GetStats();

    /// <inheritdoc/>
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(HttpCloakHandler));

        // Just pass through - LocalProxy handles TLS fingerprinting
        // HttpClient handles cookies, decompression, redirects natively
        // TRUE streaming - no memory buffering!
        return base.SendAsync(request, cancellationToken);
    }

    /// <inheritdoc/>
    protected override HttpResponseMessage Send(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(HttpCloakHandler));

        // Synchronous version
        return base.Send(request, cancellationToken);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing && _ownsProxy)
            {
                _proxy.Dispose();
            }
            _disposed = true;
        }
        base.Dispose(disposing);
    }
}

[JsonSerializable(typeof(SessionConfig))]
[JsonSerializable(typeof(RequestConfig))]
[JsonSerializable(typeof(ResponseData))]
[JsonSerializable(typeof(FastResponseMetadata))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(CookieData))]
[JsonSerializable(typeof(RedirectInfoData))]
[JsonSerializable(typeof(List<CookieData>))]
[JsonSerializable(typeof(List<RedirectInfoData>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(Dictionary<string, string[]>))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(RequestOptions))]
[JsonSerializable(typeof(StreamOptions))]
[JsonSerializable(typeof(StreamMetadata))]
[JsonSerializable(typeof(PresetInfo))]
[JsonSerializable(typeof(Dictionary<string, PresetInfo>))]
internal partial class JsonContext : JsonSerializerContext
{
    /// <summary>
    /// JsonContext with UnsafeRelaxedJsonEscaping to preserve raw characters like &amp;, +, &lt;, &gt; in request bodies.
    /// Without this, C#'s default encoder escapes them as \u0026, \u002B, etc., which can cause payload issues.
    /// </summary>
    private static readonly Lazy<JsonContext> _relaxed = new(() =>
        new JsonContext(new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }));

    public static JsonContext Relaxed => _relaxed.Value;
}
