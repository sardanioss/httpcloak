using System.Collections.Concurrent;
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
    /// </summary>
    public (long CallbackId, Task<Response> Task) RegisterRequest()
    {
        var tcs = new TaskCompletionSource<Response>(TaskCreationOptions.RunContinuationsAsynchronously);

        // Register callback with Go - each request gets unique ID
        long callbackId = Native.RegisterCallback(_callback);

        _pendingRequests[callbackId] = tcs;

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
    /// Default auth (username, password) for all requests.
    /// Can be overridden per-request.
    /// </summary>
    public (string Username, string Password)? Auth { get; set; }

    /// <summary>
    /// Create a new session with the specified options.
    /// </summary>
    /// <param name="preset">Browser preset (default: "chrome-143")</param>
    /// <param name="proxy">Proxy URL (e.g., "http://user:pass@host:port" or "socks5://host:port")</param>
    /// <param name="timeout">Request timeout in seconds (default: 30)</param>
    /// <param name="httpVersion">HTTP version: "auto", "h1", "h2", "h3" (default: "auto")</param>
    /// <param name="verify">SSL certificate verification (default: true)</param>
    /// <param name="allowRedirects">Follow redirects (default: true)</param>
    /// <param name="maxRedirects">Maximum number of redirects (default: 10)</param>
    /// <param name="retry">Number of retries on failure (default: 0)</param>
    /// <param name="preferIpv4">Prefer IPv4 addresses over IPv6 (default: false)</param>
    /// <param name="auth">Default auth (username, password) for all requests</param>
    /// <param name="connectTo">Domain fronting map (requestHost -> connectHost)</param>
    /// <param name="echConfigDomain">Domain to fetch ECH config from (e.g., "cloudflare-ech.com")</param>
    public Session(
        string preset = "chrome-143",
        string? proxy = null,
        int timeout = 30,
        string httpVersion = "auto",
        bool verify = true,
        bool allowRedirects = true,
        int maxRedirects = 10,
        int retry = 0,
        bool preferIpv4 = false,
        (string Username, string Password)? auth = null,
        Dictionary<string, string>? connectTo = null,
        string? echConfigDomain = null)
    {
        Auth = auth;

        var config = new SessionConfig
        {
            Preset = preset,
            Proxy = proxy,
            Timeout = timeout,
            HttpVersion = httpVersion,
            Verify = verify,
            AllowRedirects = allowRedirects,
            MaxRedirects = maxRedirects,
            Retry = retry,
            PreferIpv4 = preferIpv4,
            ConnectTo = connectTo,
            EchConfigDomain = echConfigDomain
        };

        string configJson = JsonSerializer.Serialize(config, JsonContext.Default.SessionConfig);
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
    /// Perform a GET request.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    public Response Get(string url, Dictionary<string, string>? headers = null, (string, string)? auth = null)
    {
        ThrowIfDisposed();

        headers = ApplyAuth(headers, auth);
        string? headersJson = headers.Count > 0
            ? JsonSerializer.Serialize(headers, JsonContext.Default.DictionaryStringString)
            : null;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        IntPtr resultPtr = Native.Get(_handle, url, headersJson);
        stopwatch.Stop();

        return ParseResponse(resultPtr, stopwatch.Elapsed);
    }

    /// <summary>
    /// Perform a POST request.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    public Response Post(string url, string? body = null, Dictionary<string, string>? headers = null, (string, string)? auth = null)
    {
        ThrowIfDisposed();

        headers = ApplyAuth(headers, auth);
        string? headersJson = headers.Count > 0
            ? JsonSerializer.Serialize(headers, JsonContext.Default.DictionaryStringString)
            : null;

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        IntPtr resultPtr = Native.Post(_handle, url, body, headersJson);
        stopwatch.Stop();

        return ParseResponse(resultPtr, stopwatch.Elapsed);
    }

    /// <summary>
    /// Perform a POST request with JSON body.
    /// </summary>
    public Response PostJson<T>(string url, T data, Dictionary<string, string>? headers = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data);
        return Post(url, body, headers);
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
    public Response Request(string method, string url, string? body = null, Dictionary<string, string>? headers = null, int? timeout = null, (string, string)? auth = null)
    {
        ThrowIfDisposed();

        headers = ApplyAuth(headers, auth);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Body = body,
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Default.RequestConfig);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        IntPtr resultPtr = Native.Request(_handle, requestJson);
        stopwatch.Stop();

        return ParseResponse(resultPtr, stopwatch.Elapsed);
    }

    /// <summary>
    /// Perform a PUT request.
    /// </summary>
    public Response Put(string url, string? body = null, Dictionary<string, string>? headers = null)
        => Request("PUT", url, body, headers);

    /// <summary>
    /// Perform a DELETE request.
    /// </summary>
    public Response Delete(string url, Dictionary<string, string>? headers = null)
        => Request("DELETE", url, null, headers);

    /// <summary>
    /// Perform a PATCH request.
    /// </summary>
    public Response Patch(string url, string? body = null, Dictionary<string, string>? headers = null)
        => Request("PATCH", url, body, headers);

    /// <summary>
    /// Perform a HEAD request.
    /// </summary>
    public Response Head(string url, Dictionary<string, string>? headers = null)
        => Request("HEAD", url, null, headers);

    // =========================================================================
    // Async Methods (Native - using Go goroutines)
    // =========================================================================

    /// <summary>
    /// Perform an async GET request using native Go goroutines.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    public Task<Response> GetAsync(string url, Dictionary<string, string>? headers = null, (string, string)? auth = null)
    {
        ThrowIfDisposed();

        headers = ApplyAuth(headers, auth);
        string? headersJson = headers.Count > 0
            ? JsonSerializer.Serialize(headers, JsonContext.Default.DictionaryStringString)
            : null;

        var (callbackId, task) = AsyncCallbackManager.Instance.RegisterRequest();
        Native.GetAsync(_handle, url, headersJson, callbackId);

        return task;
    }

    /// <summary>
    /// Perform an async POST request using native Go goroutines.
    /// </summary>
    /// <param name="url">Request URL</param>
    /// <param name="body">Request body</param>
    /// <param name="headers">Custom headers</param>
    /// <param name="auth">Basic auth (username, password). If null, uses session Auth.</param>
    public Task<Response> PostAsync(string url, string? body = null, Dictionary<string, string>? headers = null, (string, string)? auth = null)
    {
        ThrowIfDisposed();

        headers = ApplyAuth(headers, auth);
        string? headersJson = headers.Count > 0
            ? JsonSerializer.Serialize(headers, JsonContext.Default.DictionaryStringString)
            : null;

        var (callbackId, task) = AsyncCallbackManager.Instance.RegisterRequest();
        Native.PostAsync(_handle, url, body, headersJson, callbackId);

        return task;
    }

    /// <summary>
    /// Perform an async POST request with JSON body using native Go goroutines.
    /// </summary>
    public Task<Response> PostJsonAsync<T>(string url, T data, Dictionary<string, string>? headers = null)
    {
        headers ??= new Dictionary<string, string>();
        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/json";

        string body = JsonSerializer.Serialize(data);
        return PostAsync(url, body, headers);
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
    public Task<Response> RequestAsync(string method, string url, string? body = null, Dictionary<string, string>? headers = null, int? timeout = null, (string, string)? auth = null)
    {
        ThrowIfDisposed();

        headers = ApplyAuth(headers, auth);

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Body = body,
            Headers = headers.Count > 0 ? headers : null,
            Timeout = timeout
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Default.RequestConfig);

        var (callbackId, task) = AsyncCallbackManager.Instance.RegisterRequest();
        Native.RequestAsync(_handle, requestJson, callbackId);

        return task;
    }

    /// <summary>
    /// Perform an async PUT request using native Go goroutines.
    /// </summary>
    public Task<Response> PutAsync(string url, string? body = null, Dictionary<string, string>? headers = null)
        => RequestAsync("PUT", url, body, headers);

    /// <summary>
    /// Perform an async DELETE request using native Go goroutines.
    /// </summary>
    public Task<Response> DeleteAsync(string url, Dictionary<string, string>? headers = null)
        => RequestAsync("DELETE", url, null, headers);

    /// <summary>
    /// Perform an async PATCH request using native Go goroutines.
    /// </summary>
    public Task<Response> PatchAsync(string url, string? body = null, Dictionary<string, string>? headers = null)
        => RequestAsync("PATCH", url, body, headers);

    /// <summary>
    /// Perform an async HEAD request using native Go goroutines.
    /// </summary>
    public Task<Response> HeadAsync(string url, Dictionary<string, string>? headers = null)
        => RequestAsync("HEAD", url, null, headers);

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
        }
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

    /// <summary>Response headers from the redirect.</summary>
    public Dictionary<string, string> Headers { get; }

    internal RedirectInfo(int statusCode, string url, Dictionary<string, string>? headers)
    {
        StatusCode = statusCode;
        Url = url;
        Headers = headers ?? new Dictionary<string, string>();
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
        Headers = data.Headers ?? new Dictionary<string, string>();
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

    /// <summary>Response headers.</summary>
    public Dictionary<string, string> Headers { get; }

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
            string contentType = "";
            if (Headers.TryGetValue("content-type", out var ct))
                contentType = ct;
            else if (Headers.TryGetValue("Content-Type", out ct))
                contentType = ct;

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
/// Available browser presets.
/// </summary>
public static class Presets
{
    public const string Chrome143 = "chrome-143";
    public const string Chrome143Windows = "chrome-143-windows";
    public const string Chrome143Linux = "chrome-143-linux";
    public const string Chrome143MacOS = "chrome-143-macos";
    public const string Chrome131 = "chrome-131";
    public const string Firefox133 = "firefox-133";
    public const string Safari18 = "safari-18";
    public const string IosChrome143 = "ios-chrome-143";
    public const string IosSafari17 = "ios-safari-17";
    public const string AndroidChrome143 = "android-chrome-143";
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

    /// <summary>Get list of available presets.</summary>
    public static string[] AvailablePresets()
    {
        IntPtr ptr = Native.AvailablePresets();
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
    public string Preset { get; set; } = "chrome-143";

    [JsonPropertyName("proxy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Proxy { get; set; }

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

    [JsonPropertyName("prefer_ipv4")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool PreferIpv4 { get; set; }

    [JsonPropertyName("connect_to")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? ConnectTo { get; set; }

    [JsonPropertyName("ech_config_domain")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EchConfigDomain { get; set; }
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
    public Dictionary<string, string>? Headers { get; set; }
}

internal class ResponseData
{
    [JsonPropertyName("status_code")]
    public int StatusCode { get; set; }

    [JsonPropertyName("headers")]
    public Dictionary<string, string>? Headers { get; set; }

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

internal class ErrorResponse
{
    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

[JsonSerializable(typeof(SessionConfig))]
[JsonSerializable(typeof(RequestConfig))]
[JsonSerializable(typeof(ResponseData))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(CookieData))]
[JsonSerializable(typeof(RedirectInfoData))]
[JsonSerializable(typeof(List<CookieData>))]
[JsonSerializable(typeof(List<RedirectInfoData>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(string[]))]
internal partial class JsonContext : JsonSerializerContext { }
