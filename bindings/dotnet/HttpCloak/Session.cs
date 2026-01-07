using System.Text.Json;
using System.Text.Json.Serialization;

namespace HttpCloak;

/// <summary>
/// HTTP Session with browser fingerprint emulation.
/// Maintains cookies and connection state across requests.
/// </summary>
public sealed class Session : IDisposable
{
    private long _handle;
    private bool _disposed;

    /// <summary>
    /// Create a new session with the specified options.
    /// </summary>
    /// <param name="preset">Browser preset (default: "chrome-143")</param>
    /// <param name="proxy">Proxy URL (e.g., "http://user:pass@host:port")</param>
    /// <param name="timeout">Request timeout in seconds (default: 30)</param>
    /// <param name="httpVersion">HTTP version: "auto", "h1", "h2", "h3" (default: "auto")</param>
    /// <param name="verify">SSL certificate verification (default: true)</param>
    /// <param name="allowRedirects">Follow redirects (default: true)</param>
    /// <param name="maxRedirects">Maximum number of redirects (default: 10)</param>
    /// <param name="retry">Number of retries on failure (default: 0)</param>
    public Session(
        string preset = "chrome-143",
        string? proxy = null,
        int timeout = 30,
        string httpVersion = "auto",
        bool verify = true,
        bool allowRedirects = true,
        int maxRedirects = 10,
        int retry = 0)
    {
        var config = new SessionConfig
        {
            Preset = preset,
            Proxy = proxy,
            Timeout = timeout,
            HttpVersion = httpVersion,
            Verify = verify,
            AllowRedirects = allowRedirects,
            MaxRedirects = maxRedirects,
            Retry = retry
        };

        string configJson = JsonSerializer.Serialize(config, JsonContext.Default.SessionConfig);
        _handle = Native.SessionNew(configJson);

        if (_handle == 0)
            throw new HttpCloakException("Failed to create session");
    }

    /// <summary>
    /// Perform a GET request.
    /// </summary>
    public Response Get(string url, Dictionary<string, string>? headers = null)
    {
        ThrowIfDisposed();

        string? headersJson = headers != null
            ? JsonSerializer.Serialize(headers, JsonContext.Default.DictionaryStringString)
            : null;

        IntPtr resultPtr = Native.Get(_handle, url, headersJson);
        return ParseResponse(resultPtr);
    }

    /// <summary>
    /// Perform a POST request.
    /// </summary>
    public Response Post(string url, string? body = null, Dictionary<string, string>? headers = null)
    {
        ThrowIfDisposed();

        string? headersJson = headers != null
            ? JsonSerializer.Serialize(headers, JsonContext.Default.DictionaryStringString)
            : null;

        IntPtr resultPtr = Native.Post(_handle, url, body, headersJson);
        return ParseResponse(resultPtr);
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
    public Response Request(string method, string url, string? body = null, Dictionary<string, string>? headers = null, int? timeout = null)
    {
        ThrowIfDisposed();

        var request = new RequestConfig
        {
            Method = method.ToUpperInvariant(),
            Url = url,
            Body = body,
            Headers = headers,
            Timeout = timeout
        };

        string requestJson = JsonSerializer.Serialize(request, JsonContext.Default.RequestConfig);
        IntPtr resultPtr = Native.Request(_handle, requestJson);
        return ParseResponse(resultPtr);
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

    private static Response ParseResponse(IntPtr resultPtr)
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

        return new Response(response);
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
/// HTTP Response.
/// </summary>
public sealed class Response
{
    internal Response(ResponseData data)
    {
        StatusCode = data.StatusCode;
        Headers = data.Headers ?? new Dictionary<string, string>();
        Text = data.Body ?? "";
        Url = data.FinalUrl ?? "";
        Protocol = data.Protocol ?? "";
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

    /// <summary>Parse response body as JSON.</summary>
    public T? Json<T>() => JsonSerializer.Deserialize<T>(Text);

    /// <summary>Throw if status code indicates an error.</summary>
    public void RaiseForStatus()
    {
        if (!Ok)
            throw new HttpCloakException($"HTTP {StatusCode}");
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
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(string[]))]
internal partial class JsonContext : JsonSerializerContext { }
