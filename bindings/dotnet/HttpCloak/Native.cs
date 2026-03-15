using System.Runtime.InteropServices;

namespace HttpCloak;

/// <summary>
/// P/Invoke bindings to the native httpcloak library.
/// </summary>
internal static class Native
{
    private const string LibraryName = "httpcloak";

    static Native()
    {
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, DllImportResolver);
    }

    private static IntPtr DllImportResolver(string libraryName, System.Reflection.Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibraryName)
            return IntPtr.Zero;

        string? libPath = GetNativeLibraryPath();
        if (libPath != null && NativeLibrary.TryLoad(libPath, out IntPtr handle))
            return handle;

        // Fallback to default resolution
        return IntPtr.Zero;
    }

    private static string? GetNativeLibraryPath()
    {
        string arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => "x64"
        };

        string rid;
        string libName;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            rid = $"win-{arch}";
            libName = "libhttpcloak-windows-amd64.dll";
            if (arch == "arm64") libName = "libhttpcloak-windows-arm64.dll";
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            rid = $"osx-{arch}";
            libName = arch == "arm64" ? "libhttpcloak-darwin-arm64.dylib" : "libhttpcloak-darwin-amd64.dylib";
        }
        else
        {
            rid = $"linux-{arch}";
            libName = arch == "arm64" ? "libhttpcloak-linux-arm64.so" : "libhttpcloak-linux-amd64.so";
        }

        // Try different locations
        string assemblyDir = Path.GetDirectoryName(typeof(Native).Assembly.Location) ?? ".";
        string[] searchPaths =
        {
            Path.Combine(assemblyDir, "runtimes", rid, "native", libName),
            Path.Combine(assemblyDir, libName),
            Path.Combine(assemblyDir, "native", libName),
        };

        foreach (string path in searchPaths)
        {
            if (File.Exists(path))
                return path;
        }

        return null;
    }

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_new", CallingConvention = CallingConvention.Cdecl)]
    public static extern long SessionNew([MarshalAs(UnmanagedType.LPUTF8Str)] string? configJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_free", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionFree(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_refresh", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionRefresh(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_refresh_protocol", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionRefreshProtocol(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string protocol);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_warmup", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionWarmup(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, long timeoutMs);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_fork", CallingConvention = CallingConvention.Cdecl)]
    public static extern long SessionFork(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_get", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Get(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? headersJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_post", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Post(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? body, [MarshalAs(UnmanagedType.LPUTF8Str)] string? headersJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_request", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Request(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_get_cookies", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr GetCookies(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_set_cookie", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SetCookie(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string cookieJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_delete_cookie", CallingConvention = CallingConvention.Cdecl)]
    public static extern void DeleteCookie(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, [MarshalAs(UnmanagedType.LPUTF8Str)] string domain);

    [DllImport(LibraryName, EntryPoint = "httpcloak_clear_cookies", CallingConvention = CallingConvention.Cdecl)]
    public static extern void ClearCookies(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_free_string", CallingConvention = CallingConvention.Cdecl)]
    public static extern void FreeString(IntPtr str);

    [DllImport(LibraryName, EntryPoint = "httpcloak_version", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Version();

    [DllImport(LibraryName, EntryPoint = "httpcloak_available_presets", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr AvailablePresets();

    [DllImport(LibraryName, EntryPoint = "httpcloak_set_ech_dns_servers", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SetEchDnsServers([MarshalAs(UnmanagedType.LPUTF8Str)] string? serversJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_get_ech_dns_servers", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr GetEchDnsServers();

    // Async callback delegate: void (*)(int64_t callback_id, const char* response_json, const char* error)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void AsyncCallback(long callbackId, IntPtr responseJson, IntPtr error);

    [DllImport(LibraryName, EntryPoint = "httpcloak_register_callback", CallingConvention = CallingConvention.Cdecl)]
    public static extern long RegisterCallback(AsyncCallback callback);

    [DllImport(LibraryName, EntryPoint = "httpcloak_unregister_callback", CallingConvention = CallingConvention.Cdecl)]
    public static extern void UnregisterCallback(long callbackId);

    [DllImport(LibraryName, EntryPoint = "httpcloak_cancel_request", CallingConvention = CallingConvention.Cdecl)]
    public static extern void CancelRequest(long callbackId);

    [DllImport(LibraryName, EntryPoint = "httpcloak_get_async", CallingConvention = CallingConvention.Cdecl)]
    public static extern void GetAsync(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? headersJson, long callbackId);

    [DllImport(LibraryName, EntryPoint = "httpcloak_post_async", CallingConvention = CallingConvention.Cdecl)]
    public static extern void PostAsync(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? body, [MarshalAs(UnmanagedType.LPUTF8Str)] string? headersJson, long callbackId);

    [DllImport(LibraryName, EntryPoint = "httpcloak_request_async", CallingConvention = CallingConvention.Cdecl)]
    public static extern void RequestAsync(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson, long callbackId);

    // Streaming functions
    [DllImport(LibraryName, EntryPoint = "httpcloak_stream_get", CallingConvention = CallingConvention.Cdecl)]
    public static extern long StreamGet(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? optionsJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_stream_post", CallingConvention = CallingConvention.Cdecl)]
    public static extern long StreamPost(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? body, [MarshalAs(UnmanagedType.LPUTF8Str)] string? optionsJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_stream_request", CallingConvention = CallingConvention.Cdecl)]
    public static extern long StreamRequest(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_stream_get_metadata", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr StreamGetMetadata(long streamHandle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_stream_read", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr StreamRead(long streamHandle, long bufferSize);

    [DllImport(LibraryName, EntryPoint = "httpcloak_stream_close", CallingConvention = CallingConvention.Cdecl)]
    public static extern void StreamClose(long streamHandle);

    // Session persistence functions
    [DllImport(LibraryName, EntryPoint = "httpcloak_session_save", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionSave(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string path);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_load", CallingConvention = CallingConvention.Cdecl)]
    public static extern long SessionLoad([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_marshal", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionMarshal(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_unmarshal", CallingConvention = CallingConvention.Cdecl)]
    public static extern long SessionUnmarshal([MarshalAs(UnmanagedType.LPUTF8Str)] string data);

    // Proxy management functions
    [DllImport(LibraryName, EntryPoint = "httpcloak_session_set_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionSetProxy(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string? proxyUrl);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_set_tcp_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionSetTcpProxy(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string? proxyUrl);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_set_udp_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionSetUdpProxy(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string? proxyUrl);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_get_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionGetProxy(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_get_tcp_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionGetTcpProxy(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_get_udp_proxy", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionGetUdpProxy(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_set_header_order", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionSetHeaderOrder(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string orderJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_get_header_order", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionGetHeaderOrder(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_set_identifier", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionSetIdentifier(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string? sessionId);

    // Local proxy functions
    [DllImport(LibraryName, EntryPoint = "httpcloak_local_proxy_start", CallingConvention = CallingConvention.Cdecl)]
    public static extern long LocalProxyStart([MarshalAs(UnmanagedType.LPUTF8Str)] string? configJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_local_proxy_stop", CallingConvention = CallingConvention.Cdecl)]
    public static extern void LocalProxyStop(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_local_proxy_get_port", CallingConvention = CallingConvention.Cdecl)]
    public static extern int LocalProxyGetPort(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_local_proxy_is_running", CallingConvention = CallingConvention.Cdecl)]
    public static extern int LocalProxyIsRunning(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_local_proxy_get_stats", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr LocalProxyGetStats(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_local_proxy_register_session", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr LocalProxyRegisterSession(long proxyHandle, [MarshalAs(UnmanagedType.LPUTF8Str)] string sessionId, long sessionHandle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_local_proxy_unregister_session", CallingConvention = CallingConvention.Cdecl)]
    public static extern int LocalProxyUnregisterSession(long proxyHandle, [MarshalAs(UnmanagedType.LPUTF8Str)] string sessionId);

    // Raw response functions for fast-path (zero-copy)
    [DllImport(LibraryName, EntryPoint = "httpcloak_get_raw", CallingConvention = CallingConvention.Cdecl)]
    public static extern long GetRaw(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? optionsJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_post_raw", CallingConvention = CallingConvention.Cdecl)]
    public static extern long PostRaw(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, IntPtr body, int bodyLen, [MarshalAs(UnmanagedType.LPUTF8Str)] string? optionsJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_request_raw", CallingConvention = CallingConvention.Cdecl)]
    public static extern long RequestRaw(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson, IntPtr body, int bodyLen);

    [DllImport(LibraryName, EntryPoint = "httpcloak_response_get_metadata", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ResponseGetMetadata(long responseHandle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_response_get_body_len", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ResponseGetBodyLen(long responseHandle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_response_copy_body_to", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ResponseCopyBodyTo(long responseHandle, IntPtr buffer, int bufferLen);

    [DllImport(LibraryName, EntryPoint = "httpcloak_response_free", CallingConvention = CallingConvention.Cdecl)]
    public static extern void ResponseFree(long responseHandle);

    /// <summary>
    /// Convert a native string pointer to a managed string and free the native memory.
    /// </summary>
    public static string? PtrToStringAndFree(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
            return null;

        try
        {
            return Marshal.PtrToStringUTF8(ptr);
        }
        finally
        {
            FreeString(ptr);
        }
    }

    /// <summary>
    /// Convert a native string pointer to a managed string without freeing.
    /// </summary>
    public static string? PtrToString(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
            return null;

        return Marshal.PtrToStringUTF8(ptr);
    }
}
