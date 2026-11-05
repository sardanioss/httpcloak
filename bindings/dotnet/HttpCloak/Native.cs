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
        RestoreActivationSignalStack();
    }

    // The Go runtime in a c-shared library adds SA_ONSTACK to every signal
    // handler that already exists when it starts. For the CoreCLR activation
    // signal (SIGRTMIN, used to suspend threads for a GC) that is fatal: the
    // handler's call chain is deep enough to overflow the small alternate
    // signal stack once it is moved there, and the kernel then kills the
    // process with a bare SIGSEGV (exit 139, no Go or .NET output). The
    // runtime sends this signal to its own threads while they run managed
    // code, not to threads it knows are in native code, so giving the handler
    // back its original flags restores the behaviour CoreCLR expects. What
    // remains is a narrow window: a signal sent just as a thread leaves managed
    // code for Go would run the handler on the Go stack, which Go's SA_ONSTACK
    // rule exists to avoid. That window is far smaller than the certain crash
    // this removes. See GitHub issue #89.
    private static unsafe void RestoreActivationSignalStack()
    {
        // The struct offsets below are glibc's 64-bit layout; there is no
        // 32-bit Linux build of the library to need another.
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || IntPtr.Size != 8)
            return;

        try
        {
            // Any export blocks until the Go runtime has finished starting,
            // and that includes installing its signal handlers. Stripping the
            // flag before that point would be undone.
            FreeString(Version());

            if (!NativeLibrary.TryLoad("libc.so.6", out IntPtr libc))
                return;
            if (!NativeLibrary.TryGetExport(libc, "sigaction", out IntPtr sigactionPtr) ||
                !NativeLibrary.TryGetExport(libc, "__libc_current_sigrtmin", out IntPtr sigrtminPtr))
                return;

            var sigaction = (delegate* unmanaged<int, byte*, byte*, int>)sigactionPtr;
            var sigrtmin = (delegate* unmanaged<int>)sigrtminPtr;

            // glibc struct sigaction (generic layout, verified on x64; arm64
            // uses the same layout): handler (8 bytes), sa_mask (128 bytes),
            // then int sa_flags at offset 136.
            const int SaFlagsOffset = 136;
            const int SA_ONSTACK = 0x08000000;
            byte* act = stackalloc byte[256];
            int sig = sigrtmin();
            if (sigaction(sig, null, act) != 0)
                return;
            if (*(IntPtr*)act == IntPtr.Zero || *(IntPtr*)act == (IntPtr)1) // SIG_DFL / SIG_IGN
                return;
            int flags = *(int*)(act + SaFlagsOffset);
            if ((flags & SA_ONSTACK) == 0)
                return;
            *(int*)(act + SaFlagsOffset) = flags & ~SA_ONSTACK;
            sigaction(sig, act, null);
        }
        catch
        {
            // Best effort. Never let this break loading the library.
        }
    }

    private static IntPtr DllImportResolver(string libraryName, System.Reflection.Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibraryName)
            return IntPtr.Zero;

        bool windows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        string? libPath = GetNativeLibraryPath(out string? libName, out string[] probed);

        if (libPath != null)
        {
            try
            {
                return NativeLibrary.Load(libPath);
            }
            catch (Exception e) when (e is DllNotFoundException || e is BadImageFormatException)
            {
                // The bundled library is there but will not load, usually a
                // missing dependency or the wrong CPU. Off Windows, a build of
                // the caller's own on the default search path (LD_LIBRARY_PATH,
                // /usr/lib) still gets its chance, as it always had.
                if (!windows && NativeLibrary.TryLoad(libraryName, assembly, searchPath, out IntPtr fallback))
                    return fallback;
                throw new DllNotFoundException(
                    $"httpcloak: found {libPath} but could not load it: {e.Message.TrimEnd()}. " +
                    "Set HTTPCLOAK_LIB_PATH to a working build to use that instead.", e);
            }
        }

        // Nothing bundled for this platform. Off Windows the default search is
        // a real chance: the caller may have installed their own build. On
        // Windows it is not. File names there are case-insensitive, so the
        // default search for "httpcloak" finds this managed HttpCloak.dll, and
        // the failure surfaces as a baffling "Unable to find an entry point
        // named 'httpcloak_session_new'" (#131). Say what is missing instead.
        if (!windows)
            return IntPtr.Zero;
        string what = libName ?? $"a library for {RuntimeInformation.ProcessArchitecture}";
        throw new DllNotFoundException(
            $"httpcloak: no native library {what} next to the application (looked in: {string.Join(", ", probed)}). " +
            "Reinstall the HttpCloak package for this platform, or set HTTPCLOAK_LIB_PATH to the library.");
    }

    private static string? GetNativeLibraryPath(out string? libName, out string[] probed)
    {
        probed = Array.Empty<string>();
        libName = null;

        // Only the CPUs a library is built for. Anything else used to be
        // mapped to x64, which can never load in that process.
        string? arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => null
        };

        string? overridePath = Environment.GetEnvironmentVariable("HTTPCLOAK_LIB_PATH");
        if (arch == null)
        {
            // A caller-supplied build is still honoured on any CPU.
            if (!string.IsNullOrWhiteSpace(overridePath) && File.Exists(overridePath))
                return overridePath;
            return null;
        }

        string rid;

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

        // HTTPCLOAK_LIB_PATH wins over everything below. The name matches the
        // variable the Python binding has always honoured.
        //
        // It exists for a fleet that deploys many processes into one shared
        // directory. The probe paths under it are all relative to the assembly
        // directory, so a shared directory means one engine for everyone and no
        // way to stage a rollout across it. Pointing each process at its own
        // build with an environment variable gives back the per-process choice
        // without moving anyone into separate folders.
        //
        // The value may be the library file itself or a directory holding it
        // under the usual name. A value that resolves to neither is ignored
        // rather than fatal, so a stale variable degrades to the normal search
        // instead of taking the process down.
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            if (File.Exists(overridePath))
                return overridePath;
            string inDir = Path.Combine(overridePath, libName);
            if (File.Exists(inDir))
                return inDir;
        }

        // Look beside the assembly and beside the app. In a single-file app
        // Assembly.Location is empty, so the app's own directory is the only
        // anchor; without it the search ran relative to the working
        // directory and failed for a service started anywhere else.
        var dirs = new List<string>();
        string location = typeof(Native).Assembly.Location;
        if (!string.IsNullOrEmpty(location) && Path.GetDirectoryName(location) is string assemblyDir)
            dirs.Add(assemblyDir);
        if (!string.IsNullOrEmpty(AppContext.BaseDirectory) && !dirs.Contains(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar)))
            dirs.Add(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));

        var paths = new List<string>();
        foreach (string dir in dirs)
        {
            paths.Add(Path.Combine(dir, "runtimes", rid, "native", libName));
            paths.Add(Path.Combine(dir, libName));
            paths.Add(Path.Combine(dir, "native", libName));
        }
        probed = paths.ToArray();

        foreach (string path in paths)
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

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_clear_cache", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionClearCache(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_stats", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SessionStats(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_idle_time", CallingConvention = CallingConvention.Cdecl)]
    public static extern long SessionIdleTime(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_is_active", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SessionIsActive(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_touch", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionTouch(long handle);

    // Chunked upload state machine (mirrors Python's stream_upload). Lets
    // callers ship arbitrarily-large bodies without buffering in managed
    // memory: UploadStart opens an io.Pipe on the Go side, UploadWriteRaw
    // streams chunks straight to the wire, UploadFinish reads the response,
    // UploadCancel tears down a partial upload on error.
    [DllImport(LibraryName, EntryPoint = "httpcloak_upload_start", CallingConvention = CallingConvention.Cdecl)]
    public static extern long UploadStart(long sessionHandle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string optionsJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_upload_write_raw", CallingConvention = CallingConvention.Cdecl)]
    public static extern int UploadWriteRaw(long uploadHandle, IntPtr buffer, int len);

    [DllImport(LibraryName, EntryPoint = "httpcloak_upload_finish", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr UploadFinish(long uploadHandle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_upload_cancel", CallingConvention = CallingConvention.Cdecl)]
    public static extern void UploadCancel(long uploadHandle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_set_conditional_cache", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionSetConditionalCache(long handle, int enabled);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_get_conditional_cache", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SessionGetConditionalCache(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_set_client_hints", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionSetClientHints(long handle, int enabled);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_get_client_hints", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SessionGetClientHints(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_set_high_entropy_client_hints", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionSetHighEntropyClientHints(long handle, int enabled);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_get_high_entropy_client_hints", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SessionGetHighEntropyClientHints(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_set_follow_redirects", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionSetFollowRedirects(long handle, int enabled);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_get_follow_redirects", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SessionGetFollowRedirects(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_set_max_redirects", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SessionSetMaxRedirects(long handle, int max);

    [DllImport(LibraryName, EntryPoint = "httpcloak_session_get_max_redirects", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SessionGetMaxRedirects(long handle);

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

    [DllImport(LibraryName, EntryPoint = "httpcloak_trim_memory", CallingConvention = CallingConvention.Cdecl)]
    public static extern void TrimMemory();

    [DllImport(LibraryName, EntryPoint = "httpcloak_stream_request_async", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void StreamRequestAsync(long sessionHandle, string requestJson, long callbackId);

    [DllImport(LibraryName, EntryPoint = "httpcloak_stream_get_metadata", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr StreamGetMetadata(long streamHandle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_stream_read", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr StreamRead(long streamHandle, long bufferSize);

    [DllImport(LibraryName, EntryPoint = "httpcloak_stream_trailer", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr StreamTrailer(long streamHandle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_last_error", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr LastError(long sessionHandle);

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

    [DllImport(LibraryName, EntryPoint = "httpcloak_local_proxy_list_sessions", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr LocalProxyListSessions(long proxyHandle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_local_proxy_has_session", CallingConvention = CallingConvention.Cdecl)]
    public static extern int LocalProxyHasSession(long proxyHandle, [MarshalAs(UnmanagedType.LPUTF8Str)] string sessionId);

    // Custom preset loading
    [DllImport(LibraryName, EntryPoint = "httpcloak_preset_load_file", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PresetLoadFile([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

    [DllImport(LibraryName, EntryPoint = "httpcloak_preset_load_json", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PresetLoadJson([MarshalAs(UnmanagedType.LPUTF8Str)] string jsonData);

    [DllImport(LibraryName, EntryPoint = "httpcloak_preset_unregister", CallingConvention = CallingConvention.Cdecl)]
    public static extern void PresetUnregister([MarshalAs(UnmanagedType.LPUTF8Str)] string name);

    [DllImport(LibraryName, EntryPoint = "httpcloak_describe_preset", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr DescribePreset([MarshalAs(UnmanagedType.LPUTF8Str)] string name);

    // Preset pool functions
    [DllImport(LibraryName, EntryPoint = "httpcloak_pool_load_file", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolLoadFile([MarshalAs(UnmanagedType.LPUTF8Str)] string path);

    [DllImport(LibraryName, EntryPoint = "httpcloak_pool_load_json", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolLoadJson([MarshalAs(UnmanagedType.LPUTF8Str)] string jsonData);

    [DllImport(LibraryName, EntryPoint = "httpcloak_pool_pick", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolPick(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_pool_random", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolRandom(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_pool_next", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolNext(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_pool_get", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolGet(long handle, long index);

    [DllImport(LibraryName, EntryPoint = "httpcloak_pool_size", CallingConvention = CallingConvention.Cdecl)]
    public static extern long PoolSize(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_pool_name", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr PoolName(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_pool_free", CallingConvention = CallingConvention.Cdecl)]
    public static extern void PoolFree(long handle);

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

    // =========================================================================
    // Distributed session cache callbacks (sync flavor).
    // Each delegate's IntPtr arguments are raw const char* pointers from the Go
    // side; the managed body marshals via Marshal.PtrToStringUTF8. The Get-type
    // delegates return IntPtr to a malloc'd C string (the Go side copies via
    // C.GoString and never frees), so the SessionCacheBackend wrapper holds the
    // last-returned pointer in a field and frees it on the next invocation.
    // =========================================================================

    /// <summary>
    /// Sync session cache GET callback. Returns IntPtr.Zero for "not found",
    /// or a pointer to a UTF-8 C string containing the JSON-serialised
    /// transport.TLSSessionState.
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr SessionCacheGetCallback(IntPtr key);

    /// <summary>
    /// Sync session cache PUT callback. Returns 0 on success, non-zero on
    /// failure.
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int SessionCachePutCallback(IntPtr key, IntPtr valueJson, long ttlSeconds);

    /// <summary>
    /// Sync session cache DELETE callback. Returns 0 on success, non-zero on
    /// failure.
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int SessionCacheDeleteCallback(IntPtr key);

    /// <summary>
    /// Sync ECH cache GET callback. Returns IntPtr.Zero for "not found", or
    /// a pointer to a UTF-8 C string containing the base64-encoded ECH config.
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr EchCacheGetCallback(IntPtr key);

    /// <summary>
    /// Sync ECH cache PUT callback. Returns 0 on success, non-zero on failure.
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int EchCachePutCallback(IntPtr key, IntPtr valueBase64, long ttlSeconds);

    /// <summary>
    /// Cache error callback. Fired when the backend reports an error from any
    /// op (get / put / delete). Receives the operation name, key and error
    /// message strings.
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void SessionCacheErrorCallback(IntPtr operation, IntPtr key, IntPtr error);

    [DllImport(LibraryName, EntryPoint = "httpcloak_set_session_cache_callbacks", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SetSessionCacheCallbacks(
        SessionCacheGetCallback get,
        SessionCachePutCallback put,
        SessionCacheDeleteCallback delete,
        EchCacheGetCallback echGet,
        EchCachePutCallback echPut,
        SessionCacheErrorCallback onError);

    [DllImport(LibraryName, EntryPoint = "httpcloak_clear_session_cache_callbacks", CallingConvention = CallingConvention.Cdecl)]
    public static extern void ClearSessionCacheCallbacks();
}
