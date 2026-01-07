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

    [DllImport(LibraryName, EntryPoint = "httpcloak_get", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Get(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? headersJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_post", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Post(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string url, [MarshalAs(UnmanagedType.LPUTF8Str)] string? body, [MarshalAs(UnmanagedType.LPUTF8Str)] string? headersJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_request", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Request(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson);

    [DllImport(LibraryName, EntryPoint = "httpcloak_get_cookies", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr GetCookies(long handle);

    [DllImport(LibraryName, EntryPoint = "httpcloak_set_cookie", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SetCookie(long handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, [MarshalAs(UnmanagedType.LPUTF8Str)] string value);

    [DllImport(LibraryName, EntryPoint = "httpcloak_free_string", CallingConvention = CallingConvention.Cdecl)]
    public static extern void FreeString(IntPtr str);

    [DllImport(LibraryName, EntryPoint = "httpcloak_version", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr Version();

    [DllImport(LibraryName, EntryPoint = "httpcloak_available_presets", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr AvailablePresets();

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
}
