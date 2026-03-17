using System.Text.Json;

namespace HttpCloak;

/// <summary>
/// Static helper methods for loading and managing custom fingerprint presets.
/// </summary>
public static class CustomPresets
{
    /// <summary>
    /// Load a custom preset from a JSON file and register it.
    /// </summary>
    /// <param name="path">Path to the preset JSON file.</param>
    /// <returns>The registered preset name.</returns>
    public static string LoadFromFile(string path)
    {
        var resultPtr = Native.PresetLoadFile(path);
        return ParsePresetNameResult(resultPtr)
            ?? throw new HttpCloakException("Failed to load preset from file");
    }

    /// <summary>
    /// Load a custom preset from a JSON string and register it.
    /// </summary>
    /// <param name="jsonData">JSON string defining the preset.</param>
    /// <returns>The registered preset name.</returns>
    public static string LoadFromJson(string jsonData)
    {
        var resultPtr = Native.PresetLoadJson(jsonData);
        return ParsePresetNameResult(resultPtr)
            ?? throw new HttpCloakException("Failed to load preset from JSON");
    }

    /// <summary>
    /// Unregister a custom preset by name.
    /// </summary>
    /// <param name="name">The preset name to unregister.</param>
    public static void Unregister(string name)
    {
        Native.PresetUnregister(name);
    }

    private static string? ParsePresetNameResult(IntPtr ptr)
    {
        var json = Native.PtrToStringAndFree(ptr);
        if (string.IsNullOrEmpty(json))
            return null;

        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("error", out var errorElem))
            throw new HttpCloakException(errorElem.GetString() ?? "Unknown error");
        if (doc.RootElement.TryGetProperty("name", out var nameElem))
            return nameElem.GetString();

        return null;
    }
}

/// <summary>
/// A pool of custom fingerprint presets for rotation.
///
/// Pools load multiple presets from a single JSON definition and provide
/// round-robin or random selection. All presets are auto-registered on
/// construction, so you can pass the returned name directly to
/// <c>new Session(preset: name)</c>.
/// </summary>
public sealed class PresetPool : IDisposable
{
    private long _handle;
    private bool _disposed;

    /// <summary>
    /// Load a preset pool from a JSON file.
    /// </summary>
    /// <param name="path">Path to the pool JSON file.</param>
    public PresetPool(string path)
    {
        _handle = ParsePoolLoadResult(Native.PoolLoadFile(path));
    }

    private PresetPool(long handle)
    {
        _handle = handle;
    }

    /// <summary>
    /// Load a preset pool from a JSON string.
    /// </summary>
    /// <param name="jsonData">JSON string defining the pool.</param>
    /// <returns>A new PresetPool instance.</returns>
    public static PresetPool FromJson(string jsonData)
    {
        var handle = ParsePoolLoadResult(Native.PoolLoadJson(jsonData));
        return new PresetPool(handle);
    }

    private static long ParsePoolLoadResult(IntPtr ptr)
    {
        var json = Native.PtrToStringAndFree(ptr);
        if (string.IsNullOrEmpty(json))
            throw new HttpCloakException("Failed to load preset pool");

        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("error", out var errorElem))
            throw new HttpCloakException(errorElem.GetString() ?? "Unknown error");
        if (doc.RootElement.TryGetProperty("handle", out var handleElem))
            return handleElem.GetInt64();

        throw new HttpCloakException("Failed to load preset pool: invalid response");
    }

    /// <summary>
    /// Pick a preset using the pool's configured strategy.
    /// </summary>
    public string Pick()
    {
        ThrowIfDisposed();
        return ParsePoolResult(Native.PoolPick(_handle));
    }

    /// <summary>
    /// Pick a random preset from the pool.
    /// </summary>
    public string Random()
    {
        ThrowIfDisposed();
        return ParsePoolResult(Native.PoolRandom(_handle));
    }

    /// <summary>
    /// Pick the next preset in round-robin order.
    /// </summary>
    public string Next()
    {
        ThrowIfDisposed();
        return ParsePoolResult(Native.PoolNext(_handle));
    }

    /// <summary>
    /// Get a preset by index.
    /// </summary>
    public string this[int index]
    {
        get
        {
            ThrowIfDisposed();
            return ParsePoolResult(Native.PoolGet(_handle, index));
        }
    }

    /// <summary>
    /// Number of presets in the pool.
    /// </summary>
    public int Count
    {
        get
        {
            ThrowIfDisposed();
            var size = Native.PoolSize(_handle);
            if (size < 0)
                throw new HttpCloakException("Failed to get pool size");
            return (int)size;
        }
    }

    /// <summary>
    /// Name of the preset pool.
    /// </summary>
    public string Name
    {
        get
        {
            ThrowIfDisposed();
            return ParsePoolResult(Native.PoolName(_handle));
        }
    }

    private static string ParsePoolResult(IntPtr ptr)
    {
        var result = Native.PtrToStringAndFree(ptr);
        if (string.IsNullOrEmpty(result))
            throw new HttpCloakException("No result from preset pool");

        // Error responses are JSON: {"error":"..."}
        if (result.StartsWith("{"))
        {
            using var doc = JsonDocument.Parse(result);
            if (doc.RootElement.TryGetProperty("error", out var errorElem))
                throw new HttpCloakException(errorElem.GetString() ?? "Unknown error");
        }

        return result;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(PresetPool));
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_handle > 0)
            {
                Native.PoolFree(_handle);
                _handle = 0;
            }
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    ~PresetPool()
    {
        Dispose();
    }
}
