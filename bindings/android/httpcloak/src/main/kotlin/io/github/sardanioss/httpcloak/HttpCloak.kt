package io.github.sardanioss.httpcloak

import org.json.JSONArray
import org.json.JSONObject

/** Library-wide settings and information. */
public object HttpCloak {
    /** Version of the native library. */
    @JvmStatic
    public val version: String get() = Native.version()

    /** Every registered preset name, with the protocols it supports ("h1", "h2", "h3"). */
    @JvmStatic
    public fun availablePresets(): Map<String, List<String>> {
        val presets = JSONObject(Native.availablePresets())
        return presets.keys().asSequence().sorted().associateWith {
            presets.getJSONObject(it).optJSONArray("protocols").toStringList()
        }
    }

    /**
     * DNS servers ("host:port") used to look up ECH configs. Setting an empty
     * list restores the defaults.
     */
    @JvmStatic
    public var echDnsServers: List<String>
        get() = JSONArray(Native.getEchDnsServers()).toStringList()
        set(value) {
            // Unlike most exports this one returns a bare error message.
            Native.setEchDnsServers(JSONArray(value).toString())?.let { throw HttpCloakException(it) }
        }

    /**
     * Returns memory freed by closed sessions to the OS. Stops the world for a
     * full collection, so call it between batches rather than after every close.
     */
    @JvmStatic
    public fun trimMemory(): Unit = Native.trimMemory()

    /**
     * Uses [cache] for TLS session tickets of sessions and local proxies
     * created from now on, or stops using one when null.
     */
    @JvmStatic
    public fun setSessionCache(cache: SessionCache?) {
        NativeCallbacks.sessionCache = cache
        if (cache != null) Native.setSessionCacheCallbacks() else Native.clearSessionCacheCallbacks()
    }

    /** Registers a custom preset from its JSON definition and returns its name. */
    @JvmStatic
    public fun loadPreset(json: String): String = checkedObject(Native.presetLoadJson(json)).getString("name")

    /** Registers a custom preset from a JSON file and returns its name. */
    @JvmStatic
    public fun loadPresetFile(path: String): String = checkedObject(Native.presetLoadFile(path)).getString("name")

    @JvmStatic
    public fun unregisterPreset(name: String): Unit = Native.presetUnregister(name)

    /** The fully resolved definition of preset [name], as JSON. */
    @JvmStatic
    public fun describePreset(name: String): String = checked(Native.describePreset(name))
}

/** Names of presets that always track the newest browser versions. */
public object Presets {
    public const val CHROME_LATEST: String = "chrome-latest"
    public const val CHROME_LATEST_WINDOWS: String = "chrome-latest-windows"
    public const val CHROME_LATEST_LINUX: String = "chrome-latest-linux"
    public const val CHROME_LATEST_MACOS: String = "chrome-latest-macos"
    public const val CHROME_LATEST_ANDROID: String = "chrome-latest-android"
    public const val CHROME_LATEST_IOS: String = "chrome-latest-ios"
    public const val FIREFOX_LATEST: String = "firefox-latest"
    public const val FIREFOX_LATEST_WINDOWS: String = "firefox-latest-windows"
    public const val FIREFOX_LATEST_LINUX: String = "firefox-latest-linux"
    public const val FIREFOX_LATEST_MACOS: String = "firefox-latest-macos"
    public const val SAFARI_LATEST: String = "safari-latest"
    public const val SAFARI_LATEST_IOS: String = "safari-latest-ios"
    public const val SAFARI_26_IOS: String = "safari-26-ios"
    public const val IOS_SAFARI_26: String = SAFARI_26_IOS
}

/**
 * A set of presets to rotate through, loaded from a pool definition. Close it
 * when done.
 */
public class PresetPool private constructor(private val handle: Long) : java.io.Closeable {
    public val name: String get() = checked(Native.poolName(handle))
    public val size: Int get() = Native.poolSize(handle).toInt()

    /** A preset chosen by the pool's own strategy. */
    public fun pick(): String = checked(Native.poolPick(handle))
    public fun random(): String = checked(Native.poolRandom(handle))
    /** The next preset in round-robin order. */
    public fun next(): String = checked(Native.poolNext(handle))
    public operator fun get(index: Int): String = checked(Native.poolGet(handle, index.toLong()))

    override fun close(): Unit = Native.poolFree(handle)

    public companion object {
        @JvmStatic
        public fun fromJson(json: String): PresetPool = fromResult(Native.poolLoadJson(json))

        @JvmStatic
        public fun fromFile(path: String): PresetPool = fromResult(Native.poolLoadFile(path))

        private fun fromResult(result: String) = PresetPool(checkedObject(result).getLong("handle"))
    }
}
