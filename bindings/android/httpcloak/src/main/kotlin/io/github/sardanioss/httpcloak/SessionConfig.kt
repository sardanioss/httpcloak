package io.github.sardanioss.httpcloak

import org.json.JSONArray
import org.json.JSONObject

/**
 * Options for a new [Session]. Anything left null or at its default is
 * decided by the native library, so defaults match the other bindings.
 */
public data class SessionConfig @JvmOverloads constructor(
    /** Browser fingerprint preset, see [Presets] and [HttpCloak.availablePresets]. */
    public val preset: String? = null,
    /** Proxy for all traffic: http://, https://, socks5:// or masque://. */
    public val proxy: String? = null,
    /** Proxy for HTTP/1.1 and HTTP/2 only; pair with [udpProxy] for a split setup. */
    public val tcpProxy: String? = null,
    /** Proxy for HTTP/3 only (MASQUE). */
    public val udpProxy: String? = null,
    /** Request timeout in seconds (library default 30). */
    public val timeout: Int? = null,
    /** "auto", "h1", "h2" or "h3". */
    public val httpVersion: String? = null,
    /** Verify TLS certificates. */
    public val verify: Boolean = true,
    public val allowRedirects: Boolean = true,
    public val maxRedirects: Int? = null,
    /** Retries on failure. Off by default so POSTs are never silently re-sent. */
    public val retry: Int = 0,
    /** Statuses that trigger a retry. */
    public val retryOnStatus: List<Int>? = null,
    /** Minimum wait between retries, in milliseconds. */
    public val retryWaitMin: Int? = null,
    /** Maximum wait between retries, in milliseconds. */
    public val retryWaitMax: Int? = null,
    public val preferIpv4: Boolean = false,
    /** Domain fronting: request host -> host to actually connect to. */
    public val connectTo: Map<String, String>? = null,
    /** Domain to fetch the ECH config from, e.g. "cloudflare-ech.com". */
    public val echConfigDomain: String? = null,
    /** Use the preset's TLS fingerprint but none of its HTTP headers. */
    public val tlsOnly: Boolean = false,
    /** QUIC idle timeout in seconds. */
    public val quicIdleTimeout: Int? = null,
    /** Local IP to bind outgoing connections to. */
    public val localAddress: String? = null,
    /** File to write TLS keys to, for decrypting captures in Wireshark. */
    public val keyLogFile: String? = null,
    public val enableSpeculativeTls: Boolean = false,
    /** Protocol to switch to after [Session.refresh]: "h1", "h2" or "h3". */
    public val switchProtocol: String? = null,
    /** Disable the cookie jar; cookies are then only what each request sends. */
    public val withoutCookieJar: Boolean = false,
    /** Disable ETag / If-Modified-Since handling. */
    public val withoutConditionalCache: Boolean = false,
    /** Drop every sec-ch-ua client hint. */
    public val withoutClientHints: Boolean = false,
    /** Keep the sec-ch-ua trio but drop the high-entropy client hints. */
    public val withoutHighEntropyClientHints: Boolean = false,
    /** Skip the ECH DNS lookup, saving a round trip on first connect. */
    public val disableEch: Boolean = false,
    /** Never race HTTP/3; still negotiate HTTP/1.1 or HTTP/2. */
    public val disableHttp3: Boolean = false,
    /** Custom JA3 TLS fingerprint. */
    public val ja3: String? = null,
    /** Custom Akamai HTTP/2 fingerprint. */
    public val akamai: String? = null,
    /** Extra fingerprint options (tls_alpn, tls_signature_algorithms, ...). */
    public val extraFp: Map<String, Any?>? = null,
    /** TCP/IP fingerprint overrides: TTL (128 Windows, 64 Linux/macOS). */
    public val tcpTtl: Int? = null,
    public val tcpMss: Int? = null,
    public val tcpWindowSize: Int? = null,
    public val tcpWindowScale: Int? = null,
    /** IP Don't Fragment bit. */
    public val tcpDf: Boolean? = null,
    /**
     * Seconds after which an HTTP/2 connection takes no new requests and a
     * fresh one is opened. Null keeps the default of five minutes; 0 turns
     * the limit off.
     */
    public val http2MaxConnAge: Int? = null,
) {
    internal fun toJson(): String {
        val json = JSONObject()
        fun put(key: String, value: Any?) {
            if (value != null) json.put(key, value)
        }
        fun flag(key: String, value: Boolean) {
            if (value) json.put(key, true)
        }

        put("preset", preset)
        put("proxy", proxy)
        put("tcp_proxy", tcpProxy)
        put("udp_proxy", udpProxy)
        put("timeout", timeout)
        put("http_version", httpVersion)
        if (!verify) json.put("verify", false)
        if (!allowRedirects) json.put("allow_redirects", false)
        put("max_redirects", maxRedirects)
        put("retry", retry)
        put("retry_on_status", retryOnStatus?.let { JSONArray(it) })
        put("retry_wait_min", retryWaitMin)
        put("retry_wait_max", retryWaitMax)
        flag("prefer_ipv4", preferIpv4)
        put("connect_to", connectTo?.let { JSONObject(it) })
        put("ech_config_domain", echConfigDomain)
        flag("tls_only", tlsOnly)
        put("quic_idle_timeout", quicIdleTimeout)
        put("local_address", localAddress)
        put("key_log_file", keyLogFile)
        flag("enable_speculative_tls", enableSpeculativeTls)
        put("switch_protocol", switchProtocol)
        flag("without_cookie_jar", withoutCookieJar)
        flag("without_conditional_cache", withoutConditionalCache)
        flag("without_client_hints", withoutClientHints)
        flag("without_high_entropy_client_hints", withoutHighEntropyClientHints)
        flag("disable_ech", disableEch)
        flag("disable_http3", disableHttp3)
        put("ja3", ja3)
        put("akamai", akamai)
        put("extra_fp", extraFp?.let { JSONObject(it) })
        put("tcp_ttl", tcpTtl)
        put("tcp_mss", tcpMss)
        put("tcp_window_size", tcpWindowSize)
        put("tcp_window_scale", tcpWindowScale)
        put("tcp_df", tcpDf)
        put("http2_max_conn_age", http2MaxConnAge)
        return json.toString()
    }
}

/** A snapshot of a session's state, from [Session.stats]. */
public data class SessionStats(
    public val id: String,
    public val preset: String,
    /** Unix time in nanoseconds. */
    public val createdAtNanos: Long,
    /** Unix time in nanoseconds. */
    public val lastUsedNanos: Long,
    public val requestCount: Long,
    public val active: Boolean,
    public val cookieCount: Int,
    public val cacheEntryCount: Int,
    public val ageNanos: Long,
    public val idleTimeNanos: Long,
    /** Per-transport connection statistics; the shape follows the Go library. */
    public val transportStats: Map<String, Any?>,
) {
    internal companion object {
        fun fromJson(json: String): SessionStats {
            val o = JSONObject(json)
            return SessionStats(
                id = o.optString("id"),
                preset = o.optString("preset"),
                createdAtNanos = o.optLong("created_at"),
                lastUsedNanos = o.optLong("last_used"),
                requestCount = o.optLong("request_count"),
                active = o.optBoolean("active"),
                cookieCount = o.optInt("cookie_count"),
                cacheEntryCount = o.optInt("cache_entry_count"),
                ageNanos = o.optLong("age_ns"),
                idleTimeNanos = o.optLong("idle_time_ns"),
                transportStats = o.optJSONObject("transport_stats")?.toMap() ?: emptyMap(),
            )
        }
    }
}
