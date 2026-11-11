package io.github.sardanioss.httpcloak

import org.json.JSONArray
import org.json.JSONObject
import java.io.Closeable
import java.net.InetSocketAddress
import java.net.Proxy

/**
 * An HTTP proxy on 127.0.0.1 that sends what it receives through httpcloak,
 * so clients that can only be pointed at a proxy (OkHttp, HttpURLConnection)
 * get browser fingerprints. Close it to stop listening.
 *
 * Fingerprinting applies to plain-HTTP requests. To reach an HTTPS origin
 * with a fingerprint, request its http:// URL with `X-HTTPCloak-Scheme: https`;
 * HTTPS sent as a CONNECT tunnel carries the client's own TLS.
 *
 * A client picks one of the [registerSession] sessions per request with the
 * `X-HTTPCloak-Session` header.
 */
public class LocalProxy @JvmOverloads constructor(
    /** Port to listen on; 0 picks a free one. */
    port: Int = 0,
    preset: String? = null,
    /** Request timeout in seconds. */
    timeout: Int? = null,
    maxConnections: Int? = null,
    /** Upstream proxy for HTTP/1.1 and HTTP/2. */
    tcpProxy: String? = null,
    /** Upstream proxy for HTTP/3. */
    udpProxy: String? = null,
    tlsOnly: Boolean = false,
    /**
     * Verify the certificates of the sites the proxy connects to. false is
     * for testing against a self-signed certificate.
     */
    verify: Boolean = true,
) : Closeable {
    private val handle: Long

    init {
        val config = JSONObject().put("port", port)
        preset?.let { config.put("preset", it) }
        timeout?.let { config.put("timeout", it) }
        maxConnections?.let { config.put("max_connections", it) }
        tcpProxy?.let { config.put("tcp_proxy", it) }
        udpProxy?.let { config.put("udp_proxy", it) }
        if (tlsOnly) config.put("tls_only", true)
        if (!verify) config.put("verify", false)
        handle = Native.localProxyStart(config.toString())
        if (handle <= 0) throw HttpCloakException("could not start local proxy on port $port")
    }

    /** The port actually listened on. */
    public val port: Int = Native.localProxyGetPort(handle)

    public val proxyUrl: String get() = "http://127.0.0.1:$port"

    public val isRunning: Boolean get() = Native.localProxyIsRunning(handle)

    /** This proxy as a [java.net.Proxy], e.g. for OkHttpClient.Builder().proxy(...). */
    public fun asJavaProxy(): Proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port))

    public fun stats(): LocalProxyStats = LocalProxyStats.fromJson(checked(Native.localProxyGetStats(handle)))

    /** Makes [session] selectable with the header `X-HTTPCloak-Session: id`. */
    public fun registerSession(id: String, session: Session) {
        errorIn(Native.localProxyRegisterSession(handle, id, session.handle))?.let { throw HttpCloakException(it) }
    }

    /** Returns false if no session was registered under [id]. */
    public fun unregisterSession(id: String): Boolean = Native.localProxyUnregisterSession(handle, id)

    public fun listSessions(): List<String> = JSONArray(Native.localProxyListSessions(handle) ?: "[]").toStringList()

    public fun hasSession(id: String): Boolean = Native.localProxyHasSession(handle, id)

    override fun close(): Unit = Native.localProxyStop(handle)
}

public data class LocalProxyStats(
    public val running: Boolean,
    public val port: Int,
    public val activeConnections: Long,
    public val totalRequests: Long,
    public val preset: String,
    public val maxConnections: Int,
    public val registeredSessions: Int,
) {
    internal companion object {
        fun fromJson(json: String): LocalProxyStats {
            val o = JSONObject(json)
            return LocalProxyStats(
                running = o.optBoolean("running"),
                port = o.optInt("port"),
                activeConnections = o.optLong("active_conns"),
                totalRequests = o.optLong("total_requests"),
                preset = o.optString("preset"),
                maxConnections = o.optInt("max_connections"),
                registeredSessions = o.optInt("registered_sessions"),
            )
        }
    }
}
