package io.github.sardanioss.httpcloak

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.security.SecureRandom

/**
 * An HTTP request. Only [url] is required; every other field falls back to the
 * session's behaviour when left at its default.
 */
public data class Request @JvmOverloads constructor(
    public val url: String,
    public val method: String = "GET",
    public val headers: Map<String, String> = emptyMap(),
    public val body: Body? = null,
    /** Query parameters appended to [url]. */
    public val params: Map<String, String> = emptyMap(),
    /** Cookies sent with this request only, on top of the session's jar. */
    public val cookies: Map<String, String> = emptyMap(),
    /** Basic auth (username, password). Overrides [Session.auth]. */
    public val auth: Pair<String, String>? = null,
    /** Timeout in seconds. Null uses the session's. */
    public val timeout: Int? = null,
    /** Forces Sec-Fetch-Mode: "cors", "no-cors", "navigate" or "websocket". */
    public val fetchMode: String? = null,
    /** Overrides the session's redirect policy for this request. */
    public val allowRedirects: Boolean? = null,
    public val disableConditionalCache: Boolean = false,
    /** Drops every sec-ch-ua client hint. */
    public val disableClientHints: Boolean = false,
    /** Keeps the sec-ch-ua trio but drops the high-entropy client hints. */
    public val disableHighEntropyClientHints: Boolean = false,
    /** Keeps the request's Referer off redirect hops, which carry it otherwise. */
    public val disableRedirectReferer: Boolean = false,
    /**
     * Replaces the whole header pipeline: these pairs go out exactly as given,
     * in order and casing, names may repeat, and nothing is added. [headers],
     * [cookies] and [auth] are ignored when this is set.
     */
    public val exactHeaders: List<Pair<String, String>>? = null,
    /**
     * Names to send first, in this order, for this request only. Headers not
     * listed keep the preset's position.
     */
    public val headerOrder: List<String>? = null,
)

/** A request body and the Content-Type it implies. */
public class Body(public val bytes: ByteArray, public val contentType: String? = null) {
    public companion object {
        /**
         * UTF-8 text. Without a [contentType], text that looks like JSON is
         * sent as application/json, as the other httpcloak bindings do.
         */
        @JvmStatic
        @JvmOverloads
        public fun text(text: String, contentType: String? = null): Body {
            val looksLikeJson = text.trimStart().let { it.startsWith("{") || it.startsWith("[") }
            return Body(text.toByteArray(), contentType ?: "application/json".takeIf { looksLikeJson })
        }

        @JvmStatic
        public fun json(json: String): Body = Body(json.toByteArray(), "application/json")

        /** application/x-www-form-urlencoded, the way a browser encodes a form. */
        @JvmStatic
        public fun form(fields: Map<String, String>): Body {
            val encoded = fields.entries.joinToString("&") { (k, v) ->
                URLEncoder.encode(k, "UTF-8") + "=" + URLEncoder.encode(v, "UTF-8")
            }
            return Body(encoded.toByteArray(), "application/x-www-form-urlencoded")
        }

        /** multipart/form-data with a Chrome-shaped boundary. */
        @JvmStatic
        @JvmOverloads
        public fun multipart(
            fields: Map<String, String> = emptyMap(),
            files: Map<String, MultipartFile> = emptyMap(),
        ): Body {
            val boundary = chromeBoundary()
            val out = ByteArrayOutputStream()
            fun line(s: String = "") = out.write("$s\r\n".toByteArray())

            for ((name, value) in fields) {
                line("--$boundary")
                line("Content-Disposition: form-data; name=\"${escapeFormName(name)}\"")
                line()
                line(value)
            }
            for ((name, file) in files) {
                line("--$boundary")
                line(
                    "Content-Disposition: form-data; name=\"${escapeFormName(name)}\"; " +
                        "filename=\"${escapeFormName(file.filename)}\"",
                )
                line("Content-Type: ${file.contentType}")
                line()
                out.write(file.content)
                line()
            }
            line("--$boundary--")
            return Body(out.toByteArray(), "multipart/form-data; boundary=$boundary")
        }
    }
}

/** A file part for [Body.multipart]. */
public class MultipartFile @JvmOverloads constructor(
    public val content: ByteArray,
    public val filename: String,
    public val contentType: String = "application/octet-stream",
)

// Chrome's boundary: the literal prefix plus 16 characters drawn through a
// 6-bit mask over Blink's 64-entry table (A-Z, a-z, 0-9, then A and B again).
// Source: blink/renderer/platform/network/form_data_encoder.cc.
private fun chromeBoundary(): String {
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB"
    val random = ByteArray(16).also { SecureRandom().nextBytes(it) }
    return "----WebKitFormBoundary" + random.map { alphabet[it.toInt() and 0x3F] }.joinToString("")
}

// What Chrome does to a quote or line break inside a form-data name.
private fun escapeFormName(name: String): String =
    name.replace("\"", "%22").replace("\r", "%0D").replace("\n", "%0A")

/** RFC 3986 percent-encoding: everything but unreserved characters. */
internal fun percentEncode(s: String): String = buildString {
    val hex = "0123456789ABCDEF"
    for (b in s.toByteArray()) {
        val v = b.toInt() and 0xFF
        val c = v.toChar()
        if (c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c in "-._~") append(c)
        else append('%').append(hex[v shr 4]).append(hex[v and 0xF])
    }
}

internal fun Request.urlWithParams(): String {
    if (params.isEmpty()) return url
    val query = params.entries.joinToString("&") { (k, v) -> percentEncode(k) + "=" + percentEncode(v) }
    // The query goes before any fragment, which never reaches the server.
    val hash = url.indexOf('#')
    val base = if (hash < 0) url else url.substring(0, hash)
    val fragment = if (hash < 0) "" else url.substring(hash)
    val separator = when {
        '?' !in base -> "?"
        base.endsWith('?') || base.endsWith('&') -> ""
        else -> "&"
    }
    return base + separator + query + fragment
}

/** The headers to send once auth, per-request cookies and the body type are applied. */
internal fun Request.effectiveHeaders(sessionAuth: Pair<String, String>?): Map<String, String> {
    val out = LinkedHashMap(headers)

    (auth ?: sessionAuth)?.let { (user, password) ->
        out.replaceHeader("Authorization") { "Basic " + base64Encode("$user:$password".toByteArray()) }
    }
    if (cookies.isNotEmpty()) {
        val jar = cookies.entries.joinToString("; ") { (k, v) -> "$k=$v" }
        out.replaceHeader("Cookie") { current -> if (current.isEmpty()) jar else "$current; $jar" }
    }
    body?.contentType?.let { type ->
        if (out.keys.none { it.equals("Content-Type", ignoreCase = true) }) out["Content-Type"] = type
    }
    return out
}

/**
 * Sets header [name] to what [value] makes of its current values, joined as
 * a Cookie header joins them. Names ignore case: every spelling the caller
 * used folds into one entry, which keeps the first spelling.
 */
private fun MutableMap<String, String>.replaceHeader(name: String, value: (current: String) -> String) {
    val spellings = keys.filter { it.equals(name, ignoreCase = true) }
    val current = spellings.mapNotNull { this[it]?.takeIf(String::isNotEmpty) }.joinToString("; ")
    spellings.forEach { remove(it) }
    this[spellings.firstOrNull() ?: name] = value(current)
}

/**
 * The request as the C API's RequestConfig JSON.
 *
 * @param timeoutMillis the raw entry point reads "timeout" in milliseconds,
 *   the async and stream ones in seconds.
 * @param inlineBody whether the body travels inside the JSON (base64) rather
 *   than as a separate byte buffer.
 */
internal fun Request.toJson(
    sessionAuth: Pair<String, String>?,
    timeoutMillis: Boolean,
    inlineBody: Boolean,
): String {
    val json = JSONObject()
        .put("method", method.uppercase())
        .put("url", urlWithParams())
    val headers = effectiveHeaders(sessionAuth)
    if (headers.isNotEmpty()) json.put("headers", JSONObject(headers))
    exactHeaders?.let { pairs ->
        json.put("exact_headers", JSONArray(pairs.map { (k, v) -> JSONArray(listOf(k, v)) }))
    }
    headerOrder?.let { json.put("header_order", JSONArray(it)) }
    if (inlineBody && body != null && body.bytes.isNotEmpty()) {
        json.put("body", base64Encode(body.bytes)).put("body_encoding", "base64")
    }
    timeout?.let { json.put("timeout", if (timeoutMillis) it * 1000 else it) }
    fetchMode?.let { json.put("fetch_mode", it) }
    allowRedirects?.let { json.put("follow_redirects", it) }
    if (disableConditionalCache) json.put("disable_conditional_cache", true)
    if (disableClientHints) json.put("disable_client_hints", true)
    if (disableHighEntropyClientHints) json.put("disable_high_entropy_client_hints", true)
    if (disableRedirectReferer) json.put("disable_redirect_referer", true)
    return json.toString()
}
