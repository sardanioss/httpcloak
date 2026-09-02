/**
 * HTTPCloak Node.js TypeScript Definitions
 */

export class HTTPCloakError extends Error {
  name: "HTTPCloakError";
}

export class Cookie {
  /** Cookie name */
  name: string;
  /** Cookie value */
  value: string;
  /** Cookie domain */
  domain: string;
  /** Cookie path */
  path: string;
  /** Expiration date (RFC1123 format) */
  expires: string;
  /** Max age in seconds (0 means not set) */
  maxAge: number;
  /** Secure flag */
  secure: boolean;
  /** HttpOnly flag */
  httpOnly: boolean;
  /** SameSite attribute (Strict, Lax, None) */
  sameSite: string;
}

export class RedirectInfo {
  /** HTTP status code */
  statusCode: number;
  /** Request URL */
  url: string;
  /** Response headers */
  headers: Record<string, string>;
}

export class Response {
  /** HTTP status code */
  statusCode: number;
  /** Response headers */
  headers: Record<string, string>;
  /** Raw response body as Buffer */
  body: Buffer;
  /** Response body as Buffer (alias for body) */
  content: Buffer;
  /** Response body as string */
  text: string;
  /** Final URL after redirects */
  finalUrl: string;
  /** Final URL after redirects (alias for finalUrl) */
  url: string;
  /** Protocol used (http/1.1, h2, h3) */
  protocol: string;
  /** Elapsed time in milliseconds */
  elapsed: number;
  /** Cookies set by this response */
  cookies: Cookie[];
  /** Redirect history */
  history: RedirectInfo[];
  /** True if status code < 400 */
  ok: boolean;
  /** HTTP status reason phrase (e.g., 'OK', 'Not Found') */
  reason: string;
  /** Response encoding from Content-Type header */
  encoding: string | null;

  /** Parse response body as JSON */
  json<T = any>(): T;

  /** Raise error if status >= 400 */
  raiseForStatus(): void;
}

/**
 * High-performance HTTP Response with zero-copy buffer transfer.
 *
 * Use session.getFast() or session.postFast() for maximum download performance.
 * Call release() when done to return buffers to the pool.
 */
export class FastResponse {
  /** HTTP status code */
  statusCode: number;
  /** Response headers */
  headers: Record<string, string>;
  /** Raw response body as Buffer */
  body: Buffer;
  /** Response body as Buffer (alias for body) */
  content: Buffer;
  /** Response body as string */
  text: string;
  /** Final URL after redirects */
  finalUrl: string;
  /** Final URL after redirects (alias for finalUrl) */
  url: string;
  /** Protocol used (http/1.1, h2, h3) */
  protocol: string;
  /** Elapsed time in milliseconds */
  elapsed: number;
  /** Cookies set by this response */
  cookies: Cookie[];
  /** Redirect history */
  history: RedirectInfo[];
  /** True if status code < 400 */
  ok: boolean;
  /** HTTP status reason phrase (e.g., 'OK', 'Not Found') */
  reason: string;
  /** Response encoding from Content-Type header */
  encoding: string | null;

  /** Parse response body as JSON */
  json<T = any>(): T;

  /** Raise error if status >= 400 */
  raiseForStatus(): void;

  /**
   * Release the underlying buffer back to the pool.
   * Call this when done with the response to enable buffer reuse.
   * After calling release(), the body buffer should not be used.
   */
  release(): void;
}

/**
 * Streaming HTTP Response for downloading large files.
 *
 * Use session.getStream() or session.postStream() for streaming downloads.
 * Supports async iteration with for-await-of loops.
 *
 * @example
 * const stream = session.getStream(url);
 * for await (const chunk of stream) {
 *   file.write(chunk);
 * }
 * stream.close();
 */
export class StreamResponse {
  /** HTTP status code */
  statusCode: number;
  /** Response headers */
  headers: Record<string, string>;
  /** Final URL after redirects */
  finalUrl: string;
  /** Final URL after redirects (alias for finalUrl) */
  url: string;
  /** Protocol used (http/1.1, h2, h3) */
  protocol: string;
  /** Content-Length header value, or -1 if unknown */
  contentLength: number;
  /** Cookies set by this response */
  cookies: Cookie[];
  /** True if status code < 400 */
  ok: boolean;
  /** HTTP status reason phrase (e.g., 'OK', 'Not Found') */
  reason: string;

  /**
   * Read a chunk of data from the stream.
   * @param chunkSize Maximum bytes to read (default: 8192)
   * @returns Chunk of data or null if EOF
   */
  readChunk(chunkSize?: number): Buffer | null;

  /**
   * Read the entire response body as Buffer.
   * Warning: This defeats the purpose of streaming for large files.
   */
  readAll(): Buffer;

  /**
   * Async generator for iterating over chunks.
   * @param chunkSize Size of each chunk (default: 8192)
   */
  iterate(chunkSize?: number): AsyncGenerator<Buffer, void, unknown>;

  /** Async iterator for for-await-of loops */
  [Symbol.asyncIterator](): AsyncIterator<Buffer>;

  /** Read the entire response body as string */
  readonly text: string;

  /** Read the entire response body as Buffer */
  readonly body: Buffer;

  /** Parse the response body as JSON */
  json<T = any>(): T;

  /** Close the stream and release resources */
  close(): void;

  /** Raise error if status >= 400 */
  raiseForStatus(): void;
}

export interface SessionOptions {
  /** Browser preset to use (default: "chrome-146") */
  preset?: string;
  /** Proxy URL (e.g., "http://user:pass@host:port" or "socks5://host:port") */
  proxy?: string;
  /** Proxy URL for TCP protocols (HTTP/1.1, HTTP/2) - use with udpProxy for split config */
  tcpProxy?: string;
  /** Proxy URL for UDP protocols (HTTP/3 via MASQUE) - use with tcpProxy for split config */
  udpProxy?: string;
  /** Request timeout in seconds (default: 30) */
  timeout?: number;
  /** HTTP version: "auto", "h1", "h2", "h3" (default: "auto") */
  httpVersion?: string;
  /** SSL certificate verification (default: true) */
  verify?: boolean;
  /** Follow redirects (default: true) */
  allowRedirects?: boolean;
  /** Maximum number of redirects to follow (default: 10) */
  maxRedirects?: number;
  /** Number of retries on failure (default: 0, opt in by setting a positive integer) */
  retry?: number;
  /** Status codes to retry on (default: empty; set explicitly to opt in, e.g. [429, 500, 502, 503, 504]) */
  retryOnStatus?: number[];
  /** Minimum wait time between retries in milliseconds (default: 500) */
  retryWaitMin?: number;
  /** Maximum wait time between retries in milliseconds (default: 10000) */
  retryWaitMax?: number;
  /** Prefer IPv4 addresses over IPv6 (default: false) */
  preferIpv4?: boolean;
  /** Default basic auth [username, password] */
  auth?: [string, string];
  /** Domain fronting map {requestHost: connectHost} - DNS resolves connectHost but SNI/Host uses requestHost */
  connectTo?: Record<string, string>;
  /** Domain to fetch ECH config from (e.g., "cloudflare-ech.com" for any Cloudflare domain) */
  echConfigDomain?: string;
  /** TLS-only mode: skip preset HTTP headers, only apply TLS fingerprint (default: false) */
  tlsOnly?: boolean;
  /** QUIC idle timeout in seconds (default: 30). Set higher for long-lived HTTP/3 connections. */
  quicIdleTimeout?: number;
  /** Local IP address to bind outgoing connections (for IPv6 rotation with IP_FREEBIND on Linux) */
  localAddress?: string;
  /** Path to write TLS key log for Wireshark decryption (overrides SSLKEYLOGFILE env var) */
  keyLogFile?: string;
  /** Enable speculative TLS optimization for proxy connections (default: false) */
  enableSpeculativeTls?: boolean;
  /** Protocol to switch to after Refresh() (e.g., "h1", "h2", "h3") */
  switchProtocol?: string;
  /** Disable internal cookie jar entirely — caller manages cookies via per-request headers (default: false) */
  withoutCookieJar?: boolean;
  /** Disable ETag / If-Modified-Since handling for the lifetime of the session (default: false) */
  withoutConditionalCache?: boolean;
  /** Full strip: drop ALL sec-ch-ua client hints (including the always-on trio) for the lifetime of the session (default: false) */
  withoutClientHints?: boolean;
  /** High-entropy strip: keep the always-on trio but drop only the Accept-CH high-entropy hints for the lifetime of the session (default: false) */
  withoutHighEntropyClientHints?: boolean;
  /** Skip the ECH (Encrypted Client Hello) HTTPS RR lookup. Saves ~15-20ms on first connect (default: false) */
  disableEch?: boolean;
  /** Disable HTTP/3 racing while keeping H1/H2 auto-negotiation. Reachable indirectly via httpVersion: "h2" but the explicit flag is cleaner (default: false) */
  disableHttp3?: boolean;
  /** Custom JA3 fingerprint string (e.g., "771,4865-4866-4867-...,0-23-65281-...,29-23-24,0") */
  ja3?: string;
  /** Custom Akamai HTTP/2 fingerprint string (e.g., "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p") */
  akamai?: string;
  /** Extra fingerprint options: { tls_alpn, tls_signature_algorithms, tls_cert_compression, tls_permute_extensions } */
  extraFp?: Record<string, any>;
  /** TCP IP Time-To-Live in the SYN packet. 128 = Windows, 64 = Linux/macOS/iOS/Android. */
  tcpTtl?: number;
  /** TCP Maximum Segment Size option. 1460 for standard Ethernet. */
  tcpMss?: number;
  /** TCP Window Size in the SYN packet. 64240 = Windows 10/11, 65535 = Linux/macOS. */
  tcpWindowSize?: number;
  /** TCP Window Scale option exponent. 8 = Windows, 7 = Linux/Android, 6 = macOS/iOS. */
  tcpWindowScale?: number;
  /** IP Don't-Fragment flag. true on every modern client. */
  tcpDf?: boolean;
}

export interface RequestOptions {
  /** Optional custom headers */
  headers?: Record<string, string>;
  /** Optional request body (for POST, PUT, PATCH) */
  body?: string | Buffer | Record<string, any>;
  /** JSON body (will be serialized) */
  json?: Record<string, any>;
  /** Form data (will be URL encoded) */
  data?: Record<string, any>;
  /** Files to upload as multipart/form-data */
  files?: Record<string, Buffer | { filename: string; content: Buffer; contentType?: string }>;
  /** Query parameters */
  params?: Record<string, string | number | boolean>;
  /** Cookies to send with this request */
  cookies?: Record<string, string>;
  /** Basic auth [username, password] */
  auth?: [string, string];
  /** Optional request timeout in seconds */
  timeout?: number;
  /**
   * Explicit Sec-Fetch-Mode/Dest override for requests where auto-sniffing isn't enough.
   *
   * Valid values:
   * - `"cors"` - XHR/fetch() request (Sec-Fetch-Mode: cors, Sec-Fetch-Dest: empty, Sec-Fetch-Site: same-origin)
   * - `"no-cors"` - Subresource load (image/script/stylesheet tag)
   * - `"navigate"` - Top-level navigation (document load, classic form POST)
   * - `"websocket"` - WebSocket upgrade
   *
   * When unset (default), httpcloak auto-detects based on method, Accept, Content-Type, and Sec-Fetch-Dest headers.
   * Set this explicitly when the auto-sniff gets it wrong (e.g., POST to a CORS endpoint without a JSON Accept header).
   */
  fetchMode?: "cors" | "no-cors" | "navigate" | "websocket";

  /**
   * Per-request override for redirect following. true forces redirects on this
   * call, false surfaces the 3xx back to the caller; null / undefined defers
   * to the session-level setting (which itself defaults to follow).
   */
  allowRedirects?: boolean | null;

  /**
   * Per-request opt-out of the session's ETag / If-Modified-Since handling.
   * When true, no cache validators are injected on the way out and the
   * response's ETag / Last-Modified are not stored. Useful for a one-off
   * fresh fetch without touching the session-wide setting.
   */
  disableConditionalCache?: boolean;

  /**
   * Per-request full strip of sec-ch-ua client hints. When true, ALL client
   * hints are dropped for this request, including the always-on trio
   * (sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform). One-off only; the
   * session-wide setting is untouched.
   */
  disableClientHints?: boolean;

  /**
   * Per-request high-entropy strip. When true, this request keeps the
   * always-on trio but drops only the high-entropy Accept-CH hints
   * (e.g. sec-ch-ua-platform-version, -arch, -model, -bitness,
   * -full-version-list). One-off only; the session-wide setting is untouched.
   */
  disableHighEntropyClientHints?: boolean;

  /**
   * Per-request opt-out of the Referer httpcloak adds when it follows a
   * redirect. When true no Referer is synthesised for the next hop; a Referer
   * the caller set themselves still goes out.
   */
  disableRedirectReferer?: boolean;

  /**
   * Replace the whole header pipeline for this request.
   *
   * The pairs go on the wire in the order and casing given, and nothing else
   * is added: no preset header block, no client hints, no Sec-Fetch inference,
   * no alphabetical tail, and no merge of `headers` or the session cookie jar.
   * A name may repeat and each occurrence keeps its own position, which an
   * object cannot express and a captured request routinely needs.
   *
   * Host on HTTP/1.1 and the pseudo-header block on HTTP/2 and HTTP/3 are
   * still written for you as protocol framing. Connection is not; list it
   * yourself to send it.
   *
   * Honoured by `request`, `requestSync` and `requestStream`. It is an escape
   * hatch: the caller takes on the entire request shape, including the headers
   * a browser would always send.
   *
   * @example
   * await session.request("GET", "https://example.com", {
   *   exactHeaders: [
   *     ["cookie", "a=1"],
   *     ["accept", "*\/*"],
   *     ["cookie", "b=2"],
   *   ],
   * });
   */
  exactHeaders?: Array<[string, string]> | Map<string, string> | Record<string, string>;

  /**
   * AbortSignal for cancelling an in-flight request. Honored by the async
   * methods (get, post, put, patch, delete, head, options, request). When
   * the signal aborts, the underlying Go-side request is cancelled (DNS /
   * TCP / TLS / HTTP work is torn down) and the returned promise rejects
   * with the signal's reason (or a generic AbortError if none was set).
   *
   * @example
   * const controller = new AbortController();
   * setTimeout(() => controller.abort(new Error("too slow")), 5000);
   * await session.get("https://slow.example.com", { signal: controller.signal });
   */
  signal?: AbortSignal;
}

/**
 * Snapshot returned by `Session.stats()`. Mirrors the wire shape emitted by
 * the Go-side `session.Stats()` after snake_case marshalling.
 */
export interface SessionStats {
  /** Stable session ID assigned at construction. */
  id: string;
  /** Preset name the session was created with. */
  preset: string;
  /** Construction time, Unix nanoseconds. */
  created_at: number;
  /** Last-request time, Unix nanoseconds. */
  last_used: number;
  /** Total requests serviced by this session. */
  request_count: number;
  /** Whether the session is still usable (false after close). */
  active: boolean;
  /** Live cookie count in the jar. */
  cookie_count: number;
  /** Conditional-cache entry count (one per cached URL). */
  cache_entry_count: number;
  /** Age in nanoseconds (now - created_at). */
  age_ns: number;
  /** Idle time in nanoseconds (now - last_used). */
  idle_time_ns: number;
  /** Transport-level stats (per-protocol). Shape varies; treat as opaque. */
  transport_stats?: Record<string, any>;
}

export class Session {
  constructor(options?: SessionOptions);

  /** Default headers for all requests */
  headers: Record<string, string>;

  /** Default auth for all requests [username, password] */
  auth: [string, string] | null;

  /** Close the session and release resources */
  close(): void;

  /** Simulate a real browser page load to warm TLS sessions, cookies, and cache.
   * Fetches the HTML page and its subresources (CSS, JS, images) with
   * realistic headers, priorities, and timing.
   */
  warmup(url: string, options?: { timeout?: number }): void;

  /** Create n forked sessions sharing cookies and TLS session caches.
   * Forked sessions simulate multiple browser tabs from the same browser:
   * same cookies, same TLS resumption tickets, same fingerprint, but
   * independent connections for parallel requests.
   */
  fork(n?: number): Session[];

  /** Refresh the session by closing all connections while keeping TLS session tickets.
   * This simulates a browser page refresh - connections are severed but 0-RTT
   * early data can be used on reconnection due to preserved session tickets.
   *
   * @param switchProtocol - Optional protocol to switch to ("h1", "h2", "h3").
   *   Overrides any switchProtocol set at construction time. Persists for future refresh() calls.
   */
  refresh(switchProtocol?: "h1" | "h2" | "h3"): void;

  // Synchronous methods
  /** Perform a synchronous GET request */
  getSync(url: string, options?: RequestOptions): Response;

  /** Perform a synchronous POST request */
  postSync(url: string, options?: RequestOptions): Response;

  /** Perform a synchronous custom HTTP request */
  requestSync(method: string, url: string, options?: RequestOptions): Response;

  // Promise-based methods
  /** Perform an async GET request */
  get(url: string, options?: RequestOptions): Promise<Response>;

  /** Perform an async POST request */
  post(url: string, options?: RequestOptions): Promise<Response>;

  /** Perform an async custom HTTP request */
  request(method: string, url: string, options?: RequestOptions): Promise<Response>;

  /** Perform an async PUT request */
  put(url: string, options?: RequestOptions): Promise<Response>;

  /** Perform an async DELETE request */
  delete(url: string, options?: RequestOptions): Promise<Response>;

  /** Perform an async PATCH request */
  patch(url: string, options?: RequestOptions): Promise<Response>;

  /** Perform an async HEAD request */
  head(url: string, options?: RequestOptions): Promise<Response>;

  /** Perform an async OPTIONS request */
  options(url: string, options?: RequestOptions): Promise<Response>;

  // Cookie management

  /** Get all cookies with full metadata (domain, path, expiry, flags) */
  getCookiesDetailed(): Cookie[];

  /** Get a specific cookie by name with full metadata */
  getCookieDetailed(name: string): Cookie | null;

  /** Get all cookies with full metadata. Alias of getCookiesDetailed(); the older flat dict shape was removed in v1.6.5. */
  getCookies(): Cookie[];

  /** Get a specific cookie by name. Alias of getCookieDetailed(); the older value-only shape was removed in v1.6.5. */
  getCookie(name: string): Cookie | null;

  /** Set a cookie in the session */
  setCookie(
    name: string,
    value: string,
    options?: {
      domain?: string;
      path?: string;
      secure?: boolean;
      httpOnly?: boolean;
      sameSite?: string;
      maxAge?: number;
      expires?: string;
    }
  ): void;

  /** Delete a specific cookie by name. If domain is omitted, deletes from all domains. */
  deleteCookie(name: string, domain?: string): void;

  /** Clear all cookies from the session */
  clearCookies(): void;

  /** Cookies in the session jar with full metadata. Same shape as getCookies(). */
  readonly cookies: Cookie[];

  // Conditional cache and redirect runtime control

  /**
   * Drop the session's per-URL conditional-cache map (ETag / Last-Modified).
   * The next request to each URL goes out without If-None-Match /
   * If-Modified-Since headers. Cookies and TLS tickets are not touched.
   */
  clearCache(): void;

  /**
   * Snapshot of session counters, timestamps and transport-level metrics.
   * Mirrors the keys Go's session.Stats() returns, snake_case on the wire.
   */
  stats(): SessionStats;

  /**
   * Return the time since the session last serviced a request, in seconds.
   * Returns -1 if the session handle is invalid.
   */
  idleTime(): number;

  /**
   * Return true if the session is still usable (close() has not been called
   * and the handle is valid).
   */
  isActive(): boolean;

  /**
   * Reset the idle timer to now without issuing a request. Useful in
   * long-running pools where an external heartbeat shouldn't let a session
   * look idle to a reaper.
   */
  touch(): void;

  /**
   * Toggle the session's ETag / If-Modified-Since handling at runtime.
   * When disabled, the session stops injecting cache validators on outgoing
   * requests and stops storing them from responses; the existing cache map
   * is preserved (re-enabling resumes using it). Pair with clearCache() to
   * also wipe previously-stored validators.
   */
  setConditionalCache(enabled: boolean): void;

  /** Read the session's current conditional-cache state. */
  getConditionalCache(): boolean;

  /**
   * Toggle the session's client-hints handling at runtime (full strip).
   * When disabled, the session drops ALL sec-ch-ua client hints, including
   * the always-on trio (sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform).
   * The change takes effect on the next request and persists until set again.
   */
  setClientHints(enabled: boolean): void;

  /** Read the session's current client-hints state. */
  getClientHints(): boolean;

  /**
   * Toggle the session's high-entropy client-hints handling at runtime.
   * When disabled, the session keeps the always-on trio but drops only the
   * high-entropy Accept-CH hints (e.g. sec-ch-ua-platform-version, -arch,
   * -model, -bitness, -full-version-list). Takes effect on the next request.
   */
  setHighEntropyClientHints(enabled: boolean): void;

  /** Read the session's current high-entropy client-hints state. */
  getHighEntropyClientHints(): boolean;

  /**
   * Toggle the session's redirect-following policy at runtime. The change
   * takes effect on the next request and persists until set again.
   */
  setFollowRedirects(enabled: boolean): void;

  /** Read the session's current redirect-following policy. */
  getFollowRedirects(): boolean;

  /**
   * Update the session's redirect cap at runtime. Values of zero or below
   * are ignored, leaving the prior cap (or the default of 10) in place.
   */
  setMaxRedirects(max: number): void;

  /** Read the session's current redirect cap. */
  getMaxRedirects(): number;

  // Proxy management

  /**
   * Change both TCP and UDP proxies for the session.
   * This closes all existing connections and creates new ones through the new proxy.
   * @param proxyUrl - Proxy URL (e.g., "http://user:pass@host:port", "socks5://host:port"). Empty string for direct.
   */
  setProxy(proxyUrl: string): void;

  /**
   * Change only the TCP proxy (for HTTP/1.1 and HTTP/2).
   * @param proxyUrl - Proxy URL for TCP traffic
   */
  setTcpProxy(proxyUrl: string): void;

  /**
   * Change only the UDP proxy (for HTTP/3 via SOCKS5 or MASQUE).
   * @param proxyUrl - Proxy URL for UDP traffic
   */
  setUdpProxy(proxyUrl: string): void;

  /**
   * Get the current proxy URL.
   * @returns Current proxy URL, or empty string if using direct connection
   */
  getProxy(): string;

  /**
   * Get the current TCP proxy URL.
   * @returns Current TCP proxy URL, or empty string if using direct connection
   */
  getTcpProxy(): string;

  /**
   * Get the current UDP proxy URL.
   * @returns Current UDP proxy URL, or empty string if using direct connection
   */
  getUdpProxy(): string;

  /**
   * Set a custom header order for all requests.
   * @param order - Array of header names in desired order (lowercase). Pass empty array to reset to preset's default.
   * @example
   * session.setHeaderOrder(["accept-language", "sec-ch-ua", "accept", "sec-fetch-site"]);
   */
  setHeaderOrder(order: string[]): void;

  /**
   * Get the current header order.
   * @returns Array of header names in current order, or preset's default order
   */
  getHeaderOrder(): string[];

  /**
   * Set a session identifier for TLS cache key isolation.
   * This is used when the session is registered with a LocalProxy to ensure
   * TLS sessions are isolated per proxy/session configuration in distributed caches.
   * @param sessionId - Unique identifier for this session. Pass empty string to clear.
   */
  setSessionIdentifier(sessionId: string): void;

  /** Get/set the current proxy as a property */
  proxy: string;

  // ===========================================================================
  // Session Persistence
  // ===========================================================================

  /**
   * Save session state to a file.
   *
   * This saves cookies, TLS session tickets, and ECH configs.
   * Use Session.load() to restore the session later.
   *
   * @param path - Path to save the session file
   * @throws {HTTPCloakError} If the file cannot be written
   *
   * @example
   * session.save("session.json");
   * // Later...
   * const session = Session.load("session.json");
   */
  save(path: string): void;

  /**
   * Export session state to a JSON string.
   *
   * Use Session.unmarshal() to restore the session from the string.
   * Useful for storing session state in databases or caches.
   *
   * @returns JSON string containing session state
   * @throws {HTTPCloakError} If marshaling fails
   *
   * @example
   * const sessionData = session.marshal();
   * await redis.set("session:user1", sessionData);
   */
  marshal(): string;

  /**
   * Load a session from a file.
   *
   * Restores session state including cookies, TLS session tickets, and ECH configs.
   * The session uses the same preset that was used when it was saved.
   *
   * @param path - Path to the session file
   * @returns Restored Session object
   * @throws {HTTPCloakError} If the file cannot be read or is invalid
   *
   * @example
   * const session = Session.load("session.json");
   * const r = await session.get("https://example.com");
   */
  static load(path: string): Session;

  /**
   * Restore a session from a JSON string.
   *
   * @param data - JSON string containing session state (from marshal())
   * @returns Restored Session object
   * @throws {HTTPCloakError} If the data is invalid
   *
   * @example
   * const sessionData = await redis.get("session:user1");
   * const session = Session.unmarshal(sessionData);
   */
  static unmarshal(data: string): Session;

  // ===========================================================================
  // Streaming Methods
  // ===========================================================================

  /**
   * Perform a streaming GET request.
   *
   * Returns a StreamResponse that can be iterated to read chunks.
   * Use this for downloading large files without loading them into memory.
   *
   * @param url - Request URL
   * @param options - Request options
   * @returns StreamResponse for chunked reading
   *
   * @example
   * const stream = session.getStream("https://example.com/large-file.zip");
   * for await (const chunk of stream) {
   *   file.write(chunk);
   * }
   * stream.close();
   */
  getStream(url: string, options?: RequestOptions): StreamResponse;

  /**
   * Perform a streaming POST request.
   *
   * @param url - Request URL
   * @param options - Request options
   * @returns StreamResponse for chunked reading
   */
  postStream(url: string, options?: RequestOptions): StreamResponse;

  /**
   * Perform a streaming request with any HTTP method.
   *
   * @param method - HTTP method (GET, POST, PUT, etc.)
   * @param url - Request URL
   * @param options - Request options
   * @returns StreamResponse for chunked reading
   */
  requestStream(method: string, url: string, options?: RequestOptions): StreamResponse;

  // ===========================================================================
  // Fast-path Methods (Zero-copy for maximum performance)
  // ===========================================================================

  /**
   * Perform a fast GET request with zero-copy buffer transfer.
   *
   * This method bypasses JSON serialization and base64 encoding for the response body,
   * copying data directly from Go's memory to a Node.js Buffer.
   *
   * Use this method for downloading large files when you need maximum throughput.
   * Call response.release() when done to return buffers to the pool.
   *
   * @param url - Request URL
   * @param options - Request options
   * @returns FastResponse with Buffer body
   *
   * @example
   * const response = session.getFast("https://example.com/large-file.zip");
   * fs.writeFileSync("file.zip", response.body);
   * response.release();
   */
  getFast(url: string, options?: RequestOptions): FastResponse;

  /**
   * Perform a fast POST request with zero-copy buffer transfer.
   *
   * Use this method for uploading large files when you need maximum throughput.
   * Call response.release() when done to return buffers to the pool.
   *
   * @param url - Request URL
   * @param options - Request options (body must be Buffer or string)
   * @returns FastResponse with Buffer body
   *
   * @example
   * const data = fs.readFileSync("large-file.zip");
   * const response = session.postFast("https://example.com/upload", { body: data });
   * console.log(`Uploaded, status: ${response.statusCode}`);
   * response.release();
   */
  postFast(url: string, options?: RequestOptions): FastResponse;

  /**
   * Perform a fast generic HTTP request with zero-copy buffer transfer.
   *
   * Use this method for any HTTP method when you need maximum throughput.
   * Call response.release() when done to return buffers to the pool.
   *
   * @param method - HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
   * @param url - Request URL
   * @param options - Request options (body must be Buffer or string)
   * @returns FastResponse with Buffer body
   *
   * @example
   * const response = session.requestFast("PUT", "https://api.example.com/resource", {
   *   body: JSON.stringify({ key: "value" }),
   *   headers: { "Content-Type": "application/json" }
   * });
   * console.log(`Status: ${response.statusCode}`);
   * response.release();
   */
  requestFast(method: string, url: string, options?: RequestOptions): FastResponse;

  /**
   * Perform a fast PUT request with zero-copy buffer transfer.
   *
   * @param url - Request URL
   * @param options - Request options (body, headers, params, cookies, auth, timeout)
   * @returns FastResponse with Buffer body
   */
  putFast(url: string, options?: RequestOptions): FastResponse;

  /**
   * Perform a fast DELETE request with zero-copy buffer transfer.
   *
   * @param url - Request URL
   * @param options - Request options (headers, params, cookies, auth, timeout)
   * @returns FastResponse with Buffer body
   */
  deleteFast(url: string, options?: RequestOptions): FastResponse;

  /**
   * Perform a fast PATCH request with zero-copy buffer transfer.
   *
   * @param url - Request URL
   * @param options - Request options (body, headers, params, cookies, auth, timeout)
   * @returns FastResponse with Buffer body
   */
  patchFast(url: string, options?: RequestOptions): FastResponse;

  /**
   * Stream an arbitrary-sized body to the wire without buffering it in memory.
   * `chunks` is any iterable / async-iterable yielding Buffer / Uint8Array /
   * string chunks; the Go side opens an io.Pipe for the body and each chunk
   * flows straight through with no base64 wrap and no JSON envelope.
   *
   * @param method  Typically "POST", "PUT" or "PATCH".
   * @param url
   * @param chunks  Iterable or async-iterable of body chunks.
   * @param options.headers Headers (Content-Type defaults to application/octet-stream).
   * @param options.contentType Optional explicit Content-Type override.
   * @param options.timeout Per-request timeout in milliseconds.
   * @returns Resolves to a regular `Response` once the upload completes.
   */
  uploadStream(
    method: string,
    url: string,
    chunks: AsyncIterable<Buffer | Uint8Array | string> | Iterable<Buffer | Uint8Array | string>,
    options?: { headers?: Record<string, string>; contentType?: string; timeout?: number }
  ): Promise<Response>;

  /**
   * Convenience wrapper: streaming POST. Same semantics as
   * `uploadStream("POST", url, chunks, options)`.
   */
  postUpload(
    url: string,
    chunks: AsyncIterable<Buffer | Uint8Array | string> | Iterable<Buffer | Uint8Array | string>,
    options?: { headers?: Record<string, string>; contentType?: string; timeout?: number }
  ): Promise<Response>;
}

export interface LocalProxyOptions {
  /** Port to listen on (default: 0 for auto-assign) */
  port?: number;
  /** Browser preset to use (default: "chrome-146") */
  preset?: string;
  /** Request timeout in seconds (default: 30) */
  timeout?: number;
  /** Maximum concurrent connections (default: 1000) */
  maxConnections?: number;
  /** Proxy URL for TCP protocols (HTTP/1.1, HTTP/2) */
  tcpProxy?: string;
  /** Proxy URL for UDP protocols (HTTP/3 via MASQUE) */
  udpProxy?: string;
  /** TLS-only mode: skip preset HTTP headers, only apply TLS fingerprint (default: false) */
  tlsOnly?: boolean;
}

export interface LocalProxyStats {
  /** Whether the proxy is currently accepting connections */
  running: boolean;
  /** TCP port the proxy is bound to */
  port: number;
  /** Live count of in-flight connections */
  active_conns: number;
  /** Lifetime request counter since the proxy started */
  total_requests: number;
  /** Preset name the proxy was started with */
  preset: string;
  /** Max concurrent connections configured at start time */
  max_connections: number;
  /** Number of sessions currently registered via registerSession() */
  registered_sessions: number;
}

/**
 * Local HTTP proxy server that forwards requests through httpcloak with TLS fingerprinting.
 * Use this to transparently apply fingerprinting to any HTTP client (e.g., Undici, fetch).
 *
 * Supports per-request proxy rotation via X-Upstream-Proxy header.
 * Supports per-request session routing via X-HTTPCloak-Session header.
 *
 * IMPORTANT: For distributed session caching to work with X-HTTPCloak-Session header,
 * you MUST register the session with the proxy using registerSession() first.
 * Without registration, cache callbacks will not be triggered for that session.
 *
 * @example
 * // Basic usage
 * const proxy = new LocalProxy({ preset: "chrome-146", tlsOnly: true });
 * console.log(`Proxy running on ${proxy.proxyUrl}`);
 * // Use with any HTTP client pointing to the proxy
 * proxy.close();
 *
 * @example
 * // With distributed session cache
 * const proxy = new LocalProxy({ port: 8888 });
 * const session = new Session({ preset: 'chrome-144' });
 *
 * // Configure distributed cache
 * httpcloak.configureSessionCache({
 *   get: async (key) => await redis.get(key),
 *   put: async (key, value, ttl) => { await redis.setex(key, ttl, value); return 0; },
 * });
 *
 * // REQUIRED: Register session for cache callbacks to work
 * proxy.registerSession('session-1', session);
 */
export class LocalProxy {
  /**
   * Create a new LocalProxy instance.
   * The proxy starts automatically when constructed.
   * @param options - LocalProxy configuration options
   */
  constructor(options?: LocalProxyOptions);

  /** Get the port the proxy is listening on */
  readonly port: number;

  /** Check if the proxy is currently running */
  readonly isRunning: boolean;

  /** Get the proxy URL (e.g., "http://localhost:8888") */
  readonly proxyUrl: string;

  /**
   * Get proxy statistics.
   * @returns Statistics object with request counts, bytes transferred, etc.
   */
  getStats(): LocalProxyStats;

  /**
   * Register a session with an ID for use with X-HTTPCloak-Session header.
   * This allows per-request session routing through the proxy.
   *
   * IMPORTANT: This is REQUIRED for distributed session caching to work.
   * Without registration, cache callbacks will not be triggered for the session.
   *
   * When a request is made through the proxy with the `X-HTTPCloak-Session: <sessionId>` header,
   * the proxy will use the registered session for that request, applying its TLS fingerprint
   * and cookies.
   *
   * @param sessionId - Unique identifier for the session
   * @param session - The session to register
   * @throws {HTTPCloakError} If registration fails (e.g., invalid session or proxy not running)
   *
   * @example
   * ```typescript
   * const proxy = new LocalProxy({ port: 8888 });
   * const session = new Session({ preset: 'chrome-144' });
   *
   * // Register session with ID (required for cache callbacks)
   * proxy.registerSession('user-1', session);
   *
   * // Now requests with X-HTTPCloak-Session: user-1 header will use this session
   * // and trigger cache callbacks
   * ```
   */
  registerSession(sessionId: string, session: Session): void;

  /**
   * Unregister a session by ID.
   * After unregistering, the session ID can no longer be used with X-HTTPCloak-Session header.
   *
   * @param sessionId - The session ID to unregister
   * @returns True if the session was found and unregistered, false otherwise
   *
   * @example
   * ```typescript
   * const wasUnregistered = proxy.unregisterSession('user-1');
   * if (wasUnregistered) {
   *   console.log('Session unregistered');
   * }
   * ```
   */
  unregisterSession(sessionId: string): boolean;

  /**
   * Return the IDs of every session currently registered on this proxy.
   * These are the same IDs the X-HTTPCloak-Session header accepts for
   * per-request session routing.
   *
   * @returns List of registered session IDs (empty array if none).
   */
  listSessions(): string[];

  /**
   * Return true if a session with the given ID is currently registered.
   * Cheaper than `listSessions().includes(id)` when callers only need an
   * existence check (no JSON marshal across the FFI boundary).
   */
  hasSession(sessionId: string): boolean;

  /**
   * Stop and close the proxy.
   * After closing, the LocalProxy instance cannot be reused.
   */
  close(): void;
}

/** Get the httpcloak library version */
export function version(): string;

/**
 * Get available browser presets keyed by preset name.
 *
 * Each entry carries the protocols the preset supports (some H1/H2 only, some H1/H2/H3).
 * The shape is `{ [presetName: string]: { protocols: string[] } }`.
 *
 * @example
 * const presets = availablePresets();
 * Object.entries(presets).filter(([, info]) => info.protocols.includes("h3"));
 */
export function availablePresets(): Record<string, { protocols: string[] }>;

/**
 * Return a fully-resolved JSON dump of a preset's TLS / H2 / H3 / header configuration.
 *
 * Useful for inspecting what a preset name actually does at the wire level, or for
 * dumping a built-in preset, mutating it, and loading it back with `loadPresetFromJSON`
 * under a new name.
 *
 * @param name - Preset name (e.g. "chrome-148-windows", "firefox-148", "chrome-latest")
 * @returns JSON string. Parse with `JSON.parse` to get the structured form.
 * @throws {HTTPCloakError} If the preset name is not registered.
 */
export function describePreset(name: string): string;

/**
 * Configure the DNS servers used for ECH (Encrypted Client Hello) config queries.
 *
 * By default, ECH queries use Google (8.8.8.8), Cloudflare (1.1.1.1), and Quad9 (9.9.9.9).
 * This is a global setting that affects all sessions.
 *
 * @param servers - Array of DNS server addresses in "host:port" format. Pass null or empty array to reset to defaults.
 * @throws {HTTPCloakError} If the servers list is invalid.
 */
export function setEchDnsServers(servers: string[] | null): void;

/**
 * Get the current DNS servers used for ECH (Encrypted Client Hello) config queries.
 *
 * @returns Array of DNS server addresses in "host:port" format.
 */
export function getEchDnsServers(): string[];

export interface ConfigureOptions extends SessionOptions {
  /** Default headers for all requests */
  headers?: Record<string, string>;
  /** Default basic auth [username, password] */
  auth?: [string, string];
}

/** Configure defaults for module-level functions */
export function configure(options?: ConfigureOptions): void;

/** Perform a GET request */
export function get(url: string, options?: RequestOptions): Promise<Response>;

/** Perform a POST request */
export function post(url: string, options?: RequestOptions): Promise<Response>;

/** Perform a PUT request */
export function put(url: string, options?: RequestOptions): Promise<Response>;

/** Perform a DELETE request */
declare function del(url: string, options?: RequestOptions): Promise<Response>;
export { del as delete };

/** Perform a PATCH request */
export function patch(url: string, options?: RequestOptions): Promise<Response>;

/** Perform a HEAD request */
export function head(url: string, options?: RequestOptions): Promise<Response>;

/** Perform an OPTIONS request */
declare function opts(url: string, options?: RequestOptions): Promise<Response>;
export { opts as options };

/** Perform a custom HTTP request */
export function request(method: string, url: string, options?: RequestOptions): Promise<Response>;

/** Available browser presets */
export const Preset: {
  CHROME_LATEST: string;
  CHROME_LATEST_WINDOWS: string;
  CHROME_LATEST_LINUX: string;
  CHROME_LATEST_MACOS: string;
  CHROME_LATEST_IOS: string;
  CHROME_LATEST_ANDROID: string;
  CHROME_151: string;
  CHROME_151_WINDOWS: string;
  CHROME_151_LINUX: string;
  CHROME_151_MACOS: string;
  CHROME_151_ANDROID: string;
  CHROME_151_IOS: string;
  CHROME_150: string;
  CHROME_150_WINDOWS: string;
  CHROME_150_LINUX: string;
  CHROME_150_MACOS: string;
  CHROME_150_ANDROID: string;
  CHROME_150_IOS: string;
  FIREFOX_148_WINDOWS: string;
  FIREFOX_148_LINUX: string;
  FIREFOX_148_MACOS: string;
  FIREFOX_133_WINDOWS: string;
  FIREFOX_133_LINUX: string;
  FIREFOX_133_MACOS: string;
  FIREFOX_LATEST_WINDOWS: string;
  FIREFOX_LATEST_LINUX: string;
  FIREFOX_LATEST_MACOS: string;
  CHROME_149: string;
  CHROME_149_WINDOWS: string;
  CHROME_149_LINUX: string;
  CHROME_149_MACOS: string;
  CHROME_148: string;
  CHROME_148_WINDOWS: string;
  CHROME_148_LINUX: string;
  CHROME_148_MACOS: string;
  CHROME_148_IOS: string;
  CHROME_148_ANDROID: string;
  CHROME_147: string;
  CHROME_147_WINDOWS: string;
  CHROME_147_LINUX: string;
  CHROME_147_MACOS: string;
  CHROME_147_IOS: string;
  CHROME_147_ANDROID: string;
  CHROME_146: string;
  CHROME_146_WINDOWS: string;
  CHROME_146_LINUX: string;
  CHROME_146_MACOS: string;
  CHROME_145: string;
  CHROME_145_WINDOWS: string;
  CHROME_145_LINUX: string;
  CHROME_145_MACOS: string;
  CHROME_144: string;
  CHROME_144_WINDOWS: string;
  CHROME_144_LINUX: string;
  CHROME_144_MACOS: string;
  CHROME_143: string;
  CHROME_143_WINDOWS: string;
  CHROME_143_LINUX: string;
  CHROME_143_MACOS: string;
  CHROME_141: string;
  CHROME_133: string;
  CHROME_143_IOS: string;
  CHROME_144_IOS: string;
  CHROME_145_IOS: string;
  CHROME_146_IOS: string;
  CHROME_143_ANDROID: string;
  CHROME_144_ANDROID: string;
  CHROME_145_ANDROID: string;
  CHROME_146_ANDROID: string;
  FIREFOX_133: string;
  SAFARI_18: string;
  SAFARI_17_IOS: string;
  SAFARI_18_IOS: string;
  // Backwards compatibility aliases
  IOS_CHROME_143: string;
  IOS_CHROME_144: string;
  IOS_CHROME_145: string;
  IOS_CHROME_146: string;
  ANDROID_CHROME_143: string;
  ANDROID_CHROME_144: string;
  ANDROID_CHROME_145: string;
  ANDROID_CHROME_146: string;
  IOS_SAFARI_17: string;
  IOS_SAFARI_18: string;
  all(): string[];
};

// ============================================================================
// Distributed Session Cache
// ============================================================================

export interface SessionCacheOptions {
  /**
   * Function to get session data from cache.
   * Returns JSON string with session data, or null if not found.
   * Supports both sync and async callbacks.
   */
  get?: (key: string) => string | null | Promise<string | null>;

  /**
   * Function to store session data in cache.
   * Returns 0 on success, non-zero on error.
   * Supports both sync and async callbacks.
   */
  put?: (key: string, value: string, ttlSeconds: number) => number | Promise<number>;

  /**
   * Function to delete session data from cache.
   * Returns 0 on success, non-zero on error.
   * Supports both sync and async callbacks.
   */
  delete?: (key: string) => number | Promise<number>;

  /**
   * Function to get ECH config from cache.
   * Returns base64-encoded config, or null if not found.
   * Supports both sync and async callbacks.
   */
  getEch?: (key: string) => string | null | Promise<string | null>;

  /**
   * Function to store ECH config in cache.
   * Returns 0 on success, non-zero on error.
   * Supports both sync and async callbacks.
   */
  putEch?: (key: string, value: string, ttlSeconds: number) => number | Promise<number>;

  /**
   * Error callback for cache operations.
   */
  onError?: (operation: string, key: string, error: string) => void;

  /**
   * Force async mode. If not specified, async mode is auto-detected
   * based on whether any callback is an async function.
   */
  async?: boolean;
}

/**
 * Distributed TLS session cache backend for sharing sessions across instances.
 *
 * Enables TLS session resumption across distributed httpcloak instances
 * by storing session tickets in an external cache like Redis or Memcached.
 *
 * Supports both synchronous callbacks (for in-memory Map) and asynchronous
 * callbacks (for Redis, database, etc.). Async mode is auto-detected when
 * any callback is an async function.
 *
 * Cache key formats:
 * - TLS sessions: httpcloak:sessions:{preset}:{protocol}:{host}:{port}
 * - ECH configs: httpcloak:ech:{preset}:{host}:{port}
 *
 * @example
 * // Sync example with Map
 * const cache = new Map();
 * const backend = new SessionCacheBackend({
 *   get: (key) => cache.get(key) || null,
 *   put: (key, value, ttl) => { cache.set(key, value); return 0; },
 *   delete: (key) => { cache.delete(key); return 0; },
 * });
 * backend.register();
 *
 * @example
 * // Async example with Redis
 * const redis = new Redis();
 * const backend = new SessionCacheBackend({
 *   get: async (key) => await redis.get(key),
 *   put: async (key, value, ttl) => { await redis.setex(key, ttl, value); return 0; },
 *   delete: async (key) => { await redis.del(key); return 0; },
 * });
 * backend.register();
 */
export class SessionCacheBackend {
  constructor(options?: SessionCacheOptions);

  /**
   * Check if this backend is running in async mode.
   */
  readonly isAsync: boolean;

  /**
   * Register this cache backend globally.
   * After registration, all new Session and LocalProxy instances will use
   * this cache for TLS session storage.
   */
  register(): void;

  /**
   * Unregister this cache backend.
   * After unregistration, new sessions will not use distributed caching.
   */
  unregister(): void;
}

/**
 * Configure a distributed session cache backend.
 *
 * Supports both synchronous and asynchronous callbacks (auto-detected).
 *
 * @param options Cache configuration
 * @returns The registered SessionCacheBackend instance
 *
 * @example
 * // Using Redis with async callbacks
 * const redis = new Redis();
 * httpcloak.configureSessionCache({
 *   get: async (key) => await redis.get(key),
 *   put: async (key, value, ttl) => { await redis.setex(key, ttl, value); return 0; },
 *   delete: async (key) => { await redis.del(key); return 0; },
 * });
 */
export function configureSessionCache(options: SessionCacheOptions): SessionCacheBackend;

/**
 * Clear the distributed session cache backend.
 * After calling this, new sessions will not use distributed caching.
 */
export function clearSessionCache(): void;

/**
 * Load a custom preset from a JSON file and register it.
 * @param filePath - Path to the preset JSON file
 * @returns The registered preset name
 */
export function loadPreset(filePath: string): string;

/**
 * Load a custom preset from a JSON string and register it.
 * @param jsonData - JSON string defining the preset
 * @returns The registered preset name
 */
export function loadPresetFromJSON(jsonData: string): string;

/**
 * Unregister a custom preset by name.
 * @param name - The preset name to unregister
 */
export function unregisterPreset(name: string): void;

/**
 * A pool of custom fingerprint presets for rotation.
 *
 * Pools load multiple presets from a single JSON file and provide
 * round-robin or random selection. All presets are auto-registered
 * on construction, so you can pass the returned name directly to
 * `new Session({ preset: name })`.
 */
export class PresetPool {
  /**
   * Load a preset pool from a JSON file.
   * @param filePath - Path to the pool JSON file
   */
  constructor(filePath: string);

  /**
   * Load a preset pool from a JSON string.
   * @param jsonData - JSON string defining the pool
   */
  static fromJSON(jsonData: string): PresetPool;

  /** Pick a preset using the pool's configured strategy. */
  pick(): string;

  /** Pick a random preset from the pool. */
  random(): string;

  /** Pick the next preset in round-robin order. */
  next(): string;

  /** Get a preset by index. */
  get(index: number): string;

  /** Number of presets in the pool. */
  readonly size: number;

  /** Name of the preset pool. */
  readonly name: string;

  /** Free the pool handle and unregister all its presets. */
  close(): void;
}
