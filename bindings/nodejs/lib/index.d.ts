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
  /** Browser preset to use (default: "chrome-145") */
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
  /** Number of retries on failure (default: 3, set to 0 to disable) */
  retry?: number;
  /** Status codes to retry on (default: [429, 500, 502, 503, 504]) */
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
  /** Custom JA3 fingerprint string (e.g., "771,4865-4866-4867-...,0-23-65281-...,29-23-24,0") */
  ja3?: string;
  /** Custom Akamai HTTP/2 fingerprint string (e.g., "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p") */
  akamai?: string;
  /** Extra fingerprint options: { tls_alpn, tls_signature_algorithms, tls_cert_compression, tls_permute_extensions } */
  extraFp?: Record<string, any>;
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
   */
  refresh(): void;

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
  /** Get all cookies from the session */
  getCookies(): Record<string, string>;

  /** Get a specific cookie by name */
  getCookie(name: string): string | null;

  /** Set a cookie in the session */
  setCookie(name: string, value: string): void;

  /** Delete a specific cookie by name */
  deleteCookie(name: string): void;

  /** Clear all cookies from the session */
  clearCookies(): void;

  /** Get cookies as a property */
  readonly cookies: Record<string, string>;

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
}

export interface LocalProxyOptions {
  /** Port to listen on (default: 0 for auto-assign) */
  port?: number;
  /** Browser preset to use (default: "chrome-145") */
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
  /** Total number of requests processed */
  totalRequests: number;
  /** Number of active connections */
  activeConnections: number;
  /** Number of failed requests */
  failedRequests: number;
  /** Bytes sent */
  bytesSent: number;
  /** Bytes received */
  bytesReceived: number;
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
 * const proxy = new LocalProxy({ preset: "chrome-145", tlsOnly: true });
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
   * Stop and close the proxy.
   * After closing, the LocalProxy instance cannot be reused.
   */
  close(): void;
}

/** Get the httpcloak library version */
export function version(): string;

/** Get list of available browser presets */
export function availablePresets(): string[];

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
  CHROME_143_ANDROID: string;
  CHROME_144_ANDROID: string;
  CHROME_145_ANDROID: string;
  FIREFOX_133: string;
  SAFARI_18: string;
  SAFARI_17_IOS: string;
  SAFARI_18_IOS: string;
  // Backwards compatibility aliases
  IOS_CHROME_143: string;
  IOS_CHROME_144: string;
  IOS_CHROME_145: string;
  ANDROID_CHROME_143: string;
  ANDROID_CHROME_144: string;
  ANDROID_CHROME_145: string;
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
