/**
 * HTTPCloak Node.js Client
 *
 * A fetch/axios-compatible HTTP client with browser fingerprint emulation.
 * Provides TLS fingerprinting for HTTP requests.
 */

const koffi = require("koffi");
const path = require("path");
const os = require("os");
const fs = require("fs");

/**
 * Custom error class for HTTPCloak errors
 */
class HTTPCloakError extends Error {
  constructor(message) {
    super(message);
    this.name = "HTTPCloakError";
  }
}

/**
 * Available browser presets for TLS fingerprinting.
 *
 * Use these constants instead of typing preset strings manually:
 *   const httpcloak = require("httpcloak");
 *   httpcloak.configure({ preset: httpcloak.Preset.CHROME_143 });
 *
 *   // Or with Session
 *   const session = new httpcloak.Session({ preset: httpcloak.Preset.FIREFOX_133 });
 */
const Preset = {
  // Chrome 143 (latest)
  CHROME_143: "chrome-143",
  CHROME_143_WINDOWS: "chrome-143-windows",
  CHROME_143_LINUX: "chrome-143-linux",
  CHROME_143_MACOS: "chrome-143-macos",

  // Chrome 141
  CHROME_141: "chrome-141",

  // Chrome 133
  CHROME_133: "chrome-133",

  // Chrome 131
  CHROME_131: "chrome-131",
  CHROME_131_WINDOWS: "chrome-131-windows",
  CHROME_131_LINUX: "chrome-131-linux",
  CHROME_131_MACOS: "chrome-131-macos",

  // Mobile Chrome
  IOS_CHROME_143: "ios-chrome-143",
  ANDROID_CHROME_143: "android-chrome-143",

  // Firefox
  FIREFOX_133: "firefox-133",

  // Safari (desktop and mobile)
  SAFARI_18: "safari-18",
  IOS_SAFARI_17: "ios-safari-17",

  /**
   * Get all available preset names
   * @returns {string[]} List of all preset names
   */
  all() {
    return [
      this.CHROME_143, this.CHROME_143_WINDOWS, this.CHROME_143_LINUX, this.CHROME_143_MACOS,
      this.CHROME_141, this.CHROME_133, this.CHROME_131,
      this.IOS_CHROME_143, this.ANDROID_CHROME_143,
      this.FIREFOX_133,
      this.SAFARI_18, this.IOS_SAFARI_17,
    ];
  },
};

/**
 * HTTP status reason phrases
 */
const HTTP_STATUS_PHRASES = {
  100: "Continue", 101: "Switching Protocols", 102: "Processing",
  200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information",
  204: "No Content", 205: "Reset Content", 206: "Partial Content", 207: "Multi-Status",
  300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other",
  304: "Not Modified", 305: "Use Proxy", 307: "Temporary Redirect", 308: "Permanent Redirect",
  400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
  404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable",
  407: "Proxy Authentication Required", 408: "Request Timeout", 409: "Conflict",
  410: "Gone", 411: "Length Required", 412: "Precondition Failed",
  413: "Payload Too Large", 414: "URI Too Long", 415: "Unsupported Media Type",
  416: "Range Not Satisfiable", 417: "Expectation Failed", 418: "I'm a teapot",
  421: "Misdirected Request", 422: "Unprocessable Entity", 423: "Locked",
  424: "Failed Dependency", 425: "Too Early", 426: "Upgrade Required",
  428: "Precondition Required", 429: "Too Many Requests",
  431: "Request Header Fields Too Large", 451: "Unavailable For Legal Reasons",
  500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
  503: "Service Unavailable", 504: "Gateway Timeout", 505: "HTTP Version Not Supported",
  506: "Variant Also Negotiates", 507: "Insufficient Storage", 508: "Loop Detected",
  510: "Not Extended", 511: "Network Authentication Required",
};

/**
 * Cookie object from Set-Cookie header
 */
class Cookie {
  /**
   * @param {string} name - Cookie name
   * @param {string} value - Cookie value
   */
  constructor(name, value) {
    this.name = name;
    this.value = value;
  }

  toString() {
    return `Cookie(name=${this.name}, value=${this.value})`;
  }
}

/**
 * Redirect info from history
 */
class RedirectInfo {
  /**
   * @param {number} statusCode - HTTP status code
   * @param {string} url - Request URL
   * @param {Object} headers - Response headers
   */
  constructor(statusCode, url, headers) {
    this.statusCode = statusCode;
    this.url = url;
    this.headers = headers || {};
  }

  toString() {
    return `RedirectInfo(statusCode=${this.statusCode}, url=${this.url})`;
  }
}

/**
 * Response object returned from HTTP requests
 */
class Response {
  /**
   * @param {Object} data - Response data from native library
   * @param {number} [elapsed=0] - Elapsed time in milliseconds
   */
  constructor(data, elapsed = 0) {
    this.statusCode = data.status_code || 0;
    this.headers = data.headers || {};
    this._body = Buffer.from(data.body || "", "utf8");
    this._text = data.body || "";
    this.finalUrl = data.final_url || "";
    this.protocol = data.protocol || "";
    this.elapsed = elapsed; // milliseconds

    // Parse cookies from response
    this._cookies = (data.cookies || []).map(c => new Cookie(c.name || "", c.value || ""));

    // Parse redirect history
    this._history = (data.history || []).map(h => new RedirectInfo(
      h.status_code || 0,
      h.url || "",
      h.headers || {}
    ));
  }

  /** Cookies set by this response */
  get cookies() {
    return this._cookies;
  }

  /** Redirect history (list of RedirectInfo objects) */
  get history() {
    return this._history;
  }

  /** Response body as string */
  get text() {
    return this._text;
  }

  /** Response body as Buffer (requests compatibility) */
  get body() {
    return this._body;
  }

  /** Response body as Buffer (requests compatibility alias) */
  get content() {
    return this._body;
  }

  /** Final URL after redirects (requests compatibility alias) */
  get url() {
    return this.finalUrl;
  }

  /** True if status code < 400 (requests compatibility) */
  get ok() {
    return this.statusCode < 400;
  }

  /** HTTP status reason phrase (e.g., 'OK', 'Not Found') */
  get reason() {
    return HTTP_STATUS_PHRASES[this.statusCode] || "Unknown";
  }

  /**
   * Response encoding from Content-Type header.
   * Returns null if not specified.
   */
  get encoding() {
    let contentType = this.headers["content-type"] || this.headers["Content-Type"] || "";
    if (contentType.includes("charset=")) {
      const parts = contentType.split(";");
      for (const part of parts) {
        const trimmed = part.trim();
        if (trimmed.toLowerCase().startsWith("charset=")) {
          return trimmed.split("=")[1].trim().replace(/['"]/g, "");
        }
      }
    }
    return null;
  }

  /**
   * Parse response body as JSON
   */
  json() {
    return JSON.parse(this._text);
  }

  /**
   * Raise error if status >= 400 (requests compatibility)
   */
  raiseForStatus() {
    if (!this.ok) {
      throw new HTTPCloakError(`HTTP ${this.statusCode}: ${this.reason}`);
    }
  }
}

/**
 * High-performance buffer pool using SharedArrayBuffer for zero-allocation copies.
 * Pre-allocates a large buffer once and reuses it across requests.
 */
class FastBufferPool {
  constructor() {
    // Pre-allocate 256MB SharedArrayBuffer for maximum performance
    this._sharedBuffer = new SharedArrayBuffer(256 * 1024 * 1024);
    this._bufferView = Buffer.from(this._sharedBuffer);
    this._inUse = false;

    // Fallback pool for concurrent requests or very large files
    this._fallbackPools = new Map();
    this._tiers = [1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864, 134217728];
  }

  /**
   * Get a buffer of at least the requested size
   * @param {number} size - Minimum buffer size needed
   * @returns {Buffer} - A buffer (may be larger than requested)
   */
  acquire(size) {
    // Use pre-allocated SharedArrayBuffer if available and large enough
    if (!this._inUse && size <= this._sharedBuffer.byteLength) {
      this._inUse = true;
      return this._bufferView;
    }

    // Fallback to regular buffer pool for concurrent requests
    let tier = this._tiers[this._tiers.length - 1];
    for (const t of this._tiers) {
      if (t >= size) {
        tier = t;
        break;
      }
    }

    const pool = this._fallbackPools.get(tier);
    if (pool && pool.length > 0) {
      return pool.pop();
    }

    return Buffer.allocUnsafe(Math.max(tier, size));
  }

  /**
   * Return a buffer to the pool for reuse
   * @param {Buffer} buffer - Buffer to return
   */
  release(buffer) {
    // Check if this is our shared buffer
    if (buffer.buffer === this._sharedBuffer) {
      this._inUse = false;
      return;
    }

    // Otherwise add to fallback pool
    const size = buffer.length;
    if (!this._tiers.includes(size)) {
      return;
    }

    let pool = this._fallbackPools.get(size);
    if (!pool) {
      pool = [];
      this._fallbackPools.set(size, pool);
    }

    if (pool.length < 2) {
      pool.push(buffer);
    }
  }
}

// Global buffer pool instance
const _bufferPool = new FastBufferPool();

/**
 * Fast response object with zero-copy buffer transfer.
 *
 * This response type avoids JSON serialization and base64 encoding for the body,
 * copying data directly from Go's memory to a Node.js Buffer.
 *
 * Use session.getFast() for maximum download performance.
 */
class FastResponse {
  /**
   * @param {Object} metadata - Response metadata from native library
   * @param {Buffer} body - Response body as Buffer (view of pooled buffer)
   * @param {number} [elapsed=0] - Elapsed time in milliseconds
   * @param {Buffer} [pooledBuffer=null] - The underlying pooled buffer for release
   */
  constructor(metadata, body, elapsed = 0, pooledBuffer = null) {
    this.statusCode = metadata.status_code || 0;
    this.headers = metadata.headers || {};
    this._body = body;
    this._pooledBuffer = pooledBuffer;
    this.finalUrl = metadata.final_url || "";
    this.protocol = metadata.protocol || "";
    this.elapsed = elapsed;

    // Parse cookies from response
    this._cookies = (metadata.cookies || []).map(c => new Cookie(c.name || "", c.value || ""));

    // Parse redirect history
    this._history = (metadata.history || []).map(h => new RedirectInfo(
      h.status_code || 0,
      h.url || "",
      h.headers || {}
    ));
  }

  /**
   * Release the underlying buffer back to the pool.
   * Call this when done with the response to enable buffer reuse.
   * After calling release(), the body buffer should not be used.
   */
  release() {
    if (this._pooledBuffer) {
      _bufferPool.release(this._pooledBuffer);
      this._pooledBuffer = null;
      this._body = null;
    }
  }

  /** Cookies set by this response */
  get cookies() {
    return this._cookies;
  }

  /** Redirect history (list of RedirectInfo objects) */
  get history() {
    return this._history;
  }

  /** Response body as string */
  get text() {
    return this._body.toString("utf8");
  }

  /** Response body as Buffer */
  get body() {
    return this._body;
  }

  /** Response body as Buffer (requests compatibility alias) */
  get content() {
    return this._body;
  }

  /** Final URL after redirects (requests compatibility alias) */
  get url() {
    return this.finalUrl;
  }

  /** True if status code < 400 (requests compatibility) */
  get ok() {
    return this.statusCode < 400;
  }

  /** HTTP status reason phrase (e.g., 'OK', 'Not Found') */
  get reason() {
    return HTTP_STATUS_PHRASES[this.statusCode] || "Unknown";
  }

  /**
   * Response encoding from Content-Type header.
   * Returns null if not specified.
   */
  get encoding() {
    let contentType = this.headers["content-type"] || this.headers["Content-Type"] || "";
    if (contentType.includes("charset=")) {
      const parts = contentType.split(";");
      for (const part of parts) {
        const trimmed = part.trim();
        if (trimmed.toLowerCase().startsWith("charset=")) {
          return trimmed.split("=")[1].trim().replace(/['"]/g, "");
        }
      }
    }
    return null;
  }

  /**
   * Parse response body as JSON
   */
  json() {
    return JSON.parse(this._body.toString("utf8"));
  }

  /**
   * Raise error if status >= 400 (requests compatibility)
   */
  raiseForStatus() {
    if (!this.ok) {
      throw new HTTPCloakError(`HTTP ${this.statusCode}: ${this.reason}`);
    }
  }
}

/**
 * Streaming HTTP Response for downloading large files.
 *
 * Example:
 *   const stream = session.getStream(url);
 *   for await (const chunk of stream) {
 *     file.write(chunk);
 *   }
 *   stream.close();
 */
class StreamResponse {
  /**
   * @param {number} streamHandle - Native stream handle
   * @param {Object} lib - Native library
   * @param {Object} metadata - Stream metadata
   */
  constructor(streamHandle, lib, metadata) {
    this._handle = streamHandle;
    this._lib = lib;
    this.statusCode = metadata.status_code || 0;
    this.headers = metadata.headers || {};
    this.finalUrl = metadata.final_url || "";
    this.protocol = metadata.protocol || "";
    this.contentLength = metadata.content_length || -1;
    this._cookies = (metadata.cookies || []).map(c => new Cookie(c.name || "", c.value || ""));
    this._closed = false;
  }

  /** Cookies set by this response */
  get cookies() {
    return this._cookies;
  }

  /** Final URL after redirects */
  get url() {
    return this.finalUrl;
  }

  /** True if status code < 400 */
  get ok() {
    return this.statusCode < 400;
  }

  /** HTTP status reason phrase */
  get reason() {
    return HTTP_STATUS_PHRASES[this.statusCode] || "Unknown";
  }

  /**
   * Read a chunk of data from the stream.
   * @param {number} [chunkSize=8192] - Maximum bytes to read
   * @returns {Buffer|null} - Chunk of data or null if EOF
   */
  readChunk(chunkSize = 8192) {
    if (this._closed) {
      throw new HTTPCloakError("Stream is closed");
    }

    const result = this._lib.httpcloak_stream_read(this._handle, chunkSize);
    if (!result || result === "") {
      return null; // EOF
    }

    // Decode base64 to Buffer
    return Buffer.from(result, "base64");
  }

  /**
   * Async generator for iterating over chunks.
   * @param {number} [chunkSize=8192] - Size of each chunk
   * @yields {Buffer} - Chunks of response content
   *
   * Example:
   *   for await (const chunk of stream.iterate()) {
   *     file.write(chunk);
   *   }
   */
  async *iterate(chunkSize = 8192) {
    while (true) {
      const chunk = this.readChunk(chunkSize);
      if (!chunk) {
        break;
      }
      yield chunk;
    }
  }

  /**
   * Symbol.asyncIterator for for-await-of loops.
   * @yields {Buffer} - Chunks of response content
   *
   * Example:
   *   for await (const chunk of stream) {
   *     file.write(chunk);
   *   }
   */
  [Symbol.asyncIterator]() {
    return this.iterate();
  }

  /**
   * Read the entire response body as Buffer.
   * Warning: This defeats the purpose of streaming for large files.
   * @returns {Buffer}
   */
  readAll() {
    const chunks = [];
    let chunk;
    while ((chunk = this.readChunk()) !== null) {
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }

  /**
   * Read the entire response body as string.
   * @returns {string}
   */
  get text() {
    return this.readAll().toString("utf8");
  }

  /**
   * Read the entire response body as Buffer.
   * @returns {Buffer}
   */
  get body() {
    return this.readAll();
  }

  /**
   * Parse the response body as JSON.
   * @returns {any}
   */
  json() {
    return JSON.parse(this.text);
  }

  /**
   * Close the stream and release resources.
   */
  close() {
    if (!this._closed) {
      this._lib.httpcloak_stream_close(this._handle);
      this._closed = true;
    }
  }

  /**
   * Raise error if status >= 400
   */
  raiseForStatus() {
    if (!this.ok) {
      throw new HTTPCloakError(`HTTP ${this.statusCode}: ${this.reason}`);
    }
  }
}

/**
 * Get the platform package name for the current platform
 */
function getPlatformPackageName() {
  const platform = os.platform();
  const arch = os.arch();

  let platName;
  if (platform === "darwin") {
    platName = "darwin";
  } else if (platform === "win32") {
    platName = "win32";
  } else {
    platName = "linux";
  }

  let archName;
  if (arch === "x64" || arch === "amd64") {
    archName = "x64";
  } else if (arch === "arm64" || arch === "aarch64") {
    archName = "arm64";
  } else {
    archName = arch;
  }

  return `@httpcloak/${platName}-${archName}`;
}

/**
 * Get the path to the native library
 */
function getLibPath() {
  const platform = os.platform();
  const arch = os.arch();

  const envPath = process.env.HTTPCLOAK_LIB_PATH;
  if (envPath && fs.existsSync(envPath)) {
    return envPath;
  }

  const packageName = getPlatformPackageName();
  try {
    const libPath = require(packageName);
    if (fs.existsSync(libPath)) {
      return libPath;
    }
  } catch (e) {
    // Optional dependency not installed
  }

  let archName;
  if (arch === "x64" || arch === "amd64") {
    archName = "amd64";
  } else if (arch === "arm64" || arch === "aarch64") {
    archName = "arm64";
  } else {
    archName = arch;
  }

  let osName, ext;
  if (platform === "darwin") {
    osName = "darwin";
    ext = ".dylib";
  } else if (platform === "win32") {
    osName = "windows";
    ext = ".dll";
  } else {
    osName = "linux";
    ext = ".so";
  }

  const libName = `libhttpcloak-${osName}-${archName}${ext}`;

  const searchPaths = [
    path.join(__dirname, libName),
    path.join(__dirname, "..", libName),
    path.join(__dirname, "..", "lib", libName),
  ];

  for (const searchPath of searchPaths) {
    if (fs.existsSync(searchPath)) {
      return searchPath;
    }
  }

  throw new HTTPCloakError(
    `Could not find httpcloak library (${libName}). ` +
      `Try: npm install ${packageName}`
  );
}

// Define callback proto globally for koffi (must be before getLib)
const AsyncCallbackProto = koffi.proto("void AsyncCallback(int64 callbackId, str responseJson, str error)");

// Session cache callback prototypes
const SessionCacheGetProto = koffi.proto("str SessionCacheGet(str key)");
const SessionCachePutProto = koffi.proto("int SessionCachePut(str key, str valueJson, int64 ttlSeconds)");
const SessionCacheDeleteProto = koffi.proto("int SessionCacheDelete(str key)");
const SessionCacheErrorProto = koffi.proto("void SessionCacheError(str operation, str key, str error)");
const EchCacheGetProto = koffi.proto("str EchCacheGet(str key)");
const EchCachePutProto = koffi.proto("int EchCachePut(str key, str valueBase64, int64 ttlSeconds)");

// Load the native library
let lib = null;
let nativeLibHandle = null;

function getLib() {
  if (lib === null) {
    const libPath = getLibPath();
    nativeLibHandle = koffi.load(libPath);

    // Use str for string returns - koffi handles the string copy automatically
    // Note: The C strings allocated by Go are not freed, but Go's GC handles them
    lib = {
      httpcloak_session_new: nativeLibHandle.func("httpcloak_session_new", "int64", ["str"]),
      httpcloak_session_free: nativeLibHandle.func("httpcloak_session_free", "void", ["int64"]),
      httpcloak_get: nativeLibHandle.func("httpcloak_get", "str", ["int64", "str", "str"]),
      httpcloak_post: nativeLibHandle.func("httpcloak_post", "str", ["int64", "str", "str", "str"]),
      httpcloak_request: nativeLibHandle.func("httpcloak_request", "str", ["int64", "str"]),
      httpcloak_get_cookies: nativeLibHandle.func("httpcloak_get_cookies", "str", ["int64"]),
      httpcloak_set_cookie: nativeLibHandle.func("httpcloak_set_cookie", "void", ["int64", "str", "str"]),
      httpcloak_free_string: nativeLibHandle.func("httpcloak_free_string", "void", ["void*"]),
      httpcloak_version: nativeLibHandle.func("httpcloak_version", "str", []),
      httpcloak_available_presets: nativeLibHandle.func("httpcloak_available_presets", "str", []),
      httpcloak_set_ech_dns_servers: nativeLibHandle.func("httpcloak_set_ech_dns_servers", "str", ["str"]),
      httpcloak_get_ech_dns_servers: nativeLibHandle.func("httpcloak_get_ech_dns_servers", "str", []),
      // Async functions
      httpcloak_register_callback: nativeLibHandle.func("httpcloak_register_callback", "int64", [koffi.pointer(AsyncCallbackProto)]),
      httpcloak_unregister_callback: nativeLibHandle.func("httpcloak_unregister_callback", "void", ["int64"]),
      httpcloak_get_async: nativeLibHandle.func("httpcloak_get_async", "void", ["int64", "str", "str", "int64"]),
      httpcloak_post_async: nativeLibHandle.func("httpcloak_post_async", "void", ["int64", "str", "str", "str", "int64"]),
      httpcloak_request_async: nativeLibHandle.func("httpcloak_request_async", "void", ["int64", "str", "int64"]),
      // Streaming functions
      httpcloak_stream_get: nativeLibHandle.func("httpcloak_stream_get", "int64", ["int64", "str", "str"]),
      httpcloak_stream_post: nativeLibHandle.func("httpcloak_stream_post", "int64", ["int64", "str", "str", "str"]),
      httpcloak_stream_request: nativeLibHandle.func("httpcloak_stream_request", "int64", ["int64", "str"]),
      httpcloak_stream_get_metadata: nativeLibHandle.func("httpcloak_stream_get_metadata", "str", ["int64"]),
      httpcloak_stream_read: nativeLibHandle.func("httpcloak_stream_read", "str", ["int64", "int64"]),
      httpcloak_stream_close: nativeLibHandle.func("httpcloak_stream_close", "void", ["int64"]),
      // Raw response functions for fast-path (zero-copy)
      httpcloak_get_raw: nativeLibHandle.func("httpcloak_get_raw", "int64", ["int64", "str", "str"]),
      httpcloak_post_raw: nativeLibHandle.func("httpcloak_post_raw", "int64", ["int64", "str", "void*", "int", "str"]),
      httpcloak_request_raw: nativeLibHandle.func("httpcloak_request_raw", "int64", ["int64", "str", "void*", "int"]),
      httpcloak_response_get_metadata: nativeLibHandle.func("httpcloak_response_get_metadata", "str", ["int64"]),
      httpcloak_response_get_body_len: nativeLibHandle.func("httpcloak_response_get_body_len", "int", ["int64"]),
      httpcloak_response_copy_body_to: nativeLibHandle.func("httpcloak_response_copy_body_to", "int", ["int64", "void*", "int"]),
      httpcloak_response_free: nativeLibHandle.func("httpcloak_response_free", "void", ["int64"]),
      // Combined finalize function (copy + metadata + free in one call)
      httpcloak_response_finalize: nativeLibHandle.func("httpcloak_response_finalize", "str", ["int64", "void*", "int"]),
      // Session persistence functions
      httpcloak_session_save: nativeLibHandle.func("httpcloak_session_save", "str", ["int64", "str"]),
      httpcloak_session_load: nativeLibHandle.func("httpcloak_session_load", "int64", ["str"]),
      httpcloak_session_marshal: nativeLibHandle.func("httpcloak_session_marshal", "str", ["int64"]),
      httpcloak_session_unmarshal: nativeLibHandle.func("httpcloak_session_unmarshal", "int64", ["str"]),
      // Proxy management functions
      httpcloak_session_set_proxy: nativeLibHandle.func("httpcloak_session_set_proxy", "str", ["int64", "str"]),
      httpcloak_session_set_tcp_proxy: nativeLibHandle.func("httpcloak_session_set_tcp_proxy", "str", ["int64", "str"]),
      httpcloak_session_set_udp_proxy: nativeLibHandle.func("httpcloak_session_set_udp_proxy", "str", ["int64", "str"]),
      httpcloak_session_get_proxy: nativeLibHandle.func("httpcloak_session_get_proxy", "str", ["int64"]),
      httpcloak_session_get_tcp_proxy: nativeLibHandle.func("httpcloak_session_get_tcp_proxy", "str", ["int64"]),
      httpcloak_session_get_udp_proxy: nativeLibHandle.func("httpcloak_session_get_udp_proxy", "str", ["int64"]),
      // Header order customization
      httpcloak_session_set_header_order: nativeLibHandle.func("httpcloak_session_set_header_order", "str", ["int64", "str"]),
      httpcloak_session_get_header_order: nativeLibHandle.func("httpcloak_session_get_header_order", "str", ["int64"]),
      // Local proxy functions
      httpcloak_local_proxy_start: nativeLibHandle.func("httpcloak_local_proxy_start", "int64", ["str"]),
      httpcloak_local_proxy_stop: nativeLibHandle.func("httpcloak_local_proxy_stop", "void", ["int64"]),
      httpcloak_local_proxy_get_port: nativeLibHandle.func("httpcloak_local_proxy_get_port", "int", ["int64"]),
      httpcloak_local_proxy_is_running: nativeLibHandle.func("httpcloak_local_proxy_is_running", "int", ["int64"]),
      httpcloak_local_proxy_get_stats: nativeLibHandle.func("httpcloak_local_proxy_get_stats", "str", ["int64"]),
      httpcloak_local_proxy_register_session: nativeLibHandle.func("httpcloak_local_proxy_register_session", "str", ["int64", "str", "int64"]),
      httpcloak_local_proxy_unregister_session: nativeLibHandle.func("httpcloak_local_proxy_unregister_session", "int", ["int64", "str"]),
      // Session cache callbacks
      httpcloak_set_session_cache_callbacks: nativeLibHandle.func("httpcloak_set_session_cache_callbacks", "void", [
        koffi.pointer(SessionCacheGetProto),
        koffi.pointer(SessionCachePutProto),
        koffi.pointer(SessionCacheDeleteProto),
        koffi.pointer(EchCacheGetProto),
        koffi.pointer(EchCachePutProto),
        koffi.pointer(SessionCacheErrorProto),
      ]),
      httpcloak_clear_session_cache_callbacks: nativeLibHandle.func("httpcloak_clear_session_cache_callbacks", "void", []),
    };
  }
  return lib;
}

/**
 * Async callback manager for native Go goroutine-based async
 *
 * Each async request registers a callback with Go and receives a unique ID.
 * When Go completes the request, it invokes the callback with that ID.
 */
class AsyncCallbackManager {
  constructor() {
    // callbackId -> { resolve, reject, startTime }
    this._pendingRequests = new Map();
    this._callbackPtr = null;
    this._refTimer = null; // Timer to keep event loop alive
  }

  /**
   * Ref the event loop to prevent Node.js from exiting while requests are pending
   */
  _ref() {
    if (this._refTimer === null) {
      // Create a timer that keeps the event loop alive
      this._refTimer = setInterval(() => {}, 2147483647); // Max interval
    }
  }

  /**
   * Unref the event loop when no more pending requests
   */
  _unref() {
    if (this._pendingRequests.size === 0 && this._refTimer !== null) {
      clearInterval(this._refTimer);
      this._refTimer = null;
    }
  }

  /**
   * Ensure the callback is set up with koffi
   */
  _ensureCallback() {
    if (this._callbackPtr !== null) {
      return;
    }

    // Create callback function that will be invoked by Go
    // koffi.register expects koffi.pointer(proto) as the type
    this._callbackPtr = koffi.register((callbackId, responseJson, error) => {
      const pending = this._pendingRequests.get(Number(callbackId));
      if (!pending) {
        return;
      }
      this._pendingRequests.delete(Number(callbackId));
      this._unref(); // Check if we can release the event loop

      const { resolve, reject, startTime } = pending;
      const elapsed = Date.now() - startTime;

      if (error && error !== "") {
        let errMsg = error;
        try {
          const errData = JSON.parse(error);
          errMsg = errData.error || error;
        } catch (e) {
          // Use raw error string
        }
        reject(new HTTPCloakError(errMsg));
      } else if (responseJson) {
        try {
          const data = JSON.parse(responseJson);
          if (data.error) {
            reject(new HTTPCloakError(data.error));
          } else {
            resolve(new Response(data, elapsed));
          }
        } catch (e) {
          reject(new HTTPCloakError(`Failed to parse response: ${e.message}`));
        }
      } else {
        reject(new HTTPCloakError("No response received"));
      }
    }, koffi.pointer(AsyncCallbackProto));
  }

  /**
   * Register a new async request
   * @returns {{ callbackId: number, promise: Promise<Response> }}
   */
  registerRequest(nativeLib) {
    this._ensureCallback();

    // Register callback with Go (each request gets unique ID)
    const callbackId = nativeLib.httpcloak_register_callback(this._callbackPtr);

    // Create promise for this request with start time
    let resolve, reject;
    const promise = new Promise((res, rej) => {
      resolve = res;
      reject = rej;
    });
    const startTime = Date.now();

    this._pendingRequests.set(Number(callbackId), { resolve, reject, startTime });
    this._ref(); // Keep event loop alive

    return { callbackId, promise };
  }
}

// Global async callback manager
let asyncManager = null;

function getAsyncManager() {
  if (asyncManager === null) {
    asyncManager = new AsyncCallbackManager();
  }
  return asyncManager;
}

/**
 * Convert result to string (handles both direct strings and null)
 * With "str" return type, koffi automatically handles the conversion
 */
function resultToString(result) {
  if (!result) {
    return null;
  }
  return result;
}

/**
 * Parse response from the native library
 * @param {string} resultPtr - Result pointer from native function
 * @param {number} [elapsed=0] - Elapsed time in milliseconds
 * @returns {Response}
 */
function parseResponse(resultPtr, elapsed = 0) {
  const result = resultToString(resultPtr);
  if (!result) {
    throw new HTTPCloakError("No response received");
  }

  const data = JSON.parse(result);

  if (data.error) {
    throw new HTTPCloakError(data.error);
  }

  return new Response(data, elapsed);
}

/**
 * Add query parameters to URL
 */
function addParamsToUrl(url, params) {
  if (!params || Object.keys(params).length === 0) {
    return url;
  }

  const urlObj = new URL(url);
  for (const [key, value] of Object.entries(params)) {
    urlObj.searchParams.append(key, String(value));
  }
  return urlObj.toString();
}

/**
 * Apply basic auth to headers
 */
function applyAuth(headers, auth) {
  if (!auth) {
    return headers;
  }

  const [username, password] = auth;
  const credentials = Buffer.from(`${username}:${password}`).toString("base64");

  headers = headers ? { ...headers } : {};
  headers["Authorization"] = `Basic ${credentials}`;
  return headers;
}

/**
 * Detect MIME type from filename
 */
function detectMimeType(filename) {
  const ext = path.extname(filename).toLowerCase();
  const mimeTypes = {
    ".html": "text/html",
    ".htm": "text/html",
    ".css": "text/css",
    ".js": "application/javascript",
    ".json": "application/json",
    ".xml": "application/xml",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".bmp": "image/bmp",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".pdf": "application/pdf",
    ".zip": "application/zip",
    ".gz": "application/gzip",
    ".tar": "application/x-tar",
  };
  return mimeTypes[ext] || "application/octet-stream";
}

/**
 * Encode multipart form data
 * @param {Object} data - Form fields (key-value pairs)
 * @param {Object} files - Files to upload
 *   Each key is the field name, value can be:
 *   - Buffer: raw file content
 *   - { filename, content, contentType? }: file with metadata
 * @returns {{ body: Buffer, contentType: string }}
 */
function encodeMultipart(data, files) {
  const boundary = `----HTTPCloakBoundary${Date.now().toString(16)}${Math.random().toString(16).slice(2)}`;
  const parts = [];

  // Add form fields
  if (data) {
    for (const [key, value] of Object.entries(data)) {
      parts.push(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${key}"\r\n\r\n` +
        `${value}\r\n`
      );
    }
  }

  // Add files
  if (files) {
    for (const [fieldName, fileValue] of Object.entries(files)) {
      let filename, content, contentType;

      if (Buffer.isBuffer(fileValue)) {
        filename = fieldName;
        content = fileValue;
        contentType = "application/octet-stream";
      } else if (typeof fileValue === "object" && fileValue !== null) {
        filename = fileValue.filename || fieldName;
        content = fileValue.content;
        contentType = fileValue.contentType || detectMimeType(filename);

        if (!Buffer.isBuffer(content)) {
          content = Buffer.from(content);
        }
      } else {
        throw new HTTPCloakError(`Invalid file value for field '${fieldName}'`);
      }

      parts.push(Buffer.from(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\n` +
        `Content-Type: ${contentType}\r\n\r\n`
      ));
      parts.push(content);
      parts.push(Buffer.from("\r\n"));
    }
  }

  parts.push(Buffer.from(`--${boundary}--\r\n`));

  // Combine all parts
  const bodyParts = parts.map(p => Buffer.isBuffer(p) ? p : Buffer.from(p));
  const body = Buffer.concat(bodyParts);

  return {
    body,
    contentType: `multipart/form-data; boundary=${boundary}`,
  };
}

/**
 * Get the httpcloak library version
 */
function version() {
  const nativeLib = getLib();
  const resultPtr = nativeLib.httpcloak_version();
  const result = resultToString(resultPtr);
  return result || "unknown";
}

/**
 * Get list of available browser presets
 */
function availablePresets() {
  const nativeLib = getLib();
  const resultPtr = nativeLib.httpcloak_available_presets();
  const result = resultToString(resultPtr);
  if (result) {
    return JSON.parse(result);
  }
  return [];
}

/**
 * Configure the DNS servers used for ECH (Encrypted Client Hello) config queries.
 *
 * By default, ECH queries use Google (8.8.8.8), Cloudflare (1.1.1.1), and Quad9 (9.9.9.9).
 * Use this function to configure custom DNS servers for environments with restricted
 * network access or for privacy requirements.
 *
 * This is a global setting that affects all sessions.
 *
 * @param {string[]|null} servers - Array of DNS server addresses in "host:port" format (e.g., ["10.0.0.53:53"]).
 *                                  Pass null or empty array to reset to defaults.
 * @throws {Error} If the servers list is invalid.
 * @example
 * setEchDnsServers(["10.0.0.53:53", "192.168.1.1:53"]);
 * setEchDnsServers(null);  // Reset to defaults
 */
function setEchDnsServers(servers) {
  const nativeLib = getLib();
  let serversJson = null;
  if (servers && servers.length > 0) {
    serversJson = JSON.stringify(servers);
  }
  const errorPtr = nativeLib.httpcloak_set_ech_dns_servers(serversJson);
  const error = resultToString(errorPtr);
  if (error) {
    throw new HTTPCloakError(`Failed to set ECH DNS servers: ${error}`);
  }
}

/**
 * Get the current DNS servers used for ECH (Encrypted Client Hello) config queries.
 *
 * @returns {string[]} Array of DNS server addresses in "host:port" format.
 * @example
 * const servers = getEchDnsServers();
 * console.log(servers);  // ['8.8.8.8:53', '1.1.1.1:53', '9.9.9.9:53']
 */
function getEchDnsServers() {
  const nativeLib = getLib();
  const resultPtr = nativeLib.httpcloak_get_ech_dns_servers();
  const result = resultToString(resultPtr);
  if (result) {
    return JSON.parse(result);
  }
  return [];
}

/**
 * HTTP Session with browser fingerprint emulation
 */
class Session {
  /**
   * Create a new session
   * @param {Object} options - Session options
   * @param {string} [options.preset="chrome-143"] - Browser preset to use
   * @param {string} [options.proxy] - Proxy URL (e.g., "http://user:pass@host:port" or "socks5://host:port")
   * @param {string} [options.tcpProxy] - Proxy URL for TCP protocols (HTTP/1.1, HTTP/2) - use with udpProxy for split config
   * @param {string} [options.udpProxy] - Proxy URL for UDP protocols (HTTP/3 via MASQUE) - use with tcpProxy for split config
   * @param {number} [options.timeout=30] - Request timeout in seconds
   * @param {string} [options.httpVersion="auto"] - HTTP version: "auto", "h1", "h2", "h3"
   * @param {boolean} [options.verify=true] - SSL certificate verification
   * @param {boolean} [options.allowRedirects=true] - Follow redirects
   * @param {number} [options.maxRedirects=10] - Maximum number of redirects to follow
   * @param {number} [options.retry=3] - Number of retries on failure (set to 0 to disable)
   * @param {number[]} [options.retryOnStatus] - Status codes to retry on
   * @param {number} [options.retryWaitMin=500] - Minimum wait time between retries in milliseconds
   * @param {number} [options.retryWaitMax=10000] - Maximum wait time between retries in milliseconds
   * @param {Array} [options.auth] - Default auth [username, password] for all requests
   * @param {Object} [options.connectTo] - Domain fronting map {requestHost: connectHost}
   * @param {string} [options.echConfigDomain] - Domain to fetch ECH config from (e.g., "cloudflare-ech.com")
   * @param {boolean} [options.tlsOnly=false] - TLS-only mode: skip preset HTTP headers, only apply TLS fingerprint
   * @param {number} [options.quicIdleTimeout=0] - QUIC idle timeout in seconds (default: 30, 0 uses default)
   */
  constructor(options = {}) {
    const {
      preset = "chrome-143",
      proxy = null,
      tcpProxy = null,
      udpProxy = null,
      timeout = 30,
      httpVersion = "auto",
      verify = true,
      allowRedirects = true,
      maxRedirects = 10,
      retry = 3,
      retryOnStatus = null,
      retryWaitMin = 500,
      retryWaitMax = 10000,
      preferIpv4 = false,
      auth = null,
      connectTo = null,
      echConfigDomain = null,
      tlsOnly = false,
      quicIdleTimeout = 0,
    } = options;

    this._lib = getLib();
    this.headers = {}; // Default headers
    this.auth = auth; // Default auth for all requests

    const config = {
      preset,
      timeout,
      http_version: httpVersion,
    };
    if (proxy) {
      config.proxy = proxy;
    }
    if (tcpProxy) {
      config.tcp_proxy = tcpProxy;
    }
    if (udpProxy) {
      config.udp_proxy = udpProxy;
    }
    if (!verify) {
      config.verify = false;
    }
    if (!allowRedirects) {
      config.allow_redirects = false;
    } else if (maxRedirects !== 10) {
      config.max_redirects = maxRedirects;
    }
    // Always pass retry to clib (even if 0 to explicitly disable)
    config.retry = retry;
    if (retryOnStatus) {
      config.retry_on_status = retryOnStatus;
    }
    if (retryWaitMin !== 500) {
      config.retry_wait_min = retryWaitMin;
    }
    if (retryWaitMax !== 10000) {
      config.retry_wait_max = retryWaitMax;
    }
    if (preferIpv4) {
      config.prefer_ipv4 = true;
    }
    if (connectTo) {
      config.connect_to = connectTo;
    }
    if (echConfigDomain) {
      config.ech_config_domain = echConfigDomain;
    }
    if (tlsOnly) {
      config.tls_only = true;
    }
    if (quicIdleTimeout > 0) {
      config.quic_idle_timeout = quicIdleTimeout;
    }

    this._handle = this._lib.httpcloak_session_new(JSON.stringify(config));

    if (this._handle === 0n || this._handle === 0) {
      throw new HTTPCloakError("Failed to create session");
    }
  }

  /**
   * Close the session and release resources
   */
  close() {
    if (this._handle) {
      this._lib.httpcloak_session_free(this._handle);
      this._handle = 0n;
    }
  }

  /**
   * Merge session headers with request headers
   */
  _mergeHeaders(headers) {
    if (!this.headers || Object.keys(this.headers).length === 0) {
      return headers;
    }
    return { ...this.headers, ...headers };
  }

  /**
   * Apply cookies to headers
   * @param {Object} headers - Existing headers
   * @param {Object} cookies - Cookies to apply as key-value pairs
   * @returns {Object} Headers with cookies applied
   */
  _applyCookies(headers, cookies) {
    if (!cookies || Object.keys(cookies).length === 0) {
      return headers;
    }

    const cookieStr = Object.entries(cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");

    headers = headers ? { ...headers } : {};
    const existing = headers["Cookie"] || "";
    if (existing) {
      headers["Cookie"] = `${existing}; ${cookieStr}`;
    } else {
      headers["Cookie"] = cookieStr;
    }
    return headers;
  }

  // ===========================================================================
  // Synchronous Methods
  // ===========================================================================

  /**
   * Perform a synchronous GET request
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {Object} [options.headers] - Custom headers
   * @param {Object} [options.params] - Query parameters
   * @param {Object} [options.cookies] - Cookies to send with this request
   * @param {Array} [options.auth] - Basic auth [username, password]
   * @returns {Response} Response object
   */
  getSync(url, options = {}) {
    const { headers = null, params = null, cookies = null, auth = null } = options;

    url = addParamsToUrl(url, params);
    let mergedHeaders = this._mergeHeaders(headers);
    // Use request auth if provided, otherwise fall back to session auth
    const effectiveAuth = auth !== null ? auth : this.auth;
    mergedHeaders = applyAuth(mergedHeaders, effectiveAuth);
    mergedHeaders = this._applyCookies(mergedHeaders, cookies);

    // Build request options JSON with headers wrapper (clib expects {"headers": {...}})
    const reqOptions = {};
    if (mergedHeaders) {
      reqOptions.headers = mergedHeaders;
    }
    const optionsJson = Object.keys(reqOptions).length > 0 ? JSON.stringify(reqOptions) : null;

    const startTime = Date.now();
    const result = this._lib.httpcloak_get(this._handle, url, optionsJson);
    const elapsed = Date.now() - startTime;
    return parseResponse(result, elapsed);
  }

  /**
   * Perform a synchronous POST request
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {string|Buffer|Object} [options.body] - Request body
   * @param {Object} [options.json] - JSON body (will be serialized)
   * @param {Object} [options.data] - Form data (will be URL encoded)
   * @param {Object} [options.files] - Files to upload as multipart/form-data
   *   Each key is the field name, value can be:
   *   - Buffer: raw file content
   *   - { filename, content, contentType? }: file with metadata
   * @param {Object} [options.headers] - Custom headers
   * @param {Object} [options.params] - Query parameters
   * @param {Object} [options.cookies] - Cookies to send with this request
   * @param {Array} [options.auth] - Basic auth [username, password]
   * @returns {Response} Response object
   */
  postSync(url, options = {}) {
    let { body = null, json = null, data = null, files = null, headers = null, params = null, cookies = null, auth = null } = options;

    url = addParamsToUrl(url, params);
    let mergedHeaders = this._mergeHeaders(headers);

    // Handle multipart file upload
    if (files !== null) {
      const formData = (data !== null && typeof data === "object") ? data : null;
      const multipart = encodeMultipart(formData, files);
      body = multipart.body.toString("latin1"); // Preserve binary data
      mergedHeaders = mergedHeaders || {};
      mergedHeaders["Content-Type"] = multipart.contentType;
    }
    // Handle JSON body
    else if (json !== null) {
      body = JSON.stringify(json);
      mergedHeaders = mergedHeaders || {};
      if (!mergedHeaders["Content-Type"]) {
        mergedHeaders["Content-Type"] = "application/json";
      }
    }
    // Handle form data
    else if (data !== null && typeof data === "object") {
      body = new URLSearchParams(data).toString();
      mergedHeaders = mergedHeaders || {};
      if (!mergedHeaders["Content-Type"]) {
        mergedHeaders["Content-Type"] = "application/x-www-form-urlencoded";
      }
    }
    // Handle Buffer body
    else if (Buffer.isBuffer(body)) {
      body = body.toString("utf8");
    }

    // Use request auth if provided, otherwise fall back to session auth
    const effectiveAuth = auth !== null ? auth : this.auth;
    mergedHeaders = applyAuth(mergedHeaders, effectiveAuth);
    mergedHeaders = this._applyCookies(mergedHeaders, cookies);

    // Build request options JSON with headers wrapper (clib expects {"headers": {...}})
    const reqOptions = {};
    if (mergedHeaders) {
      reqOptions.headers = mergedHeaders;
    }
    const optionsJson = Object.keys(reqOptions).length > 0 ? JSON.stringify(reqOptions) : null;

    const startTime = Date.now();
    const result = this._lib.httpcloak_post(this._handle, url, body, optionsJson);
    const elapsed = Date.now() - startTime;
    return parseResponse(result, elapsed);
  }

  /**
   * Perform a synchronous custom HTTP request
   * @param {string} method - HTTP method
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {Object} [options.cookies] - Cookies to send with this request
   * @param {Object} [options.files] - Files to upload as multipart/form-data
   * @returns {Response} Response object
   */
  requestSync(method, url, options = {}) {
    let { body = null, json = null, data = null, files = null, headers = null, params = null, cookies = null, auth = null, timeout = null } = options;

    url = addParamsToUrl(url, params);
    let mergedHeaders = this._mergeHeaders(headers);

    // Handle multipart file upload
    if (files !== null) {
      const formData = (data !== null && typeof data === "object") ? data : null;
      const multipart = encodeMultipart(formData, files);
      body = multipart.body.toString("latin1"); // Preserve binary data
      mergedHeaders = mergedHeaders || {};
      mergedHeaders["Content-Type"] = multipart.contentType;
    }
    // Handle JSON body
    else if (json !== null) {
      body = JSON.stringify(json);
      mergedHeaders = mergedHeaders || {};
      if (!mergedHeaders["Content-Type"]) {
        mergedHeaders["Content-Type"] = "application/json";
      }
    }
    // Handle form data
    else if (data !== null && typeof data === "object") {
      body = new URLSearchParams(data).toString();
      mergedHeaders = mergedHeaders || {};
      if (!mergedHeaders["Content-Type"]) {
        mergedHeaders["Content-Type"] = "application/x-www-form-urlencoded";
      }
    }
    // Handle Buffer body
    else if (Buffer.isBuffer(body)) {
      body = body.toString("utf8");
    }

    // Use request auth if provided, otherwise fall back to session auth
    const effectiveAuth = auth !== null ? auth : this.auth;
    mergedHeaders = applyAuth(mergedHeaders, effectiveAuth);
    mergedHeaders = this._applyCookies(mergedHeaders, cookies);

    const requestConfig = {
      method: method.toUpperCase(),
      url,
    };
    if (mergedHeaders) requestConfig.headers = mergedHeaders;
    if (body) requestConfig.body = body;
    if (timeout) requestConfig.timeout = timeout;

    const startTime = Date.now();
    const result = this._lib.httpcloak_request(
      this._handle,
      JSON.stringify(requestConfig)
    );
    const elapsed = Date.now() - startTime;
    return parseResponse(result, elapsed);
  }

  // ===========================================================================
  // Promise-based Methods (Native async using Go goroutines)
  // ===========================================================================

  /**
   * Perform an async GET request using native Go goroutines
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {Object} [options.cookies] - Cookies to send with this request
   * @returns {Promise<Response>} Response object
   */
  get(url, options = {}) {
    const { headers = null, params = null, cookies = null, auth = null } = options;

    url = addParamsToUrl(url, params);
    let mergedHeaders = this._mergeHeaders(headers);
    // Use request auth if provided, otherwise fall back to session auth
    const effectiveAuth = auth !== null ? auth : this.auth;
    mergedHeaders = applyAuth(mergedHeaders, effectiveAuth);
    mergedHeaders = this._applyCookies(mergedHeaders, cookies);

    // Build request options JSON with headers wrapper (clib expects {"headers": {...}})
    const reqOptions = {};
    if (mergedHeaders) {
      reqOptions.headers = mergedHeaders;
    }
    const optionsJson = Object.keys(reqOptions).length > 0 ? JSON.stringify(reqOptions) : null;

    // Register async request with callback manager
    const manager = getAsyncManager();
    const { callbackId, promise } = manager.registerRequest(this._lib);

    // Start async request
    this._lib.httpcloak_get_async(this._handle, url, optionsJson, callbackId);

    return promise;
  }

  /**
   * Perform an async POST request using native Go goroutines
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {Object} [options.cookies] - Cookies to send with this request
   * @returns {Promise<Response>} Response object
   */
  post(url, options = {}) {
    let { body = null, json = null, data = null, files = null, headers = null, params = null, cookies = null, auth = null } = options;

    url = addParamsToUrl(url, params);
    let mergedHeaders = this._mergeHeaders(headers);

    // Handle multipart file upload
    if (files !== null) {
      const formData = (data !== null && typeof data === "object") ? data : null;
      const multipart = encodeMultipart(formData, files);
      body = multipart.body.toString("latin1");
      mergedHeaders = mergedHeaders || {};
      mergedHeaders["Content-Type"] = multipart.contentType;
    }
    // Handle JSON body
    else if (json !== null) {
      body = JSON.stringify(json);
      mergedHeaders = mergedHeaders || {};
      if (!mergedHeaders["Content-Type"]) {
        mergedHeaders["Content-Type"] = "application/json";
      }
    }
    // Handle form data
    else if (data !== null && typeof data === "object") {
      body = new URLSearchParams(data).toString();
      mergedHeaders = mergedHeaders || {};
      if (!mergedHeaders["Content-Type"]) {
        mergedHeaders["Content-Type"] = "application/x-www-form-urlencoded";
      }
    }
    // Handle Buffer body
    else if (Buffer.isBuffer(body)) {
      body = body.toString("utf8");
    }

    // Use request auth if provided, otherwise fall back to session auth
    const effectiveAuth = auth !== null ? auth : this.auth;
    mergedHeaders = applyAuth(mergedHeaders, effectiveAuth);
    mergedHeaders = this._applyCookies(mergedHeaders, cookies);

    // Build request options JSON with headers wrapper (clib expects {"headers": {...}})
    const reqOptions = {};
    if (mergedHeaders) {
      reqOptions.headers = mergedHeaders;
    }
    const optionsJson = Object.keys(reqOptions).length > 0 ? JSON.stringify(reqOptions) : null;

    // Register async request with callback manager
    const manager = getAsyncManager();
    const { callbackId, promise } = manager.registerRequest(this._lib);

    // Start async request
    this._lib.httpcloak_post_async(this._handle, url, body, optionsJson, callbackId);

    return promise;
  }

  /**
   * Perform an async custom HTTP request using native Go goroutines
   * @param {string} method - HTTP method
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {Object} [options.cookies] - Cookies to send with this request
   * @returns {Promise<Response>} Response object
   */
  request(method, url, options = {}) {
    let { body = null, json = null, data = null, files = null, headers = null, params = null, cookies = null, auth = null, timeout = null } = options;

    url = addParamsToUrl(url, params);
    let mergedHeaders = this._mergeHeaders(headers);

    // Handle multipart file upload
    if (files !== null) {
      const formData = (data !== null && typeof data === "object") ? data : null;
      const multipart = encodeMultipart(formData, files);
      body = multipart.body.toString("latin1");
      mergedHeaders = mergedHeaders || {};
      mergedHeaders["Content-Type"] = multipart.contentType;
    }
    // Handle JSON body
    else if (json !== null) {
      body = JSON.stringify(json);
      mergedHeaders = mergedHeaders || {};
      if (!mergedHeaders["Content-Type"]) {
        mergedHeaders["Content-Type"] = "application/json";
      }
    }
    // Handle form data
    else if (data !== null && typeof data === "object") {
      body = new URLSearchParams(data).toString();
      mergedHeaders = mergedHeaders || {};
      if (!mergedHeaders["Content-Type"]) {
        mergedHeaders["Content-Type"] = "application/x-www-form-urlencoded";
      }
    }
    // Handle Buffer body
    else if (Buffer.isBuffer(body)) {
      body = body.toString("utf8");
    }

    // Use request auth if provided, otherwise fall back to session auth
    const effectiveAuth = auth !== null ? auth : this.auth;
    mergedHeaders = applyAuth(mergedHeaders, effectiveAuth);
    mergedHeaders = this._applyCookies(mergedHeaders, cookies);

    const requestConfig = {
      method: method.toUpperCase(),
      url,
    };
    if (mergedHeaders) requestConfig.headers = mergedHeaders;
    if (body) requestConfig.body = body;
    if (timeout) requestConfig.timeout = timeout;

    // Register async request with callback manager
    const manager = getAsyncManager();
    const { callbackId, promise } = manager.registerRequest(this._lib);

    // Start async request
    this._lib.httpcloak_request_async(this._handle, JSON.stringify(requestConfig), callbackId);

    return promise;
  }

  /**
   * Perform an async PUT request
   */
  put(url, options = {}) {
    return this.request("PUT", url, options);
  }

  /**
   * Perform an async DELETE request
   */
  delete(url, options = {}) {
    return this.request("DELETE", url, options);
  }

  /**
   * Perform an async PATCH request
   */
  patch(url, options = {}) {
    return this.request("PATCH", url, options);
  }

  /**
   * Perform an async HEAD request
   */
  head(url, options = {}) {
    return this.request("HEAD", url, options);
  }

  /**
   * Perform an async OPTIONS request
   */
  options(url, options = {}) {
    return this.request("OPTIONS", url, options);
  }

  // ===========================================================================
  // Cookie Management
  // ===========================================================================

  /**
   * Get all cookies from the session
   * @returns {Object} Cookies as key-value pairs
   */
  getCookies() {
    const resultPtr = this._lib.httpcloak_get_cookies(this._handle);
    const result = resultToString(resultPtr);
    if (result) {
      return JSON.parse(result);
    }
    return {};
  }

  /**
   * Get a specific cookie by name
   * @param {string} name - Cookie name
   * @returns {string|null} Cookie value or null if not found
   */
  getCookie(name) {
    const cookies = this.getCookies();
    return cookies[name] || null;
  }

  /**
   * Set a cookie in the session
   * @param {string} name - Cookie name
   * @param {string} value - Cookie value
   */
  setCookie(name, value) {
    this._lib.httpcloak_set_cookie(this._handle, name, value);
  }

  /**
   * Delete a specific cookie by name
   * @param {string} name - Cookie name to delete
   */
  deleteCookie(name) {
    // Set cookie to empty value - effectively deletes it
    this._lib.httpcloak_set_cookie(this._handle, name, "");
  }

  /**
   * Clear all cookies from the session
   */
  clearCookies() {
    const cookies = this.getCookies();
    for (const name of Object.keys(cookies)) {
      this.deleteCookie(name);
    }
  }

  /**
   * Get cookies as a property
   */
  get cookies() {
    return this.getCookies();
  }

  // ===========================================================================
  // Proxy Management
  // ===========================================================================

  /**
   * Change both TCP and UDP proxies for the session.
   *
   * This closes all existing connections and creates new ones through the new proxy.
   * Use this for runtime proxy switching (e.g., rotating proxies).
   *
   * @param {string} proxyUrl - Proxy URL (e.g., "http://user:pass@host:port", "socks5://host:port")
   *                            Pass empty string or null to switch to direct connection.
   *
   * Example:
   *   const session = new httpcloak.Session({ proxy: "http://proxy1:8080" });
   *   await session.get("https://example.com");  // Uses proxy1
   *   session.setProxy("http://proxy2:8080");    // Switch to proxy2
   *   await session.get("https://example.com");  // Uses proxy2
   *   session.setProxy("");                      // Switch to direct connection
   */
  setProxy(proxyUrl) {
    const url = proxyUrl || "";
    this._lib.httpcloak_session_set_proxy(this._handle, url);
  }

  /**
   * Change only the TCP proxy (for HTTP/1.1 and HTTP/2).
   *
   * Use this with setUdpProxy() for split proxy configuration where
   * TCP and UDP traffic go through different proxies.
   *
   * @param {string} proxyUrl - Proxy URL for TCP traffic
   *
   * Example:
   *   session.setTcpProxy("http://tcp-proxy:8080");
   *   session.setUdpProxy("socks5://udp-proxy:1080");
   */
  setTcpProxy(proxyUrl) {
    const url = proxyUrl || "";
    this._lib.httpcloak_session_set_tcp_proxy(this._handle, url);
  }

  /**
   * Change only the UDP proxy (for HTTP/3 via SOCKS5 or MASQUE).
   *
   * HTTP/3 requires either SOCKS5 (with UDP ASSOCIATE support) or MASQUE proxy.
   *
   * @param {string} proxyUrl - Proxy URL for UDP traffic (e.g., "socks5://host:port" or MASQUE URL)
   *
   * Example:
   *   session.setUdpProxy("socks5://socks-proxy:1080");
   */
  setUdpProxy(proxyUrl) {
    const url = proxyUrl || "";
    this._lib.httpcloak_session_set_udp_proxy(this._handle, url);
  }

  /**
   * Get the current proxy URL.
   *
   * @returns {string} Current proxy URL, or empty string if using direct connection
   */
  getProxy() {
    const result = this._lib.httpcloak_session_get_proxy(this._handle);
    return result || "";
  }

  /**
   * Get the current TCP proxy URL.
   *
   * @returns {string} Current TCP proxy URL, or empty string if using direct connection
   */
  getTcpProxy() {
    const result = this._lib.httpcloak_session_get_tcp_proxy(this._handle);
    return result || "";
  }

  /**
   * Get the current UDP proxy URL.
   *
   * @returns {string} Current UDP proxy URL, or empty string if using direct connection
   */
  getUdpProxy() {
    const result = this._lib.httpcloak_session_get_udp_proxy(this._handle);
    return result || "";
  }

  /**
   * Set a custom header order for all requests.
   *
   * @param {string[]} order - Array of header names in desired order (lowercase).
   *                           Pass empty array to reset to preset's default.
   *
   * Example:
   *   session.setHeaderOrder([
   *     "accept-language", "sec-ch-ua", "accept",
   *     "sec-fetch-site", "sec-fetch-mode", "user-agent"
   *   ]);
   */
  setHeaderOrder(order) {
    const orderJson = JSON.stringify(order || []);
    const result = this._lib.httpcloak_session_set_header_order(this._handle, orderJson);
    if (result && result.includes("error")) {
      const data = JSON.parse(result);
      if (data.error) {
        throw new Error(data.error);
      }
    }
  }

  /**
   * Get the current header order.
   *
   * @returns {string[]} Array of header names in current order, or preset's default order
   */
  getHeaderOrder() {
    const result = this._lib.httpcloak_session_get_header_order(this._handle);
    if (result) {
      return JSON.parse(result);
    }
    return [];
  }

  /**
   * Set a session identifier for TLS cache key isolation.
   *
   * This is used when the session is registered with a LocalProxy to ensure
   * TLS sessions are isolated per proxy/session configuration in distributed caches.
   *
   * @param {string} sessionId - Unique identifier for this session. Pass empty string to clear.
   *
   * Example:
   *   session.setSessionIdentifier("user-123");
   */
  setSessionIdentifier(sessionId) {
    this._lib.httpcloak_session_set_identifier(this._handle, sessionId || null);
  }

  /**
   * Get the current proxy as a property.
   */
  get proxy() {
    return this.getProxy();
  }

  /**
   * Set the proxy via property assignment.
   */
  set proxy(proxyUrl) {
    this.setProxy(proxyUrl);
  }

  // ===========================================================================
  // Session Persistence
  // ===========================================================================

  /**
   * Save session state (cookies, TLS sessions) to a file.
   *
   * This allows you to persist session state across program runs,
   * including cookies and TLS session tickets for faster resumption.
   *
   * @param {string} path - Path to save the session file
   *
   * Example:
   *   const session = new httpcloak.Session({ preset: "chrome-143" });
   *   await session.get("https://example.com");  // Acquire cookies
   *   session.save("session.json");
   *
   *   // Later, restore the session
   *   const session = httpcloak.Session.load("session.json");
   */
  save(path) {
    const result = this._lib.httpcloak_session_save(this._handle, path);
    if (result) {
      const data = JSON.parse(result);
      if (data.error) {
        throw new HTTPCloakError(data.error);
      }
    }
  }

  /**
   * Export session state to JSON string.
   *
   * @returns {string} JSON string containing session state
   *
   * Example:
   *   const sessionData = session.marshal();
   *   // Store sessionData in database, cache, etc.
   *
   *   // Later, restore the session
   *   const session = httpcloak.Session.unmarshal(sessionData);
   */
  marshal() {
    const result = this._lib.httpcloak_session_marshal(this._handle);
    if (!result) {
      throw new HTTPCloakError("Failed to marshal session");
    }

    // Check for error
    try {
      const data = JSON.parse(result);
      if (data && typeof data === "object" && data.error) {
        throw new HTTPCloakError(data.error);
      }
    } catch (e) {
      if (e instanceof HTTPCloakError) throw e;
      // Not an error response, just JSON parse failed - return as is
    }

    return result;
  }

  /**
   * Load a session from a file.
   *
   * This restores session state including cookies and TLS session tickets.
   * The session uses the same preset that was used when it was saved.
   *
   * @param {string} path - Path to the session file
   * @returns {Session} Restored Session object
   *
   * Example:
   *   const session = httpcloak.Session.load("session.json");
   *   const r = await session.get("https://example.com");  // Uses restored cookies
   */
  static load(path) {
    const lib = getLib();
    const handle = lib.httpcloak_session_load(path);

    if (handle < 0 || handle === 0n) {
      throw new HTTPCloakError(`Failed to load session from ${path}`);
    }

    // Create a new Session instance without calling constructor
    const session = Object.create(Session.prototype);
    session._lib = lib;
    session._handle = handle;
    session.headers = {};
    session.auth = null;

    return session;
  }

  /**
   * Load a session from JSON string.
   *
   * @param {string} data - JSON string containing session state
   * @returns {Session} Restored Session object
   *
   * Example:
   *   // Retrieve sessionData from database, cache, etc.
   *   const session = httpcloak.Session.unmarshal(sessionData);
   */
  static unmarshal(data) {
    const lib = getLib();
    const handle = lib.httpcloak_session_unmarshal(data);

    if (handle < 0 || handle === 0n) {
      throw new HTTPCloakError("Failed to unmarshal session");
    }

    // Create a new Session instance without calling constructor
    const session = Object.create(Session.prototype);
    session._lib = lib;
    session._handle = handle;
    session.headers = {};
    session.auth = null;

    return session;
  }

  // ===========================================================================
  // Streaming Methods
  // ===========================================================================

  /**
   * Perform a streaming GET request.
   *
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {Object} [options.params] - URL query parameters
   * @param {Object} [options.headers] - Request headers
   * @param {Object} [options.cookies] - Cookies to send
   * @param {number} [options.timeout] - Request timeout in milliseconds
   * @returns {StreamResponse} - Streaming response for chunked reading
   *
   * Example:
   *   const stream = session.getStream("https://example.com/large-file.zip");
   *   for await (const chunk of stream) {
   *     file.write(chunk);
   *   }
   *   stream.close();
   */
  getStream(url, options = {}) {
    const { params, headers, cookies, timeout } = options;

    // Add params to URL
    if (params) {
      url = addParamsToUrl(url, params);
    }

    // Merge headers
    let mergedHeaders = { ...this.headers };
    if (headers) {
      mergedHeaders = { ...mergedHeaders, ...headers };
    }
    if (cookies) {
      const cookieStr = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join("; ");
      mergedHeaders["Cookie"] = mergedHeaders["Cookie"]
        ? `${mergedHeaders["Cookie"]}; ${cookieStr}`
        : cookieStr;
    }

    // Build options JSON
    const reqOptions = {};
    if (Object.keys(mergedHeaders).length > 0) {
      reqOptions.headers = mergedHeaders;
    }
    if (timeout) {
      reqOptions.timeout = timeout;
    }
    const optionsJson = Object.keys(reqOptions).length > 0 ? JSON.stringify(reqOptions) : null;

    // Start stream
    const streamHandle = this._lib.httpcloak_stream_get(this._handle, url, optionsJson);
    if (streamHandle < 0) {
      throw new HTTPCloakError("Failed to start streaming request");
    }

    // Get metadata
    const metadataStr = this._lib.httpcloak_stream_get_metadata(streamHandle);
    if (!metadataStr) {
      this._lib.httpcloak_stream_close(streamHandle);
      throw new HTTPCloakError("Failed to get stream metadata");
    }

    const metadata = JSON.parse(metadataStr);
    if (metadata.error) {
      this._lib.httpcloak_stream_close(streamHandle);
      throw new HTTPCloakError(metadata.error);
    }

    return new StreamResponse(streamHandle, this._lib, metadata);
  }

  /**
   * Perform a streaming POST request.
   *
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {string|Buffer|Object} [options.body] - Request body
   * @param {Object} [options.json] - JSON body (will be serialized)
   * @param {Object} [options.form] - Form data (will be URL-encoded)
   * @param {Object} [options.params] - URL query parameters
   * @param {Object} [options.headers] - Request headers
   * @param {Object} [options.cookies] - Cookies to send
   * @param {number} [options.timeout] - Request timeout in milliseconds
   * @returns {StreamResponse} - Streaming response for chunked reading
   */
  postStream(url, options = {}) {
    const { body: bodyOpt, json: jsonBody, form, params, headers, cookies, timeout } = options;

    // Add params to URL
    if (params) {
      url = addParamsToUrl(url, params);
    }

    // Merge headers
    let mergedHeaders = { ...this.headers };
    if (headers) {
      mergedHeaders = { ...mergedHeaders, ...headers };
    }

    // Process body
    let body = null;
    if (jsonBody) {
      body = JSON.stringify(jsonBody);
      mergedHeaders["Content-Type"] = mergedHeaders["Content-Type"] || "application/json";
    } else if (form) {
      body = Object.entries(form).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
      mergedHeaders["Content-Type"] = mergedHeaders["Content-Type"] || "application/x-www-form-urlencoded";
    } else if (bodyOpt) {
      body = typeof bodyOpt === "string" ? bodyOpt : bodyOpt.toString();
    }

    if (cookies) {
      const cookieStr = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join("; ");
      mergedHeaders["Cookie"] = mergedHeaders["Cookie"]
        ? `${mergedHeaders["Cookie"]}; ${cookieStr}`
        : cookieStr;
    }

    // Build options JSON
    const reqOptions = {};
    if (Object.keys(mergedHeaders).length > 0) {
      reqOptions.headers = mergedHeaders;
    }
    if (timeout) {
      reqOptions.timeout = timeout;
    }
    const optionsJson = Object.keys(reqOptions).length > 0 ? JSON.stringify(reqOptions) : null;

    // Start stream
    const streamHandle = this._lib.httpcloak_stream_post(this._handle, url, body, optionsJson);
    if (streamHandle < 0) {
      throw new HTTPCloakError("Failed to start streaming request");
    }

    // Get metadata
    const metadataStr = this._lib.httpcloak_stream_get_metadata(streamHandle);
    if (!metadataStr) {
      this._lib.httpcloak_stream_close(streamHandle);
      throw new HTTPCloakError("Failed to get stream metadata");
    }

    const metadata = JSON.parse(metadataStr);
    if (metadata.error) {
      this._lib.httpcloak_stream_close(streamHandle);
      throw new HTTPCloakError(metadata.error);
    }

    return new StreamResponse(streamHandle, this._lib, metadata);
  }

  /**
   * Perform a streaming request with any HTTP method.
   *
   * @param {string} method - HTTP method
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {string|Buffer} [options.body] - Request body
   * @param {Object} [options.params] - URL query parameters
   * @param {Object} [options.headers] - Request headers
   * @param {Object} [options.cookies] - Cookies to send
   * @param {number} [options.timeout] - Request timeout in seconds
   * @returns {StreamResponse} - Streaming response for chunked reading
   */
  requestStream(method, url, options = {}) {
    const { body, params, headers, cookies, timeout } = options;

    // Add params to URL
    if (params) {
      url = addParamsToUrl(url, params);
    }

    // Merge headers
    let mergedHeaders = { ...this.headers };
    if (headers) {
      mergedHeaders = { ...mergedHeaders, ...headers };
    }
    if (cookies) {
      const cookieStr = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join("; ");
      mergedHeaders["Cookie"] = mergedHeaders["Cookie"]
        ? `${mergedHeaders["Cookie"]}; ${cookieStr}`
        : cookieStr;
    }

    // Build request config
    const requestConfig = {
      method: method.toUpperCase(),
      url,
    };
    if (Object.keys(mergedHeaders).length > 0) {
      requestConfig.headers = mergedHeaders;
    }
    if (body) {
      requestConfig.body = typeof body === "string" ? body : body.toString();
    }
    if (timeout) {
      requestConfig.timeout = timeout;
    }

    // Start stream
    const streamHandle = this._lib.httpcloak_stream_request(this._handle, JSON.stringify(requestConfig));
    if (streamHandle < 0) {
      throw new HTTPCloakError("Failed to start streaming request");
    }

    // Get metadata
    const metadataStr = this._lib.httpcloak_stream_get_metadata(streamHandle);
    if (!metadataStr) {
      this._lib.httpcloak_stream_close(streamHandle);
      throw new HTTPCloakError("Failed to get stream metadata");
    }

    const metadata = JSON.parse(metadataStr);
    if (metadata.error) {
      this._lib.httpcloak_stream_close(streamHandle);
      throw new HTTPCloakError(metadata.error);
    }

    return new StreamResponse(streamHandle, this._lib, metadata);
  }

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
   *
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {Object} [options.headers] - Custom headers
   * @param {Object} [options.params] - Query parameters
   * @param {Object} [options.cookies] - Cookies to send with this request
   * @param {Array} [options.auth] - Basic auth [username, password]
   * @returns {FastResponse} Fast response object with Buffer body
   *
   * Example:
   *   const response = session.getFast("https://example.com/large-file.zip");
   *   console.log(`Downloaded ${response.body.length} bytes`);
   *   fs.writeFileSync("file.zip", response.body);
   */
  getFast(url, options = {}) {
    const { headers = null, params = null, cookies = null, auth = null } = options;

    url = addParamsToUrl(url, params);
    let mergedHeaders = this._mergeHeaders(headers);
    // Use request auth if provided, otherwise fall back to session auth
    const effectiveAuth = auth !== null ? auth : this.auth;
    mergedHeaders = applyAuth(mergedHeaders, effectiveAuth);
    mergedHeaders = this._applyCookies(mergedHeaders, cookies);

    // Build request options JSON with headers wrapper
    const reqOptions = {};
    if (mergedHeaders) {
      reqOptions.headers = mergedHeaders;
    }
    const optionsJson = Object.keys(reqOptions).length > 0 ? JSON.stringify(reqOptions) : null;

    const startTime = Date.now();

    // Get raw response handle
    const responseHandle = this._lib.httpcloak_get_raw(this._handle, url, optionsJson);
    if (responseHandle === 0 || responseHandle === 0n) {
      throw new HTTPCloakError("Failed to make request");
    }

    // Get body length first (1 FFI call)
    const bodyLen = this._lib.httpcloak_response_get_body_len(responseHandle);
    if (bodyLen < 0) {
      this._lib.httpcloak_response_free(responseHandle);
      throw new HTTPCloakError("Failed to get response body length");
    }

    // Acquire pooled buffer
    const pooledBuffer = _bufferPool.acquire(bodyLen);

    // Finalize: copy body + get metadata + free handle (1 FFI call instead of 3)
    const metadataStr = this._lib.httpcloak_response_finalize(responseHandle, pooledBuffer, bodyLen);
    if (!metadataStr) {
      _bufferPool.release(pooledBuffer);
      throw new HTTPCloakError("Failed to finalize response");
    }

    const metadata = JSON.parse(metadataStr);
    if (metadata.error) {
      _bufferPool.release(pooledBuffer);
      throw new HTTPCloakError(metadata.error);
    }

    // Create a view of just the used portion
    const buffer = pooledBuffer.subarray(0, bodyLen);

    const elapsed = Date.now() - startTime;
    return new FastResponse(metadata, buffer, elapsed, pooledBuffer);
  }

  /**
   * High-performance POST request optimized for large uploads.
   *
   * Uses binary buffer passing and response pooling for maximum throughput.
   * Call response.release() when done to return buffers to pool.
   *
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {Buffer} [options.body] - Request body as Buffer
   * @param {Object} [options.headers] - Request headers
   * @param {Object} [options.params] - Query parameters
   * @param {Object} [options.cookies] - Cookies to send with this request
   * @param {Array} [options.auth] - Basic auth [username, password]
   * @returns {FastResponse} Fast response object with Buffer body
   *
   * Example:
   *   const data = Buffer.alloc(10 * 1024 * 1024); // 10MB
   *   const response = session.postFast("https://example.com/upload", { body: data });
   *   console.log(`Uploaded, response: ${response.statusCode}`);
   *   response.release();
   */
  postFast(url, options = {}) {
    let { body = null, headers = null, params = null, cookies = null, auth = null } = options;

    url = addParamsToUrl(url, params);
    let mergedHeaders = this._mergeHeaders(headers);
    // Use request auth if provided, otherwise fall back to session auth
    const effectiveAuth = auth !== null ? auth : this.auth;
    mergedHeaders = applyAuth(mergedHeaders, effectiveAuth);
    mergedHeaders = this._applyCookies(mergedHeaders, cookies);

    // Ensure body is a Buffer
    if (body === null) {
      body = Buffer.alloc(0);
    } else if (typeof body === "string") {
      body = Buffer.from(body, "utf8");
    } else if (!Buffer.isBuffer(body)) {
      throw new HTTPCloakError("postFast body must be a Buffer or string");
    }

    // Build request options JSON with headers wrapper
    const reqOptions = {};
    if (mergedHeaders) {
      reqOptions.headers = mergedHeaders;
    }
    const optionsJson = Object.keys(reqOptions).length > 0 ? JSON.stringify(reqOptions) : null;

    const startTime = Date.now();

    // Use httpcloak_post_raw with binary buffer (no string conversion!)
    const responseHandle = this._lib.httpcloak_post_raw(this._handle, url, body, body.length, optionsJson);
    if (responseHandle === 0 || responseHandle === 0n || responseHandle < 0) {
      throw new HTTPCloakError("Failed to make POST request");
    }

    // Get body length first (1 FFI call)
    const bodyLen = this._lib.httpcloak_response_get_body_len(responseHandle);
    if (bodyLen < 0) {
      this._lib.httpcloak_response_free(responseHandle);
      throw new HTTPCloakError("Failed to get response body length");
    }

    // Acquire pooled buffer for response
    const pooledBuffer = _bufferPool.acquire(bodyLen);

    // Finalize: copy body + get metadata + free handle (1 FFI call instead of 3)
    const metadataStr = this._lib.httpcloak_response_finalize(responseHandle, pooledBuffer, bodyLen);
    if (!metadataStr) {
      _bufferPool.release(pooledBuffer);
      throw new HTTPCloakError("Failed to finalize response");
    }

    const metadata = JSON.parse(metadataStr);
    if (metadata.error) {
      _bufferPool.release(pooledBuffer);
      throw new HTTPCloakError(metadata.error);
    }

    // Create a view of just the used portion
    const responseBuffer = pooledBuffer.subarray(0, bodyLen);

    const elapsed = Date.now() - startTime;
    return new FastResponse(metadata, responseBuffer, elapsed, pooledBuffer);
  }

  /**
   * Perform a high-performance generic HTTP request with zero-copy buffer transfer.
   *
   * This method is optimized for maximum speed by:
   * - Using pre-allocated buffer pools (no per-request allocation)
   * - Returning Buffer views instead of copying (zero-copy)
   * - Using combined finalize FFI call (1 instead of 3)
   *
   * @param {string} method - HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
   * @param {string} url - Request URL
   * @param {Object} [options={}] - Request options
   * @param {Buffer|string|null} [options.body] - Request body
   * @param {Object} [options.headers] - Request headers
   * @param {Object} [options.params] - URL query parameters
   * @param {Object} [options.cookies] - Cookies to send
   * @param {Array} [options.auth] - Basic auth [username, password]
   * @param {number} [options.timeout] - Request timeout in milliseconds
   * @returns {FastResponse} Fast response object with Buffer body
   *
   * Example:
   *   const response = session.requestFast("PUT", "https://api.example.com/resource", {
   *     body: JSON.stringify({ key: "value" }),
   *     headers: { "Content-Type": "application/json" }
   *   });
   *   console.log(`Status: ${response.statusCode}`);
   *   response.release();
   */
  requestFast(method, url, options = {}) {
    let { body = null, headers = null, params = null, cookies = null, auth = null, timeout = null } = options;

    url = addParamsToUrl(url, params);
    let mergedHeaders = this._mergeHeaders(headers);
    const effectiveAuth = auth !== null ? auth : this.auth;
    mergedHeaders = applyAuth(mergedHeaders, effectiveAuth);
    mergedHeaders = this._applyCookies(mergedHeaders, cookies);

    // Ensure body is a Buffer (or null)
    if (body !== null) {
      if (typeof body === "string") {
        body = Buffer.from(body, "utf8");
      } else if (!Buffer.isBuffer(body)) {
        throw new HTTPCloakError("requestFast body must be a Buffer or string");
      }
    }

    // Build request config JSON
    const requestConfig = {
      method: method.toUpperCase(),
      url: url,
    };
    if (mergedHeaders && Object.keys(mergedHeaders).length > 0) {
      requestConfig.headers = mergedHeaders;
    }
    if (timeout) {
      requestConfig.timeout = timeout;
    }
    const requestJson = JSON.stringify(requestConfig);

    const startTime = Date.now();

    const responseHandle = this._lib.httpcloak_request_raw(
      this._handle,
      requestJson,
      body || Buffer.alloc(0),
      body ? body.length : 0
    );

    if (responseHandle === 0 || responseHandle === 0n || responseHandle < 0) {
      throw new HTTPCloakError("Failed to make request");
    }

    // Get body length first
    const bodyLen = this._lib.httpcloak_response_get_body_len(responseHandle);
    if (bodyLen < 0) {
      this._lib.httpcloak_response_free(responseHandle);
      throw new HTTPCloakError("Failed to get response body length");
    }

    // Acquire pooled buffer for response
    const pooledBuffer = _bufferPool.acquire(bodyLen);

    // Finalize: copy body + get metadata + free handle
    const metadataStr = this._lib.httpcloak_response_finalize(responseHandle, pooledBuffer, bodyLen);
    if (!metadataStr) {
      _bufferPool.release(pooledBuffer);
      throw new HTTPCloakError("Failed to finalize response");
    }

    const metadata = JSON.parse(metadataStr);
    if (metadata.error) {
      _bufferPool.release(pooledBuffer);
      throw new HTTPCloakError(metadata.error);
    }

    // Create a view of just the used portion
    const responseBuffer = pooledBuffer.subarray(0, bodyLen);

    const elapsed = Date.now() - startTime;
    return new FastResponse(metadata, responseBuffer, elapsed, pooledBuffer);
  }

  /**
   * Perform a high-performance PUT request with zero-copy buffer transfer.
   * @param {string} url - Request URL
   * @param {Object} [options={}] - Request options (body, headers, params, cookies, auth, timeout)
   * @returns {FastResponse} Fast response object with Buffer body
   */
  putFast(url, options = {}) {
    return this.requestFast("PUT", url, options);
  }

  /**
   * Perform a high-performance DELETE request with zero-copy buffer transfer.
   * @param {string} url - Request URL
   * @param {Object} [options={}] - Request options (headers, params, cookies, auth, timeout)
   * @returns {FastResponse} Fast response object with Buffer body
   */
  deleteFast(url, options = {}) {
    return this.requestFast("DELETE", url, options);
  }

  /**
   * Perform a high-performance PATCH request with zero-copy buffer transfer.
   * @param {string} url - Request URL
   * @param {Object} [options={}] - Request options (body, headers, params, cookies, auth, timeout)
   * @returns {FastResponse} Fast response object with Buffer body
   */
  patchFast(url, options = {}) {
    return this.requestFast("PATCH", url, options);
  }
}

// =============================================================================
// Module-level convenience functions
// =============================================================================

let _defaultSession = null;
let _defaultConfig = {};

/**
 * Configure defaults for module-level functions
 * @param {Object} options - Configuration options
 * @param {string} [options.preset="chrome-143"] - Browser preset
 * @param {Object} [options.headers] - Default headers
 * @param {Array} [options.auth] - Default basic auth [username, password]
 * @param {string} [options.proxy] - Proxy URL
 * @param {number} [options.timeout=30] - Default timeout in seconds
 * @param {string} [options.httpVersion="auto"] - HTTP version: "auto", "h1", "h2", "h3"
 * @param {boolean} [options.verify=true] - SSL certificate verification
 * @param {boolean} [options.allowRedirects=true] - Follow redirects
 * @param {number} [options.maxRedirects=10] - Maximum number of redirects to follow
 * @param {number} [options.retry=3] - Number of retries on failure (set to 0 to disable)
 * @param {number[]} [options.retryOnStatus] - Status codes to retry on
 */
function configure(options = {}) {
  const {
    preset = "chrome-143",
    headers = null,
    auth = null,
    proxy = null,
    timeout = 30,
    httpVersion = "auto",
    verify = true,
    allowRedirects = true,
    maxRedirects = 10,
    retry = 3,
    retryOnStatus = null,
  } = options;

  // Close existing session
  if (_defaultSession) {
    _defaultSession.close();
    _defaultSession = null;
  }

  // Apply auth to headers
  let finalHeaders = applyAuth(headers, auth) || {};

  // Store config
  _defaultConfig = {
    preset,
    proxy,
    timeout,
    httpVersion,
    verify,
    allowRedirects,
    maxRedirects,
    retry,
    retryOnStatus,
    headers: finalHeaders,
  };

  // Create new session
  _defaultSession = new Session({
    preset,
    proxy,
    timeout,
    httpVersion,
    verify,
    allowRedirects,
    maxRedirects,
    retry,
    retryOnStatus,
  });
  if (Object.keys(finalHeaders).length > 0) {
    Object.assign(_defaultSession.headers, finalHeaders);
  }
}

/**
 * Get or create the default session
 */
function _getDefaultSession() {
  if (!_defaultSession) {
    const preset = _defaultConfig.preset || "chrome-143";
    const proxy = _defaultConfig.proxy || null;
    const timeout = _defaultConfig.timeout || 30;
    const httpVersion = _defaultConfig.httpVersion || "auto";
    const verify = _defaultConfig.verify !== undefined ? _defaultConfig.verify : true;
    const allowRedirects = _defaultConfig.allowRedirects !== undefined ? _defaultConfig.allowRedirects : true;
    const maxRedirects = _defaultConfig.maxRedirects || 10;
    const retry = _defaultConfig.retry !== undefined ? _defaultConfig.retry : 3;
    const retryOnStatus = _defaultConfig.retryOnStatus || null;
    const headers = _defaultConfig.headers || {};

    _defaultSession = new Session({
      preset,
      proxy,
      timeout,
      httpVersion,
      verify,
      allowRedirects,
      maxRedirects,
      retry,
      retryOnStatus,
    });
    if (Object.keys(headers).length > 0) {
      Object.assign(_defaultSession.headers, headers);
    }
  }
  return _defaultSession;
}

/**
 * Perform a GET request
 * @param {string} url - Request URL
 * @param {Object} [options] - Request options
 * @returns {Promise<Response>}
 */
function get(url, options = {}) {
  return _getDefaultSession().get(url, options);
}

/**
 * Perform a POST request
 * @param {string} url - Request URL
 * @param {Object} [options] - Request options
 * @returns {Promise<Response>}
 */
function post(url, options = {}) {
  return _getDefaultSession().post(url, options);
}

/**
 * Perform a PUT request
 */
function put(url, options = {}) {
  return _getDefaultSession().put(url, options);
}

/**
 * Perform a DELETE request
 */
function del(url, options = {}) {
  return _getDefaultSession().delete(url, options);
}

/**
 * Perform a PATCH request
 */
function patch(url, options = {}) {
  return _getDefaultSession().patch(url, options);
}

/**
 * Perform a HEAD request
 */
function head(url, options = {}) {
  return _getDefaultSession().head(url, options);
}

/**
 * Perform an OPTIONS request
 */
function options(url, opts = {}) {
  return _getDefaultSession().options(url, opts);
}

/**
 * Perform a custom HTTP request
 */
function request(method, url, options = {}) {
  return _getDefaultSession().request(method, url, options);
}

/**
 * Local HTTP proxy server that forwards requests through httpcloak with TLS fingerprinting.
 * Use this to transparently apply fingerprinting to any HTTP client (e.g., Undici, fetch).
 *
 * Supports per-request proxy rotation via X-Upstream-Proxy header.
 *
 * @example
 * const proxy = new LocalProxy({ preset: "chrome-143", tlsOnly: true });
 * console.log(`Proxy running on ${proxy.proxyUrl}`);
 *
 * // Use with any HTTP client pointing to the proxy
 * // Pass X-Upstream-Proxy header to rotate proxies per-request
 *
 * proxy.close();
 */
class LocalProxy {
  /**
   * Create and start a local HTTP proxy server.
   * @param {Object} options - Proxy configuration options
   * @param {number} [options.port=0] - Port to listen on (0 = auto-select)
   * @param {string} [options.preset="chrome-143"] - Browser fingerprint preset
   * @param {number} [options.timeout=30] - Request timeout in seconds
   * @param {number} [options.maxConnections=1000] - Maximum concurrent connections
   * @param {string} [options.tcpProxy] - Default upstream TCP proxy URL
   * @param {string} [options.udpProxy] - Default upstream UDP proxy URL
   * @param {boolean} [options.tlsOnly=false] - TLS-only mode: skip preset HTTP headers, only apply TLS fingerprint
   */
  constructor(options = {}) {
    const {
      port = 0,
      preset = "chrome-143",
      timeout = 30,
      maxConnections = 1000,
      tcpProxy = null,
      udpProxy = null,
      tlsOnly = false,
    } = options;

    this._lib = getLib();

    const config = {
      port,
      preset,
      timeout,
      max_connections: maxConnections,
    };
    if (tcpProxy) config.tcp_proxy = tcpProxy;
    if (udpProxy) config.udp_proxy = udpProxy;
    if (tlsOnly) config.tls_only = true;

    const configJson = JSON.stringify(config);
    this._handle = this._lib.httpcloak_local_proxy_start(configJson);

    if (this._handle < 0) {
      throw new HTTPCloakError("Failed to start local proxy");
    }
  }

  /**
   * Get the port the proxy is listening on.
   * @returns {number}
   */
  get port() {
    return this._lib.httpcloak_local_proxy_get_port(this._handle);
  }

  /**
   * Check if the proxy is currently running.
   * @returns {boolean}
   */
  get isRunning() {
    return this._lib.httpcloak_local_proxy_is_running(this._handle) !== 0;
  }

  /**
   * Get the proxy URL for use with HTTP clients.
   * Uses 127.0.0.1 instead of localhost to avoid IPv6 resolution issues.
   * @returns {string}
   */
  get proxyUrl() {
    return `http://127.0.0.1:${this.port}`;
  }

  /**
   * Get proxy statistics.
   * @returns {Object} Statistics including running status, active connections, total requests
   */
  getStats() {
    const resultPtr = this._lib.httpcloak_local_proxy_get_stats(this._handle);
    const result = resultToString(resultPtr);
    if (result) {
      return JSON.parse(result);
    }
    return {};
  }

  /**
   * Register a session with an ID for use with X-HTTPCloak-Session header.
   * This allows per-request session routing through the proxy.
   *
   * @param {string} sessionId - Unique identifier for the session
   * @param {Session} session - The session to register
   * @throws {HTTPCloakError} If registration fails
   */
  registerSession(sessionId, session) {
    if (!session || !session._handle) {
      throw new HTTPCloakError("Invalid session");
    }
    const resultPtr = this._lib.httpcloak_local_proxy_register_session(
      this._handle,
      sessionId,
      session._handle
    );
    const result = resultToString(resultPtr);
    if (result) {
      const data = JSON.parse(result);
      if (data.error) {
        throw new HTTPCloakError(data.error);
      }
    }
  }

  /**
   * Unregister a session by ID.
   * After unregistering, the session ID can no longer be used with X-HTTPCloak-Session header.
   *
   * @param {string} sessionId - The session ID to unregister
   * @returns {boolean} True if the session was found and unregistered, false otherwise
   */
  unregisterSession(sessionId) {
    const result = this._lib.httpcloak_local_proxy_unregister_session(
      this._handle,
      sessionId
    );
    return result === 1;
  }

  /**
   * Stop the local proxy server.
   */
  close() {
    if (this._handle >= 0) {
      this._lib.httpcloak_local_proxy_stop(this._handle);
      this._handle = -1;
    }
  }
}


// ============================================================================
// Distributed Session Cache
// ============================================================================

// Global session cache callbacks (keep references to prevent GC)
let _sessionCacheBackend = null;
let _sessionCacheCallbackPtrs = {};

/**
 * Distributed TLS session cache backend for sharing sessions across instances.
 *
 * This enables TLS session resumption across distributed httpcloak instances
 * by storing session tickets in an external cache like Redis or Memcached.
 *
 * Example with Redis:
 * ```javascript
 * const Redis = require('ioredis');
 * const httpcloak = require('httpcloak');
 *
 * const redis = new Redis();
 *
 * const cache = new httpcloak.SessionCacheBackend({
 *   get: (key) => redis.get(key),
 *   put: (key, value, ttlSeconds) => {
 *     redis.setex(key, ttlSeconds, value);
 *     return 0;
 *   },
 *   delete: (key) => {
 *     redis.del(key);
 *     return 0;
 *   },
 *   onError: (operation, key, error) => {
 *     console.error(`Cache error: ${operation} on ${key}: ${error}`);
 *   }
 * });
 *
 * cache.register();
 *
 * // Now all Session and LocalProxy instances will use this cache
 * const session = new httpcloak.Session({ preset: 'chrome-143' });
 * await session.get('https://example.com');  // Session will be cached!
 * ```
 *
 * The cache is used for:
 * - TLS session tickets (key format: httpcloak:sessions:{preset}:{protocol}:{host}:{port})
 * - ECH configs for HTTP/3 (key format: httpcloak:ech:{preset}:{host}:{port})
 *
 * Session data is JSON with fields: ticket, state, created_at
 * ECH config data is base64-encoded binary
 */
class SessionCacheBackend {
  /**
   * Create a session cache backend.
   *
   * @param {Object} options Cache configuration
   * @param {Function} [options.get] Function to get session data: (key: string) => string|null|Promise<string|null>
   * @param {Function} [options.put] Function to store session: (key: string, value: string, ttlSeconds: number) => number|Promise<number>
   * @param {Function} [options.delete] Function to delete session: (key: string) => number|Promise<number>
   * @param {Function} [options.getEch] Function to get ECH config: (key: string) => string|null|Promise<string|null>
   * @param {Function} [options.putEch] Function to store ECH: (key: string, value: string, ttlSeconds: number) => number|Promise<number>
   * @param {Function} [options.onError] Error callback: (operation: string, key: string, error: string) => void
   */
  constructor(options = {}) {
    this._get = options.get || null;
    this._put = options.put || null;
    this._delete = options.delete || null;
    this._getEch = options.getEch || null;
    this._putEch = options.putEch || null;
    this._onError = options.onError || null;
    this._registered = false;
  }

  /**
   * Register this cache backend globally.
   *
   * After registration, all new Session and LocalProxy instances will use
   * this cache for TLS session storage.
   */
  register() {
    const lib = getLib();

    // Create callback pointers (keep references to prevent GC)
    // Use no-op callbacks for missing functions to avoid null pointer issues
    _sessionCacheCallbackPtrs = {};

    // Create get callback (or no-op)
    const getFn = this._get;
    _sessionCacheCallbackPtrs.get = koffi.register((key) => {
      if (!getFn) return null;
      try {
        const result = getFn(key);
        if (result && typeof result.then === 'function') {
          console.warn('SessionCacheBackend: Async callbacks not fully supported, returning null');
          return null;
        }
        return result || null;
      } catch (e) {
        return null;
      }
    }, koffi.pointer(SessionCacheGetProto));

    // Create put callback (or no-op)
    const putFn = this._put;
    _sessionCacheCallbackPtrs.put = koffi.register((key, value, ttlSeconds) => {
      if (!putFn) return 0;
      try {
        const result = putFn(key, value, Number(ttlSeconds));
        if (result && typeof result.then === 'function') {
          return 0;
        }
        return result || 0;
      } catch (e) {
        return -1;
      }
    }, koffi.pointer(SessionCachePutProto));

    // Create delete callback (or no-op)
    const deleteFn = this._delete;
    _sessionCacheCallbackPtrs.delete = koffi.register((key) => {
      if (!deleteFn) return 0;
      try {
        const result = deleteFn(key);
        if (result && typeof result.then === 'function') {
          return 0;
        }
        return result || 0;
      } catch (e) {
        return -1;
      }
    }, koffi.pointer(SessionCacheDeleteProto));

    // Create ECH get callback (or no-op)
    const getEchFn = this._getEch;
    _sessionCacheCallbackPtrs.getEch = koffi.register((key) => {
      if (!getEchFn) return null;
      try {
        const result = getEchFn(key);
        if (result && typeof result.then === 'function') {
          return null;
        }
        return result || null;
      } catch (e) {
        return null;
      }
    }, koffi.pointer(EchCacheGetProto));

    // Create ECH put callback (or no-op)
    const putEchFn = this._putEch;
    _sessionCacheCallbackPtrs.putEch = koffi.register((key, value, ttlSeconds) => {
      if (!putEchFn) return 0;
      try {
        const result = putEchFn(key, value, Number(ttlSeconds));
        if (result && typeof result.then === 'function') {
          return 0;
        }
        return result || 0;
      } catch (e) {
        return -1;
      }
    }, koffi.pointer(EchCachePutProto));

    // Create error callback (or no-op)
    const errorFn = this._onError;
    _sessionCacheCallbackPtrs.error = koffi.register((operation, key, error) => {
      if (!errorFn) return;
      try {
        errorFn(operation, key, error);
      } catch (e) {
        // Ignore errors in error callback
      }
    }, koffi.pointer(SessionCacheErrorProto));

    // Register with library
    lib.httpcloak_set_session_cache_callbacks(
      _sessionCacheCallbackPtrs.get,
      _sessionCacheCallbackPtrs.put,
      _sessionCacheCallbackPtrs.delete,
      _sessionCacheCallbackPtrs.getEch,
      _sessionCacheCallbackPtrs.putEch,
      _sessionCacheCallbackPtrs.error
    );

    _sessionCacheBackend = this;
    this._registered = true;
  }

  /**
   * Unregister this cache backend.
   *
   * After unregistration, new sessions will not use distributed caching.
   */
  unregister() {
    if (!this._registered) {
      return;
    }

    const lib = getLib();
    lib.httpcloak_clear_session_cache_callbacks();

    _sessionCacheBackend = null;
    _sessionCacheCallbackPtrs = {};
    this._registered = false;
  }
}

/**
 * Configure a distributed session cache backend.
 *
 * This is a convenience function that creates and registers a SessionCacheBackend.
 *
 * @param {Object} options Cache configuration (same as SessionCacheBackend constructor)
 * @returns {SessionCacheBackend} The registered backend
 *
 * Example:
 * ```javascript
 * const Redis = require('ioredis');
 * const httpcloak = require('httpcloak');
 *
 * const redis = new Redis();
 *
 * httpcloak.configureSessionCache({
 *   get: (key) => redis.get(key),
 *   put: (key, value, ttl) => { redis.setex(key, ttl, value); return 0; },
 *   delete: (key) => { redis.del(key); return 0; },
 * });
 *
 * // Now all sessions will use Redis for TLS session storage
 * const session = new httpcloak.Session();
 * await session.get('https://example.com');
 * ```
 */
function configureSessionCache(options) {
  const backend = new SessionCacheBackend(options);
  backend.register();
  return backend;
}

/**
 * Clear the distributed session cache backend.
 *
 * After calling this, new sessions will not use distributed caching.
 */
function clearSessionCache() {
  const lib = getLib();
  lib.httpcloak_clear_session_cache_callbacks();
  _sessionCacheBackend = null;
  _sessionCacheCallbackPtrs = {};
}


module.exports = {
  // Classes
  Session,
  LocalProxy,
  Response,
  FastResponse,
  StreamResponse,
  Cookie,
  RedirectInfo,
  HTTPCloakError,
  SessionCacheBackend,
  // Presets
  Preset,
  // Configuration
  configure,
  configureSessionCache,
  clearSessionCache,
  // Module-level functions
  get,
  post,
  put,
  delete: del,
  patch,
  head,
  options,
  request,
  // Utility
  version,
  availablePresets,
  // DNS configuration
  setEchDnsServers,
  getEchDnsServers,
};
