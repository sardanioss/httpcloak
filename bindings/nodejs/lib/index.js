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
      this.CHROME_131, this.CHROME_131_WINDOWS, this.CHROME_131_LINUX, this.CHROME_131_MACOS,
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
      // Async functions
      httpcloak_register_callback: nativeLibHandle.func("httpcloak_register_callback", "int64", [koffi.pointer(AsyncCallbackProto)]),
      httpcloak_unregister_callback: nativeLibHandle.func("httpcloak_unregister_callback", "void", ["int64"]),
      httpcloak_get_async: nativeLibHandle.func("httpcloak_get_async", "void", ["int64", "str", "str", "int64"]),
      httpcloak_post_async: nativeLibHandle.func("httpcloak_post_async", "void", ["int64", "str", "str", "str", "int64"]),
      httpcloak_request_async: nativeLibHandle.func("httpcloak_request_async", "void", ["int64", "str", "int64"]),
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
 * HTTP Session with browser fingerprint emulation
 */
class Session {
  /**
   * Create a new session
   * @param {Object} options - Session options
   * @param {string} [options.preset="chrome-143"] - Browser preset to use
   * @param {string} [options.proxy] - Proxy URL (e.g., "http://user:pass@host:port" or "socks5://host:port")
   * @param {number} [options.timeout=30] - Request timeout in seconds
   * @param {string} [options.httpVersion="auto"] - HTTP version: "auto", "h1", "h2", "h3"
   * @param {boolean} [options.verify=true] - SSL certificate verification
   * @param {boolean} [options.allowRedirects=true] - Follow redirects
   * @param {number} [options.maxRedirects=10] - Maximum number of redirects to follow
   * @param {number} [options.retry=3] - Number of retries on failure (set to 0 to disable)
   * @param {number[]} [options.retryOnStatus] - Status codes to retry on
   * @param {Array} [options.auth] - Default auth [username, password] for all requests
   * @param {Object} [options.connectTo] - Domain fronting map {requestHost: connectHost}
   * @param {string} [options.echConfigDomain] - Domain to fetch ECH config from (e.g., "cloudflare-ech.com")
   */
  constructor(options = {}) {
    const {
      preset = "chrome-143",
      proxy = null,
      timeout = 30,
      httpVersion = "auto",
      verify = true,
      allowRedirects = true,
      maxRedirects = 10,
      retry = 3,
      retryOnStatus = null,
      preferIpv4 = false,
      auth = null,
      connectTo = null,
      echConfigDomain = null,
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
    if (preferIpv4) {
      config.prefer_ipv4 = true;
    }
    if (connectTo) {
      config.connect_to = connectTo;
    }
    if (echConfigDomain) {
      config.ech_config_domain = echConfigDomain;
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

    const headersJson = mergedHeaders ? JSON.stringify(mergedHeaders) : null;
    const startTime = Date.now();
    const result = this._lib.httpcloak_get(this._handle, url, headersJson);
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

    const headersJson = mergedHeaders ? JSON.stringify(mergedHeaders) : null;
    const startTime = Date.now();
    const result = this._lib.httpcloak_post(this._handle, url, body, headersJson);
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

    const headersJson = mergedHeaders ? JSON.stringify(mergedHeaders) : null;

    // Register async request with callback manager
    const manager = getAsyncManager();
    const { callbackId, promise } = manager.registerRequest(this._lib);

    // Start async request
    this._lib.httpcloak_get_async(this._handle, url, headersJson, callbackId);

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

    const headersJson = mergedHeaders ? JSON.stringify(mergedHeaders) : null;

    // Register async request with callback manager
    const manager = getAsyncManager();
    const { callbackId, promise } = manager.registerRequest(this._lib);

    // Start async request
    this._lib.httpcloak_post_async(this._handle, url, body, headersJson, callbackId);

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

module.exports = {
  // Classes
  Session,
  Response,
  Cookie,
  RedirectInfo,
  HTTPCloakError,
  // Presets
  Preset,
  // Configuration
  configure,
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
};
