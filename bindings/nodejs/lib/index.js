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
 * Response object returned from HTTP requests
 */
class Response {
  constructor(data) {
    this.statusCode = data.status_code || 0;
    this.headers = data.headers || {};
    this._body = Buffer.from(data.body || "", "utf8");
    this._text = data.body || "";
    this.finalUrl = data.final_url || "";
    this.protocol = data.protocol || "";
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
      throw new HTTPCloakError(`HTTP ${this.statusCode}`);
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

// Load the native library
let lib = null;

function getLib() {
  if (lib === null) {
    const libPath = getLibPath();
    const nativeLib = koffi.load(libPath);

    // Use void* for string returns so we can free them properly
    lib = {
      httpcloak_session_new: nativeLib.func("httpcloak_session_new", "int64", ["str"]),
      httpcloak_session_free: nativeLib.func("httpcloak_session_free", "void", ["int64"]),
      httpcloak_get: nativeLib.func("httpcloak_get", "void*", ["int64", "str", "str"]),
      httpcloak_post: nativeLib.func("httpcloak_post", "void*", ["int64", "str", "str", "str"]),
      httpcloak_request: nativeLib.func("httpcloak_request", "void*", ["int64", "str"]),
      httpcloak_get_cookies: nativeLib.func("httpcloak_get_cookies", "void*", ["int64"]),
      httpcloak_set_cookie: nativeLib.func("httpcloak_set_cookie", "void", ["int64", "str", "str"]),
      httpcloak_free_string: nativeLib.func("httpcloak_free_string", "void", ["void*"]),
      httpcloak_version: nativeLib.func("httpcloak_version", "void*", []),
      httpcloak_available_presets: nativeLib.func("httpcloak_available_presets", "void*", []),
    };
  }
  return lib;
}

/**
 * Convert a C string pointer to JS string and free the memory
 */
function ptrToString(ptr) {
  if (!ptr) {
    return null;
  }
  try {
    // Decode the C string from the pointer
    const str = koffi.decode(ptr, "str");
    return str;
  } finally {
    // Always free the C string to prevent memory leaks
    getLib().httpcloak_free_string(ptr);
  }
}

/**
 * Parse response from the native library
 */
function parseResponse(resultPtr) {
  const result = ptrToString(resultPtr);
  if (!result) {
    throw new HTTPCloakError("No response received");
  }

  const data = JSON.parse(result);

  if (data.error) {
    throw new HTTPCloakError(data.error);
  }

  return new Response(data);
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
  const result = ptrToString(resultPtr);
  return result || "unknown";
}

/**
 * Get list of available browser presets
 */
function availablePresets() {
  const nativeLib = getLib();
  const resultPtr = nativeLib.httpcloak_available_presets();
  const result = ptrToString(resultPtr);
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
   * @param {string} [options.proxy] - Proxy URL (e.g., "http://user:pass@host:port")
   * @param {number} [options.timeout=30] - Request timeout in seconds
   * @param {string} [options.httpVersion="auto"] - HTTP version: "auto", "h1", "h2", "h3"
   * @param {boolean} [options.verify=true] - SSL certificate verification
   * @param {boolean} [options.allowRedirects=true] - Follow redirects
   * @param {number} [options.maxRedirects=10] - Maximum number of redirects to follow
   * @param {number} [options.retry=0] - Number of retries on failure
   * @param {number[]} [options.retryOnStatus] - Status codes to retry on
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
      retry = 0,
      retryOnStatus = null,
    } = options;

    this._lib = getLib();
    this.headers = {}; // Default headers

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
    if (retry > 0) {
      config.retry = retry;
      if (retryOnStatus) {
        config.retry_on_status = retryOnStatus;
      }
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

  // ===========================================================================
  // Synchronous Methods
  // ===========================================================================

  /**
   * Perform a synchronous GET request
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {Object} [options.headers] - Custom headers
   * @param {Object} [options.params] - Query parameters
   * @param {Array} [options.auth] - Basic auth [username, password]
   * @returns {Response} Response object
   */
  getSync(url, options = {}) {
    const { headers = null, params = null, auth = null } = options;

    url = addParamsToUrl(url, params);
    let mergedHeaders = this._mergeHeaders(headers);
    mergedHeaders = applyAuth(mergedHeaders, auth);

    const headersJson = mergedHeaders ? JSON.stringify(mergedHeaders) : null;
    const result = this._lib.httpcloak_get(this._handle, url, headersJson);
    return parseResponse(result);
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
   * @param {Array} [options.auth] - Basic auth [username, password]
   * @returns {Response} Response object
   */
  postSync(url, options = {}) {
    let { body = null, json = null, data = null, files = null, headers = null, params = null, auth = null } = options;

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

    mergedHeaders = applyAuth(mergedHeaders, auth);

    const headersJson = mergedHeaders ? JSON.stringify(mergedHeaders) : null;
    const result = this._lib.httpcloak_post(this._handle, url, body, headersJson);
    return parseResponse(result);
  }

  /**
   * Perform a synchronous custom HTTP request
   * @param {string} method - HTTP method
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @param {Object} [options.files] - Files to upload as multipart/form-data
   * @returns {Response} Response object
   */
  requestSync(method, url, options = {}) {
    let { body = null, json = null, data = null, files = null, headers = null, params = null, auth = null, timeout = null } = options;

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

    mergedHeaders = applyAuth(mergedHeaders, auth);

    const requestConfig = {
      method: method.toUpperCase(),
      url,
    };
    if (mergedHeaders) requestConfig.headers = mergedHeaders;
    if (body) requestConfig.body = body;
    if (timeout) requestConfig.timeout = timeout;

    const result = this._lib.httpcloak_request(
      this._handle,
      JSON.stringify(requestConfig)
    );
    return parseResponse(result);
  }

  // ===========================================================================
  // Promise-based Methods
  // ===========================================================================

  /**
   * Perform an async GET request
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @returns {Promise<Response>} Response object
   */
  get(url, options = {}) {
    return new Promise((resolve, reject) => {
      setImmediate(() => {
        try {
          resolve(this.getSync(url, options));
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  /**
   * Perform an async POST request
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @returns {Promise<Response>} Response object
   */
  post(url, options = {}) {
    return new Promise((resolve, reject) => {
      setImmediate(() => {
        try {
          resolve(this.postSync(url, options));
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  /**
   * Perform an async custom HTTP request
   * @param {string} method - HTTP method
   * @param {string} url - Request URL
   * @param {Object} [options] - Request options
   * @returns {Promise<Response>} Response object
   */
  request(method, url, options = {}) {
    return new Promise((resolve, reject) => {
      setImmediate(() => {
        try {
          resolve(this.requestSync(method, url, options));
        } catch (err) {
          reject(err);
        }
      });
    });
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
    const result = ptrToString(resultPtr);
    if (result) {
      return JSON.parse(result);
    }
    return {};
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
 * @param {number} [options.retry=0] - Number of retries on failure
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
    retry = 0,
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
    const retry = _defaultConfig.retry || 0;
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
