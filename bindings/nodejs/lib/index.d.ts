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

export interface SessionOptions {
  /** Browser preset to use (default: "chrome-143") */
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

  /** Get/set the current proxy as a property */
  proxy: string;
}

export interface LocalProxyOptions {
  /** Port to listen on (default: 0 for auto-assign) */
  port?: number;
  /** Browser preset to use (default: "chrome-143") */
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
  CHROME_143: string;
  CHROME_143_WINDOWS: string;
  CHROME_143_LINUX: string;
  CHROME_143_MACOS: string;
  CHROME_131: string;
  CHROME_131_WINDOWS: string;
  CHROME_131_LINUX: string;
  CHROME_131_MACOS: string;
  IOS_CHROME_143: string;
  ANDROID_CHROME_143: string;
  FIREFOX_133: string;
  SAFARI_18: string;
  IOS_SAFARI_17: string;
  all(): string[];
};
