/**
 * HTTPCloak Node.js TypeScript Definitions
 */

export class HTTPCloakError extends Error {
  name: "HTTPCloakError";
}

export class Response {
  /** HTTP status code */
  statusCode: number;
  /** Response headers */
  headers: Record<string, string>;
  /** Raw response body as Buffer */
  body: Buffer;
  /** Response body as string */
  text: string;
  /** Final URL after redirects */
  finalUrl: string;
  /** Protocol used (http/1.1, h2, h3) */
  protocol: string;

  /** Parse response body as JSON */
  json<T = any>(): T;
}

export interface SessionOptions {
  /** Browser preset to use (default: "chrome-143") */
  preset?: string;
  /** Proxy URL (e.g., "http://user:pass@host:port" or "socks5://host:port") */
  proxy?: string;
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
}

export interface RequestOptions {
  /** HTTP method */
  method: string;
  /** Request URL */
  url: string;
  /** Optional custom headers */
  headers?: Record<string, string>;
  /** Optional request body */
  body?: string | Buffer | Record<string, any>;
  /** Optional request timeout in seconds */
  timeout?: number;
}

export class Session {
  constructor(options?: SessionOptions);

  /** Close the session and release resources */
  close(): void;

  // Synchronous methods
  /** Perform a synchronous GET request */
  getSync(url: string, headers?: Record<string, string>): Response;

  /** Perform a synchronous POST request */
  postSync(
    url: string,
    body?: string | Buffer | Record<string, any>,
    headers?: Record<string, string>
  ): Response;

  /** Perform a synchronous custom HTTP request */
  requestSync(options: RequestOptions): Response;

  // Promise-based methods
  /** Perform an async GET request */
  get(url: string, headers?: Record<string, string>): Promise<Response>;

  /** Perform an async POST request */
  post(
    url: string,
    body?: string | Buffer | Record<string, any>,
    headers?: Record<string, string>
  ): Promise<Response>;

  /** Perform an async custom HTTP request */
  request(options: RequestOptions): Promise<Response>;

  /** Perform an async PUT request */
  put(
    url: string,
    body?: string | Buffer | Record<string, any>,
    headers?: Record<string, string>
  ): Promise<Response>;

  /** Perform an async DELETE request */
  delete(url: string, headers?: Record<string, string>): Promise<Response>;

  /** Perform an async PATCH request */
  patch(
    url: string,
    body?: string | Buffer | Record<string, any>,
    headers?: Record<string, string>
  ): Promise<Response>;

  /** Perform an async HEAD request */
  head(url: string, headers?: Record<string, string>): Promise<Response>;

  /** Perform an async OPTIONS request */
  options(url: string, headers?: Record<string, string>): Promise<Response>;

  // Cookie management
  /** Get all cookies from the session */
  getCookies(): Record<string, string>;

  /** Set a cookie in the session */
  setCookie(name: string, value: string): void;

  /** Get cookies as a property */
  readonly cookies: Record<string, string>;
}

/** Get the httpcloak library version */
export function version(): string;

/** Get list of available browser presets */
export function availablePresets(): string[];

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
export function options(url: string, options?: RequestOptions): Promise<Response>;

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
