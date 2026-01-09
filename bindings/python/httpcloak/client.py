"""
HTTPCloak Python Client

A requests-compatible HTTP client with browser fingerprint emulation.
Drop-in replacement for the requests library with TLS fingerprinting.

Example:
    import httpcloak

    # Simple usage (like requests)
    r = httpcloak.get("https://example.com")
    print(r.status_code, r.text)

    # With session (recommended for multiple requests)
    session = httpcloak.Session(preset="chrome-143")
    r = session.get("https://example.com")
    print(r.json())
"""

import asyncio
import base64
import json
import mimetypes
import os
import platform
import time
import uuid
from ctypes import c_char_p, c_int64, c_void_p, cdll, cast, CFUNCTYPE
from io import IOBase
from pathlib import Path
from threading import Lock
from typing import Any, BinaryIO, Dict, List, Optional, Tuple, Union
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs


# File type for files parameter
FileValue = Union[
    bytes,                                          # Raw bytes
    BinaryIO,                                       # File-like object
    Tuple[str, bytes],                              # (filename, content)
    Tuple[str, bytes, str],                         # (filename, content, content_type)
    Tuple[str, BinaryIO],                           # (filename, file_object)
    Tuple[str, BinaryIO, str],                      # (filename, file_object, content_type)
]
FilesType = Dict[str, FileValue]


def _encode_multipart(
    data: Optional[Dict[str, str]] = None,
    files: Optional[FilesType] = None,
) -> Tuple[bytes, str]:
    """
    Encode data and files as multipart/form-data.

    Returns:
        Tuple of (body_bytes, content_type_with_boundary)
    """
    boundary = f"----HTTPCloakBoundary{uuid.uuid4().hex}"
    lines: List[bytes] = []

    # Add form fields
    if data:
        for key, value in data.items():
            lines.append(f"--{boundary}\r\n".encode())
            lines.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode())
            lines.append(f"{value}\r\n".encode())

    # Add files
    if files:
        for field_name, file_value in files.items():
            filename: str
            content: bytes
            content_type: str

            if isinstance(file_value, bytes):
                # Just raw bytes
                filename = field_name
                content = file_value
                content_type = "application/octet-stream"
            elif isinstance(file_value, IOBase):
                # File-like object
                filename = getattr(file_value, "name", field_name)
                if isinstance(filename, (bytes, bytearray)):
                    filename = filename.decode()
                filename = os.path.basename(filename)
                content = file_value.read()
                content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            elif isinstance(file_value, tuple):
                if len(file_value) == 2:
                    filename, file_content = file_value
                    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
                else:
                    filename, file_content, content_type = file_value

                if isinstance(file_content, IOBase):
                    content = file_content.read()
                else:
                    content = file_content
            else:
                raise ValueError(f"Invalid file value for field '{field_name}'")

            lines.append(f"--{boundary}\r\n".encode())
            lines.append(
                f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode()
            )
            lines.append(f"Content-Type: {content_type}\r\n\r\n".encode())
            lines.append(content)
            lines.append(b"\r\n")

    lines.append(f"--{boundary}--\r\n".encode())

    body = b"".join(lines)
    content_type_header = f"multipart/form-data; boundary={boundary}"

    return body, content_type_header


class HTTPCloakError(Exception):
    """Base exception for HTTPCloak errors."""
    pass


class Preset:
    """
    Available browser presets for TLS fingerprinting.

    Use these constants instead of typing preset strings manually:
        import httpcloak
        httpcloak.configure(preset=httpcloak.Preset.CHROME_143)

        # Or with Session
        session = httpcloak.Session(preset=httpcloak.Preset.FIREFOX_133)

    All available presets:
        Desktop Chrome: CHROME_143, CHROME_143_WINDOWS, CHROME_143_LINUX, CHROME_143_MACOS
                        CHROME_131, CHROME_131_WINDOWS, CHROME_131_LINUX, CHROME_131_MACOS
        Mobile Chrome: IOS_CHROME_143, ANDROID_CHROME_143
        Firefox: FIREFOX_133
        Safari: SAFARI_18, IOS_SAFARI_17
    """
    # Chrome 143 (latest)
    CHROME_143 = "chrome-143"
    CHROME_143_WINDOWS = "chrome-143-windows"
    CHROME_143_LINUX = "chrome-143-linux"
    CHROME_143_MACOS = "chrome-143-macos"

    # Chrome 131
    CHROME_131 = "chrome-131"
    CHROME_131_WINDOWS = "chrome-131-windows"
    CHROME_131_LINUX = "chrome-131-linux"
    CHROME_131_MACOS = "chrome-131-macos"

    # Mobile Chrome
    IOS_CHROME_143 = "ios-chrome-143"
    ANDROID_CHROME_143 = "android-chrome-143"

    # Firefox
    FIREFOX_133 = "firefox-133"

    # Safari (desktop and mobile)
    SAFARI_18 = "safari-18"
    IOS_SAFARI_17 = "ios-safari-17"

    @classmethod
    def all(cls) -> List[str]:
        """Return list of all available preset names."""
        return [
            cls.CHROME_143, cls.CHROME_143_WINDOWS, cls.CHROME_143_LINUX, cls.CHROME_143_MACOS,
            cls.CHROME_131, cls.CHROME_131_WINDOWS, cls.CHROME_131_LINUX, cls.CHROME_131_MACOS,
            cls.IOS_CHROME_143, cls.ANDROID_CHROME_143,
            cls.FIREFOX_133,
            cls.SAFARI_18, cls.IOS_SAFARI_17,
        ]


# HTTP status reason phrases
HTTP_STATUS_PHRASES = {
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
}


class Cookie:
    """
    Represents a cookie from Set-Cookie header.

    Attributes:
        name: Cookie name
        value: Cookie value
    """

    def __init__(self, name: str, value: str):
        self.name = name
        self.value = value

    def __repr__(self):
        return f"Cookie(name={self.name!r}, value={self.value!r})"


class RedirectInfo:
    """
    Information about a redirect response in the history.

    Attributes:
        status_code: HTTP status code of the redirect
        url: URL that was requested
        headers: Response headers from the redirect
    """

    def __init__(self, status_code: int, url: str, headers: Dict[str, str]):
        self.status_code = status_code
        self.url = url
        self.headers = headers

    def __repr__(self):
        return f"RedirectInfo(status_code={self.status_code}, url={self.url!r})"


class Response:
    """
    HTTP Response object (requests-compatible).

    Attributes:
        status_code: HTTP status code
        headers: Response headers
        text: Response body as string
        content: Response body as bytes
        url: Final URL after redirects
        ok: True if status_code < 400
        protocol: Protocol used (http/1.1, h2, h3)
        elapsed: Time elapsed for the request (seconds as float)
        reason: HTTP status reason phrase
        encoding: Response encoding (from Content-Type header)
        cookies: List of cookies set by this response
        history: List of redirect responses (RedirectInfo objects)
    """

    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: bytes,
        text: str,
        final_url: str,
        protocol: str,
        elapsed: float = 0.0,
        cookies: Optional[List[Cookie]] = None,
        history: Optional[List[RedirectInfo]] = None,
    ):
        self.status_code = status_code
        self.headers = headers
        self.content = body  # requests compatibility
        self.text = text
        self.url = final_url  # requests compatibility
        self.protocol = protocol
        self.elapsed = elapsed  # seconds as float
        self.cookies = cookies or []
        self.history = history or []

        # Keep old names as aliases
        self.body = body
        self.final_url = final_url

    @property
    def ok(self) -> bool:
        """True if status_code < 400."""
        return self.status_code < 400

    @property
    def reason(self) -> str:
        """HTTP status reason phrase (e.g., 'OK', 'Not Found')."""
        return HTTP_STATUS_PHRASES.get(self.status_code, "Unknown")

    @property
    def encoding(self) -> Optional[str]:
        """
        Response encoding from Content-Type header.
        Returns None if not specified.
        """
        content_type = self.headers.get("content-type", "")
        if not content_type:
            content_type = self.headers.get("Content-Type", "")
        if "charset=" in content_type:
            # Extract charset from Content-Type: text/html; charset=utf-8
            for part in content_type.split(";"):
                part = part.strip()
                if part.lower().startswith("charset="):
                    return part.split("=", 1)[1].strip().strip('"\'')
        return None

    def json(self, **kwargs) -> Any:
        """Parse response body as JSON."""
        return json.loads(self.text, **kwargs)

    def raise_for_status(self):
        """Raise HTTPCloakError if status_code >= 400."""
        if not self.ok:
            raise HTTPCloakError(f"HTTP {self.status_code}: {self.reason}")

    @classmethod
    def _from_dict(cls, data: dict, elapsed: float = 0.0) -> "Response":
        body = data.get("body", "")
        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = body

        # Parse cookies from response (use `or []` to handle null values)
        cookies = []
        for cookie_data in data.get("cookies") or []:
            if isinstance(cookie_data, dict):
                cookies.append(Cookie(
                    name=cookie_data.get("name", ""),
                    value=cookie_data.get("value", ""),
                ))

        # Parse redirect history (use `or []` to handle null values)
        history = []
        for redirect_data in data.get("history") or []:
            if isinstance(redirect_data, dict):
                history.append(RedirectInfo(
                    status_code=redirect_data.get("status_code", 0),
                    url=redirect_data.get("url", ""),
                    headers=redirect_data.get("headers") or {},
                ))

        return cls(
            status_code=data.get("status_code", 0),
            headers=data.get("headers") or {},
            body=body_bytes,
            text=body if isinstance(body, str) else body.decode("utf-8", errors="replace"),
            final_url=data.get("final_url", ""),
            protocol=data.get("protocol", ""),
            elapsed=elapsed,
            cookies=cookies,
            history=history,
        )


def _get_lib_path() -> str:
    """Get the path to the shared library based on platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        arch = machine

    if system == "darwin":
        ext = ".dylib"
        os_name = "darwin"
    elif system == "windows":
        ext = ".dll"
        os_name = "windows"
    else:
        ext = ".so"
        os_name = "linux"

    lib_name = f"libhttpcloak-{os_name}-{arch}{ext}"

    search_paths = [
        Path(__file__).parent / lib_name,
        Path(__file__).parent / "lib" / lib_name,
        Path(__file__).parent.parent / "lib" / lib_name,
        Path(f"/usr/local/lib/{lib_name}"),
        Path(f"/usr/lib/{lib_name}"),
    ]

    env_path = os.environ.get("HTTPCLOAK_LIB_PATH")
    if env_path:
        search_paths.insert(0, Path(env_path))

    for path in search_paths:
        if path.exists():
            return str(path)

    raise HTTPCloakError(
        f"Could not find httpcloak library ({lib_name}). "
        f"Set HTTPCLOAK_LIB_PATH environment variable or install the library."
    )


_lib = None
_lib_lock = Lock()


def _get_lib():
    """Get or load the shared library."""
    global _lib
    if _lib is None:
        with _lib_lock:
            if _lib is None:
                lib_path = _get_lib_path()
                _lib = cdll.LoadLibrary(lib_path)
                _setup_lib(_lib)
    return _lib


# Async callback type: void (*)(int64_t callback_id, const char* response_json, const char* error)
ASYNC_CALLBACK = CFUNCTYPE(None, c_int64, c_char_p, c_char_p)


class _AsyncCallbackManager:
    """
    Manages native async callbacks from Go goroutines.

    This class handles the bridge between Go's goroutine-based async
    and Python's asyncio. Callbacks from Go run in different threads,
    so we use loop.call_soon_threadsafe() to safely resolve futures.

    Each async request registers a NEW callback with Go and receives a unique ID.
    The callback function is shared but each request gets its own callback_id.
    """

    def __init__(self):
        self._lock = Lock()
        # Pending requests: callback_id -> (future, loop, start_time)
        self._pending: Dict[int, Tuple[asyncio.Future, asyncio.AbstractEventLoop, float]] = {}
        self._callback_ref: Optional[ASYNC_CALLBACK] = None  # prevent GC
        self._lib = None

    def _on_callback(self, callback_id: int, response_json: Optional[bytes], error: Optional[bytes]):
        """Called from Go goroutine when async request completes."""
        with self._lock:
            if callback_id not in self._pending:
                return
            future, loop, start_time = self._pending.pop(callback_id)

        # Calculate elapsed time
        elapsed = time.perf_counter() - start_time

        # Parse result
        if error and error != b"":
            err_str = error.decode("utf-8")
            try:
                err_data = json.loads(err_str)
                err_msg = err_data.get("error", err_str)
            except (json.JSONDecodeError, ValueError):
                err_msg = err_str
            # Resolve in the correct event loop thread
            loop.call_soon_threadsafe(future.set_exception, HTTPCloakError(err_msg))
        elif response_json:
            try:
                data = json.loads(response_json.decode("utf-8"))
                response = Response._from_dict(data, elapsed=elapsed)
                loop.call_soon_threadsafe(future.set_result, response)
            except Exception as e:
                loop.call_soon_threadsafe(future.set_exception, HTTPCloakError(f"Failed to parse response: {e}"))
        else:
            loop.call_soon_threadsafe(future.set_exception, HTTPCloakError("No response received"))

    def _ensure_callback(self, lib):
        """Ensure callback function is created and stored."""
        if self._callback_ref is None:
            self._lib = lib
            self._callback_ref = ASYNC_CALLBACK(self._on_callback)

    def register_request(self, lib) -> Tuple[int, asyncio.Future]:
        """
        Register a new async request. Returns (callback_id, future).

        Each request gets a unique callback_id from Go. The callback function
        is shared but Go tracks each request separately by ID.
        """
        self._ensure_callback(lib)

        # Register a NEW callback for this request (Go gives us a unique ID)
        callback_id = lib.httpcloak_register_callback(self._callback_ref)

        # Create future and store it with start time
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        start_time = time.perf_counter()
        with self._lock:
            self._pending[callback_id] = (future, loop, start_time)

        return callback_id, future


# Global async callback manager
_async_manager: Optional[_AsyncCallbackManager] = None
_async_manager_lock = Lock()


def _get_async_manager() -> _AsyncCallbackManager:
    """Get or create the global async callback manager."""
    global _async_manager
    if _async_manager is None:
        with _async_manager_lock:
            if _async_manager is None:
                _async_manager = _AsyncCallbackManager()
    return _async_manager


def _setup_lib(lib):
    """Setup function signatures for the library."""
    lib.httpcloak_session_new.argtypes = [c_char_p]
    lib.httpcloak_session_new.restype = c_int64
    lib.httpcloak_session_free.argtypes = [c_int64]
    lib.httpcloak_session_free.restype = None
    # Use c_void_p for string returns so we can free them properly
    lib.httpcloak_get.argtypes = [c_int64, c_char_p, c_char_p]
    lib.httpcloak_get.restype = c_void_p
    lib.httpcloak_post.argtypes = [c_int64, c_char_p, c_char_p, c_char_p]
    lib.httpcloak_post.restype = c_void_p
    lib.httpcloak_request.argtypes = [c_int64, c_char_p]
    lib.httpcloak_request.restype = c_void_p
    lib.httpcloak_get_cookies.argtypes = [c_int64]
    lib.httpcloak_get_cookies.restype = c_void_p
    lib.httpcloak_set_cookie.argtypes = [c_int64, c_char_p, c_char_p]
    lib.httpcloak_set_cookie.restype = None
    lib.httpcloak_free_string.argtypes = [c_void_p]
    lib.httpcloak_free_string.restype = None
    lib.httpcloak_version.argtypes = []
    lib.httpcloak_version.restype = c_void_p
    lib.httpcloak_available_presets.argtypes = []
    lib.httpcloak_available_presets.restype = c_void_p

    # Async functions
    lib.httpcloak_register_callback.argtypes = [ASYNC_CALLBACK]
    lib.httpcloak_register_callback.restype = c_int64
    lib.httpcloak_unregister_callback.argtypes = [c_int64]
    lib.httpcloak_unregister_callback.restype = None
    lib.httpcloak_get_async.argtypes = [c_int64, c_char_p, c_char_p, c_int64]
    lib.httpcloak_get_async.restype = None
    lib.httpcloak_post_async.argtypes = [c_int64, c_char_p, c_char_p, c_char_p, c_int64]
    lib.httpcloak_post_async.restype = None
    lib.httpcloak_request_async.argtypes = [c_int64, c_char_p, c_int64]
    lib.httpcloak_request_async.restype = None


def _ptr_to_string(ptr) -> Optional[str]:
    """Convert a C string pointer to Python string and free it."""
    if ptr is None or ptr == 0:
        return None
    try:
        # Cast void pointer to char pointer and get the value
        result = cast(ptr, c_char_p).value
        if result is None:
            return None
        return result.decode("utf-8")
    finally:
        # Always free the C string to prevent memory leaks
        _get_lib().httpcloak_free_string(ptr)


def _parse_response(result_ptr, elapsed: float = 0.0) -> Response:
    """Parse JSON response from library."""
    result = _ptr_to_string(result_ptr)
    if result is None:
        raise HTTPCloakError("No response received")
    data = json.loads(result)
    if "error" in data:
        raise HTTPCloakError(data["error"])
    return Response._from_dict(data, elapsed=elapsed)


def _add_params_to_url(url: str, params: Optional[Dict[str, Any]]) -> str:
    """Add query parameters to URL."""
    if not params:
        return url
    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query)
    existing_params.update({k: [str(v)] for k, v in params.items()})
    new_query = urlencode(existing_params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _apply_auth(
    headers: Optional[Dict[str, str]],
    auth: Optional[Tuple[str, str]],
) -> Optional[Dict[str, str]]:
    """Apply basic auth to headers."""
    if auth is None:
        return headers

    username, password = auth
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()

    headers = headers.copy() if headers else {}
    headers["Authorization"] = f"Basic {credentials}"
    return headers


def version() -> str:
    """Get the httpcloak library version."""
    lib = _get_lib()
    result_ptr = lib.httpcloak_version()
    result = _ptr_to_string(result_ptr)
    return result if result else "unknown"


def available_presets() -> List[str]:
    """Get list of available browser presets."""
    lib = _get_lib()
    result_ptr = lib.httpcloak_available_presets()
    result = _ptr_to_string(result_ptr)
    if result:
        return json.loads(result)
    return []


class Session:
    """
    HTTP Session with browser fingerprint emulation.

    Maintains cookies and connection state across requests.
    API is compatible with requests.Session.

    Args:
        preset: Browser preset (default: "chrome-143")
        proxy: Proxy URL (e.g., "http://user:pass@host:port" or "socks5://host:port")
        timeout: Default request timeout in seconds (default: 30)
        http_version: Force HTTP version - "auto", "h1", "h2", "h3" (default: "auto")
        verify: SSL certificate verification (default: True)
        allow_redirects: Follow redirects (default: True)
        max_redirects: Maximum number of redirects to follow (default: 10)
        retry: Number of retries on failure (default: 3, set to 0 to disable)
        retry_on_status: List of status codes to retry on (default: [429, 500, 502, 503, 504])
        prefer_ipv4: Prefer IPv4 addresses over IPv6 (default: False)
        connect_to: Domain fronting map {request_host: connect_host} - DNS resolves connect_host but SNI/Host uses request_host
        ech_config_domain: Domain to fetch ECH config from (e.g., "cloudflare-ech.com" for any CF domain)

    Example:
        with httpcloak.Session(preset="chrome-143") as session:
            r = session.get("https://example.com")
            print(r.json())

        # With retry and no SSL verification
        with httpcloak.Session(preset="chrome-143", verify=False, retry=3) as session:
            r = session.get("https://example.com")

        # Force IPv4 on networks with poor IPv6 connectivity
        with httpcloak.Session(preset="chrome-143", prefer_ipv4=True) as session:
            r = session.get("https://example.com")

        # With ECH enabled (encrypted SNI) for Cloudflare domains
        with httpcloak.Session(preset="chrome-143", ech_config_domain="cloudflare-ech.com") as session:
            r = session.get("https://www.cloudflare.com/cdn-cgi/trace")
            # Should show sni=encrypted in response
    """

    def __init__(
        self,
        preset: str = "chrome-143",
        proxy: Optional[str] = None,
        timeout: int = 30,
        http_version: str = "auto",
        verify: bool = True,
        allow_redirects: bool = True,
        max_redirects: int = 10,
        retry: int = 3,
        retry_on_status: Optional[List[int]] = None,
        prefer_ipv4: bool = False,
        auth: Optional[Tuple[str, str]] = None,
        connect_to: Optional[Dict[str, str]] = None,
        ech_config_domain: Optional[str] = None,
    ):
        self._lib = _get_lib()
        self._default_timeout = timeout
        self.headers: Dict[str, str] = {}  # Default headers
        self.auth: Optional[Tuple[str, str]] = auth  # Default auth for all requests

        config = {"preset": preset, "timeout": timeout, "http_version": http_version}
        if proxy:
            config["proxy"] = proxy
        if not verify:
            config["verify"] = False
        if not allow_redirects:
            config["allow_redirects"] = False
        elif max_redirects != 10:
            config["max_redirects"] = max_redirects
        # Always pass retry to clib (even if 0 to explicitly disable)
        config["retry"] = retry
        if retry_on_status:
            config["retry_on_status"] = retry_on_status
        if prefer_ipv4:
            config["prefer_ipv4"] = True
        if connect_to:
            config["connect_to"] = connect_to
        if ech_config_domain:
            config["ech_config_domain"] = ech_config_domain

        config_json = json.dumps(config).encode("utf-8")
        self._handle = self._lib.httpcloak_session_new(config_json)

        if self._handle == 0:
            raise HTTPCloakError("Failed to create session")

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Close the session and release resources."""
        if hasattr(self, "_handle") and self._handle:
            self._lib.httpcloak_session_free(self._handle)
            self._handle = 0

    def _merge_headers(self, headers: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        """Merge session headers with request headers."""
        if not self.headers and not headers:
            return None
        merged = dict(self.headers)
        if headers:
            merged.update(headers)
        return merged if merged else None

    def _apply_cookies(
        self, headers: Optional[Dict[str, str]], cookies: Optional[Dict[str, str]]
    ) -> Optional[Dict[str, str]]:
        """Apply cookies to headers."""
        if not cookies:
            return headers

        # Build cookie string
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

        headers = headers.copy() if headers else {}
        # Merge with existing Cookie header if present
        existing = headers.get("Cookie", "")
        if existing:
            headers["Cookie"] = f"{existing}; {cookie_str}"
        else:
            headers["Cookie"] = cookie_str
        return headers

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """
        Perform a GET request.

        Args:
            url: Request URL
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password). If None, uses session.auth
            timeout: Request timeout in seconds
        """
        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)
        # Use request auth if provided, otherwise fall back to session auth
        effective_auth = auth if auth is not None else self.auth
        merged_headers = _apply_auth(merged_headers, effective_auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        if timeout:
            return self.request("GET", url, headers=merged_headers, timeout=timeout)

        headers_json = json.dumps(merged_headers).encode("utf-8") if merged_headers else None
        start_time = time.perf_counter()
        result = self._lib.httpcloak_get(
            self._handle,
            url.encode("utf-8"),
            headers_json,
        )
        elapsed = time.perf_counter() - start_time
        return _parse_response(result, elapsed=elapsed)

    def post(
        self,
        url: str,
        data: Union[str, bytes, Dict, None] = None,
        json: Optional[Dict] = None,
        files: Optional[FilesType] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """
        Perform a POST request.

        Args:
            url: Request URL
            data: Request body (string, bytes, or dict for form data)
            json: JSON body (will be serialized)
            files: Files to upload as multipart/form-data.
                   Dict mapping field names to file values:
                   - bytes: Raw file content
                   - file object: Open file
                   - (filename, content): Tuple with filename and bytes
                   - (filename, content, content_type): With explicit MIME type
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in seconds

        Example:
            # Upload a file
            session.post(url, files={"file": open("image.png", "rb")})

            # Upload with custom filename
            session.post(url, files={"file": ("photo.jpg", image_bytes, "image/jpeg")})

            # Upload with form data
            session.post(url, data={"name": "test"}, files={"file": file_bytes})
        """
        import json as json_module

        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)

        body = None

        # Handle multipart file upload
        if files is not None:
            form_data = data if isinstance(data, dict) else None
            body, content_type = _encode_multipart(data=form_data, files=files)
            merged_headers = merged_headers or {}
            merged_headers["Content-Type"] = content_type
        elif json is not None:
            body = json_module.dumps(json).encode("utf-8")
            merged_headers = merged_headers or {}
            merged_headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, dict):
                body = urlencode(data).encode("utf-8")
                merged_headers = merged_headers or {}
                merged_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, str):
                body = data.encode("utf-8")
            else:
                body = data

        # Use request auth if provided, otherwise fall back to session auth
        effective_auth = auth if auth is not None else self.auth
        merged_headers = _apply_auth(merged_headers, effective_auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        if timeout:
            return self.request("POST", url, headers=merged_headers, data=body, timeout=timeout)

        headers_json = json_module.dumps(merged_headers).encode("utf-8") if merged_headers else None
        start_time = time.perf_counter()
        result = self._lib.httpcloak_post(
            self._handle,
            url.encode("utf-8"),
            body,
            headers_json,
        )
        elapsed = time.perf_counter() - start_time
        return _parse_response(result, elapsed=elapsed)

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Union[str, bytes, Dict, None] = None,
        json: Optional[Dict] = None,
        files: Optional[FilesType] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """
        Perform a custom HTTP request.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Request URL
            params: URL query parameters
            data: Request body
            json: JSON body (will be serialized)
            files: Files to upload as multipart/form-data
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in seconds
        """
        import json as json_module

        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)

        body = None
        # Handle multipart file upload
        if files is not None:
            form_data = data if isinstance(data, dict) else None
            body_bytes, content_type = _encode_multipart(data=form_data, files=files)
            body = body_bytes.decode("latin-1")  # Preserve binary data
            merged_headers = merged_headers or {}
            merged_headers["Content-Type"] = content_type
        elif json is not None:
            body = json_module.dumps(json)
            merged_headers = merged_headers or {}
            merged_headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, dict):
                body = urlencode(data)
                merged_headers = merged_headers or {}
                merged_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, bytes):
                body = data.decode("utf-8")
            else:
                body = data

        # Use request auth if provided, otherwise fall back to session auth
        effective_auth = auth if auth is not None else self.auth
        merged_headers = _apply_auth(merged_headers, effective_auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        request_config = {
            "method": method.upper(),
            "url": url,
        }
        if merged_headers:
            request_config["headers"] = merged_headers
        if body:
            request_config["body"] = body
        if timeout:
            request_config["timeout"] = timeout

        start_time = time.perf_counter()
        result = self._lib.httpcloak_request(
            self._handle,
            json_module.dumps(request_config).encode("utf-8"),
        )
        elapsed = time.perf_counter() - start_time
        return _parse_response(result, elapsed=elapsed)

    def put(
        self,
        url: str,
        data: Union[str, bytes, Dict, None] = None,
        json: Optional[Dict] = None,
        files: Optional[FilesType] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """Perform a PUT request."""
        return self.request("PUT", url, params=params, data=data, json=json, files=files, headers=headers, cookies=cookies, auth=auth, timeout=timeout)

    def delete(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """Perform a DELETE request."""
        return self.request("DELETE", url, params=params, headers=headers, cookies=cookies, auth=auth, timeout=timeout)

    def patch(
        self,
        url: str,
        data: Union[str, bytes, Dict, None] = None,
        json: Optional[Dict] = None,
        files: Optional[FilesType] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """Perform a PATCH request."""
        return self.request("PATCH", url, params=params, data=data, json=json, files=files, headers=headers, cookies=cookies, auth=auth, timeout=timeout)

    def head(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """Perform a HEAD request."""
        return self.request("HEAD", url, params=params, headers=headers, cookies=cookies, auth=auth, timeout=timeout)

    def options(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """Perform an OPTIONS request."""
        return self.request("OPTIONS", url, params=params, headers=headers, cookies=cookies, auth=auth, timeout=timeout)

    # =========================================================================
    # Async Methods (Native - using Go goroutines)
    # =========================================================================

    async def get_async(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
    ) -> Response:
        """
        Async GET request using native Go goroutines.

        This is more efficient than thread pool-based async as it uses
        Go's native concurrency primitives.

        Args:
            url: Request URL
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
        """
        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)
        merged_headers = _apply_auth(merged_headers, auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        # Get async manager and register this request (each request gets unique ID)
        manager = _get_async_manager()
        callback_id, future = manager.register_request(self._lib)

        # Prepare headers JSON
        headers_json = json.dumps(merged_headers).encode("utf-8") if merged_headers else None

        # Start async request
        self._lib.httpcloak_get_async(
            self._handle,
            url.encode("utf-8"),
            headers_json,
            callback_id,
        )

        return await future

    async def post_async(
        self,
        url: str,
        data: Union[str, bytes, Dict, None] = None,
        json_data: Optional[Dict] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
    ) -> Response:
        """
        Async POST request using native Go goroutines.

        Args:
            url: Request URL
            data: Request body (string, bytes, or dict for form data)
            json_data: JSON body (will be serialized)
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
        """
        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)

        body = None
        if json_data is not None:
            body = json.dumps(json_data).encode("utf-8")
            merged_headers = merged_headers or {}
            merged_headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, dict):
                body = urlencode(data).encode("utf-8")
                merged_headers = merged_headers or {}
                merged_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, str):
                body = data.encode("utf-8")
            else:
                body = data

        merged_headers = _apply_auth(merged_headers, auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        # Get async manager and register this request (each request gets unique ID)
        manager = _get_async_manager()
        callback_id, future = manager.register_request(self._lib)

        # Prepare headers JSON
        headers_json = json.dumps(merged_headers).encode("utf-8") if merged_headers else None

        # Start async request
        self._lib.httpcloak_post_async(
            self._handle,
            url.encode("utf-8"),
            body,
            headers_json,
            callback_id,
        )

        return await future

    async def request_async(
        self,
        method: str,
        url: str,
        data: Union[str, bytes, Dict, None] = None,
        json_data: Optional[Dict] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
    ) -> Response:
        """
        Async custom HTTP request using native Go goroutines.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Request URL
            data: Request body
            json_data: JSON body (will be serialized)
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
        """
        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)

        body = None
        if json_data is not None:
            body = json.dumps(json_data)
            merged_headers = merged_headers or {}
            merged_headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, dict):
                body = urlencode(data)
                merged_headers = merged_headers or {}
                merged_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, bytes):
                body = data.decode("utf-8")
            else:
                body = data

        merged_headers = _apply_auth(merged_headers, auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        # Build request config
        request_config = {
            "method": method.upper(),
            "url": url,
        }
        if merged_headers:
            request_config["headers"] = merged_headers
        if body:
            request_config["body"] = body

        # Get async manager and register this request (each request gets unique ID)
        manager = _get_async_manager()
        callback_id, future = manager.register_request(self._lib)

        # Start async request
        self._lib.httpcloak_request_async(
            self._handle,
            json.dumps(request_config).encode("utf-8"),
            callback_id,
        )

        return await future

    async def put_async(self, url: str, **kwargs) -> Response:
        """Async PUT request."""
        return await self.request_async("PUT", url, **kwargs)

    async def delete_async(self, url: str, **kwargs) -> Response:
        """Async DELETE request."""
        return await self.request_async("DELETE", url, **kwargs)

    async def patch_async(self, url: str, **kwargs) -> Response:
        """Async PATCH request."""
        return await self.request_async("PATCH", url, **kwargs)

    async def head_async(self, url: str, **kwargs) -> Response:
        """Async HEAD request."""
        return await self.request_async("HEAD", url, **kwargs)

    async def options_async(self, url: str, **kwargs) -> Response:
        """Async OPTIONS request."""
        return await self.request_async("OPTIONS", url, **kwargs)

    # =========================================================================
    # Cookie Management
    # =========================================================================

    def get_cookies(self) -> Dict[str, str]:
        """Get all cookies from the session."""
        result_ptr = self._lib.httpcloak_get_cookies(self._handle)
        result = _ptr_to_string(result_ptr)
        if result:
            return json.loads(result)
        return {}

    def get_cookie(self, name: str) -> Optional[str]:
        """
        Get a specific cookie by name.

        Args:
            name: Cookie name

        Returns:
            Cookie value or None if not found
        """
        cookies = self.get_cookies()
        return cookies.get(name)

    def set_cookie(self, name: str, value: str):
        """Set a cookie in the session."""
        self._lib.httpcloak_set_cookie(
            self._handle,
            name.encode("utf-8"),
            value.encode("utf-8"),
        )

    def delete_cookie(self, name: str):
        """
        Delete a specific cookie by name.

        Note: This sets the cookie to an empty value with immediate expiry.
        The cookie will not be sent in subsequent requests.
        """
        # Set cookie to empty value - effectively deletes it
        self._lib.httpcloak_set_cookie(
            self._handle,
            name.encode("utf-8"),
            b"",
        )

    def clear_cookies(self):
        """
        Clear all cookies from the session.

        Note: This deletes all cookies by setting them to empty values.
        """
        cookies = self.get_cookies()
        for name in cookies:
            self.delete_cookie(name)

    @property
    def cookies(self) -> Dict[str, str]:
        """Get cookies as a property."""
        return self.get_cookies()


# =============================================================================
# Module-level convenience functions (like requests.get, requests.post, etc.)
# =============================================================================

_default_session: Optional[Session] = None
_default_session_lock = Lock()
_default_config: Dict[str, Any] = {}


def configure(
    preset: str = "chrome-143",
    headers: Optional[Dict[str, str]] = None,
    auth: Optional[Tuple[str, str]] = None,
    proxy: Optional[str] = None,
    timeout: int = 30,
    http_version: str = "auto",
    verify: bool = True,
    allow_redirects: bool = True,
    max_redirects: int = 10,
    retry: int = 3,
    retry_on_status: Optional[List[int]] = None,
    prefer_ipv4: bool = False,
) -> None:
    """
    Configure defaults for module-level functions.

    This creates/recreates the default session with the specified settings.
    All subsequent calls to httpcloak.get(), httpcloak.post(), etc. will use these defaults.

    Args:
        preset: Browser preset (default: "chrome-143")
        headers: Default headers for all requests
        auth: Default basic auth tuple (username, password)
        proxy: Proxy URL (e.g., "http://user:pass@host:port")
        timeout: Default request timeout in seconds (default: 30)
        http_version: Force HTTP version - "auto", "h1", "h2", "h3" (default: "auto")
        verify: SSL certificate verification (default: True)
        allow_redirects: Follow redirects (default: True)
        max_redirects: Maximum number of redirects to follow (default: 10)
        retry: Number of retries on failure (default: 3, set to 0 to disable)
        retry_on_status: List of status codes to retry on (default: None)
        prefer_ipv4: Prefer IPv4 addresses over IPv6 (default: False)

    Example:
        import httpcloak

        httpcloak.configure(
            preset="chrome-143-windows",
            headers={"Authorization": "Bearer token"},
            http_version="h2",  # Force HTTP/2
            retry=3,  # Retry failed requests 3 times
        )

        r = httpcloak.get("https://example.com")  # uses configured defaults
    """
    global _default_session, _default_config

    with _default_session_lock:
        # Close existing session if any
        if _default_session is not None:
            _default_session.close()
            _default_session = None

        # Apply auth to headers if provided
        final_headers = _apply_auth(headers, auth) or {}

        # Store config
        _default_config = {
            "preset": preset,
            "proxy": proxy,
            "timeout": timeout,
            "http_version": http_version,
            "verify": verify,
            "allow_redirects": allow_redirects,
            "max_redirects": max_redirects,
            "retry": retry,
            "retry_on_status": retry_on_status,
            "headers": final_headers,
            "prefer_ipv4": prefer_ipv4,
        }

        # Create new session with config
        _default_session = Session(
            preset=preset,
            proxy=proxy,
            timeout=timeout,
            http_version=http_version,
            verify=verify,
            allow_redirects=allow_redirects,
            max_redirects=max_redirects,
            retry=retry,
            retry_on_status=retry_on_status,
            prefer_ipv4=prefer_ipv4,
        )
        if final_headers:
            _default_session.headers.update(final_headers)


def _get_default_session() -> Session:
    """Get or create the default session."""
    global _default_session
    if _default_session is None:
        with _default_session_lock:
            if _default_session is None:
                preset = _default_config.get("preset", "chrome-143")
                proxy = _default_config.get("proxy")
                timeout = _default_config.get("timeout", 30)
                http_version = _default_config.get("http_version", "auto")
                verify = _default_config.get("verify", True)
                allow_redirects = _default_config.get("allow_redirects", True)
                max_redirects = _default_config.get("max_redirects", 10)
                retry = _default_config.get("retry", 0)
                retry_on_status = _default_config.get("retry_on_status")
                headers = _default_config.get("headers", {})
                prefer_ipv4 = _default_config.get("prefer_ipv4", False)

                _default_session = Session(
                    preset=preset,
                    proxy=proxy,
                    timeout=timeout,
                    http_version=http_version,
                    verify=verify,
                    allow_redirects=allow_redirects,
                    max_redirects=max_redirects,
                    retry=retry,
                    retry_on_status=retry_on_status,
                    prefer_ipv4=prefer_ipv4,
                )
                if headers:
                    _default_session.headers.update(headers)
    return _default_session


def _get_session_for_request(kwargs: dict) -> Tuple[Session, bool]:
    """
    Get session for a request, creating a temporary one if needed.

    Modifies kwargs in-place to remove session-level params.
    Returns (session, is_temporary) - caller must close temporary sessions.
    """
    # Check for session-level kwargs that require a temporary session
    verify = kwargs.pop("verify", None)
    allow_redirects = kwargs.pop("allow_redirects", None)

    # If no session-level overrides, use default session
    if verify is None and allow_redirects is None:
        return _get_default_session(), False

    # Get current defaults
    preset = _default_config.get("preset", "chrome-143")
    proxy = _default_config.get("proxy")
    timeout = _default_config.get("timeout", 30)
    http_version = _default_config.get("http_version", "auto")
    max_redirects = _default_config.get("max_redirects", 10)
    retry = _default_config.get("retry", 0)
    retry_on_status = _default_config.get("retry_on_status")
    prefer_ipv4 = _default_config.get("prefer_ipv4", False)

    # Apply overrides
    if verify is None:
        verify = _default_config.get("verify", True)
    if allow_redirects is None:
        allow_redirects = _default_config.get("allow_redirects", True)

    # Create temporary session with overrides
    temp_session = Session(
        preset=preset,
        proxy=proxy,
        timeout=timeout,
        http_version=http_version,
        verify=verify,
        allow_redirects=allow_redirects,
        max_redirects=max_redirects,
        retry=retry,
        retry_on_status=retry_on_status,
        prefer_ipv4=prefer_ipv4,
    )

    # Copy default headers
    default_headers = _default_config.get("headers", {})
    if default_headers:
        temp_session.headers.update(default_headers)

    return temp_session, True


def get(url: str, **kwargs) -> Response:
    """
    Perform a GET request.

    Args:
        url: Request URL
        params: URL query parameters
        headers: Request headers
        cookies: Cookies to send
        auth: Basic auth tuple (username, password)
        timeout: Request timeout in seconds
        verify: SSL verification (default: True)
        allow_redirects: Follow redirects (default: True)

    Example:
        r = httpcloak.get("https://example.com")
        print(r.text)

        # Disable SSL verification
        r = httpcloak.get("https://example.com", verify=False)

        # Disable redirects
        r = httpcloak.get("https://example.com", allow_redirects=False)
    """
    session, is_temp = _get_session_for_request(kwargs)
    try:
        return session.get(url, **kwargs)
    finally:
        if is_temp:
            session.close()


def post(url: str, data=None, json=None, files=None, **kwargs) -> Response:
    """
    Perform a POST request.

    Args:
        url: Request URL
        data: Request body (string, bytes, or dict for form data)
        json: JSON body (will be serialized)
        files: Files to upload
        verify: SSL verification (default: True)
        allow_redirects: Follow redirects (default: True)

    Example:
        r = httpcloak.post("https://api.example.com", json={"key": "value"})
        print(r.json())

        # With file upload
        r = httpcloak.post("https://api.example.com/upload", files={"file": open("image.png", "rb")})
    """
    session, is_temp = _get_session_for_request(kwargs)
    try:
        return session.post(url, data=data, json=json, files=files, **kwargs)
    finally:
        if is_temp:
            session.close()


def put(url: str, data=None, json=None, files=None, **kwargs) -> Response:
    """Perform a PUT request."""
    session, is_temp = _get_session_for_request(kwargs)
    try:
        return session.put(url, data=data, json=json, files=files, **kwargs)
    finally:
        if is_temp:
            session.close()


def delete(url: str, **kwargs) -> Response:
    """Perform a DELETE request."""
    session, is_temp = _get_session_for_request(kwargs)
    try:
        return session.delete(url, **kwargs)
    finally:
        if is_temp:
            session.close()


def patch(url: str, data=None, json=None, files=None, **kwargs) -> Response:
    """Perform a PATCH request."""
    session, is_temp = _get_session_for_request(kwargs)
    try:
        return session.patch(url, data=data, json=json, files=files, **kwargs)
    finally:
        if is_temp:
            session.close()


def head(url: str, **kwargs) -> Response:
    """Perform a HEAD request."""
    session, is_temp = _get_session_for_request(kwargs)
    try:
        return session.head(url, **kwargs)
    finally:
        if is_temp:
            session.close()


def options(url: str, **kwargs) -> Response:
    """Perform an OPTIONS request."""
    session, is_temp = _get_session_for_request(kwargs)
    try:
        return session.options(url, **kwargs)
    finally:
        if is_temp:
            session.close()


def request(method: str, url: str, **kwargs) -> Response:
    """Perform a custom HTTP request."""
    session, is_temp = _get_session_for_request(kwargs)
    try:
        return session.request(method, url, **kwargs)
    finally:
        if is_temp:
            session.close()
