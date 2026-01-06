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
import os
import platform
from ctypes import c_char_p, c_int64, cdll
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs


class HTTPCloakError(Exception):
    """Base exception for HTTPCloak errors."""
    pass


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
    """

    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: bytes,
        text: str,
        final_url: str,
        protocol: str,
    ):
        self.status_code = status_code
        self.headers = headers
        self.content = body  # requests compatibility
        self.text = text
        self.url = final_url  # requests compatibility
        self.protocol = protocol

        # Keep old names as aliases
        self.body = body
        self.final_url = final_url

    @property
    def ok(self) -> bool:
        """True if status_code < 400."""
        return self.status_code < 400

    def json(self, **kwargs) -> Any:
        """Parse response body as JSON."""
        return json.loads(self.text, **kwargs)

    def raise_for_status(self):
        """Raise HTTPCloakError if status_code >= 400."""
        if not self.ok:
            raise HTTPCloakError(f"HTTP {self.status_code}")

    @classmethod
    def _from_dict(cls, data: dict) -> "Response":
        body = data.get("body", "")
        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = body
        return cls(
            status_code=data.get("status_code", 0),
            headers=data.get("headers", {}),
            body=body_bytes,
            text=body if isinstance(body, str) else body.decode("utf-8", errors="replace"),
            final_url=data.get("final_url", ""),
            protocol=data.get("protocol", ""),
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


def _setup_lib(lib):
    """Setup function signatures for the library."""
    lib.httpcloak_session_new.argtypes = [c_char_p]
    lib.httpcloak_session_new.restype = c_int64
    lib.httpcloak_session_free.argtypes = [c_int64]
    lib.httpcloak_session_free.restype = None
    lib.httpcloak_get.argtypes = [c_int64, c_char_p, c_char_p]
    lib.httpcloak_get.restype = c_char_p
    lib.httpcloak_post.argtypes = [c_int64, c_char_p, c_char_p, c_char_p]
    lib.httpcloak_post.restype = c_char_p
    lib.httpcloak_request.argtypes = [c_int64, c_char_p]
    lib.httpcloak_request.restype = c_char_p
    lib.httpcloak_get_cookies.argtypes = [c_int64]
    lib.httpcloak_get_cookies.restype = c_char_p
    lib.httpcloak_set_cookie.argtypes = [c_int64, c_char_p, c_char_p]
    lib.httpcloak_set_cookie.restype = None
    lib.httpcloak_free_string.argtypes = [c_char_p]
    lib.httpcloak_free_string.restype = None
    lib.httpcloak_version.argtypes = []
    lib.httpcloak_version.restype = c_char_p
    lib.httpcloak_available_presets.argtypes = []
    lib.httpcloak_available_presets.restype = c_char_p


def _parse_response(result: bytes) -> Response:
    """Parse JSON response from library."""
    if result is None:
        raise HTTPCloakError("No response received")
    data = json.loads(result.decode("utf-8"))
    if "error" in data:
        raise HTTPCloakError(data["error"])
    return Response._from_dict(data)


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
    result = lib.httpcloak_version()
    return result.decode("utf-8") if result else "unknown"


def available_presets() -> List[str]:
    """Get list of available browser presets."""
    lib = _get_lib()
    result = lib.httpcloak_available_presets()
    if result:
        return json.loads(result.decode("utf-8"))
    return []


class Session:
    """
    HTTP Session with browser fingerprint emulation.

    Maintains cookies and connection state across requests.
    API is compatible with requests.Session.

    Args:
        preset: Browser preset (default: "chrome-143")
        proxy: Proxy URL (e.g., "http://user:pass@host:port")
        timeout: Default request timeout in seconds (default: 30)

    Example:
        with httpcloak.Session(preset="chrome-143") as session:
            r = session.get("https://example.com")
            print(r.json())
    """

    def __init__(
        self,
        preset: str = "chrome-143",
        proxy: Optional[str] = None,
        timeout: int = 30,
    ):
        self._lib = _get_lib()
        self._default_timeout = timeout
        self.headers: Dict[str, str] = {}  # Default headers

        config = {"preset": preset, "timeout": timeout}
        if proxy:
            config["proxy"] = proxy

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

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """
        Perform a GET request.

        Args:
            url: Request URL
            params: URL query parameters
            headers: Request headers
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in seconds
        """
        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)
        merged_headers = _apply_auth(merged_headers, auth)

        if timeout:
            return self.request("GET", url, headers=merged_headers, timeout=timeout)

        headers_json = json.dumps(merged_headers).encode("utf-8") if merged_headers else None
        result = self._lib.httpcloak_get(
            self._handle,
            url.encode("utf-8"),
            headers_json,
        )
        return _parse_response(result)

    def post(
        self,
        url: str,
        data: Union[str, bytes, Dict, None] = None,
        json: Optional[Dict] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """
        Perform a POST request.

        Args:
            url: Request URL
            data: Request body (string, bytes, or dict for form data)
            json: JSON body (will be serialized)
            params: URL query parameters
            headers: Request headers
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in seconds
        """
        import json as json_module

        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)

        body = None
        if json is not None:
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

        merged_headers = _apply_auth(merged_headers, auth)

        if timeout:
            return self.request("POST", url, headers=merged_headers, data=body, timeout=timeout)

        headers_json = json_module.dumps(merged_headers).encode("utf-8") if merged_headers else None
        result = self._lib.httpcloak_post(
            self._handle,
            url.encode("utf-8"),
            body,
            headers_json,
        )
        return _parse_response(result)

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Union[str, bytes, Dict, None] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None,
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
            headers: Request headers
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in seconds
        """
        import json as json_module

        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)

        body = None
        if json is not None:
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

        merged_headers = _apply_auth(merged_headers, auth)

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

        result = self._lib.httpcloak_request(
            self._handle,
            json_module.dumps(request_config).encode("utf-8"),
        )
        return _parse_response(result)

    def put(
        self,
        url: str,
        data: Union[str, bytes, Dict, None] = None,
        json: Optional[Dict] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """Perform a PUT request."""
        return self.request("PUT", url, params=params, data=data, json=json, headers=headers, auth=auth, timeout=timeout)

    def delete(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """Perform a DELETE request."""
        return self.request("DELETE", url, params=params, headers=headers, auth=auth, timeout=timeout)

    def patch(
        self,
        url: str,
        data: Union[str, bytes, Dict, None] = None,
        json: Optional[Dict] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """Perform a PATCH request."""
        return self.request("PATCH", url, params=params, data=data, json=json, headers=headers, auth=auth, timeout=timeout)

    def head(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """Perform a HEAD request."""
        return self.request("HEAD", url, params=params, headers=headers, auth=auth, timeout=timeout)

    def options(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> Response:
        """Perform an OPTIONS request."""
        return self.request("OPTIONS", url, params=params, headers=headers, auth=auth, timeout=timeout)

    # =========================================================================
    # Async Methods
    # =========================================================================

    async def get_async(self, url: str, **kwargs) -> Response:
        """Async GET request."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.get(url, **kwargs))

    async def post_async(self, url: str, **kwargs) -> Response:
        """Async POST request."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.post(url, **kwargs))

    async def request_async(self, method: str, url: str, **kwargs) -> Response:
        """Async custom request."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.request(method, url, **kwargs))

    # =========================================================================
    # Cookie Management
    # =========================================================================

    def get_cookies(self) -> Dict[str, str]:
        """Get all cookies from the session."""
        result = self._lib.httpcloak_get_cookies(self._handle)
        if result:
            return json.loads(result.decode("utf-8"))
        return {}

    def set_cookie(self, name: str, value: str):
        """Set a cookie in the session."""
        self._lib.httpcloak_set_cookie(
            self._handle,
            name.encode("utf-8"),
            value.encode("utf-8"),
        )

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

    Example:
        import httpcloak

        httpcloak.configure(
            preset="chrome-143-windows",
            headers={"Authorization": "Bearer token"},
            auth=("user", "pass"),
            proxy="http://proxy:8080",
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
            "headers": final_headers,
        }

        # Create new session with config
        _default_session = Session(preset=preset, proxy=proxy, timeout=timeout)
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
                headers = _default_config.get("headers", {})

                _default_session = Session(preset=preset, proxy=proxy, timeout=timeout)
                if headers:
                    _default_session.headers.update(headers)
    return _default_session


def get(url: str, **kwargs) -> Response:
    """
    Perform a GET request.

    Example:
        r = httpcloak.get("https://example.com")
        print(r.text)
    """
    return _get_default_session().get(url, **kwargs)


def post(url: str, data=None, json=None, **kwargs) -> Response:
    """
    Perform a POST request.

    Example:
        r = httpcloak.post("https://api.example.com", json={"key": "value"})
        print(r.json())
    """
    return _get_default_session().post(url, data=data, json=json, **kwargs)


def put(url: str, data=None, json=None, **kwargs) -> Response:
    """Perform a PUT request."""
    return _get_default_session().put(url, data=data, json=json, **kwargs)


def delete(url: str, **kwargs) -> Response:
    """Perform a DELETE request."""
    return _get_default_session().delete(url, **kwargs)


def patch(url: str, data=None, json=None, **kwargs) -> Response:
    """Perform a PATCH request."""
    return _get_default_session().patch(url, data=data, json=json, **kwargs)


def head(url: str, **kwargs) -> Response:
    """Perform a HEAD request."""
    return _get_default_session().head(url, **kwargs)


def options(url: str, **kwargs) -> Response:
    """Perform an OPTIONS request."""
    return _get_default_session().options(url, **kwargs)


def request(method: str, url: str, **kwargs) -> Response:
    """Perform a custom HTTP request."""
    return _get_default_session().request(method, url, **kwargs)
