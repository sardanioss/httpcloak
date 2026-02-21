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
from ctypes import c_char_p, c_int, c_int64, c_void_p, cdll, cast, CFUNCTYPE, POINTER
from io import IOBase
from pathlib import Path
from threading import Lock
from typing import Any, BinaryIO, Dict, List, Optional, Tuple, Union
from urllib.parse import urlencode, quote


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
        Desktop Chrome: CHROME_145, CHROME_145_WINDOWS, CHROME_145_LINUX, CHROME_145_MACOS
                        CHROME_144, CHROME_144_WINDOWS, CHROME_144_LINUX, CHROME_144_MACOS
                        CHROME_143, CHROME_143_WINDOWS, CHROME_143_LINUX, CHROME_143_MACOS
                        CHROME_141, CHROME_133
        Mobile Chrome: CHROME_145_IOS, CHROME_144_IOS, CHROME_143_IOS,
                       CHROME_145_ANDROID, CHROME_144_ANDROID, CHROME_143_ANDROID
        Firefox: FIREFOX_133
        Safari: SAFARI_18, SAFARI_17_IOS, SAFARI_18_IOS
    """
    # Chrome 145 (latest)
    CHROME_145 = "chrome-145"
    CHROME_145_WINDOWS = "chrome-145-windows"
    CHROME_145_LINUX = "chrome-145-linux"
    CHROME_145_MACOS = "chrome-145-macos"

    # Chrome 144
    CHROME_144 = "chrome-144"
    CHROME_144_WINDOWS = "chrome-144-windows"
    CHROME_144_LINUX = "chrome-144-linux"
    CHROME_144_MACOS = "chrome-144-macos"

    # Chrome 143
    CHROME_143 = "chrome-143"
    CHROME_143_WINDOWS = "chrome-143-windows"
    CHROME_143_LINUX = "chrome-143-linux"
    CHROME_143_MACOS = "chrome-143-macos"

    # Chrome 141
    CHROME_141 = "chrome-141"

    # Chrome 133
    CHROME_133 = "chrome-133"

    # Mobile Chrome
    CHROME_143_IOS = "chrome-143-ios"
    CHROME_144_IOS = "chrome-144-ios"
    CHROME_145_IOS = "chrome-145-ios"
    CHROME_143_ANDROID = "chrome-143-android"
    CHROME_144_ANDROID = "chrome-144-android"
    CHROME_145_ANDROID = "chrome-145-android"

    # Firefox
    FIREFOX_133 = "firefox-133"

    # Safari (desktop and mobile)
    SAFARI_18 = "safari-18"
    SAFARI_17_IOS = "safari-17-ios"
    SAFARI_18_IOS = "safari-18-ios"

    # Backwards compatibility aliases (old naming convention)
    IOS_CHROME_143 = CHROME_143_IOS
    IOS_CHROME_144 = CHROME_144_IOS
    IOS_CHROME_145 = CHROME_145_IOS
    ANDROID_CHROME_143 = CHROME_143_ANDROID
    ANDROID_CHROME_144 = CHROME_144_ANDROID
    ANDROID_CHROME_145 = CHROME_145_ANDROID
    IOS_SAFARI_17 = SAFARI_17_IOS
    IOS_SAFARI_18 = SAFARI_18_IOS

    @classmethod
    def all(cls) -> List[str]:
        """Return list of all available preset names."""
        return [
            cls.CHROME_145, cls.CHROME_145_WINDOWS, cls.CHROME_145_LINUX, cls.CHROME_145_MACOS,
            cls.CHROME_144, cls.CHROME_144_WINDOWS, cls.CHROME_144_LINUX, cls.CHROME_144_MACOS,
            cls.CHROME_143, cls.CHROME_143_WINDOWS, cls.CHROME_143_LINUX, cls.CHROME_143_MACOS,
            cls.CHROME_141, cls.CHROME_133,
            cls.CHROME_145_IOS, cls.CHROME_144_IOS, cls.CHROME_143_IOS,
            cls.CHROME_145_ANDROID, cls.CHROME_144_ANDROID, cls.CHROME_143_ANDROID,
            cls.FIREFOX_133,
            cls.SAFARI_18, cls.SAFARI_17_IOS, cls.SAFARI_18_IOS,
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
        domain: Cookie domain
        path: Cookie path
        expires: Expiration date (RFC1123 format)
        max_age: Max age in seconds (0 means not set)
        secure: Secure flag
        http_only: HttpOnly flag
        same_site: SameSite attribute (Strict, Lax, None)
    """

    def __init__(
        self,
        name: str,
        value: str,
        domain: str = "",
        path: str = "",
        expires: str = "",
        max_age: int = 0,
        secure: bool = False,
        http_only: bool = False,
        same_site: str = "",
    ):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.expires = expires
        self.max_age = max_age
        self.secure = secure
        self.http_only = http_only
        self.same_site = same_site

    def __repr__(self):
        parts = [f"name={self.name!r}", f"value={self.value!r}"]
        if self.domain:
            parts.append(f"domain={self.domain!r}")
        if self.path:
            parts.append(f"path={self.path!r}")
        if self.secure:
            parts.append("secure=True")
        if self.http_only:
            parts.append("http_only=True")
        if self.same_site:
            parts.append(f"same_site={self.same_site!r}")
        return f"Cookie({', '.join(parts)})"


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
    def _from_dict(cls, data: dict, elapsed: float = 0.0, raw_body: Optional[bytes] = None) -> "Response":
        # Use raw_body if provided (optimized path), otherwise parse from dict
        if raw_body is not None:
            body_bytes = raw_body
            body = raw_body.decode("utf-8", errors="replace")
        else:
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
                    domain=cookie_data.get("domain", ""),
                    path=cookie_data.get("path", ""),
                    expires=cookie_data.get("expires", ""),
                    max_age=cookie_data.get("max_age", 0),
                    secure=cookie_data.get("secure", False),
                    http_only=cookie_data.get("http_only", False),
                    same_site=cookie_data.get("same_site", ""),
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


class FastResponse:
    """
    High-performance HTTP Response using zero-copy memoryview.

    WARNING: The content memoryview is only valid until the next fast request
    on the same session. Copy the data if you need to keep it longer.

    This provides ~5000-6500 MB/s download speeds compared to ~1100 MB/s
    for regular Response by avoiding memory copies.

    Attributes:
        status_code: HTTP status code
        headers: Response headers
        content: Response body as memoryview (zero-copy, read-only)
        content_bytes: Response body copied to bytes (creates a copy)
        body: Alias for content_bytes (creates a copy)
        url: Final URL after redirects
        ok: True if status_code < 400
        protocol: Protocol used (http/1.1, h2, h3)
        elapsed: Time elapsed for the request (seconds as float)
        reason: HTTP status reason phrase
        encoding: Response encoding (from Content-Type header)
        cookies: List of cookies set by this response
        history: List of redirect responses (RedirectInfo objects)

    Example:
        # Fast path - process data immediately
        resp = session.get_fast("https://example.com/large-file")
        process_data(resp.content)  # memoryview, valid until next get_fast()

        # If you need to keep the data
        data = resp.content_bytes  # creates a copy
    """

    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        content_view: memoryview,
        final_url: str,
        protocol: str,
        elapsed: float = 0.0,
        cookies: Optional[List[Cookie]] = None,
        history: Optional[List[RedirectInfo]] = None,
    ):
        self.status_code = status_code
        self.headers = headers
        self.content = content_view  # memoryview - zero copy
        self.url = final_url
        self.final_url = final_url  # Alias
        self.protocol = protocol
        self.elapsed = elapsed
        self.cookies = cookies or []
        self.history = history or []

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
            for part in content_type.split(";"):
                part = part.strip()
                if part.lower().startswith("charset="):
                    return part.split("=", 1)[1].strip().strip('"\'')
        return None

    @property
    def content_bytes(self) -> bytes:
        """Get content as bytes (creates a copy)."""
        return bytes(self.content)

    @property
    def body(self) -> bytes:
        """Alias for content_bytes (creates a copy)."""
        return bytes(self.content)

    @property
    def text(self) -> str:
        """Get content as string (creates a copy)."""
        return bytes(self.content).decode("utf-8", errors="replace")

    def json(self, **kwargs) -> Any:
        """Parse response body as JSON (creates a copy)."""
        return json.loads(self.text, **kwargs)

    def raise_for_status(self):
        """Raise HTTPCloakError if status_code >= 400."""
        if not self.ok:
            raise HTTPCloakError(f"HTTP {self.status_code}: {self.reason}")


class _FastBufferPool:
    """
    Pre-allocated buffer pool for zero-copy fast responses.
    Uses tiered buffers to minimize memory waste.
    """

    # Buffer size tiers (1MB, 10MB, 100MB, 500MB)
    TIERS = [1 * 1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024, 500 * 1024 * 1024]

    def __init__(self):
        self._buffers: Dict[int, bytearray] = {}
        self._ctypes_ptrs: Dict[int, Any] = {}
        self._lock = Lock()

    def get_buffer(self, size: int) -> Tuple[bytearray, Any, int]:
        """
        Get a buffer that can hold at least `size` bytes.
        Returns (buffer, ctypes_ptr, buffer_size).
        """
        import ctypes

        # Find appropriate tier
        tier_size = self.TIERS[-1]  # Default to largest
        for tier in self.TIERS:
            if size <= tier:
                tier_size = tier
                break

        with self._lock:
            # Create buffer for this tier if needed
            if tier_size not in self._buffers:
                buf = bytearray(tier_size)
                self._buffers[tier_size] = buf
                self._ctypes_ptrs[tier_size] = (ctypes.c_char * tier_size).from_buffer(buf)

            return self._buffers[tier_size], self._ctypes_ptrs[tier_size], tier_size


# Global fast buffer pool (one per process)
_fast_buffer_pool = _FastBufferPool()


class StreamResponse:
    """
    Streaming HTTP Response for downloading large files.

    Use as a context manager:
        with session.get(url, stream=True) as r:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    Or iterate directly:
        r = session.get(url, stream=True)
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)
        r.close()

    Attributes:
        status_code: HTTP status code
        headers: Response headers
        url: Final URL after redirects
        ok: True if status_code < 400
        protocol: Protocol used (h1, h2, h3)
        content_length: Expected size or -1 if unknown (chunked)
        cookies: List of cookies set by this response
    """

    def __init__(
        self,
        stream_handle: int,
        lib,
        status_code: int,
        headers: Dict[str, str],
        final_url: str,
        protocol: str,
        content_length: int,
        cookies: Optional[List[Cookie]] = None,
    ):
        self._handle = stream_handle
        self._lib = lib
        self.status_code = status_code
        self.headers = headers
        self.url = final_url
        self.final_url = final_url  # Alias
        self.protocol = protocol
        self.content_length = content_length
        self.cookies = cookies or []
        self._closed = False

    @property
    def ok(self) -> bool:
        """True if status_code < 400."""
        return self.status_code < 400

    @property
    def reason(self) -> str:
        """HTTP status reason phrase."""
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
            for part in content_type.split(";"):
                part = part.strip()
                if part.lower().startswith("charset="):
                    return part.split("=", 1)[1].strip().strip('"\'')
        return None

    def iter_content(self, chunk_size: int = 8192):
        """
        Iterate over response content in chunks.

        Args:
            chunk_size: Size of each chunk in bytes (default: 8192)

        Yields:
            bytes: Chunks of response content

        Example:
            with session.get(url, stream=True) as r:
                for chunk in r.iter_content(chunk_size=8192):
                    file.write(chunk)
        """
        if self._closed:
            raise HTTPCloakError("Stream is closed")

        while True:
            result_ptr = self._lib.httpcloak_stream_read(self._handle, chunk_size)
            if result_ptr is None or result_ptr == 0:
                # Error or end of stream
                break

            # Get base64 encoded chunk
            result = cast(result_ptr, c_char_p).value
            self._lib.httpcloak_free_string(result_ptr)

            if result is None or result == b"":
                # EOF
                break

            # Decode base64 to bytes
            chunk = base64.b64decode(result)
            if not chunk:
                break

            yield chunk

    def iter_lines(self, chunk_size: int = 8192, decode_unicode: bool = True):
        """
        Iterate over response content line by line.

        Args:
            chunk_size: Size of chunks to read at a time
            decode_unicode: If True, yield strings; otherwise yield bytes

        Yields:
            str or bytes: Lines from response content
        """
        pending = b""
        for chunk in self.iter_content(chunk_size=chunk_size):
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if decode_unicode:
                    yield line.decode("utf-8", errors="replace")
                else:
                    yield line

        # Yield any remaining content
        if pending:
            if decode_unicode:
                yield pending.decode("utf-8", errors="replace")
            else:
                yield pending

    @property
    def content(self) -> bytes:
        """
        Read entire response content into memory.

        Warning: This defeats the purpose of streaming for large files.
        """
        chunks = []
        for chunk in self.iter_content():
            chunks.append(chunk)
        return b"".join(chunks)

    @property
    def text(self) -> str:
        """Read entire response as text."""
        return self.content.decode("utf-8", errors="replace")

    def json(self, **kwargs) -> Any:
        """Parse response body as JSON."""
        return json.loads(self.text, **kwargs)

    def close(self):
        """Close the stream and release resources."""
        if not self._closed:
            self._lib.httpcloak_stream_close(self._handle)
            self._closed = True

    def raise_for_status(self):
        """Raise HTTPCloakError if status_code >= 400."""
        if not self.ok:
            raise HTTPCloakError(f"HTTP {self.status_code}: {self.reason}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures stream is closed."""
        self.close()
        return False

    def __iter__(self):
        """Iterate over response content."""
        return self.iter_content()

    def __repr__(self):
        return f"<StreamResponse [{self.status_code}]>"


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

# Session cache callback types
# get: char* (*)(const char* key) - returns JSON string or NULL
SESSION_CACHE_GET_CALLBACK = CFUNCTYPE(c_char_p, c_char_p)
# put: int (*)(const char* key, const char* value_json, int64_t ttl_seconds)
SESSION_CACHE_PUT_CALLBACK = CFUNCTYPE(c_int, c_char_p, c_char_p, c_int64)
# delete: int (*)(const char* key)
SESSION_CACHE_DELETE_CALLBACK = CFUNCTYPE(c_int, c_char_p)
# error: void (*)(const char* operation, const char* key, const char* error)
SESSION_CACHE_ERROR_CALLBACK = CFUNCTYPE(None, c_char_p, c_char_p, c_char_p)
# ech_get: char* (*)(const char* key) - returns base64 string or NULL
ECH_CACHE_GET_CALLBACK = CFUNCTYPE(c_char_p, c_char_p)
# ech_put: int (*)(const char* key, const char* value_base64, int64_t ttl_seconds)
ECH_CACHE_PUT_CALLBACK = CFUNCTYPE(c_int, c_char_p, c_char_p, c_int64)


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
    lib.httpcloak_session_refresh.argtypes = [c_int64]
    lib.httpcloak_session_refresh.restype = None
    lib.httpcloak_session_refresh_protocol.argtypes = [c_int64, c_char_p]
    lib.httpcloak_session_refresh_protocol.restype = c_void_p
    lib.httpcloak_session_warmup.argtypes = [c_int64, c_char_p, c_int64]
    lib.httpcloak_session_warmup.restype = c_void_p
    lib.httpcloak_session_fork.argtypes = [c_int64]
    lib.httpcloak_session_fork.restype = c_int64
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
    lib.httpcloak_set_ech_dns_servers.argtypes = [c_char_p]
    lib.httpcloak_set_ech_dns_servers.restype = c_void_p
    lib.httpcloak_get_ech_dns_servers.argtypes = []
    lib.httpcloak_get_ech_dns_servers.restype = c_void_p

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

    # Streaming functions
    lib.httpcloak_stream_get.argtypes = [c_int64, c_char_p, c_char_p]
    lib.httpcloak_stream_get.restype = c_int64
    lib.httpcloak_stream_post.argtypes = [c_int64, c_char_p, c_char_p, c_char_p]
    lib.httpcloak_stream_post.restype = c_int64
    lib.httpcloak_stream_request.argtypes = [c_int64, c_char_p]
    lib.httpcloak_stream_request.restype = c_int64
    lib.httpcloak_stream_get_metadata.argtypes = [c_int64]
    lib.httpcloak_stream_get_metadata.restype = c_void_p
    lib.httpcloak_stream_read.argtypes = [c_int64, c_int64]
    lib.httpcloak_stream_read.restype = c_void_p
    lib.httpcloak_stream_close.argtypes = [c_int64]
    lib.httpcloak_stream_close.restype = None

    # Upload streaming functions
    lib.httpcloak_upload_start.argtypes = [c_int64, c_char_p, c_char_p]
    lib.httpcloak_upload_start.restype = c_int64
    lib.httpcloak_upload_write.argtypes = [c_int64, c_char_p]
    lib.httpcloak_upload_write.restype = c_int
    lib.httpcloak_upload_write_raw.argtypes = [c_int64, c_void_p, c_int]
    lib.httpcloak_upload_write_raw.restype = c_int
    lib.httpcloak_upload_finish.argtypes = [c_int64]
    lib.httpcloak_upload_finish.restype = c_void_p
    lib.httpcloak_upload_cancel.argtypes = [c_int64]
    lib.httpcloak_upload_cancel.restype = None

    # Session persistence functions
    lib.httpcloak_session_save.argtypes = [c_int64, c_char_p]
    lib.httpcloak_session_save.restype = c_void_p
    lib.httpcloak_session_load.argtypes = [c_char_p]
    lib.httpcloak_session_load.restype = c_int64
    lib.httpcloak_session_marshal.argtypes = [c_int64]
    lib.httpcloak_session_marshal.restype = c_void_p
    lib.httpcloak_session_unmarshal.argtypes = [c_char_p]
    lib.httpcloak_session_unmarshal.restype = c_int64

    # Proxy management functions
    lib.httpcloak_session_set_proxy.argtypes = [c_int64, c_char_p]
    lib.httpcloak_session_set_proxy.restype = c_void_p
    lib.httpcloak_session_set_tcp_proxy.argtypes = [c_int64, c_char_p]
    lib.httpcloak_session_set_tcp_proxy.restype = c_void_p
    lib.httpcloak_session_set_udp_proxy.argtypes = [c_int64, c_char_p]
    lib.httpcloak_session_set_udp_proxy.restype = c_void_p
    lib.httpcloak_session_get_proxy.argtypes = [c_int64]
    lib.httpcloak_session_get_proxy.restype = c_void_p
    lib.httpcloak_session_get_tcp_proxy.argtypes = [c_int64]
    lib.httpcloak_session_get_tcp_proxy.restype = c_void_p
    lib.httpcloak_session_get_udp_proxy.argtypes = [c_int64]
    lib.httpcloak_session_get_udp_proxy.restype = c_void_p
    lib.httpcloak_session_set_header_order.argtypes = [c_int64, c_char_p]
    lib.httpcloak_session_set_header_order.restype = c_void_p
    lib.httpcloak_session_get_header_order.argtypes = [c_int64]
    lib.httpcloak_session_get_header_order.restype = c_void_p
    lib.httpcloak_session_set_identifier.argtypes = [c_int64, c_char_p]
    lib.httpcloak_session_set_identifier.restype = None

    # Optimized raw response functions (body passed separately from JSON)
    lib.httpcloak_get_raw.argtypes = [c_int64, c_char_p, c_char_p]
    lib.httpcloak_get_raw.restype = c_int64
    lib.httpcloak_post_raw.argtypes = [c_int64, c_char_p, c_char_p, c_int, c_char_p]
    lib.httpcloak_post_raw.restype = c_int64
    lib.httpcloak_request_raw.argtypes = [c_int64, c_char_p, c_char_p, c_int]
    lib.httpcloak_request_raw.restype = c_int64
    lib.httpcloak_response_get_metadata.argtypes = [c_int64]
    lib.httpcloak_response_get_metadata.restype = c_void_p
    lib.httpcloak_response_get_body.argtypes = [c_int64, POINTER(c_int)]
    lib.httpcloak_response_get_body.restype = c_void_p
    lib.httpcloak_response_get_body_len.argtypes = [c_int64]
    lib.httpcloak_response_get_body_len.restype = c_int
    lib.httpcloak_response_copy_body_to.argtypes = [c_int64, c_void_p, c_int]
    lib.httpcloak_response_copy_body_to.restype = c_int
    lib.httpcloak_response_free.argtypes = [c_int64]
    lib.httpcloak_response_free.restype = None

    # Local proxy functions
    lib.httpcloak_local_proxy_start.argtypes = [c_char_p]
    lib.httpcloak_local_proxy_start.restype = c_int64
    lib.httpcloak_local_proxy_stop.argtypes = [c_int64]
    lib.httpcloak_local_proxy_stop.restype = None
    lib.httpcloak_local_proxy_get_port.argtypes = [c_int64]
    lib.httpcloak_local_proxy_get_port.restype = c_int
    lib.httpcloak_local_proxy_is_running.argtypes = [c_int64]
    lib.httpcloak_local_proxy_is_running.restype = c_int
    lib.httpcloak_local_proxy_get_stats.argtypes = [c_int64]
    lib.httpcloak_local_proxy_get_stats.restype = c_void_p
    lib.httpcloak_local_proxy_register_session.argtypes = [c_int64, c_char_p, c_int64]
    lib.httpcloak_local_proxy_register_session.restype = c_void_p
    lib.httpcloak_local_proxy_unregister_session.argtypes = [c_int64, c_char_p]
    lib.httpcloak_local_proxy_unregister_session.restype = c_int

    # Session cache callbacks
    lib.httpcloak_set_session_cache_callbacks.argtypes = [
        SESSION_CACHE_GET_CALLBACK,
        SESSION_CACHE_PUT_CALLBACK,
        SESSION_CACHE_DELETE_CALLBACK,
        ECH_CACHE_GET_CALLBACK,
        ECH_CACHE_PUT_CALLBACK,
        SESSION_CACHE_ERROR_CALLBACK,
    ]
    lib.httpcloak_set_session_cache_callbacks.restype = None
    lib.httpcloak_clear_session_cache_callbacks.argtypes = []
    lib.httpcloak_clear_session_cache_callbacks.restype = None


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


def _parse_raw_response(lib, response_handle: int, elapsed: float = 0.0) -> Response:
    """Parse raw response with body passed separately (optimized for large responses)."""
    import ctypes

    try:
        # Get metadata (JSON without body)
        meta_ptr = lib.httpcloak_response_get_metadata(response_handle)
        if meta_ptr is None or meta_ptr == 0:
            raise HTTPCloakError("Failed to get response metadata")

        meta_str = cast(meta_ptr, c_char_p).value
        lib.httpcloak_free_string(meta_ptr)

        if meta_str is None:
            raise HTTPCloakError("Empty response metadata")

        data = json.loads(meta_str.decode("utf-8"))
        if "error" in data:
            raise HTTPCloakError(data["error"])

        # Get body length first
        body_len = lib.httpcloak_response_get_body_len(response_handle)

        body = b""
        if body_len > 0:
            # Use bytearray for faster allocation than ctypes.create_string_buffer
            # Then copy directly from Go to Python memory
            buf = bytearray(body_len)
            buf_ptr = (ctypes.c_char * body_len).from_buffer(buf)
            copied = lib.httpcloak_response_copy_body_to(
                response_handle,
                ctypes.cast(buf_ptr, c_void_p),
                body_len
            )
            if copied > 0:
                # Convert to bytes for API compatibility
                # For maximum performance, users can access _content_bytearray directly
                body = bytes(buf[:copied])

        # Build response with raw body
        return Response._from_dict(data, elapsed=elapsed, raw_body=body)

    finally:
        # Always free the response handle
        lib.httpcloak_response_free(response_handle)


def _parse_fast_response(lib, response_handle: int, elapsed: float = 0.0) -> FastResponse:
    """
    Parse response using zero-copy fast path with pre-allocated buffers.
    Returns FastResponse with memoryview content.
    """
    import ctypes

    try:
        # Get metadata (JSON without body)
        meta_ptr = lib.httpcloak_response_get_metadata(response_handle)
        if meta_ptr is None or meta_ptr == 0:
            raise HTTPCloakError("Failed to get response metadata")

        meta_str = cast(meta_ptr, c_char_p).value
        lib.httpcloak_free_string(meta_ptr)

        if meta_str is None:
            raise HTTPCloakError("Empty response metadata")

        data = json.loads(meta_str.decode("utf-8"))
        if "error" in data:
            raise HTTPCloakError(data["error"])

        # Parse cookies from response
        cookies = []
        for cookie_data in data.get("cookies") or []:
            if isinstance(cookie_data, dict):
                cookies.append(Cookie(
                    name=cookie_data.get("name", ""),
                    value=cookie_data.get("value", ""),
                    domain=cookie_data.get("domain", ""),
                    path=cookie_data.get("path", ""),
                    expires=cookie_data.get("expires", ""),
                    max_age=cookie_data.get("max_age", 0),
                    secure=cookie_data.get("secure", False),
                    http_only=cookie_data.get("http_only", False),
                    same_site=cookie_data.get("same_site", ""),
                ))

        # Parse redirect history
        history = []
        for redirect_data in data.get("history") or []:
            if isinstance(redirect_data, dict):
                history.append(RedirectInfo(
                    status_code=redirect_data.get("status_code", 0),
                    url=redirect_data.get("url", ""),
                    headers=redirect_data.get("headers") or {},
                ))

        # Get body length
        body_len = lib.httpcloak_response_get_body_len(response_handle)

        if body_len > 0:
            # Get pre-allocated buffer from pool (no allocation!)
            buf, buf_ptr, buf_size = _fast_buffer_pool.get_buffer(body_len)

            # Copy directly from Go to pre-allocated Python buffer
            copied = lib.httpcloak_response_copy_body_to(
                response_handle,
                ctypes.cast(buf_ptr, c_void_p),
                body_len
            )

            # Create memoryview of just the copied data (no copy!)
            content_view = memoryview(buf)[:copied]
        else:
            content_view = memoryview(b"")

        return FastResponse(
            status_code=data.get("status_code", 0),
            headers=data.get("headers") or {},
            content_view=content_view,
            final_url=data.get("final_url", ""),
            protocol=data.get("protocol", ""),
            elapsed=elapsed,
            cookies=cookies,
            history=history,
        )

    finally:
        # Always free the response handle
        lib.httpcloak_response_free(response_handle)


def _add_params_to_url(url: str, params: Optional[Dict[str, Any]]) -> str:
    """Add query parameters to URL, preserving insertion order and encoding."""
    if not params:
        return url
    sep = '&' if '?' in url else '?'
    parts = []
    for k, v in params.items():
        parts.append(f"{quote(str(k), safe='')}={quote(str(v), safe='')}")
    return url + sep + '&'.join(parts)


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


def available_presets() -> dict:
    """Get available browser presets with their supported protocols.

    Returns a dict mapping preset names to their info:
        {
            "chrome-145": {"protocols": ["h1", "h2", "h3"]},
            "firefox-133": {"protocols": ["h1", "h2"]},
            ...
        }
    """
    lib = _get_lib()
    result_ptr = lib.httpcloak_available_presets()
    result = _ptr_to_string(result_ptr)
    if result:
        return json.loads(result)
    return {}


def set_ech_dns_servers(servers: Optional[List[str]] = None) -> None:
    """
    Configure the DNS servers used for ECH (Encrypted Client Hello) config queries.

    By default, ECH queries use Google (8.8.8.8), Cloudflare (1.1.1.1), and Quad9 (9.9.9.9).
    Use this function to configure custom DNS servers for environments with restricted
    network access or for privacy requirements.

    This is a global setting that affects all sessions.

    Args:
        servers: List of DNS server addresses in "host:port" format (e.g., ["10.0.0.53:53"]).
                 Pass None or empty list to reset to defaults.

    Example:
        >>> import httpcloak
        >>> httpcloak.set_ech_dns_servers(["10.0.0.53:53", "192.168.1.1:53"])
        >>> httpcloak.set_ech_dns_servers(None)  # Reset to defaults
    """
    lib = _get_lib()
    if servers is None or len(servers) == 0:
        lib.httpcloak_set_ech_dns_servers(None)
    else:
        servers_json = json.dumps(servers).encode("utf-8")
        error_ptr = lib.httpcloak_set_ech_dns_servers(servers_json)
        if error_ptr:
            error = _ptr_to_string(error_ptr)
            if error:
                raise HTTPCloakError(f"Failed to set ECH DNS servers: {error}")


def get_ech_dns_servers() -> List[str]:
    """
    Get the current DNS servers used for ECH (Encrypted Client Hello) config queries.

    Returns:
        List of DNS server addresses in "host:port" format.

    Example:
        >>> import httpcloak
        >>> servers = httpcloak.get_ech_dns_servers()
        >>> print(servers)
        ['8.8.8.8:53', '1.1.1.1:53', '9.9.9.9:53']
    """
    lib = _get_lib()
    result_ptr = lib.httpcloak_get_ech_dns_servers()
    result = _ptr_to_string(result_ptr)
    if result:
        return json.loads(result)
    return []


def _is_iterator(obj) -> bool:
    """Check if an object is an iterator/generator (but not bytes/str)."""
    if isinstance(obj, (bytes, str, dict)):
        return False
    try:
        iter(obj)
        return True
    except TypeError:
        return False


class Session:
    """
    HTTP Session with browser fingerprint emulation.

    Maintains cookies and connection state across requests.
    API is compatible with requests.Session.

    Args:
        preset: Browser preset (default: "chrome-145")
        proxy: Proxy URL (e.g., "http://user:pass@host:port" or "socks5://host:port")
        tcp_proxy: Proxy URL for TCP protocols (HTTP/1.1, HTTP/2) - use with udp_proxy for split config
        udp_proxy: Proxy URL for UDP protocols (HTTP/3 via MASQUE) - use with tcp_proxy for split config
        timeout: Default request timeout in seconds (default: 30)
        http_version: Force HTTP version - "auto", "h1", "h2", "h3" (default: "auto")
        verify: SSL certificate verification (default: True)
        allow_redirects: Follow redirects (default: True)
        max_redirects: Maximum number of redirects to follow (default: 10)
        retry: Number of retries on failure (default: 3, set to 0 to disable)
        retry_on_status: List of status codes to retry on (default: [429, 500, 502, 503, 504])
        retry_wait_min: Minimum wait time between retries in milliseconds (default: 500)
        retry_wait_max: Maximum wait time between retries in milliseconds (default: 10000)
        prefer_ipv4: Prefer IPv4 addresses over IPv6 (default: False)
        connect_to: Domain fronting map {request_host: connect_host} - DNS resolves connect_host but SNI/Host uses request_host
        ech_config_domain: Domain to fetch ECH config from (e.g., "cloudflare-ech.com" for any CF domain)
        tls_only: TLS-only mode - skip preset HTTP headers, only apply TLS fingerprint (default: False)
        quic_idle_timeout: QUIC connection idle timeout in seconds (default: 30). Set higher for long-lived H3 connections.
        local_address: Local IP address to bind outgoing connections to (e.g., "192.168.1.100" or "::1")
        key_log_file: Path to write TLS key log (NSS format) for Wireshark decryption
        enable_speculative_tls: Enable speculative TLS optimization for proxy connections (default: False).
            When True, CONNECT and TLS ClientHello are sent together saving one round-trip.
            May cause issues with certain proxies or debugging tools.

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

        # Split proxy configuration (e.g., Bright Data MASQUE for H3, HTTP proxy for H1/H2)
        with httpcloak.Session(
            preset="chrome-143",
            tcp_proxy="http://user:pass@datacenter-proxy:8080",
            udp_proxy="masque://user:pass@brd.superproxy.io:443"
        ) as session:
            r = session.get("https://example.com")
    """

    def __init__(
        self,
        preset: str = "chrome-145",
        proxy: Optional[str] = None,
        tcp_proxy: Optional[str] = None,
        udp_proxy: Optional[str] = None,
        timeout: int = 30,
        http_version: str = "auto",
        verify: bool = True,
        allow_redirects: bool = True,
        max_redirects: int = 10,
        retry: int = 3,
        retry_on_status: Optional[List[int]] = None,
        retry_wait_min: int = 500,
        retry_wait_max: int = 10000,
        prefer_ipv4: bool = False,
        auth: Optional[Tuple[str, str]] = None,
        connect_to: Optional[Dict[str, str]] = None,
        ech_config_domain: Optional[str] = None,
        tls_only: bool = False,
        quic_idle_timeout: int = 0,
        local_address: Optional[str] = None,
        key_log_file: Optional[str] = None,
        enable_speculative_tls: bool = False,
        switch_protocol: Optional[str] = None,
    ):
        self._lib = _get_lib()
        self._default_timeout = timeout
        self.headers: Dict[str, str] = {}  # Default headers
        self.auth: Optional[Tuple[str, str]] = auth  # Default auth for all requests

        config = {"preset": preset, "timeout": timeout, "http_version": http_version}
        if proxy:
            config["proxy"] = proxy
        if tcp_proxy:
            config["tcp_proxy"] = tcp_proxy
        if udp_proxy:
            config["udp_proxy"] = udp_proxy
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
        if retry_wait_min != 500:
            config["retry_wait_min"] = retry_wait_min
        if retry_wait_max != 10000:
            config["retry_wait_max"] = retry_wait_max
        if prefer_ipv4:
            config["prefer_ipv4"] = True
        if connect_to:
            config["connect_to"] = connect_to
        if ech_config_domain:
            config["ech_config_domain"] = ech_config_domain
        if tls_only:
            config["tls_only"] = True
        if quic_idle_timeout > 0:
            config["quic_idle_timeout"] = quic_idle_timeout
        if local_address:
            config["local_address"] = local_address
        if key_log_file:
            config["key_log_file"] = key_log_file
        if enable_speculative_tls:
            config["enable_speculative_tls"] = True
        if switch_protocol:
            config["switch_protocol"] = switch_protocol

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

    def refresh(self, switch_protocol: Optional[str] = None):
        """Refresh the session by closing all connections while keeping TLS session tickets.

        This simulates a browser page refresh - connections are severed but 0-RTT
        early data can be used on reconnection due to preserved session tickets.

        Args:
            switch_protocol: Optional protocol to switch to ("h1", "h2", "h3").
                Overrides any switch_protocol set at construction time.
                The change persists for future refresh() calls.
        """
        if hasattr(self, "_handle") and self._handle:
            if switch_protocol:
                result_ptr = self._lib.httpcloak_session_refresh_protocol(
                    self._handle, switch_protocol.encode("utf-8")
                )
                if result_ptr is not None and result_ptr != 0:
                    result = _ptr_to_string(result_ptr)
                    if result:
                        data = json.loads(result)
                        if "error" in data:
                            raise HTTPCloakError(data["error"])
            else:
                self._lib.httpcloak_session_refresh(self._handle)

    def warmup(self, url: str, timeout: Optional[int] = None):
        """Simulate a real browser page load to warm TLS sessions, cookies, and cache.

        Fetches the HTML page and its subresources (CSS, JS, images) with
        realistic headers, priorities, and timing. After warmup, subsequent
        requests look like follow-up navigation from a real user.

        Args:
            url: The page URL to warm up (e.g., "https://example.com").
            timeout: Timeout in milliseconds. Defaults to 60000 (60s).

        Raises:
            HTTPCloakError: If the navigation request fails.
        """
        if hasattr(self, "_handle") and self._handle:
            timeout_ms = timeout if timeout else 0
            result_ptr = self._lib.httpcloak_session_warmup(
                self._handle, url.encode("utf-8"), timeout_ms
            )
            if result_ptr is not None and result_ptr != 0:
                result = _ptr_to_string(result_ptr)
                if result:
                    data = json.loads(result)
                    if "error" in data:
                        raise HTTPCloakError(data["error"])

    def fork(self, n: int = 1) -> List["Session"]:
        """Create n forked sessions sharing cookies and TLS session caches.

        Forked sessions simulate multiple browser tabs from the same browser:
        same cookies, same TLS resumption tickets, same fingerprint, but
        independent connections for parallel requests.

        Args:
            n: Number of sessions to create.

        Returns:
            List of new Session objects.
        """
        lib = self._lib
        forks = []
        for _ in range(n):
            handle = lib.httpcloak_session_fork(self._handle)
            if handle < 0:
                raise HTTPCloakError("Failed to fork session")
            session = object.__new__(type(self))
            session._lib = lib
            session._handle = handle
            session._default_timeout = self._default_timeout
            session.headers = dict(self.headers) if self.headers else {}
            session.auth = self.auth
            forks.append(session)
        return forks

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

    def _streaming_upload(
        self,
        method: str,
        url: str,
        data_iter,
        headers: Optional[Dict[str, str]] = None,
        content_type: str = "application/octet-stream",
        timeout: Optional[int] = None,
    ) -> Response:
        """
        Perform a streaming upload using an iterator/generator.

        Args:
            method: HTTP method (POST, PUT, etc.)
            url: Request URL
            data_iter: Iterator/generator yielding bytes chunks
            headers: Request headers
            content_type: Content-Type header value
            timeout: Request timeout in milliseconds

        Returns:
            Response object
        """
        import json as json_module

        # Build options
        options = {
            "method": method,
            "headers": headers or {},
            "content_type": content_type,
        }
        if timeout:
            options["timeout"] = timeout

        options_json = json_module.dumps(options).encode("utf-8")

        # Start the upload
        upload_handle = self._lib.httpcloak_upload_start(
            self._handle,
            url.encode("utf-8"),
            options_json,
        )

        if upload_handle <= 0:
            raise HTTPCloakError("Failed to start streaming upload")

        try:
            start_time = time.perf_counter()

            # Write chunks from iterator using raw binary transfer
            for chunk in data_iter:
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                # Use raw binary write (no base64 encoding)
                chunk_ptr = cast(c_char_p(chunk), c_void_p)
                written = self._lib.httpcloak_upload_write_raw(upload_handle, chunk_ptr, len(chunk))
                if written < 0:
                    raise HTTPCloakError("Failed to write upload chunk")

            # Finish the upload and get response
            result_ptr = self._lib.httpcloak_upload_finish(upload_handle)
            elapsed = time.perf_counter() - start_time

            if result_ptr is None or result_ptr == 0:
                raise HTTPCloakError("Failed to finish streaming upload")

            # Get the string value and free the pointer
            result_bytes = cast(result_ptr, c_char_p).value
            self._lib.httpcloak_free_string(result_ptr)

            if result_bytes is None:
                raise HTTPCloakError("Empty response from streaming upload")

            # Parse the JSON response directly (don't call _parse_response which expects a pointer)
            data = json_module.loads(result_bytes.decode("utf-8"))
            if "error" in data:
                raise HTTPCloakError(data["error"])
            return Response._from_dict(data, elapsed=elapsed)

        except Exception:
            # Cancel upload on error
            self._lib.httpcloak_upload_cancel(upload_handle)
            raise

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

        # Check if data is an iterator/generator for streaming upload
        if data is not None and _is_iterator(data):
            # Use streaming upload for iterators
            effective_auth = auth if auth is not None else self.auth
            merged_headers = _apply_auth(merged_headers, effective_auth)
            merged_headers = self._apply_cookies(merged_headers, cookies)
            content_type = (merged_headers or {}).get("Content-Type", "application/octet-stream")
            return self._streaming_upload(
                "POST",
                url,
                data,
                headers=merged_headers,
                content_type=content_type,
                timeout=timeout * 1000 if timeout else None,  # Convert to ms
            )

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

        # Build options JSON with headers wrapper (clib expects {"headers": {...}})
        options = {}
        if merged_headers:
            options["headers"] = merged_headers
        options_json = json_module.dumps(options).encode("utf-8") if options else None

        start_time = time.perf_counter()
        result = self._lib.httpcloak_post(
            self._handle,
            url.encode("utf-8"),
            body,
            options_json,
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
            timeout: Request timeout in milliseconds
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
        effective_auth = auth if auth is not None else self.auth
        merged_headers = _apply_auth(merged_headers, effective_auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        # Get async manager and register this request (each request gets unique ID)
        manager = _get_async_manager()
        callback_id, future = manager.register_request(self._lib)

        # Build options JSON with headers wrapper (clib expects {"headers": {...}})
        options = {}
        if merged_headers:
            options["headers"] = merged_headers
        options_json = json.dumps(options).encode("utf-8") if options else None

        # Start async request
        self._lib.httpcloak_get_async(
            self._handle,
            url.encode("utf-8"),
            options_json,
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

        effective_auth = auth if auth is not None else self.auth
        merged_headers = _apply_auth(merged_headers, effective_auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        # Get async manager and register this request (each request gets unique ID)
        manager = _get_async_manager()
        callback_id, future = manager.register_request(self._lib)

        # Build options JSON with headers wrapper (clib expects {"headers": {...}})
        options = {}
        if merged_headers:
            options["headers"] = merged_headers
        options_json = json.dumps(options).encode("utf-8") if options else None

        # Start async request
        self._lib.httpcloak_post_async(
            self._handle,
            url.encode("utf-8"),
            body,
            options_json,
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

        effective_auth = auth if auth is not None else self.auth
        merged_headers = _apply_auth(merged_headers, effective_auth)
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

    # =========================================================================
    # Session Persistence
    # =========================================================================

    def save(self, path: str) -> None:
        """
        Save session state (cookies, TLS sessions) to a file.

        This allows you to persist session state across program runs,
        including cookies and TLS session tickets for faster resumption.

        Args:
            path: Path to save the session file

        Example:
            session = httpcloak.Session(preset="chrome-143")
            session.get("https://example.com")  # Acquire cookies
            session.save("session.json")

            # Later, restore the session
            session = httpcloak.Session.load("session.json")
        """
        result_ptr = self._lib.httpcloak_session_save(
            self._handle,
            path.encode("utf-8"),
        )
        result = _ptr_to_string(result_ptr)
        if result is None:
            raise HTTPCloakError("Failed to save session")

        data = json.loads(result)
        if "error" in data:
            raise HTTPCloakError(data["error"])

    def marshal(self) -> str:
        """
        Export session state to JSON string.

        Returns:
            JSON string containing session state

        Example:
            session_data = session.marshal()
            # Store session_data in database, cache, etc.

            # Later, restore the session
            session = httpcloak.Session.unmarshal(session_data)
        """
        result_ptr = self._lib.httpcloak_session_marshal(self._handle)
        result = _ptr_to_string(result_ptr)
        if result is None:
            raise HTTPCloakError("Failed to marshal session")

        # Check for error
        try:
            data = json.loads(result)
            if isinstance(data, dict) and "error" in data:
                raise HTTPCloakError(data["error"])
        except json.JSONDecodeError:
            pass  # Not an error response

        return result

    @classmethod
    def load(cls, path: str) -> "Session":
        """
        Load a session from a file.

        This restores session state including cookies and TLS session tickets.
        The session uses the same preset that was used when it was saved.

        Args:
            path: Path to the session file

        Returns:
            Restored Session object

        Example:
            session = httpcloak.Session.load("session.json")
            r = session.get("https://example.com")  # Uses restored cookies
        """
        lib = _get_lib()
        handle = lib.httpcloak_session_load(path.encode("utf-8"))

        if handle < 0:
            raise HTTPCloakError(f"Failed to load session from {path}")

        # Create a new Session instance with the loaded handle
        session = object.__new__(cls)
        session._lib = lib
        session._handle = handle
        session._default_timeout = 30
        session.headers = {}
        session.auth = None

        return session

    @classmethod
    def unmarshal(cls, data: str) -> "Session":
        """
        Load a session from JSON string.

        Args:
            data: JSON string containing session state

        Returns:
            Restored Session object

        Example:
            # Retrieve session_data from database, cache, etc.
            session = httpcloak.Session.unmarshal(session_data)
        """
        lib = _get_lib()
        handle = lib.httpcloak_session_unmarshal(data.encode("utf-8"))

        if handle < 0:
            raise HTTPCloakError("Failed to unmarshal session")

        # Create a new Session instance with the loaded handle
        session = object.__new__(cls)
        session._lib = lib
        session._handle = handle
        session._default_timeout = 30
        session.headers = {}
        session.auth = None

        return session

    # =========================================================================
    # Proxy Management
    # =========================================================================

    def set_proxy(self, proxy_url: str) -> None:
        """
        Set or update the proxy for all protocols (HTTP/1.1, HTTP/2, HTTP/3).

        This closes existing connections and recreates transports with the new proxy.
        Pass empty string to switch to direct connection.

        Args:
            proxy_url: Proxy URL (e.g., "http://proxy:8080", "socks5h://proxy:1080")
                      Pass empty string "" to disable proxy

        Example:
            session = httpcloak.Session(preset="chrome-143", proxy="http://proxy1:8080")
            session.get("https://example.com")  # Uses proxy1

            session.set_proxy("http://proxy2:8080")  # Switch to proxy2
            session.get("https://example.com")  # Uses proxy2

            session.set_proxy("")  # Switch to direct connection
            session.get("https://example.com")  # Direct connection
        """
        proxy_bytes = proxy_url.encode("utf-8") if proxy_url else b""
        result_ptr = self._lib.httpcloak_session_set_proxy(self._handle, proxy_bytes)
        result = _ptr_to_string(result_ptr)
        if result:
            data = json.loads(result)
            if "error" in data:
                raise HTTPCloakError(data["error"])

    def set_tcp_proxy(self, proxy_url: str) -> None:
        """
        Set the proxy for TCP protocols (HTTP/1.1, HTTP/2).

        Args:
            proxy_url: Proxy URL for TCP connections

        Example:
            session.set_tcp_proxy("http://tcp-proxy:8080")
            session.set_udp_proxy("socks5h://udp-proxy:1080")  # Split proxy config
        """
        proxy_bytes = proxy_url.encode("utf-8") if proxy_url else b""
        result_ptr = self._lib.httpcloak_session_set_tcp_proxy(self._handle, proxy_bytes)
        result = _ptr_to_string(result_ptr)
        if result:
            data = json.loads(result)
            if "error" in data:
                raise HTTPCloakError(data["error"])

    def set_udp_proxy(self, proxy_url: str) -> None:
        """
        Set the proxy for UDP protocols (HTTP/3 via SOCKS5 or MASQUE).

        Args:
            proxy_url: Proxy URL for UDP connections (SOCKS5 or MASQUE)

        Example:
            session.set_udp_proxy("socks5h://socks-proxy:1080")  # For HTTP/3
        """
        proxy_bytes = proxy_url.encode("utf-8") if proxy_url else b""
        result_ptr = self._lib.httpcloak_session_set_udp_proxy(self._handle, proxy_bytes)
        result = _ptr_to_string(result_ptr)
        if result:
            data = json.loads(result)
            if "error" in data:
                raise HTTPCloakError(data["error"])

    def get_proxy(self) -> str:
        """
        Get the current proxy URL (unified proxy or TCP proxy).

        Returns:
            Current proxy URL or empty string if no proxy
        """
        result_ptr = self._lib.httpcloak_session_get_proxy(self._handle)
        return _ptr_to_string(result_ptr) or ""

    def get_tcp_proxy(self) -> str:
        """
        Get the current TCP proxy URL.

        Returns:
            Current TCP proxy URL or empty string if no proxy
        """
        result_ptr = self._lib.httpcloak_session_get_tcp_proxy(self._handle)
        return _ptr_to_string(result_ptr) or ""

    def get_udp_proxy(self) -> str:
        """
        Get the current UDP proxy URL.

        Returns:
            Current UDP proxy URL or empty string if no proxy
        """
        result_ptr = self._lib.httpcloak_session_get_udp_proxy(self._handle)
        return _ptr_to_string(result_ptr) or ""

    def set_header_order(self, order: List[str]) -> None:
        """
        Set a custom header order for all requests.

        Args:
            order: List of header names in desired order (lowercase).
                   Pass empty list to reset to preset's default.

        Example:
            session.set_header_order([
                "accept-language", "sec-ch-ua", "accept",
                "sec-fetch-site", "sec-fetch-mode", "user-agent"
            ])
        """
        order_json = json.dumps(order) if order else "[]"
        order_bytes = order_json.encode("utf-8")
        result_ptr = self._lib.httpcloak_session_set_header_order(self._handle, order_bytes)
        result = _ptr_to_string(result_ptr)
        if result and "error" in result:
            data = json.loads(result)
            if "error" in data:
                raise ValueError(data["error"])

    def get_header_order(self) -> List[str]:
        """
        Get the current header order.

        Returns:
            List of header names in current order, or preset's default order
        """
        result_ptr = self._lib.httpcloak_session_get_header_order(self._handle)
        result = _ptr_to_string(result_ptr)
        if result:
            return json.loads(result)
        return []

    def set_session_identifier(self, session_id: str) -> None:
        """
        Set a session identifier for TLS cache key isolation.

        This is used when the session is registered with a LocalProxy to ensure
        TLS sessions are isolated per proxy/session configuration in distributed caches.

        Args:
            session_id: Unique identifier for this session. Pass empty string to clear.

        Example:
            session.set_session_identifier("user-123")
        """
        id_bytes = session_id.encode("utf-8") if session_id else None
        self._lib.httpcloak_session_set_identifier(self._handle, id_bytes)

    # =========================================================================
    # Streaming Methods
    # =========================================================================

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
        stream: bool = False,
    ) -> Union[Response, StreamResponse]:
        """
        Perform a GET request.

        Args:
            url: Request URL
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in milliseconds
            stream: If True, return StreamResponse for streaming downloads

        Returns:
            Response or StreamResponse if stream=True

        Example:
            # Normal request
            r = session.get("https://example.com")
            print(r.text)

            # Streaming download
            with session.get(url, stream=True) as r:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        """
        # Use request auth if provided, otherwise fall back to session auth
        effective_auth = auth if auth is not None else self.auth

        if stream:
            return self._get_stream(url, params, headers, cookies, effective_auth, timeout)

        # Regular request (existing implementation)
        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)
        merged_headers = _apply_auth(merged_headers, effective_auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        if timeout:
            return self.request("GET", url, headers=merged_headers, timeout=timeout)

        # Build options JSON with headers wrapper (clib expects {"headers": {...}})
        options = {}
        if merged_headers:
            options["headers"] = merged_headers
        options_json = json.dumps(options).encode("utf-8") if options else None

        start_time = time.perf_counter()
        # Use optimized raw response path for better performance
        response_handle = self._lib.httpcloak_get_raw(
            self._handle,
            url.encode("utf-8"),
            options_json,
        )
        elapsed = time.perf_counter() - start_time

        if response_handle < 0:
            raise HTTPCloakError("Request failed")

        return _parse_raw_response(self._lib, response_handle, elapsed=elapsed)

    def get_fast(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
    ) -> FastResponse:
        """
        High-performance GET request returning FastResponse with memoryview.

        This method is optimized for maximum download speed by:
        - Using pre-allocated buffer pools (no per-request allocation)
        - Returning memoryview instead of bytes (zero-copy)

        Args:
            url: Request URL
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)

        Returns:
            FastResponse with memoryview content

        Example:
            r = session.get_fast("https://example.com/large-file")
            # r.content is a memoryview - use it directly or copy if needed
            data = bytes(r.content)  # Creates a copy

        Note:
            The memoryview in FastResponse.content may be reused by subsequent
            requests. If you need to keep the data, copy it with bytes(r.content).
        """
        # Use request auth if provided, otherwise fall back to session auth
        effective_auth = auth if auth is not None else self.auth

        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)
        merged_headers = _apply_auth(merged_headers, effective_auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        # Build options JSON with headers wrapper
        options = {}
        if merged_headers:
            options["headers"] = merged_headers
        options_json = json.dumps(options).encode("utf-8") if options else None

        start_time = time.perf_counter()
        response_handle = self._lib.httpcloak_get_raw(
            self._handle,
            url.encode("utf-8"),
            options_json,
        )
        elapsed = time.perf_counter() - start_time

        if response_handle < 0:
            raise HTTPCloakError("Request failed")

        return _parse_fast_response(self._lib, response_handle, elapsed=elapsed)

    def post_fast(
        self,
        url: str,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
    ) -> FastResponse:
        """
        High-performance POST request returning FastResponse with memoryview.

        This method is optimized for maximum speed by:
        - Using pre-allocated buffer pools (no per-request allocation)
        - Returning memoryview instead of bytes (zero-copy)

        Args:
            url: Request URL
            data: Request body (string, bytes, or dict for form data)
            json_data: JSON body (will be serialized)
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)

        Returns:
            FastResponse with memoryview content

        Example:
            r = session.post_fast("https://api.example.com/upload", data=large_bytes)
            # r.content is a memoryview - use it directly or copy if needed
            result = bytes(r.content)  # Creates a copy

        Note:
            The memoryview in FastResponse.content may be reused by subsequent
            requests. If you need to keep the data, copy it with bytes(r.content).
        """
        # Use request auth if provided, otherwise fall back to session auth
        effective_auth = auth if auth is not None else self.auth

        merged_headers = self._merge_headers(headers)
        merged_headers = _apply_auth(merged_headers, effective_auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        # Build body
        body_bytes = None
        body_len = 0
        if json_data is not None:
            body_bytes = json.dumps(json_data).encode("utf-8")
            body_len = len(body_bytes)
            merged_headers["content-type"] = "application/json"
        elif data is not None:
            if isinstance(data, dict):
                # Form data
                from urllib.parse import urlencode
                body_bytes = urlencode(data).encode("utf-8")
                body_len = len(body_bytes)
                merged_headers["content-type"] = "application/x-www-form-urlencoded"
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
                body_len = len(body_bytes)
            else:
                body_bytes = data
                body_len = len(body_bytes)

        # Build options JSON with headers wrapper
        options = {}
        if merged_headers:
            options["headers"] = merged_headers
        options_json = json.dumps(options).encode("utf-8") if options else None

        start_time = time.perf_counter()
        response_handle = self._lib.httpcloak_post_raw(
            self._handle,
            url.encode("utf-8"),
            body_bytes,
            body_len,
            options_json,
        )
        elapsed = time.perf_counter() - start_time

        if response_handle < 0:
            raise HTTPCloakError("Request failed")

        return _parse_fast_response(self._lib, response_handle, elapsed=elapsed)

    def request_fast(
        self,
        method: str,
        url: str,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> FastResponse:
        """
        High-performance generic HTTP request returning FastResponse with memoryview.

        This method is optimized for maximum speed by:
        - Using pre-allocated buffer pools (no per-request allocation)
        - Returning memoryview instead of bytes (zero-copy)

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
            url: Request URL
            data: Request body (string, bytes, or dict for form data)
            json_data: JSON body (will be serialized)
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in milliseconds

        Returns:
            FastResponse with memoryview content

        Example:
            r = session.request_fast("PUT", "https://api.example.com/resource", json_data={"key": "value"})
            print(r.status_code, r.text)

        Note:
            The memoryview in FastResponse.content may be reused by subsequent
            requests. If you need to keep the data, copy it with bytes(r.content).
        """
        # Use request auth if provided, otherwise fall back to session auth
        effective_auth = auth if auth is not None else self.auth

        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)
        merged_headers = _apply_auth(merged_headers, effective_auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        # Build body
        body_bytes = None
        body_len = 0
        if json_data is not None:
            body_bytes = json.dumps(json_data).encode("utf-8")
            body_len = len(body_bytes)
            merged_headers["content-type"] = "application/json"
        elif data is not None:
            if isinstance(data, dict):
                body_bytes = urlencode(data).encode("utf-8")
                body_len = len(body_bytes)
                merged_headers["content-type"] = "application/x-www-form-urlencoded"
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
                body_len = len(body_bytes)
            else:
                body_bytes = data
                body_len = len(body_bytes)

        # Build request config JSON
        request_config = {
            "method": method.upper(),
            "url": url,
        }
        if merged_headers:
            request_config["headers"] = merged_headers
        if timeout:
            request_config["timeout"] = timeout

        request_json = json.dumps(request_config).encode("utf-8")

        start_time = time.perf_counter()
        response_handle = self._lib.httpcloak_request_raw(
            self._handle,
            request_json,
            body_bytes,
            body_len,
        )
        elapsed = time.perf_counter() - start_time

        if response_handle < 0:
            raise HTTPCloakError("Request failed")

        return _parse_fast_response(self._lib, response_handle, elapsed=elapsed)

    def put_fast(
        self,
        url: str,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> FastResponse:
        """
        High-performance PUT request returning FastResponse with memoryview.

        Args:
            url: Request URL
            data: Request body (string, bytes, or dict for form data)
            json_data: JSON body (will be serialized)
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in milliseconds

        Returns:
            FastResponse with memoryview content
        """
        return self.request_fast(
            "PUT", url, data=data, json_data=json_data, params=params,
            headers=headers, cookies=cookies, auth=auth, timeout=timeout,
        )

    def delete_fast(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> FastResponse:
        """
        High-performance DELETE request returning FastResponse with memoryview.

        Args:
            url: Request URL
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in milliseconds

        Returns:
            FastResponse with memoryview content
        """
        return self.request_fast(
            "DELETE", url, params=params, headers=headers,
            cookies=cookies, auth=auth, timeout=timeout,
        )

    def patch_fast(
        self,
        url: str,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> FastResponse:
        """
        High-performance PATCH request returning FastResponse with memoryview.

        Args:
            url: Request URL
            data: Request body (string, bytes, or dict for form data)
            json_data: JSON body (will be serialized)
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in milliseconds

        Returns:
            FastResponse with memoryview content
        """
        return self.request_fast(
            "PATCH", url, data=data, json_data=json_data, params=params,
            headers=headers, cookies=cookies, auth=auth, timeout=timeout,
        )

    def _get_stream(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> StreamResponse:
        """Internal method to perform a streaming GET request."""
        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)
        merged_headers = _apply_auth(merged_headers, auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        # Build options JSON
        options = {}
        if merged_headers:
            options["headers"] = merged_headers
        if timeout:
            options["timeout"] = timeout
        options_json = json.dumps(options).encode("utf-8") if options else None

        # Start stream
        stream_handle = self._lib.httpcloak_stream_get(
            self._handle,
            url.encode("utf-8"),
            options_json,
        )

        if stream_handle < 0:
            raise HTTPCloakError("Failed to start streaming request")

        # Get metadata
        metadata_ptr = self._lib.httpcloak_stream_get_metadata(stream_handle)
        metadata_str = _ptr_to_string(metadata_ptr)
        if metadata_str is None:
            self._lib.httpcloak_stream_close(stream_handle)
            raise HTTPCloakError("Failed to get stream metadata")

        metadata = json.loads(metadata_str)
        if "error" in metadata:
            self._lib.httpcloak_stream_close(stream_handle)
            raise HTTPCloakError(metadata["error"])

        # Parse cookies
        cookies_list = []
        for cookie_data in metadata.get("cookies") or []:
            if isinstance(cookie_data, dict):
                cookies_list.append(Cookie(
                    name=cookie_data.get("name", ""),
                    value=cookie_data.get("value", ""),
                ))

        return StreamResponse(
            stream_handle=stream_handle,
            lib=self._lib,
            status_code=metadata.get("status_code", 0),
            headers=metadata.get("headers") or {},
            final_url=metadata.get("final_url", url),
            protocol=metadata.get("protocol", ""),
            content_length=metadata.get("content_length", -1),
            cookies=cookies_list,
        )

    def post_stream(
        self,
        url: str,
        data: Union[str, bytes, Dict, None] = None,
        json_data: Optional[Dict] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> StreamResponse:
        """
        Perform a streaming POST request.

        Args:
            url: Request URL
            data: Request body (string, bytes, or dict for form data)
            json_data: JSON body (will be serialized)
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in milliseconds

        Returns:
            StreamResponse for streaming the response body
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

        effective_auth = auth if auth is not None else self.auth
        merged_headers = _apply_auth(merged_headers, effective_auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        # Build options JSON
        options = {}
        if merged_headers:
            options["headers"] = merged_headers
        if timeout:
            options["timeout"] = timeout
        options_json = json.dumps(options).encode("utf-8") if options else None

        # Start stream
        stream_handle = self._lib.httpcloak_stream_post(
            self._handle,
            url.encode("utf-8"),
            body,
            options_json,
        )

        if stream_handle < 0:
            raise HTTPCloakError("Failed to start streaming request")

        # Get metadata
        metadata_ptr = self._lib.httpcloak_stream_get_metadata(stream_handle)
        metadata_str = _ptr_to_string(metadata_ptr)
        if metadata_str is None:
            self._lib.httpcloak_stream_close(stream_handle)
            raise HTTPCloakError("Failed to get stream metadata")

        metadata = json.loads(metadata_str)
        if "error" in metadata:
            self._lib.httpcloak_stream_close(stream_handle)
            raise HTTPCloakError(metadata["error"])

        # Parse cookies
        cookies_list = []
        for cookie_data in metadata.get("cookies") or []:
            if isinstance(cookie_data, dict):
                cookies_list.append(Cookie(
                    name=cookie_data.get("name", ""),
                    value=cookie_data.get("value", ""),
                ))

        return StreamResponse(
            stream_handle=stream_handle,
            lib=self._lib,
            status_code=metadata.get("status_code", 0),
            headers=metadata.get("headers") or {},
            final_url=metadata.get("final_url", url),
            protocol=metadata.get("protocol", ""),
            content_length=metadata.get("content_length", -1),
            cookies=cookies_list,
        )

    def request_stream(
        self,
        method: str,
        url: str,
        data: Union[str, bytes, None] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> StreamResponse:
        """
        Perform a streaming HTTP request with any method.

        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            url: Request URL
            data: Request body
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in milliseconds

        Returns:
            StreamResponse for streaming the response body
        """
        url = _add_params_to_url(url, params)
        merged_headers = self._merge_headers(headers)
        effective_auth = auth if auth is not None else self.auth
        merged_headers = _apply_auth(merged_headers, effective_auth)
        merged_headers = self._apply_cookies(merged_headers, cookies)

        # Build request config
        request_config = {
            "method": method.upper(),
            "url": url,
        }
        if merged_headers:
            request_config["headers"] = merged_headers
        if data:
            if isinstance(data, bytes):
                request_config["body"] = data.decode("utf-8")
            else:
                request_config["body"] = data
        if timeout:
            request_config["timeout"] = timeout

        # Start stream
        stream_handle = self._lib.httpcloak_stream_request(
            self._handle,
            json.dumps(request_config).encode("utf-8"),
        )

        if stream_handle < 0:
            raise HTTPCloakError("Failed to start streaming request")

        # Get metadata
        metadata_ptr = self._lib.httpcloak_stream_get_metadata(stream_handle)
        metadata_str = _ptr_to_string(metadata_ptr)
        if metadata_str is None:
            self._lib.httpcloak_stream_close(stream_handle)
            raise HTTPCloakError("Failed to get stream metadata")

        metadata = json.loads(metadata_str)
        if "error" in metadata:
            self._lib.httpcloak_stream_close(stream_handle)
            raise HTTPCloakError(metadata["error"])

        # Parse cookies
        cookies_list = []
        for cookie_data in metadata.get("cookies") or []:
            if isinstance(cookie_data, dict):
                cookies_list.append(Cookie(
                    name=cookie_data.get("name", ""),
                    value=cookie_data.get("value", ""),
                ))

        return StreamResponse(
            stream_handle=stream_handle,
            lib=self._lib,
            status_code=metadata.get("status_code", 0),
            headers=metadata.get("headers") or {},
            final_url=metadata.get("final_url", url),
            protocol=metadata.get("protocol", ""),
            content_length=metadata.get("content_length", -1),
            cookies=cookies_list,
        )

    def get_stream(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> StreamResponse:
        """
        Perform a streaming GET request.

        Args:
            url: Request URL
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in milliseconds

        Returns:
            StreamResponse for streaming the response body

        Example:
            with session.get_stream("https://example.com/large-file") as r:
                for chunk in r.iter_content(chunk_size=8192):
                    file.write(chunk)
        """
        return self._get_stream(
            url, params=params, headers=headers,
            cookies=cookies, auth=auth, timeout=timeout,
        )

    def put_stream(
        self,
        url: str,
        data: Union[str, bytes, Dict, None] = None,
        json_data: Optional[Dict] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> StreamResponse:
        """
        Perform a streaming PUT request.

        Args:
            url: Request URL
            data: Request body (string, bytes, or dict for form data)
            json_data: JSON body (will be serialized)
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in milliseconds

        Returns:
            StreamResponse for streaming the response body
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

        return self.request_stream(
            "PUT", url, data=body, headers=merged_headers,
            cookies=cookies, auth=auth, timeout=timeout,
        )

    def delete_stream(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> StreamResponse:
        """
        Perform a streaming DELETE request.

        Args:
            url: Request URL
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in milliseconds

        Returns:
            StreamResponse for streaming the response body
        """
        return self.request_stream(
            "DELETE", url, params=params, headers=headers,
            cookies=cookies, auth=auth, timeout=timeout,
        )

    def patch_stream(
        self,
        url: str,
        data: Union[str, bytes, Dict, None] = None,
        json_data: Optional[Dict] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> StreamResponse:
        """
        Perform a streaming PATCH request.

        Args:
            url: Request URL
            data: Request body (string, bytes, or dict for form data)
            json_data: JSON body (will be serialized)
            params: URL query parameters
            headers: Request headers
            cookies: Cookies to send with this request
            auth: Basic auth tuple (username, password)
            timeout: Request timeout in milliseconds

        Returns:
            StreamResponse for streaming the response body
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

        return self.request_stream(
            "PATCH", url, data=body, headers=merged_headers,
            cookies=cookies, auth=auth, timeout=timeout,
        )


# =============================================================================
# Module-level convenience functions (like requests.get, requests.post, etc.)
# =============================================================================

_default_session: Optional[Session] = None
_default_session_lock = Lock()
_default_config: Dict[str, Any] = {}


def configure(
    preset: str = "chrome-145",
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
        preset: Browser preset (default: "chrome-145")
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


class LocalProxy:
    """
    Local HTTP proxy server that forwards requests through HTTPCloak with TLS fingerprinting.

    Use this to transparently apply TLS fingerprinting to any HTTP client (e.g., requests, httpx).
    Supports per-request proxy rotation via X-Upstream-Proxy header.

    Example:
        from httpcloak import LocalProxy

        # Start local proxy with TLS-only mode (pass headers through, only apply TLS fingerprint)
        proxy = LocalProxy(preset="chrome-143", tls_only=True)
        print(f"Proxy running on {proxy.proxy_url}")

        # Use with requests
        import requests
        response = requests.get("https://example.com", proxies={"https": proxy.proxy_url})

        # Per-request proxy rotation
        response = requests.get(
            "https://example.com",
            proxies={"https": proxy.proxy_url},
            headers={"X-Upstream-Proxy": "http://user:pass@rotating-proxy.example.com:8080"}
        )

        proxy.close()
    """

    def __init__(
        self,
        port: int = 0,
        preset: str = "chrome-145",
        timeout: int = 30,
        max_connections: int = 1000,
        tcp_proxy: Optional[str] = None,
        udp_proxy: Optional[str] = None,
        tls_only: bool = False,
    ):
        """
        Create and start a local HTTP proxy server.

        Args:
            port: Port to listen on (0 = auto-select available port)
            preset: Browser fingerprint preset (default: "chrome-145")
            timeout: Request timeout in seconds (default: 30)
            max_connections: Maximum concurrent connections (default: 1000)
            tcp_proxy: Default upstream TCP proxy URL (can be overridden per-request)
            udp_proxy: Default upstream UDP proxy URL (can be overridden per-request)
            tls_only: TLS-only mode - skip preset HTTP headers, only apply TLS fingerprint.
                      Use this when your client already provides authentic browser headers.
        """
        self._lib = _get_lib()
        self._handle: int = -1

        config = {
            "port": port,
            "preset": preset,
            "timeout": timeout,
            "max_connections": max_connections,
        }
        if tcp_proxy:
            config["tcp_proxy"] = tcp_proxy
        if udp_proxy:
            config["udp_proxy"] = udp_proxy
        if tls_only:
            config["tls_only"] = True

        config_json = json.dumps(config).encode("utf-8")
        self._handle = self._lib.httpcloak_local_proxy_start(config_json)

        if self._handle < 0:
            raise HTTPCloakError("Failed to start local proxy")

    @property
    def port(self) -> int:
        """Get the port the proxy is listening on."""
        return self._lib.httpcloak_local_proxy_get_port(self._handle)

    @property
    def is_running(self) -> bool:
        """Check if the proxy is currently running."""
        return self._lib.httpcloak_local_proxy_is_running(self._handle) != 0

    @property
    def proxy_url(self) -> str:
        """Get the proxy URL for use with HTTP clients.
        Uses 127.0.0.1 instead of localhost to avoid IPv6 resolution issues.
        """
        return f"http://127.0.0.1:{self.port}"

    def get_stats(self) -> Dict[str, Any]:
        """
        Get proxy statistics.

        Returns:
            dict: Statistics including running status, active connections, total requests
        """
        result_ptr = self._lib.httpcloak_local_proxy_get_stats(self._handle)
        result = _ptr_to_string(result_ptr)
        if result:
            return json.loads(result)
        return {}

    def register_session(self, session_id: str, session: "Session") -> None:
        """
        Register a session with the proxy for per-request routing.

        Clients can use the X-HTTPCloak-Session header to select which session to use.
        Each registered session maintains its own cookies, TLS sessions, and proxy config.

        Args:
            session_id: Unique identifier for this session
            session: The Session object to register

        Raises:
            HTTPCloakError: If session_id already exists or registration fails

        Example:
            proxy = LocalProxy(preset="chrome-143")

            session1 = Session(preset="chrome-143")
            session2 = Session(preset="firefox-133")

            proxy.register_session("user-1", session1)
            proxy.register_session("user-2", session2)

            # Clients use X-HTTPCloak-Session header to select:
            import requests
            r = requests.get("https://example.com",
                proxies={"https": proxy.proxy_url},
                headers={"X-HTTPCloak-Session": "user-1"}
            )
        """
        if not session_id:
            raise ValueError("session_id cannot be empty")
        if session is None:
            raise ValueError("session cannot be None")

        session_id_bytes = session_id.encode("utf-8")
        error_ptr = self._lib.httpcloak_local_proxy_register_session(
            self._handle, session_id_bytes, session._handle
        )
        error = _ptr_to_string(error_ptr)
        if error:
            raise HTTPCloakError(error)

    def unregister_session(self, session_id: str) -> bool:
        """
        Unregister a session from the proxy.

        Args:
            session_id: The session ID to unregister

        Returns:
            bool: True if the session was found and removed, False otherwise

        Note:
            This does NOT close the session - you must close it separately.
        """
        if not session_id:
            return False

        session_id_bytes = session_id.encode("utf-8")
        result = self._lib.httpcloak_local_proxy_unregister_session(
            self._handle, session_id_bytes
        )
        return result == 1

    def close(self) -> None:
        """Stop the local proxy server."""
        if self._handle >= 0:
            self._lib.httpcloak_local_proxy_stop(self._handle)
            self._handle = -1

    def __enter__(self):
        """Context manager support."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager support - automatically close proxy."""
        self.close()
        return False

    def __del__(self):
        """Destructor - ensure proxy is stopped."""
        self.close()


# ============================================================================
# Distributed Session Cache
# ============================================================================

# Global session cache callbacks (must keep references to prevent GC)
_session_cache_callbacks: Dict[str, Any] = {}
_session_cache_lock = Lock()


class SessionCacheBackend:
    """
    Distributed TLS session cache backend for sharing sessions across instances.

    This enables TLS session resumption across distributed httpcloak instances
    by storing session tickets in an external cache like Redis or Memcached.

    Example with Redis:
        import redis
        import json
        import httpcloak

        redis_client = redis.Redis()

        def get_session(key: str) -> Optional[str]:
            data = redis_client.get(key)
            return data.decode() if data else None

        def put_session(key: str, value: str, ttl_seconds: int) -> int:
            redis_client.setex(key, ttl_seconds, value)
            return 0  # Success

        def delete_session(key: str) -> int:
            redis_client.delete(key)
            return 0

        def on_error(operation: str, key: str, error: str):
            print(f"Cache error: {operation} on {key}: {error}")

        # Register the cache backend globally
        cache = httpcloak.SessionCacheBackend(
            get=get_session,
            put=put_session,
            delete=delete_session,
            on_error=on_error,
        )
        cache.register()

        # Now all Session and LocalProxy instances will use this cache
        session = httpcloak.Session(preset="chrome-143")
        session.get("https://example.com")  # Session will be cached!

    The cache is used for:
    - TLS session tickets (key format: httpcloak:sessions:{preset}:{protocol}:{host}:{port})
    - ECH configs for HTTP/3 (key format: httpcloak:ech:{preset}:{host}:{port})

    Session data is JSON with fields: ticket, state, created_at
    ECH config data is base64-encoded binary
    """

    def __init__(
        self,
        get: Optional[callable] = None,
        put: Optional[callable] = None,
        delete: Optional[callable] = None,
        get_ech: Optional[callable] = None,
        put_ech: Optional[callable] = None,
        on_error: Optional[callable] = None,
    ):
        """
        Create a session cache backend.

        Args:
            get: Function to get session data. Signature: (key: str) -> Optional[str]
                 Returns JSON string with session data, or None if not found.
            put: Function to store session data. Signature: (key: str, value: str, ttl_seconds: int) -> int
                 Returns 0 on success, non-zero on error.
            delete: Function to delete session data. Signature: (key: str) -> int
                    Returns 0 on success, non-zero on error.
            get_ech: Function to get ECH config. Signature: (key: str) -> Optional[str]
                     Returns base64-encoded config, or None if not found.
            put_ech: Function to store ECH config. Signature: (key: str, value: str, ttl_seconds: int) -> int
                     Returns 0 on success, non-zero on error.
            on_error: Function called on cache errors. Signature: (operation: str, key: str, error: str) -> None
        """
        self._get = get
        self._put = put
        self._delete = delete
        self._get_ech = get_ech
        self._put_ech = put_ech
        self._on_error = on_error
        self._registered = False

        # C callback wrappers (kept as instance attrs to prevent GC)
        self._c_get = None
        self._c_put = None
        self._c_delete = None
        self._c_get_ech = None
        self._c_put_ech = None
        self._c_error = None

    def _make_get_callback(self):
        """Create C callback wrapper for get."""
        get_fn = self._get

        def callback(key_ptr):
            if get_fn is None:
                return None
            try:
                key = key_ptr.decode("utf-8") if key_ptr else ""
                result = get_fn(key)
                if result is None:
                    return None
                return result.encode("utf-8")
            except Exception:
                return None

        return SESSION_CACHE_GET_CALLBACK(callback)

    def _make_put_callback(self):
        """Create C callback wrapper for put."""
        put_fn = self._put

        def callback(key_ptr, value_ptr, ttl_seconds):
            if put_fn is None:
                return -1
            try:
                key = key_ptr.decode("utf-8") if key_ptr else ""
                value = value_ptr.decode("utf-8") if value_ptr else ""
                return put_fn(key, value, int(ttl_seconds))
            except Exception:
                return -1

        return SESSION_CACHE_PUT_CALLBACK(callback)

    def _make_delete_callback(self):
        """Create C callback wrapper for delete."""
        delete_fn = self._delete

        def callback(key_ptr):
            if delete_fn is None:
                return -1
            try:
                key = key_ptr.decode("utf-8") if key_ptr else ""
                return delete_fn(key)
            except Exception:
                return -1

        return SESSION_CACHE_DELETE_CALLBACK(callback)

    def _make_get_ech_callback(self):
        """Create C callback wrapper for ECH get."""
        get_fn = self._get_ech

        def callback(key_ptr):
            if get_fn is None:
                return None
            try:
                key = key_ptr.decode("utf-8") if key_ptr else ""
                result = get_fn(key)
                if result is None:
                    return None
                return result.encode("utf-8")
            except Exception:
                return None

        return ECH_CACHE_GET_CALLBACK(callback)

    def _make_put_ech_callback(self):
        """Create C callback wrapper for ECH put."""
        put_fn = self._put_ech

        def callback(key_ptr, value_ptr, ttl_seconds):
            if put_fn is None:
                return -1
            try:
                key = key_ptr.decode("utf-8") if key_ptr else ""
                value = value_ptr.decode("utf-8") if value_ptr else ""
                return put_fn(key, value, int(ttl_seconds))
            except Exception:
                return -1

        return ECH_CACHE_PUT_CALLBACK(callback)

    def _make_error_callback(self):
        """Create C callback wrapper for error."""
        error_fn = self._on_error

        def callback(op_ptr, key_ptr, error_ptr):
            if error_fn is None:
                return
            try:
                operation = op_ptr.decode("utf-8") if op_ptr else ""
                key = key_ptr.decode("utf-8") if key_ptr else ""
                error = error_ptr.decode("utf-8") if error_ptr else ""
                error_fn(operation, key, error)
            except Exception:
                pass

        return SESSION_CACHE_ERROR_CALLBACK(callback)

    def _make_noop_get_callback(self):
        """Create a no-op get callback that always returns None."""
        def callback(key_ptr):
            return None
        return SESSION_CACHE_GET_CALLBACK(callback)

    def _make_noop_put_callback(self):
        """Create a no-op put callback that always succeeds."""
        def callback(key_ptr, value_ptr, ttl_seconds):
            return 0
        return SESSION_CACHE_PUT_CALLBACK(callback)

    def _make_noop_delete_callback(self):
        """Create a no-op delete callback that always succeeds."""
        def callback(key_ptr):
            return 0
        return SESSION_CACHE_DELETE_CALLBACK(callback)

    def _make_noop_ech_get_callback(self):
        """Create a no-op ECH get callback that always returns None."""
        def callback(key_ptr):
            return None
        return ECH_CACHE_GET_CALLBACK(callback)

    def _make_noop_ech_put_callback(self):
        """Create a no-op ECH put callback that always succeeds."""
        def callback(key_ptr, value_ptr, ttl_seconds):
            return 0
        return ECH_CACHE_PUT_CALLBACK(callback)

    def _make_noop_error_callback(self):
        """Create a no-op error callback."""
        def callback(op_ptr, key_ptr, error_ptr):
            pass
        return SESSION_CACHE_ERROR_CALLBACK(callback)

    def register(self):
        """
        Register this cache backend globally.

        After registration, all new Session and LocalProxy instances will use
        this cache for TLS session storage.
        """
        global _session_cache_callbacks

        lib = _get_lib()

        with _session_cache_lock:
            # Create C callbacks (use no-op for missing callbacks to avoid null pointer issues)
            self._c_get = self._make_get_callback() if self._get else self._make_noop_get_callback()
            self._c_put = self._make_put_callback() if self._put else self._make_noop_put_callback()
            self._c_delete = self._make_delete_callback() if self._delete else self._make_noop_delete_callback()
            self._c_get_ech = self._make_get_ech_callback() if self._get_ech else self._make_noop_ech_get_callback()
            self._c_put_ech = self._make_put_ech_callback() if self._put_ech else self._make_noop_ech_put_callback()
            self._c_error = self._make_error_callback() if self._on_error else self._make_noop_error_callback()

            # Register with library
            lib.httpcloak_set_session_cache_callbacks(
                self._c_get,
                self._c_put,
                self._c_delete,
                self._c_get_ech,
                self._c_put_ech,
                self._c_error,
            )

            # Store reference to prevent GC
            _session_cache_callbacks["backend"] = self
            self._registered = True

    def unregister(self):
        """
        Unregister this cache backend.

        After unregistration, new sessions will not use distributed caching.
        """
        global _session_cache_callbacks

        if not self._registered:
            return

        lib = _get_lib()

        with _session_cache_lock:
            lib.httpcloak_clear_session_cache_callbacks()
            _session_cache_callbacks.clear()
            self._registered = False

    def __del__(self):
        """Destructor - unregister on cleanup."""
        try:
            if self._registered:
                self.unregister()
        except Exception:
            pass


def configure_session_cache(
    get: Optional[callable] = None,
    put: Optional[callable] = None,
    delete: Optional[callable] = None,
    get_ech: Optional[callable] = None,
    put_ech: Optional[callable] = None,
    on_error: Optional[callable] = None,
) -> SessionCacheBackend:
    """
    Configure a distributed session cache backend.

    This is a convenience function that creates and registers a SessionCacheBackend.

    Args:
        get: Function to get session data. Signature: (key: str) -> Optional[str]
        put: Function to store session data. Signature: (key: str, value: str, ttl_seconds: int) -> int
        delete: Function to delete session data. Signature: (key: str) -> int
        get_ech: Function to get ECH config. Signature: (key: str) -> Optional[str]
        put_ech: Function to store ECH config. Signature: (key: str, value: str, ttl_seconds: int) -> int
        on_error: Function called on cache errors. Signature: (operation: str, key: str, error: str) -> None

    Returns:
        The registered SessionCacheBackend instance.

    Example:
        import redis
        import httpcloak

        r = redis.Redis()

        httpcloak.configure_session_cache(
            get=lambda key: r.get(key).decode() if r.get(key) else None,
            put=lambda key, value, ttl: (r.setex(key, ttl, value), 0)[1],
            delete=lambda key: (r.delete(key), 0)[1],
        )

        # Now all sessions will use Redis for TLS session storage
        session = httpcloak.Session()
        session.get("https://example.com")
    """
    backend = SessionCacheBackend(
        get=get,
        put=put,
        delete=delete,
        get_ech=get_ech,
        put_ech=put_ech,
        on_error=on_error,
    )
    backend.register()
    return backend


def clear_session_cache():
    """
    Clear the distributed session cache backend.

    After calling this, new sessions will not use distributed caching.
    """
    global _session_cache_callbacks

    lib = _get_lib()

    with _session_cache_lock:
        lib.httpcloak_clear_session_cache_callbacks()
        _session_cache_callbacks.clear()


def _get_default_session() -> Session:
    """Get or create the default session."""
    global _default_session
    if _default_session is None:
        with _default_session_lock:
            if _default_session is None:
                preset = _default_config.get("preset", "chrome-145")
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
    # Pop all session-level kwargs (these should not be passed to request methods)
    preset = kwargs.pop("preset", None)
    proxy = kwargs.pop("proxy", None)
    tcp_proxy = kwargs.pop("tcp_proxy", None)
    udp_proxy = kwargs.pop("udp_proxy", None)
    verify = kwargs.pop("verify", None)
    allow_redirects = kwargs.pop("allow_redirects", None)
    http_version = kwargs.pop("http_version", None)
    max_redirects = kwargs.pop("max_redirects", None)
    retry = kwargs.pop("retry", None)
    retry_on_status = kwargs.pop("retry_on_status", None)
    prefer_ipv4 = kwargs.pop("prefer_ipv4", None)
    connect_to = kwargs.pop("connect_to", None)
    ech_config_domain = kwargs.pop("ech_config_domain", None)

    # Check if any session-level override was provided
    has_override = any(v is not None for v in [
        preset, proxy, tcp_proxy, udp_proxy, verify, allow_redirects,
        http_version, max_redirects, retry, retry_on_status, prefer_ipv4,
        connect_to, ech_config_domain
    ])

    # If no session-level overrides, use default session
    if not has_override:
        return _get_default_session(), False

    # Get current defaults and apply overrides
    final_preset = preset if preset is not None else _default_config.get("preset", "chrome-145")
    final_proxy = proxy if proxy is not None else _default_config.get("proxy")
    final_tcp_proxy = tcp_proxy if tcp_proxy is not None else _default_config.get("tcp_proxy")
    final_udp_proxy = udp_proxy if udp_proxy is not None else _default_config.get("udp_proxy")
    final_timeout = _default_config.get("timeout", 30)
    final_http_version = http_version if http_version is not None else _default_config.get("http_version", "auto")
    final_verify = verify if verify is not None else _default_config.get("verify", True)
    final_allow_redirects = allow_redirects if allow_redirects is not None else _default_config.get("allow_redirects", True)
    final_max_redirects = max_redirects if max_redirects is not None else _default_config.get("max_redirects", 10)
    final_retry = retry if retry is not None else _default_config.get("retry", 0)
    final_retry_on_status = retry_on_status if retry_on_status is not None else _default_config.get("retry_on_status")
    final_prefer_ipv4 = prefer_ipv4 if prefer_ipv4 is not None else _default_config.get("prefer_ipv4", False)
    final_connect_to = connect_to if connect_to is not None else _default_config.get("connect_to")
    final_ech_config_domain = ech_config_domain if ech_config_domain is not None else _default_config.get("ech_config_domain")

    # Create temporary session with overrides
    temp_session = Session(
        preset=final_preset,
        proxy=final_proxy,
        tcp_proxy=final_tcp_proxy,
        udp_proxy=final_udp_proxy,
        timeout=final_timeout,
        http_version=final_http_version,
        verify=final_verify,
        allow_redirects=final_allow_redirects,
        max_redirects=final_max_redirects,
        retry=final_retry,
        retry_on_status=final_retry_on_status,
        prefer_ipv4=final_prefer_ipv4,
        connect_to=final_connect_to,
        ech_config_domain=final_ech_config_domain,
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
        timeout: Request timeout in milliseconds
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
