"""
httpcloak - Browser fingerprint emulation HTTP client

A requests-compatible HTTP client with TLS fingerprinting.
Drop-in replacement for the requests library.

Example:
    import httpcloak

    # Simple usage (like requests)
    r = httpcloak.get("https://example.com")
    print(r.status_code, r.text)

    # POST with JSON
    r = httpcloak.post("https://api.example.com", json={"key": "value"})
    print(r.json())

    # Configure defaults (preset, headers, proxy)
    httpcloak.configure(
        preset="chrome-143-windows",
        headers={"Authorization": "Bearer token"},
    )
    r = httpcloak.get("https://example.com")  # uses configured preset

    # With session (for full control)
    with httpcloak.Session(preset="firefox-133") as session:
        r = session.get("https://example.com")
        print(r.json())
"""

from .client import (
    # Classes
    Session,
    LocalProxy,
    Response,
    FastResponse,
    HTTPCloakError,
    Preset,
    SessionCacheBackend,
    # Configuration
    configure,
    configure_session_cache,
    clear_session_cache,
    # Module-level functions (requests-compatible)
    get,
    post,
    put,
    delete,
    patch,
    head,
    options,
    request,
    # Utility functions
    available_presets,
    version,
    # DNS configuration
    set_ech_dns_servers,
    get_ech_dns_servers,
)

__all__ = [
    "Session",
    "LocalProxy",
    "Response",
    "FastResponse",
    "HTTPCloakError",
    "Preset",
    "SessionCacheBackend",
    "configure",
    "configure_session_cache",
    "clear_session_cache",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "options",
    "request",
    "available_presets",
    "version",
    "set_ech_dns_servers",
    "get_ech_dns_servers",
]
__version__ = "1.5.8"
