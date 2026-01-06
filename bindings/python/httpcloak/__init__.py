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
    Response,
    HTTPCloakError,
    Preset,
    # Configuration
    configure,
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
)

__all__ = [
    "Session",
    "Response",
    "HTTPCloakError",
    "Preset",
    "configure",
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
]
__version__ = "1.0.3"
