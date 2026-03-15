#!/usr/bin/env python3
"""
Sessions and Cookie Management

This example demonstrates:
- Using Session for persistent connections
- Cookie management
- Default headers
- Context manager usage
"""

import httpcloak

# Session with context manager
print("=" * 60)
print("Example 1: Session with Context Manager")
print("-" * 60)

with httpcloak.Session(preset="chrome-latest") as session:
    # First request
    r = session.get("https://httpbin.org/cookies/set/session_id/abc123")
    print(f"Set cookie - Status: {r.status_code}")

    # Check cookies
    cookies = session.cookies
    print(f"Cookies in session: {cookies}")

    # Second request (cookies sent automatically)
    r = session.get("https://httpbin.org/cookies")
    print(f"Cookies endpoint: {r.json()}")

# Session with default headers
print("\n" + "=" * 60)
print("Example 2: Session with Default Headers")
print("-" * 60)

session = httpcloak.Session(preset="chrome-latest")
session.headers["Authorization"] = "Bearer my-token"
session.headers["X-API-Key"] = "secret-key"

r = session.get("https://httpbin.org/headers")
headers = r.json()["headers"]
print(f"Authorization sent: {'Authorization' in headers}")
print(f"X-API-Key sent: {'X-Api-Key' in headers}")

session.close()

# Manual cookie management
print("\n" + "=" * 60)
print("Example 3: Manual Cookie Management")
print("-" * 60)

session = httpcloak.Session(preset="chrome-latest")

# Set cookies manually
session.set_cookie("user_id", "12345")
session.set_cookie("preferences", "dark_mode")

# Check cookies
print(f"Cookies set: {session.get_cookies()}")

# Make request with cookies
r = session.get("https://httpbin.org/cookies")
print(f"Cookies sent to server: {r.json()}")

session.close()

# Multiple requests with same session
print("\n" + "=" * 60)
print("Example 4: Multiple Requests (Connection Reuse)")
print("-" * 60)

with httpcloak.Session(preset="chrome-latest") as session:
    urls = [
        "https://httpbin.org/get",
        "https://httpbin.org/headers",
        "https://httpbin.org/user-agent",
    ]

    for i, url in enumerate(urls, 1):
        r = session.get(url)
        print(f"Request {i}: {url.split('/')[-1]:15} | Status: {r.status_code} | Protocol: {r.protocol}")

print("\n" + "=" * 60)
print("Session examples completed!")
print("=" * 60)
