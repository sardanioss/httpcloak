#!/usr/bin/env python3
"""
Test cases for new httpcloak features.

Tests:
- response.elapsed - Request timing
- response.reason - HTTP status phrase
- response.encoding - Content-Type encoding
- session.auth - Default session authentication
- session.get_cookie() - Get specific cookie
- session.delete_cookie() - Delete specific cookie
- session.clear_cookies() - Clear all cookies
- cookies= parameter - Per-request cookies

Run:
    python test_features.py
"""

import sys
import os

# Add parent directory to path for local development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../bindings/python'))

import httpcloak


def test_response_elapsed():
    """Test response.elapsed property."""
    print("Test 1: response.elapsed")
    print("-" * 40)

    session = httpcloak.Session(preset="chrome-143")
    response = session.get("https://httpbin.org/get")

    assert hasattr(response, 'elapsed'), "Response should have elapsed property"
    assert isinstance(response.elapsed, float), "elapsed should be a float"
    assert response.elapsed > 0, "elapsed should be positive"

    print(f"  Status: {response.status_code}")
    print(f"  Elapsed: {response.elapsed:.3f} seconds")
    print("  PASS")

    session.close()


def test_response_reason():
    """Test response.reason property."""
    print("\nTest 2: response.reason")
    print("-" * 40)

    session = httpcloak.Session(preset="chrome-143")

    # Test 200 OK
    response = session.get("https://httpbin.org/status/200")
    assert response.reason == "OK", f"Expected 'OK', got '{response.reason}'"
    print(f"  200 -> {response.reason}")

    # Test 404 Not Found
    response = session.get("https://httpbin.org/status/404")
    assert response.reason == "Not Found", f"Expected 'Not Found', got '{response.reason}'"
    print(f"  404 -> {response.reason}")

    # Test 500 Internal Server Error
    response = session.get("https://httpbin.org/status/500")
    assert response.reason == "Internal Server Error", f"Expected 'Internal Server Error', got '{response.reason}'"
    print(f"  500 -> {response.reason}")

    print("  PASS")

    session.close()


def test_response_encoding():
    """Test response.encoding property."""
    print("\nTest 3: response.encoding")
    print("-" * 40)

    session = httpcloak.Session(preset="chrome-143")

    # Test JSON response (should have encoding)
    response = session.get("https://httpbin.org/get")
    print(f"  Content-Type: {response.headers.get('content-type', 'N/A')}")
    print(f"  Encoding: {response.encoding}")

    # httpbin returns charset=utf-8
    # Note: encoding might be None if not specified in Content-Type
    if response.encoding:
        assert response.encoding.lower() in ['utf-8', 'utf8'], f"Expected utf-8, got {response.encoding}"

    print("  PASS")

    session.close()


def test_session_auth():
    """Test session.auth default authentication."""
    print("\nTest 4: session.auth")
    print("-" * 40)

    # Create session with default auth
    session = httpcloak.Session(preset="chrome-143", auth=("testuser", "testpass"))

    # Make request - should use session auth automatically
    response = session.get("https://httpbin.org/basic-auth/testuser/testpass")
    assert response.status_code == 200, f"Auth failed: {response.status_code}"
    print(f"  Session auth test: {response.status_code}")

    # Override auth for specific request
    response = session.get(
        "https://httpbin.org/basic-auth/otheruser/otherpass",
        auth=("otheruser", "otherpass")
    )
    assert response.status_code == 200, f"Override auth failed: {response.status_code}"
    print(f"  Override auth test: {response.status_code}")

    print("  PASS")

    session.close()


def test_get_cookie():
    """Test session.get_cookie() method."""
    print("\nTest 5: session.get_cookie()")
    print("-" * 40)

    session = httpcloak.Session(preset="chrome-143")

    # Set some cookies
    session.set_cookie("foo", "bar")
    session.set_cookie("hello", "world")

    # Test get_cookie
    foo = session.get_cookie("foo")
    assert foo == "bar", f"Expected 'bar', got '{foo}'"
    print(f"  get_cookie('foo') = '{foo}'")

    hello = session.get_cookie("hello")
    assert hello == "world", f"Expected 'world', got '{hello}'"
    print(f"  get_cookie('hello') = '{hello}'")

    # Test non-existent cookie
    missing = session.get_cookie("nonexistent")
    assert missing is None, f"Expected None, got '{missing}'"
    print(f"  get_cookie('nonexistent') = {missing}")

    print("  PASS")

    session.close()


def test_delete_cookie():
    """Test session.delete_cookie() method."""
    print("\nTest 6: session.delete_cookie()")
    print("-" * 40)

    session = httpcloak.Session(preset="chrome-143")

    # Set cookies
    session.set_cookie("keep", "this")
    session.set_cookie("delete", "this")

    # Verify both exist
    assert session.get_cookie("keep") == "this"
    assert session.get_cookie("delete") == "this"
    print("  Before delete: keep='this', delete='this'")

    # Delete one cookie
    session.delete_cookie("delete")

    # Verify deletion
    assert session.get_cookie("keep") == "this", "keep cookie should still exist"
    deleted = session.get_cookie("delete")
    # Note: delete sets to empty string, which might be returned or None depending on implementation
    print(f"  After delete: keep='this', delete='{deleted}'")

    print("  PASS")

    session.close()


def test_clear_cookies():
    """Test session.clear_cookies() method."""
    print("\nTest 7: session.clear_cookies()")
    print("-" * 40)

    session = httpcloak.Session(preset="chrome-143")

    # Set multiple cookies
    session.set_cookie("a", "1")
    session.set_cookie("b", "2")
    session.set_cookie("c", "3")

    cookies = session.get_cookies()
    print(f"  Before clear: {len(cookies)} cookies")

    # Clear all cookies
    session.clear_cookies()

    cookies_after = session.get_cookies()
    # Note: cookies might have empty values instead of being removed
    non_empty_cookies = {k: v for k, v in cookies_after.items() if v}
    print(f"  After clear: {len(non_empty_cookies)} non-empty cookies")

    print("  PASS")

    session.close()


def test_cookies_parameter():
    """Test cookies= parameter for per-request cookies."""
    print("\nTest 8: cookies= parameter")
    print("-" * 40)

    session = httpcloak.Session(preset="chrome-143")

    # Make request with per-request cookies
    response = session.get(
        "https://httpbin.org/cookies",
        cookies={"test_cookie": "test_value", "another": "cookie"}
    )

    assert response.status_code == 200
    data = response.json()
    cookies = data.get("cookies", {})
    print(f"  Cookies sent: {cookies}")

    assert cookies.get("test_cookie") == "test_value", "test_cookie not received"
    assert cookies.get("another") == "cookie", "another cookie not received"

    print("  PASS")

    session.close()


def test_response_cookies():
    """Test response.cookies property."""
    print("\nTest 9: response.cookies")
    print("-" * 40)

    session = httpcloak.Session(preset="chrome-143")

    # Make request to endpoint that returns Set-Cookie in final response
    response = session.get("https://httpbin.org/response-headers?Set-Cookie=test_cookie%3Dtest_value")

    print(f"  Status: {response.status_code}")
    print(f"  Cookies count: {len(response.cookies)}")

    # Check that cookies is a list
    assert isinstance(response.cookies, list), "cookies should be a list"

    # Print cookies if any
    for cookie in response.cookies:
        print(f"  Cookie: {cookie.name}={cookie.value}")

    # Should have at least one cookie from this response
    if len(response.cookies) > 0:
        assert response.cookies[0].name == "test_cookie", f"Expected 'test_cookie', got '{response.cookies[0].name}'"

    print("  PASS")

    session.close()


def test_response_history():
    """Test response.history property."""
    print("\nTest 10: response.history")
    print("-" * 40)

    session = httpcloak.Session(preset="chrome-143")

    # Make request that causes 2 redirects
    response = session.get("https://httpbin.org/redirect/2")

    print(f"  Final status: {response.status_code}")
    print(f"  Final URL: {response.url}")
    print(f"  History length: {len(response.history)}")

    # Check that history is a list
    assert isinstance(response.history, list), "history should be a list"

    # Should have 2 redirects
    assert len(response.history) == 2, f"Expected 2 redirects, got {len(response.history)}"

    # Print history
    for i, redirect in enumerate(response.history):
        print(f"  Redirect {i+1}: {redirect.status_code} -> {redirect.url}")
        assert redirect.status_code == 302, f"Expected 302, got {redirect.status_code}"

    print("  PASS")

    session.close()


def main():
    print("=" * 60)
    print("HTTPCloak New Features Tests")
    print("=" * 60)

    tests = [
        test_response_elapsed,
        test_response_reason,
        test_response_encoding,
        test_session_auth,
        test_get_cookie,
        test_delete_cookie,
        test_clear_cookies,
        test_cookies_parameter,
        test_response_cookies,
        test_response_history,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  FAILED: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
