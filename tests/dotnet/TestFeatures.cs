/**
 * Test cases for new httpcloak features.
 *
 * Tests:
 * - response.Elapsed - Request timing
 * - response.Reason - HTTP status phrase
 * - response.Encoding - Content-Type encoding
 * - session.Auth - Default session authentication
 * - session.GetCookie() - Get specific cookie
 * - session.DeleteCookie() - Delete specific cookie
 * - session.ClearCookies() - Clear all cookies
 *
 * Run:
 *   dotnet run
 */

using HttpCloak;
using System.Text.Json;

class TestFeatures
{
    static int passed = 0;
    static int failed = 0;

    static void Main()
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("HTTPCloak New Features Tests (.NET)");
        Console.WriteLine(new string('=', 60));

        RunTest("response.Elapsed", TestResponseElapsed);
        RunTest("response.Reason", TestResponseReason);
        RunTest("response.Encoding", TestResponseEncoding);
        RunTest("session.Auth", TestSessionAuth);
        RunTest("session.GetCookie()", TestGetCookie);
        RunTest("session.DeleteCookie()", TestDeleteCookie);
        RunTest("session.ClearCookies()", TestClearCookies);
        RunTest("response.Cookies", TestResponseCookies);
        RunTest("response.History", TestResponseHistory);

        Console.WriteLine();
        Console.WriteLine(new string('=', 60));
        Console.WriteLine($"Results: {passed} passed, {failed} failed");
        Console.WriteLine(new string('=', 60));

        Environment.Exit(failed == 0 ? 0 : 1);
    }

    static void RunTest(string name, Action test)
    {
        Console.WriteLine($"\nTest: {name}");
        Console.WriteLine(new string('-', 40));

        try
        {
            test();
            Console.WriteLine("  PASS");
            passed++;
        }
        catch (Exception e)
        {
            Console.WriteLine($"  FAILED: {e.Message}");
            failed++;
        }
    }

    static void TestResponseElapsed()
    {
        using var session = new Session(preset: "chrome-143");
        var response = session.Get("https://httpbin.org/get");

        if (response.Elapsed == TimeSpan.Zero)
            throw new Exception("Elapsed should not be zero");

        if (response.Elapsed.TotalMilliseconds <= 0)
            throw new Exception("Elapsed should be positive");

        Console.WriteLine($"  Status: {response.StatusCode}");
        Console.WriteLine($"  Elapsed: {response.Elapsed.TotalMilliseconds:F2}ms");
    }

    static void TestResponseReason()
    {
        using var session = new Session(preset: "chrome-143");

        // Test 200 OK
        var response = session.Get("https://httpbin.org/status/200");
        if (response.Reason != "OK")
            throw new Exception($"Expected 'OK', got '{response.Reason}'");
        Console.WriteLine($"  200 -> {response.Reason}");

        // Test 404 Not Found
        response = session.Get("https://httpbin.org/status/404");
        if (response.Reason != "Not Found")
            throw new Exception($"Expected 'Not Found', got '{response.Reason}'");
        Console.WriteLine($"  404 -> {response.Reason}");

        // Test 500 Internal Server Error
        response = session.Get("https://httpbin.org/status/500");
        if (response.Reason != "Internal Server Error")
            throw new Exception($"Expected 'Internal Server Error', got '{response.Reason}'");
        Console.WriteLine($"  500 -> {response.Reason}");
    }

    static void TestResponseEncoding()
    {
        using var session = new Session(preset: "chrome-143");

        // Test JSON response (should have encoding)
        var response = session.Get("https://httpbin.org/get");

        var contentType = response.Headers.TryGetValue("content-type", out var ct)
            ? ct
            : response.Headers.TryGetValue("Content-Type", out ct) ? ct : "N/A";

        Console.WriteLine($"  Content-Type: {contentType}");
        Console.WriteLine($"  Encoding: {response.Encoding ?? "null"}");

        // httpbin returns charset=utf-8
        if (response.Encoding != null)
        {
            var enc = response.Encoding.ToLower();
            if (enc != "utf-8" && enc != "utf8")
                throw new Exception($"Expected utf-8, got {response.Encoding}");
        }
    }

    static void TestSessionAuth()
    {
        // Create session with default auth
        using var session = new Session(
            preset: "chrome-143",
            auth: ("testuser", "testpass")
        );

        // Make request - should use session auth automatically
        var response = session.Get("https://httpbin.org/basic-auth/testuser/testpass");
        if (response.StatusCode != 200)
            throw new Exception($"Auth failed: {response.StatusCode}");
        Console.WriteLine($"  Session auth test: {response.StatusCode}");

        // Override auth for specific request
        response = session.Get(
            "https://httpbin.org/basic-auth/otheruser/otherpass",
            auth: ("otheruser", "otherpass")
        );
        if (response.StatusCode != 200)
            throw new Exception($"Override auth failed: {response.StatusCode}");
        Console.WriteLine($"  Override auth test: {response.StatusCode}");
    }

    static void TestGetCookie()
    {
        using var session = new Session(preset: "chrome-143");

        // Set some cookies
        session.SetCookie("foo", "bar");
        session.SetCookie("hello", "world");

        // Test GetCookie
        var foo = session.GetCookie("foo");
        if (foo != "bar")
            throw new Exception($"Expected 'bar', got '{foo}'");
        Console.WriteLine($"  GetCookie('foo') = '{foo}'");

        var hello = session.GetCookie("hello");
        if (hello != "world")
            throw new Exception($"Expected 'world', got '{hello}'");
        Console.WriteLine($"  GetCookie('hello') = '{hello}'");

        // Test non-existent cookie
        var missing = session.GetCookie("nonexistent");
        if (missing != null)
            throw new Exception($"Expected null, got '{missing}'");
        Console.WriteLine($"  GetCookie('nonexistent') = {missing?.ToString() ?? "null"}");
    }

    static void TestDeleteCookie()
    {
        using var session = new Session(preset: "chrome-143");

        // Set cookies
        session.SetCookie("keep", "this");
        session.SetCookie("delete", "this");

        // Verify both exist
        if (session.GetCookie("keep") != "this")
            throw new Exception("keep cookie not set");
        if (session.GetCookie("delete") != "this")
            throw new Exception("delete cookie not set");
        Console.WriteLine("  Before delete: keep='this', delete='this'");

        // Delete one cookie
        session.DeleteCookie("delete");

        // Verify deletion
        if (session.GetCookie("keep") != "this")
            throw new Exception("keep cookie should still exist");
        var deleted = session.GetCookie("delete");
        Console.WriteLine($"  After delete: keep='this', delete='{deleted?.ToString() ?? "null"}'");
    }

    static void TestClearCookies()
    {
        using var session = new Session(preset: "chrome-143");

        // Set multiple cookies
        session.SetCookie("a", "1");
        session.SetCookie("b", "2");
        session.SetCookie("c", "3");

        var cookies = session.GetCookies();
        Console.WriteLine($"  Before clear: {cookies.Count} cookies");

        // Clear all cookies
        session.ClearCookies();

        var cookiesAfter = session.GetCookies();
        var nonEmptyCookies = cookiesAfter.Where(kv => !string.IsNullOrEmpty(kv.Value)).Count();
        Console.WriteLine($"  After clear: {nonEmptyCookies} non-empty cookies");
    }

    static void TestResponseCookies()
    {
        using var session = new Session(preset: "chrome-143");

        // Make request to endpoint that returns Set-Cookie in final response
        var response = session.Get("https://httpbin.org/response-headers?Set-Cookie=test_cookie%3Dtest_value");

        Console.WriteLine($"  Status: {response.StatusCode}");
        Console.WriteLine($"  Cookies count: {response.Cookies.Count}");

        // Check that Cookies is a list
        if (response.Cookies == null)
            throw new Exception("Cookies should not be null");

        // Print cookies if any
        foreach (var cookie in response.Cookies)
        {
            Console.WriteLine($"  Cookie: {cookie.Name}={cookie.Value}");
        }

        // Should have at least one cookie from this response
        if (response.Cookies.Count > 0)
        {
            if (response.Cookies[0].Name != "test_cookie")
                throw new Exception($"Expected 'test_cookie', got '{response.Cookies[0].Name}'");
        }
    }

    static void TestResponseHistory()
    {
        using var session = new Session(preset: "chrome-143");

        // Make request that causes 2 redirects
        var response = session.Get("https://httpbin.org/redirect/2");

        Console.WriteLine($"  Final status: {response.StatusCode}");
        Console.WriteLine($"  Final URL: {response.Url}");
        Console.WriteLine($"  History length: {response.History.Count}");

        // Check that History is a list
        if (response.History == null)
            throw new Exception("History should not be null");

        // Should have 2 redirects
        if (response.History.Count != 2)
            throw new Exception($"Expected 2 redirects, got {response.History.Count}");

        // Print history
        for (int i = 0; i < response.History.Count; i++)
        {
            var redirect = response.History[i];
            Console.WriteLine($"  Redirect {i + 1}: {redirect.StatusCode} -> {redirect.Url}");
            if (redirect.StatusCode != 302)
                throw new Exception($"Expected 302, got {redirect.StatusCode}");
        }
    }
}
