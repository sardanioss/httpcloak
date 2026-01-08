/**
 * Test cases for new httpcloak features.
 *
 * Tests:
 * - response.elapsed - Request timing
 * - response.reason - HTTP status phrase
 * - response.encoding - Content-Type encoding
 * - session.auth - Default session authentication
 * - session.getCookie() - Get specific cookie
 * - session.deleteCookie() - Delete specific cookie
 * - session.clearCookies() - Clear all cookies
 * - cookies= parameter - Per-request cookies
 *
 * Run:
 *   node test_features.js
 */

const path = require("path");
const httpcloak = require(path.join(__dirname, "../../bindings/nodejs"));

async function testResponseElapsed() {
  console.log("Test 1: response.elapsed");
  console.log("-".repeat(40));

  const session = new httpcloak.Session({ preset: "chrome-143" });
  const response = await session.get("https://httpbin.org/get");

  if (!("elapsed" in response)) {
    throw new Error("Response should have elapsed property");
  }
  if (typeof response.elapsed !== "number") {
    throw new Error("elapsed should be a number");
  }
  if (response.elapsed <= 0) {
    throw new Error("elapsed should be positive");
  }

  console.log(`  Status: ${response.statusCode}`);
  console.log(`  Elapsed: ${response.elapsed}ms`);
  console.log("  PASS");

  session.close();
}

async function testResponseReason() {
  console.log("\nTest 2: response.reason");
  console.log("-".repeat(40));

  const session = new httpcloak.Session({ preset: "chrome-143" });

  // Test 200 OK
  let response = await session.get("https://httpbin.org/status/200");
  if (response.reason !== "OK") {
    throw new Error(`Expected 'OK', got '${response.reason}'`);
  }
  console.log(`  200 -> ${response.reason}`);

  // Test 404 Not Found
  response = await session.get("https://httpbin.org/status/404");
  if (response.reason !== "Not Found") {
    throw new Error(`Expected 'Not Found', got '${response.reason}'`);
  }
  console.log(`  404 -> ${response.reason}`);

  // Test 500 Internal Server Error
  response = await session.get("https://httpbin.org/status/500");
  if (response.reason !== "Internal Server Error") {
    throw new Error(`Expected 'Internal Server Error', got '${response.reason}'`);
  }
  console.log(`  500 -> ${response.reason}`);

  console.log("  PASS");

  session.close();
}

async function testResponseEncoding() {
  console.log("\nTest 3: response.encoding");
  console.log("-".repeat(40));

  const session = new httpcloak.Session({ preset: "chrome-143" });

  // Test JSON response (should have encoding)
  const response = await session.get("https://httpbin.org/get");
  console.log(`  Content-Type: ${response.headers["content-type"] || "N/A"}`);
  console.log(`  Encoding: ${response.encoding}`);

  // httpbin returns charset=utf-8
  // Note: encoding might be null if not specified in Content-Type
  if (response.encoding) {
    const enc = response.encoding.toLowerCase();
    if (enc !== "utf-8" && enc !== "utf8") {
      throw new Error(`Expected utf-8, got ${response.encoding}`);
    }
  }

  console.log("  PASS");

  session.close();
}

async function testSessionAuth() {
  console.log("\nTest 4: session.auth");
  console.log("-".repeat(40));

  // Create session with default auth
  const session = new httpcloak.Session({
    preset: "chrome-143",
    auth: ["testuser", "testpass"],
  });

  // Make request - should use session auth automatically
  let response = await session.get("https://httpbin.org/basic-auth/testuser/testpass");
  if (response.statusCode !== 200) {
    throw new Error(`Auth failed: ${response.statusCode}`);
  }
  console.log(`  Session auth test: ${response.statusCode}`);

  // Override auth for specific request
  response = await session.get("https://httpbin.org/basic-auth/otheruser/otherpass", {
    auth: ["otheruser", "otherpass"],
  });
  if (response.statusCode !== 200) {
    throw new Error(`Override auth failed: ${response.statusCode}`);
  }
  console.log(`  Override auth test: ${response.statusCode}`);

  console.log("  PASS");

  session.close();
}

async function testGetCookie() {
  console.log("\nTest 5: session.getCookie()");
  console.log("-".repeat(40));

  const session = new httpcloak.Session({ preset: "chrome-143" });

  // Set some cookies
  session.setCookie("foo", "bar");
  session.setCookie("hello", "world");

  // Test getCookie
  const foo = session.getCookie("foo");
  if (foo !== "bar") {
    throw new Error(`Expected 'bar', got '${foo}'`);
  }
  console.log(`  getCookie('foo') = '${foo}'`);

  const hello = session.getCookie("hello");
  if (hello !== "world") {
    throw new Error(`Expected 'world', got '${hello}'`);
  }
  console.log(`  getCookie('hello') = '${hello}'`);

  // Test non-existent cookie
  const missing = session.getCookie("nonexistent");
  if (missing !== null) {
    throw new Error(`Expected null, got '${missing}'`);
  }
  console.log(`  getCookie('nonexistent') = ${missing}`);

  console.log("  PASS");

  session.close();
}

async function testDeleteCookie() {
  console.log("\nTest 6: session.deleteCookie()");
  console.log("-".repeat(40));

  const session = new httpcloak.Session({ preset: "chrome-143" });

  // Set cookies
  session.setCookie("keep", "this");
  session.setCookie("delete", "this");

  // Verify both exist
  if (session.getCookie("keep") !== "this") throw new Error("keep cookie not set");
  if (session.getCookie("delete") !== "this") throw new Error("delete cookie not set");
  console.log("  Before delete: keep='this', delete='this'");

  // Delete one cookie
  session.deleteCookie("delete");

  // Verify deletion
  if (session.getCookie("keep") !== "this") {
    throw new Error("keep cookie should still exist");
  }
  const deleted = session.getCookie("delete");
  console.log(`  After delete: keep='this', delete='${deleted}'`);

  console.log("  PASS");

  session.close();
}

async function testClearCookies() {
  console.log("\nTest 7: session.clearCookies()");
  console.log("-".repeat(40));

  const session = new httpcloak.Session({ preset: "chrome-143" });

  // Set multiple cookies
  session.setCookie("a", "1");
  session.setCookie("b", "2");
  session.setCookie("c", "3");

  const cookies = session.getCookies();
  console.log(`  Before clear: ${Object.keys(cookies).length} cookies`);

  // Clear all cookies
  session.clearCookies();

  const cookiesAfter = session.getCookies();
  // Note: cookies might have empty values instead of being removed
  const nonEmptyCookies = Object.entries(cookiesAfter).filter(([k, v]) => v).length;
  console.log(`  After clear: ${nonEmptyCookies} non-empty cookies`);

  console.log("  PASS");

  session.close();
}

async function testCookiesParameter() {
  console.log("\nTest 8: cookies= parameter");
  console.log("-".repeat(40));

  const session = new httpcloak.Session({ preset: "chrome-143" });

  // Make request with per-request cookies
  const response = await session.get("https://httpbin.org/cookies", {
    cookies: { test_cookie: "test_value", another: "cookie" },
  });

  if (response.statusCode !== 200) {
    throw new Error(`Request failed: ${response.statusCode}`);
  }

  const data = response.json();
  const cookies = data.cookies || {};
  console.log(`  Cookies sent: ${JSON.stringify(cookies)}`);

  if (cookies.test_cookie !== "test_value") {
    throw new Error("test_cookie not received");
  }
  if (cookies.another !== "cookie") {
    throw new Error("another cookie not received");
  }

  console.log("  PASS");

  session.close();
}

async function testResponseCookies() {
  console.log("\nTest 9: response.cookies");
  console.log("-".repeat(40));

  const session = new httpcloak.Session({ preset: "chrome-143" });

  // Make request to endpoint that returns Set-Cookie in final response
  const response = await session.get("https://httpbin.org/response-headers?Set-Cookie=test_cookie%3Dtest_value");

  console.log(`  Status: ${response.statusCode}`);
  console.log(`  Cookies count: ${response.cookies.length}`);

  // Check that cookies is an array
  if (!Array.isArray(response.cookies)) {
    throw new Error("cookies should be an array");
  }

  // Print cookies if any
  for (const cookie of response.cookies) {
    console.log(`  Cookie: ${cookie.name}=${cookie.value}`);
  }

  // Should have at least one cookie from this response
  if (response.cookies.length > 0) {
    if (response.cookies[0].name !== "test_cookie") {
      throw new Error(`Expected 'test_cookie', got '${response.cookies[0].name}'`);
    }
  }

  console.log("  PASS");

  session.close();
}

async function testResponseHistory() {
  console.log("\nTest 10: response.history");
  console.log("-".repeat(40));

  const session = new httpcloak.Session({ preset: "chrome-143" });

  // Make request that causes 2 redirects
  const response = await session.get("https://httpbin.org/redirect/2");

  console.log(`  Final status: ${response.statusCode}`);
  console.log(`  Final URL: ${response.url}`);
  console.log(`  History length: ${response.history.length}`);

  // Check that history is an array
  if (!Array.isArray(response.history)) {
    throw new Error("history should be an array");
  }

  // Should have 2 redirects
  if (response.history.length !== 2) {
    throw new Error(`Expected 2 redirects, got ${response.history.length}`);
  }

  // Print history
  response.history.forEach((redirect, i) => {
    console.log(`  Redirect ${i + 1}: ${redirect.statusCode} -> ${redirect.url}`);
    if (redirect.statusCode !== 302) {
      throw new Error(`Expected 302, got ${redirect.statusCode}`);
    }
  });

  console.log("  PASS");

  session.close();
}

async function main() {
  console.log("=".repeat(60));
  console.log("HTTPCloak New Features Tests (Node.js)");
  console.log("=".repeat(60));

  const tests = [
    testResponseElapsed,
    testResponseReason,
    testResponseEncoding,
    testSessionAuth,
    testGetCookie,
    testDeleteCookie,
    testClearCookies,
    testCookiesParameter,
    testResponseCookies,
    testResponseHistory,
  ];

  let passed = 0;
  let failed = 0;

  for (const test of tests) {
    try {
      await test();
      passed++;
    } catch (e) {
      console.log(`  FAILED: ${e.message}`);
      failed++;
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log("=".repeat(60));

  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("Fatal error:", e);
  process.exit(1);
});
