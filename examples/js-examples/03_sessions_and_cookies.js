/**
 * Sessions and Cookie Management
 *
 * This example demonstrates:
 * - Using Session for persistent connections
 * - Cookie management
 * - Default headers
 *
 * Run: node 03_sessions_and_cookies.js
 */

const httpcloak = require("httpcloak");

async function main() {
  // Session with cookies
  console.log("=".repeat(60));
  console.log("Example 1: Session with Cookies");
  console.log("-".repeat(60));

  const session1 = new httpcloak.Session({ preset: "chrome-latest" });

  // Set a cookie via endpoint
  let r = await session1.get("https://httpbin.org/cookies/set/session_id/abc123");
  console.log(`Set cookie - Status: ${r.statusCode}`);

  // Check cookies in session
  const cookies = session1.cookies;
  console.log(`Cookies in session:`, cookies);

  // Second request (cookies sent automatically)
  r = await session1.get("https://httpbin.org/cookies");
  console.log(`Cookies endpoint:`, r.json());

  session1.close();

  // Session with default headers
  console.log("\n" + "=".repeat(60));
  console.log("Example 2: Session with Default Headers");
  console.log("-".repeat(60));

  const session2 = new httpcloak.Session({ preset: "chrome-latest" });
  session2.headers["Authorization"] = "Bearer my-token";
  session2.headers["X-API-Key"] = "secret-key";

  r = await session2.get("https://httpbin.org/headers");
  const headers = r.json().headers;
  console.log(`Authorization sent: ${"Authorization" in headers}`);
  console.log(`X-API-Key sent: ${"X-Api-Key" in headers}`);

  session2.close();

  // Manual cookie management
  console.log("\n" + "=".repeat(60));
  console.log("Example 3: Manual Cookie Management");
  console.log("-".repeat(60));

  const session3 = new httpcloak.Session({ preset: "chrome-latest" });

  // Set cookies manually
  session3.setCookie("user_id", "12345");
  session3.setCookie("preferences", "dark_mode");

  // Check cookies
  console.log(`Cookies set:`, session3.getCookies());

  // Make request with cookies
  r = await session3.get("https://httpbin.org/cookies");
  console.log(`Cookies sent to server:`, r.json());

  session3.close();

  // Multiple requests with same session
  console.log("\n" + "=".repeat(60));
  console.log("Example 4: Multiple Requests (Connection Reuse)");
  console.log("-".repeat(60));

  const session4 = new httpcloak.Session({ preset: "chrome-latest" });

  const urls = [
    "https://httpbin.org/get",
    "https://httpbin.org/headers",
    "https://httpbin.org/user-agent",
  ];

  for (let i = 0; i < urls.length; i++) {
    const url = urls[i];
    const r = await session4.get(url);
    const endpoint = url.split("/").pop();
    console.log(
      `Request ${i + 1}: ${endpoint.padEnd(15)} | Status: ${r.statusCode} | Protocol: ${r.protocol}`
    );
  }

  session4.close();

  console.log("\n" + "=".repeat(60));
  console.log("Session examples completed!");
  console.log("=".repeat(60));
}

main().catch(console.error);
