/**
 * Authentication and Proxy Usage
 *
 * This example demonstrates:
 * - Basic authentication
 * - Using proxies
 * - Timeout configuration
 * - Error handling
 *
 * Run: node 04_auth_and_proxy.js
 */

const httpcloak = require("httpcloak");

async function main() {
  // Basic authentication
  console.log("=".repeat(60));
  console.log("Example 1: Basic Authentication");
  console.log("-".repeat(60));

  // Per-request auth
  let r = await httpcloak.get("https://httpbin.org/basic-auth/user/pass", {
    auth: ["user", "pass"],
  });
  console.log(`Status: ${r.statusCode}`);
  console.log(`Authenticated: ${r.json().authenticated}`);
  console.log(`User: ${r.json().user}`);

  // Auth with wrong credentials
  r = await httpcloak.get("https://httpbin.org/basic-auth/user/pass", {
    auth: ["wrong", "credentials"],
  });
  console.log(`\nWrong credentials - Status: ${r.statusCode}`);

  // Global auth configuration
  console.log("\n" + "=".repeat(60));
  console.log("Example 2: Global Auth Configuration");
  console.log("-".repeat(60));

  httpcloak.configure({
    preset: "chrome-latest",
    auth: ["user", "pass"],
  });

  r = await httpcloak.get("https://httpbin.org/basic-auth/user/pass");
  console.log(`Status: ${r.statusCode}`);
  console.log("Auth header sent automatically");

  // Reset configuration
  httpcloak.configure({ preset: "chrome-latest" });

  // Timeout configuration
  console.log("\n" + "=".repeat(60));
  console.log("Example 3: Timeout Configuration");
  console.log("-".repeat(60));

  // Session-level timeout
  const session = new httpcloak.Session({ preset: "chrome-latest", timeout: 10 });

  try {
    // This should complete within timeout
    r = await session.get("https://httpbin.org/delay/2");
    console.log(`2s delay - Status: ${r.statusCode} (completed)`);
  } catch (e) {
    console.log(`2s delay - Error: ${e.message}`);
  }

  session.close();

  // Error handling
  console.log("\n" + "=".repeat(60));
  console.log("Example 4: Error Handling");
  console.log("-".repeat(60));

  r = await httpcloak.get("https://httpbin.org/status/404");
  console.log(`404 response - Status: ${r.statusCode}, OK: ${r.ok}`);

  try {
    r.raiseForStatus();
  } catch (e) {
    console.log(`raiseForStatus() raised: ${e.message}`);
  }

  r = await httpcloak.get("https://httpbin.org/status/500");
  console.log(`500 response - Status: ${r.statusCode}, OK: ${r.ok}`);

  // Proxy example (reference)
  console.log("\n" + "=".repeat(60));
  console.log("Example 5: Proxy Configuration (Reference)");
  console.log("-".repeat(60));

  console.log(`
// To use a proxy:
const session = new httpcloak.Session({
  preset: "chrome-latest",
  proxy: "http://user:pass@proxy.example.com:8080"
});

// Or with configure():
httpcloak.configure({
  preset: "chrome-latest",
  proxy: "socks5://user:pass@proxy.example.com:1080"
});

// Supported proxy formats:
// - http://host:port
// - http://user:pass@host:port
// - socks5://host:port
// - socks5://user:pass@host:port

// Speculative TLS optimization (enabled by default):
// Sends CONNECT + TLS ClientHello together, saving one round-trip (~25% faster).
// If you experience issues with certain proxies, disable it:
const session2 = new httpcloak.Session({
  preset: "chrome-latest",
  proxy: "http://user:pass@proxy.example.com:8080",
  disableSpeculativeTls: true
});
`);

  console.log("=".repeat(60));
  console.log("Auth and proxy examples completed!");
  console.log("=".repeat(60));
}

main().catch(console.error);
