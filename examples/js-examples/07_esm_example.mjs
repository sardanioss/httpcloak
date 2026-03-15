/**
 * ESM (ES Modules) Example
 *
 * This example demonstrates using httpcloak with ES Modules syntax.
 * ES Modules use 'import' instead of 'require'.
 *
 * Note: This file uses .mjs extension to indicate it's an ES Module.
 * Alternatively, you can set "type": "module" in your package.json.
 *
 * Run: node 07_esm_example.mjs
 */

// ============================================================
// Import Styles
// ============================================================

// Default import - get the entire module
import httpcloak from "httpcloak";

// Named imports - import specific functions/classes
import { Session, get, post, version, availablePresets, Preset } from "httpcloak";

// ============================================================
// Example 1: Using Named Imports
// ============================================================
console.log("=".repeat(60));
console.log("Example 1: Using Named Imports");
console.log("-".repeat(60));

// version() and availablePresets() are utility functions
console.log(`httpcloak version: ${version()}`);
console.log(`Available presets: ${availablePresets().slice(0, 5).join(", ")}...`);

// Preset is an object with preset name constants
console.log(`\nPreset constants:`);
console.log(`  Preset.CHROME_143 = "${Preset.CHROME_143}"`);
console.log(`  Preset.FIREFOX_133 = "${Preset.FIREFOX_133}"`);

// ============================================================
// Example 2: Module-Level get() and post()
// ============================================================
console.log("\n" + "=".repeat(60));
console.log("Example 2: Module-Level Functions");
console.log("-".repeat(60));

// Simple GET using the module-level function
const response = await get("https://httpbin.org/get");
console.log(`GET Status: ${response.statusCode}`);
console.log(`Protocol: ${response.protocol}`);

// POST with JSON
const postResponse = await post("https://httpbin.org/post", {
  json: { source: "ESM module", timestamp: new Date().toISOString() },
});
console.log(`POST Status: ${postResponse.statusCode}`);

// ============================================================
// Example 3: Using the Session Class
// ============================================================
console.log("\n" + "=".repeat(60));
console.log("Example 3: Session Class");
console.log("-".repeat(60));

// Create a session with named import
const session = new Session({
  preset: Preset.CHROME_143,
  httpVersion: "h2",
});

// Make requests
const r1 = await session.get("https://httpbin.org/get");
console.log(`Session GET: ${r1.statusCode}`);

// Set and get cookies
session.setCookie("esm_test", "hello_from_esm");
console.log(`Cookies:`, session.getCookies());

// Cleanup
session.close();

// ============================================================
// Example 4: Default Import Usage
// ============================================================
console.log("\n" + "=".repeat(60));
console.log("Example 4: Default Import");
console.log("-".repeat(60));

// You can also use the default import for everything
const session2 = new httpcloak.Session({ preset: "chrome-latest" });
const r2 = await session2.get("https://httpbin.org/headers");
console.log(`Default import GET: ${r2.statusCode}`);
session2.close();

// ============================================================
// Example 5: Async/Await Pattern with ESM
// ============================================================
console.log("\n" + "=".repeat(60));
console.log("Example 5: Top-Level Await (ESM Feature)");
console.log("-".repeat(60));

// ESM supports top-level await (no need to wrap in async function)
// This entire file uses top-level await!

const urls = ["https://httpbin.org/get", "https://httpbin.org/ip"];
const responses = await Promise.all(urls.map((url) => get(url)));
console.log(`Fetched ${responses.length} URLs concurrently`);
responses.forEach((r, i) => {
  console.log(`  ${urls[i].split("/").pop()}: ${r.statusCode}`);
});

console.log("\n" + "=".repeat(60));
console.log("ESM examples completed!");
console.log("=".repeat(60));
