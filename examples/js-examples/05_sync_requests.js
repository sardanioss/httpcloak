/**
 * Synchronous Requests
 *
 * This example demonstrates:
 * - Sync GET, POST requests
 * - Using sync methods for simple scripts
 *
 * Run: node 05_sync_requests.js
 */

const httpcloak = require("httpcloak");

// Sync requests (useful when you can't use async/await)
console.log("=".repeat(60));
console.log("Example 1: Synchronous GET Request");
console.log("-".repeat(60));

const session = new httpcloak.Session({ preset: "chrome-latest" });

let r = session.getSync("https://httpbin.org/get");
console.log(`Status: ${r.statusCode}`);
console.log(`Protocol: ${r.protocol}`);

// Sync POST with JSON
console.log("\n" + "=".repeat(60));
console.log("Example 2: Synchronous POST with JSON");
console.log("-".repeat(60));

r = session.postSync("https://httpbin.org/post", {
  json: { message: "Hello from sync!" },
});
console.log(`Status: ${r.statusCode}`);
console.log(`Echoed:`, r.json().json);

// Sync POST with form data
console.log("\n" + "=".repeat(60));
console.log("Example 3: Synchronous POST with Form Data");
console.log("-".repeat(60));

r = session.postSync("https://httpbin.org/post", {
  data: { field1: "value1", field2: "value2" },
});
console.log(`Status: ${r.statusCode}`);
console.log(`Echoed:`, r.json().form);

// Sync with params and headers
console.log("\n" + "=".repeat(60));
console.log("Example 4: Sync with Params and Headers");
console.log("-".repeat(60));

r = session.getSync("https://httpbin.org/get", {
  params: { search: "test", page: 1 },
  headers: { "X-Custom": "value" },
});
console.log(`Status: ${r.statusCode}`);
console.log(`URL: ${r.url}`);

// Sync custom request
console.log("\n" + "=".repeat(60));
console.log("Example 5: Sync Custom Request (PUT)");
console.log("-".repeat(60));

r = session.requestSync("PUT", "https://httpbin.org/put", {
  json: { update: "data" },
});
console.log(`Status: ${r.statusCode}`);
console.log(`Method received:`, r.json().method);

// Multiple sync requests
console.log("\n" + "=".repeat(60));
console.log("Example 6: Multiple Sync Requests");
console.log("-".repeat(60));

const urls = [
  "https://httpbin.org/get",
  "https://httpbin.org/headers",
  "https://httpbin.org/user-agent",
];

urls.forEach((url, i) => {
  const r = session.getSync(url);
  const endpoint = url.split("/").pop();
  console.log(`${i + 1}. ${endpoint.padEnd(12)} | Status: ${r.statusCode}`);
});

session.close();

console.log("\n" + "=".repeat(60));
console.log("Sync examples completed!");
console.log("=".repeat(60));
