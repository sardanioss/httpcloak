/**
 * HTTPCloak Node.js Test
 */

const { Session, version, availablePresets, HTTPCloakError } = require("./lib");

async function main() {
  console.log("=== HTTPCloak Node.js Test ===\n");

  // Test version
  console.log("Version:", version());

  // Test presets
  const presets = availablePresets();
  console.log("Presets:", presets.slice(0, 5).join(", "), "...");
  console.log("");

  // Create session
  const session = new Session({ preset: "chrome-143" });

  try {
    // Test sync GET
    console.log("--- Sync GET ---");
    const syncResponse = session.getSync(
      "https://www.cloudflare.com/cdn-cgi/trace"
    );
    console.log("Status:", syncResponse.statusCode);
    console.log("Protocol:", syncResponse.protocol);
    console.log("");

    // Test async GET
    console.log("--- Async GET (Promise) ---");
    const asyncResponse = await session.get(
      "https://www.cloudflare.com/cdn-cgi/trace"
    );
    console.log("Status:", asyncResponse.statusCode);
    console.log("Protocol:", asyncResponse.protocol);
    console.log("");


    // Test concurrent requests
    console.log("--- Concurrent Requests ---");
    const startTime = Date.now();
    const responses = await Promise.all([
      session.get("https://www.cloudflare.com/cdn-cgi/trace"),
      session.get("https://www.cloudflare.com/cdn-cgi/trace"),
    ]);
    const elapsed = Date.now() - startTime;
    console.log("Concurrent requests:", responses.length);
    console.log("Time:", elapsed, "ms");
    console.log("");

    // Test cookies
    console.log("--- Cookies ---");
    session.setCookie("test_cookie", "test_value");
    const cookies = session.getCookies();
    console.log("Cookies:", JSON.stringify(cookies));
    console.log("");

    console.log("=== All tests passed! ===");
  } catch (err) {
    console.error("Test failed:", err);
    process.exit(1);
  } finally {
    session.close();
  }
}

main();
