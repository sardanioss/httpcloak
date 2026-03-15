/**
 * Configuration and Browser Presets
 *
 * This example demonstrates:
 * - Using configure() for global defaults
 * - Different browser presets
 * - Forcing HTTP versions
 * - Header order customization
 *
 * Run: node 02_configure_and_presets.js
 */

const httpcloak = require("httpcloak");

async function main() {
  // Configure global defaults
  console.log("=".repeat(60));
  console.log("Example 1: Configure Global Defaults");
  console.log("-".repeat(60));

  httpcloak.configure({
    preset: "chrome-latest-linux",
    headers: { "Accept-Language": "en-US,en;q=0.9" },
    timeout: 30,
  });

  let r = await httpcloak.get("https://www.cloudflare.com/cdn-cgi/trace");
  console.log(`Protocol: ${r.protocol}`);
  console.log("First few lines of trace:");
  r.text
    .split("\n")
    .slice(0, 5)
    .forEach((line) => console.log(`  ${line}`));

  // Different browser presets
  console.log("\n" + "=".repeat(60));
  console.log("Example 2: Different Browser Presets");
  console.log("-".repeat(60));

  const presets = [
    "chrome-latest",
    "chrome-latest-windows",
    "chrome-latest-linux",
    "chrome-143",
    "firefox-133",
    "safari-18",
  ];

  for (const preset of presets) {
    const session = new httpcloak.Session({ preset });
    const r = await session.get("https://www.cloudflare.com/cdn-cgi/trace");

    // Parse trace to get HTTP version
    const trace = {};
    r.text.split("\n").forEach((line) => {
      const [key, value] = line.split("=");
      if (key && value) trace[key] = value;
    });

    console.log(
      `${preset.padEnd(25)} | Protocol: ${r.protocol.padEnd(5)} | http=${trace.http || "N/A"}`
    );
    session.close();
  }

  // Force HTTP versions
  console.log("\n" + "=".repeat(60));
  console.log("Example 3: Force HTTP Versions");
  console.log("-".repeat(60));

  const httpVersions = ["auto", "h1", "h2", "h3"];

  for (const version of httpVersions) {
    const session = new httpcloak.Session({
      preset: "chrome-latest",
      httpVersion: version,
    });

    try {
      const r = await session.get("https://www.cloudflare.com/cdn-cgi/trace");
      const trace = {};
      r.text.split("\n").forEach((line) => {
        const [key, value] = line.split("=");
        if (key && value) trace[key] = value;
      });

      console.log(
        `httpVersion=${version.padEnd(5)} | Actual Protocol: ${r.protocol.padEnd(5)} | http=${trace.http || "N/A"}`
      );
    } catch (e) {
      console.log(`httpVersion=${version.padEnd(5)} | Error: ${e.message}`);
    } finally {
      session.close();
    }
  }

  // List available presets
  console.log("\n" + "=".repeat(60));
  console.log("Example 4: List Available Presets");
  console.log("-".repeat(60));

  const availablePresets = httpcloak.availablePresets();
  console.log("Available presets:");
  availablePresets.forEach((preset) => console.log(`  - ${preset}`));

  console.log(`\nhttpcloak version: ${httpcloak.version()}`);

  // Header order customization
  console.log("\n" + "=".repeat(60));
  console.log("Example 5: Header Order Customization");
  console.log("-".repeat(60));

  const session = new httpcloak.Session({ preset: "chrome-latest" });

  // Get default header order from preset
  const defaultOrder = session.getHeaderOrder();
  console.log(`Default header order (${defaultOrder.length} headers):`);
  defaultOrder.slice(0, 5).forEach((header, i) => {
    console.log(`  ${i + 1}. ${header}`);
  });
  console.log(`  ... and ${defaultOrder.length - 5} more`);

  // Set custom header order
  const customOrder = ["accept", "user-agent", "sec-ch-ua", "accept-language", "accept-encoding"];
  session.setHeaderOrder(customOrder);
  console.log(`\nCustom order set: ${JSON.stringify(session.getHeaderOrder())}`);

  // Make request with custom order
  const resp = await session.get("https://httpbin.org/headers");
  console.log(`Request with custom order - Status: ${resp.statusCode}, Protocol: ${resp.protocol}`);

  // Reset to default
  session.setHeaderOrder([]);
  const resetOrder = session.getHeaderOrder();
  console.log(`Reset to default (${resetOrder.length} headers): ${JSON.stringify(resetOrder.slice(0, 3))}...`);

  session.close();

  console.log("\n" + "=".repeat(60));
  console.log("Configuration examples completed!");
  console.log("=".repeat(60));
}

main().catch(console.error);
