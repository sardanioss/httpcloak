/**
 * Runtime Proxy Switching
 *
 * This example demonstrates:
 * - Switching proxies mid-session without creating new sessions
 * - Split proxy configuration (different proxies for TCP and UDP)
 * - Getting current proxy configuration
 * - H2 and H3 proxy switching
 */

const httpcloak = require("httpcloak");

// Test URL that shows your IP
const TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace";

function parseTrace(body) {
  const result = {};
  for (const line of body.trim().split("\n")) {
    const idx = line.indexOf("=");
    if (idx !== -1) {
      result[line.slice(0, idx)] = line.slice(idx + 1);
    }
  }
  return result;
}

async function main() {
  // Basic proxy switching
  console.log("=".repeat(60));
  console.log("Example 1: Basic Proxy Switching");
  console.log("-".repeat(60));

  // Create session without proxy (direct connection)
  const session = new httpcloak.Session({ preset: "chrome-latest" });

  // Make request with direct connection
  let r = await session.get(TEST_URL);
  let trace = parseTrace(r.text);
  console.log("Direct connection:");
  console.log(`  Protocol: ${r.protocol}, IP: ${trace.ip}, Colo: ${trace.colo}`);

  // Switch to a proxy (replace with your actual proxy)
  // session.setProxy("http://user:pass@proxy.example.com:8080");
  // r = await session.get(TEST_URL);
  // trace = parseTrace(r.text);
  // console.log("\nAfter switching to HTTP proxy:");
  // console.log(`  Protocol: ${r.protocol}, IP: ${trace.ip}`);

  // Switch back to direct connection
  // session.setProxy("");
  // console.log(`\nSwitched back to direct: ${session.getProxy()}`);

  session.close();

  // Getting current proxy
  console.log("\n" + "=".repeat(60));
  console.log("Example 2: Getting Current Proxy Configuration");
  console.log("-".repeat(60));

  const session2 = new httpcloak.Session({ preset: "chrome-latest" });

  console.log(`Initial proxy: '${session2.getProxy()}' (empty = direct)`);
  console.log(`TCP proxy: '${session2.getTcpProxy()}'`);
  console.log(`UDP proxy: '${session2.getUdpProxy()}'`);

  // Using property accessor
  console.log(`Proxy (via property): '${session2.proxy}'`);

  session2.close();

  // Split proxy configuration
  console.log("\n" + "=".repeat(60));
  console.log("Example 3: Split Proxy Configuration (TCP vs UDP)");
  console.log("-".repeat(60));

  console.log(`
// Use different proxies for HTTP/1.1+HTTP/2 (TCP) and HTTP/3 (UDP):

const session = new httpcloak.Session({ preset: "chrome-latest" });

// Set TCP proxy for HTTP/1.1 and HTTP/2
session.setTcpProxy("http://tcp-proxy.example.com:8080");

// Set UDP proxy for HTTP/3 (requires SOCKS5 with UDP ASSOCIATE or MASQUE)
session.setUdpProxy("socks5://udp-proxy.example.com:1080");

// Now HTTP/2 requests go through TCP proxy
// and HTTP/3 requests go through UDP proxy

console.log(\`TCP proxy: \${session.getTcpProxy()}\`);
console.log(\`UDP proxy: \${session.getUdpProxy()}\`);
`);

  // HTTP/3 proxy switching
  console.log("\n" + "=".repeat(60));
  console.log("Example 4: HTTP/3 Proxy Switching");
  console.log("-".repeat(60));

  console.log(`
// HTTP/3 requires special proxy support:
// - SOCKS5 with UDP ASSOCIATE (most residential proxies)
// - MASQUE (CONNECT-UDP) - premium providers like Bright Data, Oxylabs

const session = new httpcloak.Session({ preset: "chrome-latest", httpVersion: "h3" });

// Direct H3 connection
let r = await session.get("https://example.com");
console.log(\`Direct: \${r.protocol}\`);

// Switch to SOCKS5 proxy with UDP support
session.setUdpProxy("socks5://user:pass@proxy.example.com:1080");
r = await session.get("https://example.com");
console.log(\`Via SOCKS5: \${r.protocol}\`);

// Switch to MASQUE proxy
session.setUdpProxy("https://user:pass@brd.superproxy.io:10001");
r = await session.get("https://example.com");
console.log(\`Via MASQUE: \${r.protocol}\`);
`);

  // Proxy rotation pattern
  console.log("\n" + "=".repeat(60));
  console.log("Example 5: Proxy Rotation Pattern");
  console.log("-".repeat(60));

  console.log(`
// Rotate through multiple proxies without recreating sessions:

const proxies = [
  "http://proxy1.example.com:8080",
  "http://proxy2.example.com:8080",
  "http://proxy3.example.com:8080",
];

const session = new httpcloak.Session({ preset: "chrome-latest" });

for (let i = 0; i < proxies.length; i++) {
  session.setProxy(proxies[i]);
  const r = await session.get("https://api.ipify.org");
  console.log(\`Request \${i + 1} via \${proxies[i]}: IP = \${r.text}\`);
}

session.close();
`);

  console.log("\n" + "=".repeat(60));
  console.log("Proxy switching examples completed!");
  console.log("=".repeat(60));
}

main().catch(console.error);
