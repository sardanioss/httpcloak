/**
 * Session Resumption (0-RTT)
 *
 * This example demonstrates TLS session resumption which dramatically
 * improves bot detection scores by making connections look like
 * returning visitors rather than new connections.
 *
 * Key concepts:
 * - First connection: Bot score ~43 (new TLS handshake)
 * - Resumed connection: Bot score ~99 (looks like returning visitor)
 * - Cross-domain warming: Session tickets work across same-infrastructure sites
 *
 * Run: node 11_session_resumption.js
 */

const httpcloak = require("httpcloak");
const fs = require("fs");

const SESSION_FILE = "session_state.json";

async function main() {
  // ===========================================================================
  // Example 1: Basic Session Save/Load (File-based)
  // ===========================================================================
  console.log("=".repeat(60));
  console.log("Example 1: Save and Load Session (File)");
  console.log("-".repeat(60));

  let session;

  if (fs.existsSync(SESSION_FILE)) {
    console.log("Loading existing session...");
    session = httpcloak.Session.load(SESSION_FILE);
    console.log("Session loaded with TLS tickets!");
  } else {
    console.log("Creating new session...");
    session = new httpcloak.Session({ preset: "chrome-143" });

    // Warm up - this acquires TLS session tickets
    console.log("Warming up session...");
    const r = await session.get("https://cloudflare.com/cdn-cgi/trace");
    console.log(`Warmup complete - Protocol: ${r.protocol}`);
  }

  // Make request (will use 0-RTT if session was loaded)
  let r = await session.get("https://www.cloudflare.com/cdn-cgi/trace");
  console.log(`Request - Protocol: ${r.protocol}`);

  // Save session for next run
  session.save(SESSION_FILE);
  console.log(`Session saved to ${SESSION_FILE}`);
  session.close();

  // ===========================================================================
  // Example 2: Marshal/Unmarshal (For databases, Redis, etc.)
  // ===========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("Example 2: Marshal/Unmarshal Session (String)");
  console.log("-".repeat(60));

  // Create and warm up session
  session = new httpcloak.Session({ preset: "chrome-143" });
  await session.get("https://cloudflare.com/");

  // Export to JSON string (store in Redis, database, etc.)
  const sessionData = session.marshal();
  console.log(`Marshaled session: ${sessionData.length} bytes`);
  session.close();

  // Later: restore from string
  const restored = httpcloak.Session.unmarshal(sessionData);
  r = await restored.get("https://www.cloudflare.com/cdn-cgi/trace");
  console.log(`Restored session request - Protocol: ${r.protocol}`);
  restored.close();

  // ===========================================================================
  // Example 3: Cross-Domain Session Warming (Cloudflare)
  // ===========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("Example 3: Cross-Domain Warming");
  console.log("-".repeat(60));

  session = new httpcloak.Session({ preset: "chrome-143" });

  // Warm up on cloudflare.com (safe, no bot detection)
  console.log("Warming up on cloudflare.com...");
  r = await session.get("https://cloudflare.com/cdn-cgi/trace");
  console.log(`Warmup - Protocol: ${r.protocol}`);

  // The TLS session ticket works on OTHER Cloudflare sites!
  console.log("\nUsing warmed session on cf.erisa.uk (CF-protected)...");
  r = await session.get("https://cf.erisa.uk/");
  const data = r.json();
  const botScore = data.botManagement?.score ?? "N/A";
  console.log(`Bot Score: ${botScore}`);
  console.log(`Protocol: ${r.protocol}`);

  session.close();

  // ===========================================================================
  // Example 4: Synchronous Session Save/Load
  // ===========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("Example 4: Sync Operations");
  console.log("-".repeat(60));

  session = new httpcloak.Session({ preset: "chrome-143" });

  // Sync warmup
  session.getSync("https://cloudflare.com/cdn-cgi/trace");
  console.log("Warmup complete (sync)");

  // Save
  session.save("sync_session.json");

  // Load and use
  const syncSession = httpcloak.Session.load("sync_session.json");
  r = syncSession.getSync("https://cf.erisa.uk/");
  console.log(`Bot Score: ${r.json().botManagement?.score}`);

  syncSession.close();
  session.close();

  // Cleanup
  for (const f of [SESSION_FILE, "sync_session.json"]) {
    if (fs.existsSync(f)) fs.unlinkSync(f);
  }

  console.log("\n" + "=".repeat(60));
  console.log("Session resumption examples completed!");
  console.log("=".repeat(60));
}

main().catch(console.error);
