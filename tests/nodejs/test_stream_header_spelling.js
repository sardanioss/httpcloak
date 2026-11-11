// The stream methods follow the same header-spelling rules as the buffered
// ones, json/data never write into the caller's own headers object, and the
// ESM entry exports what the CJS one does.
//
// getStream and friends are synchronous FFI calls, so the echo server runs in
// a child process: one in this process could never answer them.
//
// Run from the repo root: node tests/nodejs/test_stream_header_spelling.js

const assert = require("assert");
const path = require("path");
const { spawn } = require("child_process");

const lib = path.join(__dirname, "../../bindings/nodejs/lib");
const httpcloak = require(path.join(lib, "index.js"));

const serverSrc = `
const http = require("http");
const s = http.createServer((req, res) => {
  req.resume();
  req.on("end", () => {
    const all = (n) => { const o = []; for (let i = 0; i < req.rawHeaders.length; i += 2) if (req.rawHeaders[i].toLowerCase() === n) o.push(req.rawHeaders[i + 1]); return o; };
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ cookie: all("cookie"), contentType: all("content-type"), authorization: all("authorization") }));
  });
});
s.listen(0, "127.0.0.1", () => console.log(s.address().port));
`;

async function main() {
  const child = spawn(process.execPath, ["-e", serverSrc], { stdio: ["ignore", "pipe", "inherit"] });
  const port = await new Promise((resolve) => child.stdout.once("data", (d) => resolve(String(d).trim())));
  const url = `http://127.0.0.1:${port}/`;
  const session = new httpcloak.Session({ preset: "chrome-latest", httpVersion: "h1" });
  const read = (s) => { try { return JSON.parse(s.readAll().toString()); } finally { s.close(); } };
  try {
    session.headers = { Authorization: "Bearer SESSION" };
    const opts = { headers: { authorization: "Bearer REQ", cookie: "mine=1" }, cookies: { c: "3" } };
    for (const [name, got] of [
      ["getStream", read(session.getStream(url, opts))],
      ["postStream", read(session.postStream(url, { ...opts, json: { a: 1 } }))],
      ["requestStream", read(session.requestStream("POST", url, opts))],
    ]) {
      assert.deepStrictEqual(got.authorization, ["Bearer REQ"], `${name}: ${JSON.stringify(got)}`);
      assert.strictEqual(got.cookie.length, 1, `${name}: ${JSON.stringify(got)}`);
      for (const part of ["mine=1", "c=3"]) assert.ok(got.cookie[0].includes(part), `${name}: ${JSON.stringify(got)}`);
    }
    session.headers = {};

    // json= must not write its Content-Type into the caller's object.
    const mine = { "x-a": "1" };
    await session.post(url, { json: { a: 1 }, headers: mine });
    assert.deepStrictEqual(mine, { "x-a": "1" });

    // An upload keeps a lowercase content-type over the octet-stream default.
    const up = await session.uploadStream("POST", url, [Buffer.from("a,b\n")], { headers: { "content-type": "text/csv" } });
    assert.deepStrictEqual(up.json().contentType, ["text/csv"]);

    for (const bad of ["90", true, Infinity, NaN]) {
      assert.throws(() => new httpcloak.Session({ http2MaxConnAge: bad }), TypeError, String(bad));
    }
    new httpcloak.Session({ http2MaxConnAge: 1.5 }).close();
  } finally {
    session.close();
    child.kill();
  }

  const esm = await import(path.join(lib, "index.mjs"));
  const cjsNames = Object.keys(httpcloak).filter((k) => k !== "default" && k !== "__esModule");
  const missing = cjsNames.filter((k) => !(k in esm));
  assert.deepStrictEqual(missing, [], `ESM entry is missing ${missing.join(", ")}`);
  console.log("ok");
}

main().catch((e) => { console.error(e); process.exit(1); });
