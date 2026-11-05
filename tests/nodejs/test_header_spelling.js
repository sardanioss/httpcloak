// Lock for header spellings the caller chose.
//
// The transport sends one spelling of a header name and prefers the canonical
// one, so anything the binding or the session adds beside a caller's lowercase
// spelling must not replace the caller's value. Local server only.
//
// Run from the repo root: node tests/nodejs/test_header_spelling.js

const assert = require("assert");
const http = require("http");
const path = require("path");

const httpcloak = require(path.join(__dirname, "../../bindings/nodejs/lib/index.js"));

const server = http.createServer((req, res) => {
  req.resume();
  req.on("end", () => {
    const all = (name) => {
      const out = [];
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        if (req.rawHeaders[i].toLowerCase() === name) out.push(req.rawHeaders[i + 1]);
      }
      return out;
    };
    const body = JSON.stringify({ cookie: all("cookie"), contentType: all("content-type"), authorization: all("authorization") });
    res.writeHead(200, { "Set-Cookie": "jar=1; Path=/", "Content-Type": "application/json" });
    res.end(body);
  });
});

server.listen(0, "127.0.0.1", async () => {
  const url = `http://127.0.0.1:${server.address().port}/`;
  const session = new httpcloak.Session({ preset: "chrome-latest", httpVersion: "h1" });
  try {
    await session.get(url); // the jar now holds jar=1
    for (let i = 0; i < 5; i++) {
      let got = (await session.get(url, { headers: { cookie: "mine=1" }, cookies: { c: "3" } })).json();
      assert.strictEqual(got.cookie.length, 1, JSON.stringify(got));
      for (const part of ["mine=1", "c=3", "jar=1"]) assert.ok(got.cookie[0].includes(part), JSON.stringify(got));

      got = (await session.post(url, { json: { a: 1 }, headers: { "content-type": "application/vnd.api+json" } })).json();
      assert.deepStrictEqual(got.contentType, ["application/vnd.api+json"]);
    }
    const got = (await session.get(url, { auth: ["u", "p"], headers: { authorization: "Bearer mine" } })).json();
    assert.deepStrictEqual(got.authorization, ["Basic dTpw"]);
    console.log("ok");
  } finally {
    session.close();
    server.close();
  }
});
