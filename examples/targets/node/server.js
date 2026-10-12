// Intentionally simple Node.js practice target for PeregrineStoop.
// Run locally and point stoop at it. Authorized self-testing only.
//   node examples/targets/node/server.js   (listens on 127.0.0.1:8001)
const http = require("http");
const { URL } = require("url");

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://127.0.0.1:8001");
  res.setHeader("Server", "nginx");
  res.setHeader("Set-Cookie", "connect.sid=s%3Ademo; Path=/");

  if (u.pathname === "/robots.txt") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("User-agent: *\nDisallow: /internal/\n");
  }
  if (u.pathname === "/go") {
    // demo open-redirect: reflects `next` into Location unchanged
    res.writeHead(302, { Location: u.searchParams.get("next") || "/" });
    return res.end();
  }
  if (u.pathname === "/api/v1/users") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify([{ id: 1, name: "demo" }]));
  }

  // demo reflected input: `q` echoed into HTML unencoded
  const q = u.searchParams.get("q") || "";
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(
    `<!doctype html><title>Node demo target</title><body>` +
    `<h1>Node demo target</h1><p>You searched for: ${q}</p>` +
    `<a href="/admin/panel">admin</a>` +
    `<script>axios.get("/api/v1/users");fetch("/internal/debug");</script>` +
    `</body>`
  );
});

server.listen(8001, "127.0.0.1", () =>
  console.log("Node demo target on http://127.0.0.1:8001")
);
