/**
 * WARNING: This app is intentionally vulnerable for security testing.
 * Use ONLY in local/lab environments.
 */

const express = require("express");
const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();

const app = express();

// 🔥 Insecure CORS (any origin + credentials)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

// ❌ Hardcoded secrets / creds
const JWT_SECRET = "super-secret-123";          // hardcoded secret
const ADMIN_TOKEN = "admin-token-please-dont";  // hardcoded API token

// ✅ tiny sqlite db (we'll do raw string concat -> SQLi)
const db = new sqlite3.Database(":memory:");
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
  db.run("INSERT INTO users (username, password) VALUES ('admin','admin123'), ('eza','pass123')");
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Set cookie (❌ no HttpOnly/Secure/SameSite)
app.get("/set-cookie", (req, res) => {
  res.setHeader("Set-Cookie", "sessionId=abc123; Path=/"); // insecure cookie
  res.send("cookie set insecurely");
});

// 1) ❌ Reflected XSS
// http://127.0.0.1:3000/hello?name=<script>alert(1)</script>
app.get("/hello", (req, res) => {
  const name = req.query.name || "world";
  res.send(`<h1>hi ${name}</h1>`); // no escaping
});

// 2) ❌ Command Injection
// http://127.0.0.1:3000/cmd?cmd=whoami
// (Windows: cmd.exe /c dir) (Linux: ls; id; whoami; etc.)
app.get("/cmd", (req, res) => {
  const { cmd } = req.query;
  if (!cmd) return res.status(400).send("cmd query required");
  cp.exec(cmd, (err, stdout, stderr) => {
    if (err) return res.status(500).send(String(err));
    res.type("text/plain").send(stdout + stderr);
  });
});

// 3) ❌ eval() RCE
// http://127.0.0.1:3000/eval?code=process.version
app.get("/eval", (req, res) => {
  const { code } = req.query;
  try {
    // eslint-disable-next-line no-eval
    const out = eval(code); // 💀
    res.send(String(out));
  } catch (e) {
    res.status(500).send(String(e));
  }
});

// 4) ❌ SQL Injection (raw concat)
// http://127.0.0.1:3000/login?u=admin&p=admin123
// http://127.0.0.1:3000/login?u=admin'--&p=x
app.get("/login", (req, res) => {
  const u = req.query.u || "";
  const p = req.query.p || "";
  const q = `SELECT * FROM users WHERE username='${u}' AND password='${p}'`;
  db.all(q, (err, rows) => {
    if (err) return res.status(500).send(err.message);
    if (rows.length) return res.json({ ok: true, user: rows[0] });
    res.status(401).json({ ok: false });
  });
});

// 5) ❌ Path Traversal
// http://127.0.0.1:3000/read?path=../../etc/passwd
app.get("/read", (req, res) => {
  const p = req.query.path;
  if (!p) return res.status(400).send("path query required");
  fs.readFile(path.join(__dirname, p), "utf8", (err, data) => {
    if (err) return res.status(404).send("not found");
    res.type("text/plain").send(data);
  });
});

// 6) ❌ Insecure Redirect
// http://127.0.0.1:3000/redirect?to=https://evil.com
app.get("/redirect", (req, res) => {
  const to = req.query.to || "/";
  res.redirect(to); // no allowlist
});

// 7) ❌ Weak JWT usage + long-lived token
app.get("/token", (req, res) => {
  const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// 8) ❌ Broken Auth via header token
// curl -H "X-Admin-Token: admin-token-please-dont" http://127.0.0.1:3000/admin
app.get("/admin", (req, res) => {
  const tok = req.header("X-Admin-Token");
  if (tok === ADMIN_TOKEN) return res.send("welcome admin (bad auth pattern)");
  res.status(403).send("forbidden");
});

// 9) ❌ Insecure crypto (MD5 via Node 'crypto' fallback)
app.get("/hash", async (req, res) => {
  const text = req.query.text || "password";
  // lazy dynamic import to avoid extra deps
  const { createHash } = await import("node:crypto");
  const md5 = createHash("md5").update("static_salt_" + text).digest("hex");
  res.json({ algorithm: "md5", hash: md5 });
});

// 10) ❌ Leaky debug (stack traces + env)
app.get("/debug", (req, res) => {
  try {
    // force error
    JSON.parse("not-json");
  } catch (e) {
    res.status(500).json({
      error: String(e),
      env: process.env, // leaking env vars
      cwd: process.cwd(),
    });
  }
});

// Root
app.get("/", (_req, res) => {
  res.type("text/plain").send(
    [
      "Intentionally Vulnerable Test App",
      "Endpoints:",
      "/hello?name=<script>alert(1)</script>   (XSS)",
      "/cmd?cmd=whoami                        (Command Injection)",
      "/eval?code=process.version             (eval RCE)",
      "/login?u=admin&p=admin123              (SQL Injection)",
      "/read?path=../../etc/passwd            (Path Traversal)",
      "/redirect?to=https://example.com       (Open Redirect)",
      "/token                                 (Weak JWT usage)",
      "/admin (X-Admin-Token: hardcoded)      (Broken Auth)",
      "/hash?text=secret                      (Weak crypto/MD5)",
      "/debug                                 (Info leakage)",
      "/set-cookie                            (Insecure cookie)",
    ].join("\n")
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`⚠️ Vulnerable app running at http://127.0.0.1:${PORT}`);
});
