/**
 * simple_vuln.js
 * Minimal intentionally-vulnerable app for testing/audit.
 * - Reflected XSS at /greet
 * - Command injection at /cmd
 *
 * Use ONLY in a local/lab environment.
 */

const express = require("express");
const cp = require("child_process");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Reflected XSS (no escaping)
app.get("/greet", (req, res) => {
  const name = req.query.name || "world";
  // intentionally unsafe: directly injects user input into HTML
  res.send(`<html><body><h1>Hello, ${name}!</h1></body></html>`);
});

// Command injection (dangerous if exposed)
app.get("/cmd", (req, res) => {
  const cmd = req.query.cmd;
  if (!cmd) return res.status(400).send("Provide ?cmd=...");
  // intentionally unsafe: executes user-supplied shell command
  cp.exec(cmd, { timeout: 5000 }, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).type("text/plain").send(String(err));
    }
    res.type("text/plain").send(stdout + (stderr ? ("\nSTDERR:\n" + stderr) : ""));
  });
});

app.get("/", (req, res) => {
  res.type("text/plain").send(
    "Simple vuln app:\n" +
    "/greet?name=<script>...  (Reflected XSS)\n" +
    "/cmd?cmd=whoami          (Command injection)\n"
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`⚠️ simple_vuln running at http://127.0.0.1:${PORT}`));
