#!/usr/bin/env node
/** Serve the isolated password/passkey test on localhost; no SDK database opens. */
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const portIndex = process.argv.indexOf("--port");
const port = portIndex >= 0 ? Number(process.argv[portIndex + 1]) : 8765;
if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error("invalid --port");

const files = new Map([
  ["/", ["text/html; charset=utf-8", join(root, "key-vault-demo.html")]],
  ["/key-vault-demo.js", ["text/javascript", join(root, "key-vault-demo.js")]],
  ["/key-vault-demo.css", ["text/css", join(root, "key-vault-demo.css")]],
  ["/key-vault.js", ["text/javascript", join(root, "..", "js", "key-vault.js")]],
]);
const actions = new Set(["Create password vault", "Password unlock", "Passkey enrollment", "Passkey unlock", "Password change", "Passkey password recovery"]);
const codes = new Set(["ok", "invalid-record", "invalid-password", "unlock-failed", "storage-blocked", "conflict", "missing-key", "already-exists", "passkey-unavailable", "passkey-cancelled", "wrong-passkey", "invalid-passkey", "wrong-origin", "prf-unavailable", "missing-passkey", "cancelled-or-unavailable", "failed"]);
const results = [];
const headers = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

function send(response, status, type, body) {
  const data = Buffer.isBuffer(body) ? body : Buffer.from(body);
  response.writeHead(status, { ...headers, "Content-Type": type, "Content-Length": data.length });
  response.end(data);
}

createServer(async (request, response) => {
  const host = `localhost:${port}`;
  if (request.headers.host !== host) return send(response, 403, "text/plain", "Use the localhost URL");
  if (request.method === "GET" && request.url === "/results") {
    return send(response, 200, "application/json", JSON.stringify(results));
  }
  if (request.method === "GET" && files.has(request.url)) {
    const [type, path] = files.get(request.url);
    return send(response, 200, type, await readFile(path));
  }
  if (request.method !== "POST" || request.url !== "/result" || request.headers.origin !== `http://${host}` || request.headers["content-type"] !== "application/json") {
    return send(response, 404, "text/plain", "Not found");
  }
  try {
    const length = Number(request.headers["content-length"]);
    if (!Number.isInteger(length) || length < 1 || length > 2048) throw Error("size");
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (Object.keys(value).sort().join() !== "action,browser,code,ok" || !actions.has(value.action) || typeof value.ok !== "boolean" || typeof value.browser !== "string" || value.browser.length > 512 || !codes.has(value.code)) throw Error("invalid result");
    value.time = new Date().toISOString();
    results.push(value);
    process.stdout.write(`${JSON.stringify(value)}\n`);
    return send(response, 200, "application/json", '{"recorded":true}');
  } catch {
    return send(response, 400, "text/plain", "Invalid result");
  }
}).listen(port, "127.0.0.1", () => process.stdout.write(`Key vault test: http://localhost:${port}/\n`));
