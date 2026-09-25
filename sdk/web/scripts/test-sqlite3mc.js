#!/usr/bin/env node
/**
 * Exercise the built SDK's password-protected storage in a fresh, isolated
 * browser profile through WebDriver.
 *
 * --legacy-db PATH also checks the migration of an earlier version's
 * unencrypted database: the file (made by the native SDK, e.g.
 * `gvkey-gen generate --db PATH`) is placed where earlier versions kept it,
 * then encrypted by the first `create`. With --legacy-gvk FILE, the GVK
 * authority key saved in it must survive.
 */
import assert from "node:assert/strict";
import { closeSync, openSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import net from "node:net";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

function parseArgs(argv) {
  const args = { browser: "chromium" };
  for (let index = 0; index < argv.length; index++) {
    const name = argv[index].replace(/^--/, "");
    if (["artifacts", "browser", "binary", "driver", "legacy-db", "legacy-gvk"].includes(name)) args[name] = argv[++index];
    else throw Error(`unknown argument: ${argv[index]}`);
  }
  if (!args.artifacts) throw Error("--artifacts is required");
  if (!["chromium", "firefox"].includes(args.browser)) throw Error("--browser must be chromium or firefox");
  return args;
}

const args = parseArgs(process.argv.slice(2));
const scripts = dirname(fileURLToPath(import.meta.url));
const web = resolve(scripts, "..");
const artifacts = resolve(args.artifacts);
const profile = join(artifacts, "profile");
await mkdir(artifacts, { recursive: true });
await mkdir(profile);

const contentTypes = new Map([[".html", "text/html"], [".js", "text/javascript"], [".mjs", "text/javascript"], [".wasm", "application/wasm"], [".css", "text/css"], [".json", "application/json"]]);
const html = "<!doctype html><title>Storage integration test</title>";
const server = createServer(async (request, response) => {
  try {
    const requestPath = new URL(request.url, "http://localhost").pathname;
    let body;
    let type = "text/javascript";
    if (requestPath === "/test.html") { body = html; type = "text/html"; }
    else {
      const path = join(web, normalize(requestPath).replace(/^\/+/, ""));
      if (!path.startsWith(web)) throw Error("invalid path");
      body = await readFile(path);
      type = contentTypes.get(extname(path)) || "application/octet-stream";
    }
    response.writeHead(200, { "Content-Type": type, "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp" });
    response.end(body);
  } catch {
    response.writeHead(404);
    response.end("Not found");
  }
});
await new Promise(resolveListen => server.listen(0, "127.0.0.1", resolveListen));
const serverPort = server.address().port;

async function freePort() {
  const socket = net.createServer();
  await new Promise(resolveListen => socket.listen(0, "127.0.0.1", resolveListen));
  const port = socket.address().port;
  await new Promise(resolveClose => socket.close(resolveClose));
  return port;
}
const driverPort = await freePort();
const firefox = args.browser === "firefox";
const driver = args.driver || (firefox ? "geckodriver" : "chromedriver");
const command = firefox ? ["--port", String(driverPort), "--host", "127.0.0.1"] : [`--port=${driverPort}`, "--allowed-ips=127.0.0.1"];
const log = openSync(join(artifacts, "driver.log"), "w");
const processDriver = spawn(driver, command, { stdio: ["ignore", log, log] });
const driverUrl = `http://127.0.0.1:${driverPort}`;
const origin = `http://127.0.0.1:${serverPort}/test.html`;

const PASSWORD = "correct horse battery staple";
const NEW_PASSWORD = "a different passphrase for spp";
const ctx = {
  args, web, artifacts, firefox, sid: null,
  marker: "PROTECTED_OPFS_INTEGRATION_01b8af6d", checks: [],
};
ctx.request = async (method, path, value) => {
  const response = await fetch(driverUrl + path, { method, headers: { "Content-Type": "application/json" }, body: value === undefined ? undefined : JSON.stringify(value), signal: AbortSignal.timeout(150_000) });
  const payload = await response.json();
  const result = payload.value;
  if (result && typeof result === "object" && "error" in result) throw Error(`${result.error}: ${result.message || ""}`);
  if (!response.ok) throw Error(`WebDriver ${response.status}: ${JSON.stringify(payload)}`);
  return result;
};
ctx.session = async () => {
  const caps = firefox
    ? { browserName: "firefox", "moz:firefoxOptions": { binary: args.binary || "/usr/bin/firefox", args: ["-headless", "-profile", profile] } }
    : { browserName: "chrome", "goog:chromeOptions": { binary: args.binary || "/usr/bin/chromium", args: ["--headless=new", "--disable-dev-shm-usage", "--disable-background-networking", `--user-data-dir=${profile}`] } };
  const result = await ctx.request("POST", "/session", { capabilities: { alwaysMatch: caps } });
  ctx.sid = result.sessionId;
  await ctx.request("POST", `/session/${ctx.sid}/timeouts`, { script: 120_000, pageLoad: 120_000 });
  return result.capabilities.browserVersion;
};
ctx.js = async (code, values = []) => {
  const script = `const done=arguments[arguments.length-1];(async()=>{${code}})().then(x=>done({ok:x})).catch(e=>done({error:String(e)}));`;
  const result = await ctx.request("POST", `/session/${ctx.sid}/execute/async`, { script, args: values });
  if (result && "error" in result) throw Error(result.error);
  return result?.ok;
};
ctx.load = async () => {
  await ctx.request("POST", `/session/${ctx.sid}/url`, { url: origin });
  await ctx.js("window.sdk=await import('/js/index.js');await sdk.default();return true;");
};
ctx.connect = async () => ctx.js("window.storage=await sdk.Storage.connect();return await storage.status();");
ctx.status = async () => ctx.js("return await storage.status();");
ctx.create = async password => ctx.js("await storage.create(arguments[0]);return true;", [password]);
ctx.unlock = async password => ctx.js("await storage.unlock(arguments[0]);return true;", [password]);
// The error code of a password operation, or "ok".
ctx.outcome = async (operation, ...values) => ctx.js(`try{await storage.${operation}(...arguments);return 'ok';}catch(e){return e.code||String(e);}`, values);
ctx.setMarker = async () => ctx.js("await storage.call({SetSetting:{key:'integration-protected',value_json:JSON.stringify(arguments[0])}});return true;", [ctx.marker]);
ctx.marked = async () => (await ctx.js("return await storage.call({GetSetting:'integration-protected'});")).Setting === JSON.stringify(ctx.marker);
ctx.close = async () => ctx.js("await storage.close();storage.free();window.storage=null;return true;");
ctx.snapshot = async () => ctx.js("const root=await navigator.storage.getDirectory();const result=[];async function walk(d,path){for await(const [name,h] of d.entries()){if(h.kind==='directory'){result.push({path:path+name+'/',kind:'directory'});await walk(h,path+name+'/');}else{const bytes=new Uint8Array(await(await h.getFile()).arrayBuffer());const hash=await crypto.subtle.digest('SHA-256',bytes);result.push({path:path+name,bytes:bytes.length,sha256:Array.from(new Uint8Array(hash),x=>x.toString(16).padStart(2,'0')).join(''),protected:argumentsSecrets.some(secret=>new TextDecoder().decode(bytes).includes(secret))});}}}const argumentsSecrets=arguments[0];await walk(root,'');return result.sort((a,b)=>a.path.localeCompare(b.path));", [ctx.secrets ?? [ctx.marker]]);
// Place an earlier version's unencrypted database where it kept it: a slot of
// the default OPFS pool, with the pool's header (name, flags) before the data.
ctx.injectLegacy = async bytes => ctx.js("const data=Uint8Array.from(atob(arguments[0]),c=>c.charCodeAt(0));const root=await navigator.storage.getDirectory();const opaque=await (await root.getDirectoryHandle('.opfs-sahpool',{create:true})).getDirectoryHandle('.opaque',{create:true});const header=new Uint8Array(4096);header.set(new TextEncoder().encode('spp.db'));new DataView(header.buffer).setUint32(512,0x106);const file=await opaque.getFileHandle('legacyslot000000',{create:true});const writable=await file.createWritable();await writable.write(header);await writable.write(data);await writable.close();return true;", [bytes.toString("base64")]);

async function waitForDriver() {
  for (let tries = 0; tries < 100; tries++) {
    try { await ctx.request("GET", "/status"); return; } catch { await new Promise(resolveWait => setTimeout(resolveWait, 100)); }
  }
  throw Error("WebDriver did not start");
}
async function expectFailure(operation, includes) {
  try { await operation(); } catch (error) { if (includes) assert.match(String(error), new RegExp(includes)); return; }
  assert.fail("operation unexpectedly succeeded");
}

try {
  await waitForDriver();
  const version = await ctx.session();
  await ctx.load();

  let legacyGvk;
  if (args["legacy-db"]) {
    await ctx.injectLegacy(await readFile(args["legacy-db"]));
    if (args["legacy-gvk"]) {
      legacyGvk = JSON.parse(await readFile(args["legacy-gvk"], "utf8"));
      // The GVK private key must not stay readable anywhere once encrypted.
      ctx.secrets = [ctx.marker, legacyGvk.privateKey];
    }
    assert.equal(await ctx.connect(), "unencrypted");
    ctx.checks.push("an earlier unencrypted database is found");
  } else {
    assert.equal(await ctx.connect(), "new");
    ctx.checks.push("a fresh profile reports a new database");
  }

  assert.match(await ctx.outcome("create", "too short"), /at least 15 characters/);
  assert.notEqual(await ctx.status(), "unlocked");
  ctx.checks.push("a short password is refused");

  await ctx.create(PASSWORD);
  assert.equal(await ctx.status(), "unlocked");
  await ctx.setMarker();
  if (args["legacy-db"]) {
    const snapshot = await ctx.snapshot();
    assert(!snapshot.some(file => file.path.startsWith(".opfs-sahpool/")), "the unencrypted pool is still there");
    assert(!snapshot.some(file => file.protected), "an unencrypted secret is still readable in OPFS");
    if (legacyGvk) {
      const stored = (await ctx.js("return await storage.call({GetSetting:'gvk_authority'});")).Setting;
      assert.equal(JSON.parse(stored).privateKey, legacyGvk.privateKey, "the GVK authority key did not survive");
    }
    ctx.checks.push("the unencrypted database is encrypted, then deleted with its pool");
  } else {
    ctx.checks.push("create opens a new encrypted database");
  }
  await ctx.close();

  // The app recognises a second tab by this exact message.
  const firstTab = await ctx.request("GET", `/session/${ctx.sid}/window`);
  await ctx.load();
  assert.equal(await ctx.connect(), "locked");
  const secondTab = await ctx.request("POST", `/session/${ctx.sid}/window/new`, { type: "tab" });
  await ctx.request("POST", `/session/${ctx.sid}/window`, { handle: secondTab.handle });
  await ctx.load();
  await expectFailure(() => ctx.connect(), "Another tab or window is using this app's local database");
  await ctx.request("DELETE", `/session/${ctx.sid}/window`);
  await ctx.request("POST", `/session/${ctx.sid}/window`, { handle: firstTab });
  ctx.checks.push("second tab reports the database lock");

  const locked = await ctx.snapshot();
  assert.equal(await ctx.outcome("unlock", "not the password at all"), "wrong-password");
  assert.equal(await ctx.status(), "locked");
  assert.deepEqual(await ctx.snapshot(), locked, "a wrong password modified OPFS");
  ctx.checks.push("a wrong password is refused without modifying OPFS and can be retried");
  await ctx.unlock(PASSWORD);
  assert(await ctx.marked());
  ctx.checks.push("unlock opens the database with its data");

  assert.equal(await ctx.outcome("changePassword", "not the password at all", NEW_PASSWORD), "wrong-password");
  assert.equal(await ctx.outcome("changePassword", PASSWORD, NEW_PASSWORD), "ok");
  await ctx.close();
  await ctx.load();
  assert.equal(await ctx.connect(), "locked");
  assert.equal(await ctx.outcome("unlock", PASSWORD), "wrong-password");
  await ctx.unlock(NEW_PASSWORD);
  assert(await ctx.marked());
  await ctx.close();
  ctx.checks.push("change password needs the current one and keeps the data");

  await ctx.request("DELETE", `/session/${ctx.sid}`); ctx.sid = null;
  await ctx.session(); await ctx.load();
  assert.equal(await ctx.connect(), "locked");
  await ctx.unlock(NEW_PASSWORD);
  assert(await ctx.marked());
  const final = await ctx.snapshot();
  assert(final.some(file => file.path.startsWith(".opfs-sahpool-encrypted/")));
  assert(!final.some(file => file.protected), "a protected value is readable in OPFS");
  ctx.checks.push("encrypted browser-process restart, and no protected value readable in OPFS");

  await ctx.js("await storage.reset();return true;");
  assert.equal(await ctx.status(), "new");
  await ctx.create(PASSWORD);
  assert(!(await ctx.marked()), "reset kept the old data");
  await ctx.close();
  ctx.checks.push("reset discards the database and a new password starts over");

  const result = { browser: args.browser, version, checks: ctx.checks, passed: true };
  await writeFile(join(artifacts, "result.json"), `${JSON.stringify(result, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} finally {
  if (ctx.sid) await ctx.request("DELETE", `/session/${ctx.sid}`).catch(() => {});
  processDriver.kill("SIGTERM");
  await new Promise(resolveExit => { processDriver.once("exit", resolveExit); setTimeout(resolveExit, 15_000); });
  closeSync(log);
  await new Promise(resolveClose => server.close(resolveClose));
}
