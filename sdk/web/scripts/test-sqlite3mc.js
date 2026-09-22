#!/usr/bin/env node
/** Exercise the built SDK in a fresh, isolated browser profile through WebDriver. */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { closeSync, openSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import net from "node:net";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

function parseArgs(argv) {
  const args = { browser: "chromium" };
  const flags = new Set(["plaintext-only", "migration", "app-startup", "key-vault", "app-access", "app-migration", "app-wallet", "backup"]);
  for (let index = 0; index < argv.length; index++) {
    const name = argv[index].replace(/^--/, "");
    if (flags.has(name)) args[name.replaceAll("-", "_")] = true;
    else if (["artifacts", "browser", "binary", "driver"].includes(name)) args[name] = argv[++index];
    else throw Error(`unknown argument: ${argv[index]}`);
  }
  if (!args.artifacts) throw Error("--artifacts is required");
  if (!["chromium", "firefox"].includes(args.browser)) throw Error("--browser must be chromium or firefox");
  args.app_access ||= args.app_migration || args.app_wallet;
  return args;
}

const args = parseArgs(process.argv.slice(2));
const scripts = dirname(fileURLToPath(import.meta.url));
const web = resolve(scripts, "..");
const repository = resolve(web, "..", "..");
const artifacts = resolve(args.artifacts);
const profile = join(artifacts, "profile");
await mkdir(artifacts, { recursive: true });
await mkdir(profile);

const contentTypes = new Map([[".html", "text/html"], [".js", "text/javascript"], [".mjs", "text/javascript"], [".wasm", "application/wasm"], [".css", "text/css"], [".json", "application/json"]]);
const appPaths = new Set(["/app/js/wasm-facade.js", "/app/js/storage-startup.js", "/app/js/app-storage.js", "/app/js/storage-access.js", "/app/js/storage-access-ui.js", "/app/js/database-backup.js"]);
const html = `<!doctype html><title>Storage integration test</title>
<script type="importmap">{"imports":{"stellar-private-payments":"/js/index.js","stellar-private-payments/freighter":"/test-freighter.js","stellar-private-payments/key-vault":"/js/key-vault.js"}}</script>`;
const server = createServer(async (request, response) => {
  try {
    const requestPath = new URL(request.url, "http://localhost").pathname;
    let body;
    let type = "text/javascript";
    if (requestPath === "/test.html") { body = html; type = "text/html"; }
    else if ((args.app_startup || args.app_access || args.backup) && requestPath === "/test-freighter.js") {
      body = args.app_wallet
        ? "export class FreighterSigner { getPublicKey() { return window.walletFixture.signer.getPublicKey(); } signMessage(...args) { return window.walletFixture.signer.signMessage(...args); } }"
        : "export class FreighterSigner { constructor() { throw Error('Wallet use is outside this test'); } }";
    } else if ((args.app_access || args.backup) && requestPath === "/test-access-entry.js") {
      body = "import * as accessUi from '/app/js/storage-access-ui.js';import * as facade from '/app/js/wasm-facade.js';import * as keyModule from '/js/key-vault.js';Object.assign(window,{accessUi,facade,keyModule});";
    } else if (args.app_startup && requestPath === "/test-app-entry.js") {
      body = "import * as facade from '/app/js/wasm-facade.js';window.appFacade=facade;window.workerCount=0;const Original=Worker;window.Worker=class extends Original{constructor(...args){super(...args);window.workerCount++;}};";
    } else {
      const path = appPaths.has(requestPath) ? join(repository, requestPath) : join(web, normalize(requestPath).replace(/^\/+/, ""));
      if (!path.startsWith(appPaths.has(requestPath) ? repository : web)) throw Error("invalid path");
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
const originHost = args.key_vault || args.app_access ? "localhost" : "127.0.0.1";
const origin = `http://${originHost}:${serverPort}/test.html`;

const ctx = {
  args, web, repository, artifacts, firefox, sid: null,
  key: randomBytes(32), marker: "PROTECTED_OPFS_INTEGRATION_01b8af6d", checks: [],
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
ctx.encrypted = async (create = false, supplied = ctx.key) => ctx.js("const supplied=Uint8Array.from(arguments[0]);try{window.storage=await sdk.Storage.openEncrypted({createNew:arguments[1],keyProvider:async(id,purpose)=>{if(id!=='spp.encrypted.db'||purpose!==(arguments[1]?'create':'open'))throw Error('provider context');return supplied;}});return true;}finally{supplied.fill(0);}", [Array.from(supplied), create]);
ctx.close = async () => ctx.js("await storage.close();storage.free();window.storage=null;return true;");
ctx.snapshot = async () => ctx.js("const root=await navigator.storage.getDirectory();const result=[];async function walk(d,path){for await(const [name,h] of d.entries()){if(h.kind==='directory'){result.push({path:path+name+'/',kind:'directory'});await walk(h,path+name+'/');}else{const bytes=new Uint8Array(await(await h.getFile()).arrayBuffer());const hash=await crypto.subtle.digest('SHA-256',bytes);result.push({path:path+name,bytes:bytes.length,sha256:Array.from(new Uint8Array(hash),x=>x.toString(16).padStart(2,'0')).join(''),protected:new TextDecoder().decode(bytes).includes(argumentsMarker)});}}}const argumentsMarker=arguments[0];await walk(root,'');return result.sort((a,b)=>a.path.localeCompare(b.path));", [ctx.marker]);

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
  await ctx.js("window.storage=await sdk.Storage.open();await storage.call({SetSetting:{key:'integration-legacy',value_json:JSON.stringify('legacy-preserved')}});return true;");
  await ctx.close();
  ctx.legacy = await ctx.snapshot();
  await ctx.load();
  await ctx.js("window.storage=await sdk.Storage.open();return true;");
  assert.equal((await ctx.js("return await storage.call({GetSetting:'integration-legacy'});" )).Setting, '"legacy-preserved"');
  await ctx.close();
  ctx.checks.push("plaintext create, close and worker restart");

  const scenario = args.app_wallet ? "app-wallet" : args.app_migration ? "app-migration" : args.backup ? "backup" : args.app_access ? "app-access" : args.key_vault ? "key-vault" : args.app_startup ? "app-startup" : args.migration ? "migration" : null;
  if (scenario) {
    const module = await import(`./test-sqlite3mc-${scenario}.js`);
    await module.run(ctx);
  } else if (args.plaintext_only) {
    await expectFailure(() => ctx.encrypted(true), "sqlite3mc feature");
    ctx.checks.push("default build rejects encrypted API");
    assert(await ctx.js("try{await sdk.Storage.openMigration({keyProvider:async()=>{throw Error('provider should not run');}});return false;}catch(e){return String(e).includes('sqlite3mc feature');}"));
    ctx.checks.push("default build rejects migration API");
    assert(await ctx.js("try{await sdk.Storage.recoverMigrationSetup({keyProvider:async()=>{throw Error('provider should not run');}});return false;}catch(e){return String(e).includes('sqlite3mc feature');}"));
    ctx.checks.push("default build rejects setup recovery API");
  } else {
    await ctx.encrypted(true);
    await ctx.js("await storage.call({SetSetting:{key:'integration-protected',value_json:JSON.stringify(arguments[0])}});window.fork=storage.fork();return true;", [ctx.marker]);
    assert.match((await ctx.js("return await fork.call({GetSetting:'integration-protected'});" )).Setting, new RegExp(ctx.marker));
    await ctx.close();
    assert(await ctx.js("try{await fork.call('Ping');return false;}catch{return true;}finally{fork.free();}"));
    ctx.checks.push("encrypted create, fork and close invalidates forks");
    const before = await ctx.snapshot();
    for (const [label, supplied, create] of [["wrong key", randomBytes(32), false], ["zero key", Buffer.alloc(32), false], ["missing key", Buffer.alloc(0), false], ["short key", Buffer.alloc(31), false], ["long key", Buffer.alloc(33), false], ["create existing", ctx.key, true]]) {
      await expectFailure(() => ctx.encrypted(create, supplied));
      assert.deepEqual(await ctx.snapshot(), before, `${label} modified OPFS`);
      ctx.checks.push(`${label} rejects without modifying OPFS`);
    }
    assert(await ctx.js("try{await sdk.Storage.openEncrypted({keyProvider:async()=>{throw Error('provider unavailable');}});return false;}catch{return true;}"));
    assert.deepEqual(await ctx.snapshot(), before);
    ctx.checks.push("provider failure leaves OPFS unchanged");
    await ctx.load(); await ctx.encrypted();
    assert.match((await ctx.js("return await storage.call({GetSetting:'integration-protected'});" )).Setting, new RegExp(ctx.marker));
    await ctx.close();
    ctx.checks.push("encrypted worker restart");
    await ctx.request("DELETE", `/session/${ctx.sid}`); ctx.sid = null;
    await ctx.session(); await ctx.load(); await ctx.encrypted();
    assert.match((await ctx.js("return await storage.call({GetSetting:'integration-protected'});" )).Setting, new RegExp(ctx.marker));
    await ctx.close();
    ctx.checks.push("encrypted browser-process restart");
    const final = await ctx.snapshot();
    const encryptedFiles = final.filter(file => file.path.startsWith(".opfs-sahpool-encrypted/"));
    assert(encryptedFiles.length && !encryptedFiles.some(file => file.protected));
    assert.deepEqual(final.filter(file => !file.path.startsWith(".opfs-sahpool-encrypted/")), ctx.legacy);
    ctx.checks.push("encrypted artifact scan and original plaintext byte identity");
  }
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
