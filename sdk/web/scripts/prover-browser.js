/**
 * Harness of test-prover-threads.js and bench-prover-threads.js: builds the
 * prover driver (src/bin/prover_driver.rs), serves the built SDK with or
 * without cross-origin isolation, and drives fresh browser profiles through
 * WebDriver.
 */
import { spawn, spawnSync } from "node:child_process";
import { closeSync, openSync } from "node:fs";
import { mkdir, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import net from "node:net";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scripts = dirname(fileURLToPath(import.meta.url));
export const web = resolve(scripts, "..");
const root = resolve(web, "../..");

export function parseArgs(argv, extra = {}) {
  const args = { browser: "chromium", ...extra };
  for (let index = 0; index < argv.length; index++) {
    const name = argv[index].replace(/^--/, "");
    if (["artifacts", "browser", "binary", "driver", ...Object.keys(extra)].includes(name)) args[name] = argv[++index];
    else throw Error(`unknown argument: ${argv[index]}`);
  }
  if (!args.artifacts) throw Error("--artifacts is required");
  if (!["chromium", "firefox"].includes(args.browser)) throw Error("--browser must be chromium or firefox");
  return args;
}

/** Build the driver with the profile and target directory of build.sh, so it reuses that build. */
function buildDriver(out) {
  const profile = process.env.WASM_PROFILE || "release";
  const targetDir = process.env.CARGO_TARGET_DIR || join(root, "target");
  const run = (command, commandArgs) => {
    const result = spawnSync(command, commandArgs, { cwd: root, stdio: ["ignore", "inherit", "inherit"] });
    if (result.status !== 0) throw Error(`${command} failed (${result.error || `exit ${result.status}`})`);
  };
  run("cargo", ["build", "--locked", "-p", "stellar-private-payments-web", "--bin", "prover-driver", "--features", "prover-driver", "--target", "wasm32-unknown-unknown", ...(profile === "release" ? ["--release"] : ["--profile", profile])]);
  run("wasm-bindgen", ["--target", "web", "--out-dir", out, "--out-name", "prover_driver", join(targetDir, "wasm32-unknown-unknown", profile, "prover-driver.wasm")]);
}

const contentTypes = new Map([[".html", "text/html"], [".js", "text/javascript"], [".mjs", "text/javascript"], [".wasm", "application/wasm"], [".css", "text/css"], [".json", "application/json"]]);
const html = "<!doctype html><title>Prover integration test</title>";

async function freePort() {
  const socket = net.createServer();
  await new Promise(resolveListen => socket.listen(0, "127.0.0.1", resolveListen));
  const port = socket.address().port;
  await new Promise(resolveClose => socket.close(resolveClose));
  return port;
}

/**
 * Run `body(harness)` and tear everything down afterwards. `harness.page(name,
 * { isolated })` opens a fresh browser profile on the test page, served with or
 * without the COOP/COEP headers that make it cross-origin isolated.
 */
export async function withProverHarness(args, body) {
  const artifacts = resolve(args.artifacts);
  const driverDir = join(artifacts, "driver");
  await mkdir(artifacts, { recursive: true });
  await rm(driverDir, { recursive: true, force: true });
  buildDriver(driverDir);

  const deployment = JSON.parse(await readFile(join(root, "deployments/testnet/deployments.json"), "utf8"));
  const pool = deployment.pools[0];
  const fixture = {
    contractConfig: deployment, pool: pool.poolContractId, token: pool.tokenContractId,
    lock: await readFile(join(web, "dist/circuits/circuits.json"), "utf8"),
  };

  let isolated = true;
  const server = createServer(async (request, response) => {
    const headers = { "Cache-Control": "no-store" };
    if (isolated) Object.assign(headers, { "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp" });
    try {
      const requestPath = normalize(new URL(request.url, "http://localhost").pathname).replace(/^\/+/, "");
      let body;
      let type = "text/html";
      if (requestPath === "test.html") body = html;
      else {
        const base = requestPath.startsWith("driver/") ? artifacts : web;
        const path = join(base, requestPath);
        if (!path.startsWith(base)) throw Error("invalid path");
        body = await readFile(path);
        type = contentTypes.get(extname(path)) || "application/octet-stream";
      }
      response.writeHead(200, { ...headers, "Content-Type": type });
      response.end(body);
    } catch {
      response.writeHead(404, headers);
      response.end("Not found");
    }
  });
  await new Promise(resolveListen => server.listen(0, "127.0.0.1", resolveListen));
  const origin = `http://127.0.0.1:${server.address().port}`;

  const firefox = args.browser === "firefox";
  const driverPort = await freePort();
  const driverCommand = args.driver || (firefox ? "geckodriver" : "chromedriver");
  const command = firefox ? ["--port", String(driverPort), "--host", "127.0.0.1"] : [`--port=${driverPort}`, "--allowed-ips=127.0.0.1"];
  const log = openSync(join(artifacts, "driver.log"), "w");
  const processDriver = spawn(driverCommand, command, { stdio: ["ignore", log, log] });
  const driverUrl = `http://127.0.0.1:${driverPort}`;
  const sessions = new Set();

  async function request(method, path, value) {
    const response = await fetch(driverUrl + path, { method, headers: { "Content-Type": "application/json" }, body: value === undefined ? undefined : JSON.stringify(value), signal: AbortSignal.timeout(900_000) });
    const payload = await response.json();
    const result = payload.value;
    if (result && typeof result === "object" && "error" in result) throw Error(`${result.error}: ${result.message || ""}`);
    if (!response.ok) throw Error(`WebDriver ${response.status}: ${JSON.stringify(payload)}`);
    return result;
  }

  async function page(name, options) {
    isolated = options.isolated;
    // A fresh profile per page: no OPFS database or cache from an earlier one.
    const profile = join(artifacts, `profile-${name}`);
    await rm(profile, { recursive: true, force: true });
    await mkdir(profile);
    const caps = firefox
      ? { browserName: "firefox", "moz:firefoxOptions": { binary: args.binary || "/usr/bin/firefox", args: ["-headless", "-profile", profile] } }
      : { browserName: "chrome", "goog:chromeOptions": { binary: args.binary || "/usr/bin/chromium", args: ["--headless=new", "--disable-dev-shm-usage", "--disable-background-networking", `--user-data-dir=${profile}`] } };
    const session = await request("POST", "/session", { capabilities: { alwaysMatch: caps } });
    const sid = session.sessionId;
    sessions.add(sid);
    // The first proof downloads and parses the proving key.
    await request("POST", `/session/${sid}/timeouts`, { script: 600_000, pageLoad: 120_000 });
    const js = async (code, values = []) => {
      const script = `const done=arguments[arguments.length-1];(async()=>{${code}})().then(x=>done({ok:x})).catch(e=>done({error:String(e)}));`;
      const result = await request("POST", `/session/${sid}/execute/async`, { script, args: values });
      if (result && "error" in result) throw Error(result.error);
      return result?.ok;
    };
    await request("POST", `/session/${sid}/url`, { url: `${origin}/test.html` });
    const environment = await js("window.driverModule=await import('/driver/prover_driver.js');await driverModule.default();return {crossOriginIsolated:globalThis.crossOriginIsolated===true,cores:navigator.hardwareConcurrency};");

    return {
      browser: { name: args.browser, version: session.capabilities.browserVersion },
      ...environment,
      /** The prover the SDK's `Client.new()` picks on this page: `{ mode, threads }`. */
      selection: () => js("const sdk=await import('/js/index.js');await sdk.default();const client=await sdk.Client.new({rpcUrl:location.origin+'/rpc',contractConfig:arguments[0],circuitLock:JSON.parse(arguments[1]),circuitsBaseUrl:new URL('/dist/circuits/',location.href).href,keyProvider:async()=>crypto.getRandomValues(new Uint8Array(32)),createNew:true});try{return client.proverInfo();}finally{client.dispose();}", [fixture.contractConfig, fixture.lock]),
      /**
       * Prove `runs` transactions on a new `worker` (a file in dist/workers),
       * after sizing its pool to `threads` if given. Resolves to the time of
       * each proof in ms and the pool size the worker logged, if any.
       */
      prove: ({ worker, threads, runs = 1 }) => js("const [worker,threads,runs,pool,token,lock]=arguments;const driver=new driverModule.ProverDriver(new URL('/dist/workers/'+worker,location.href).href);try{const configured=threads?await driver.configureThreads(threads):null;await driver.configure(new URL('/dist/circuits/',location.href).href,lock);const times=[];for(let run=0;run<runs;run++){const start=performance.now();const proof=await driver.proveTransact(pool,token);times.push(Math.round(performance.now()-start));if(proof.length!==256)throw Error('proof is '+proof.length+' bytes');}const logs=await driver.logs();const started=/rayon pool started with (\\d+) threads/.exec(logs);return {configured,times,poolThreads:started?Number(started[1]):null,warnings:logs.split('\\n').filter(line=>/\\[(WARN|ERROR)\\]/.test(line))};}finally{driver.free();}", [worker, threads ?? null, runs, fixture.pool, fixture.token, fixture.lock]),
      close: async () => { sessions.delete(sid); await request("DELETE", `/session/${sid}`); },
    };
  }

  try {
    for (let tries = 0; ; tries++) {
      try { await request("GET", "/status"); break; } catch (error) {
        if (tries >= 100) throw Error(`WebDriver did not start: ${error}`);
        await new Promise(resolveWait => setTimeout(resolveWait, 100));
      }
    }
    return await body({ page });
  } finally {
    for (const sid of sessions) await request("DELETE", `/session/${sid}`).catch(() => {});
    processDriver.kill("SIGTERM");
    await new Promise(resolveExit => { processDriver.once("exit", resolveExit); setTimeout(resolveExit, 15_000); });
    closeSync(log);
    await new Promise(resolveClose => server.close(resolveClose));
  }
}
