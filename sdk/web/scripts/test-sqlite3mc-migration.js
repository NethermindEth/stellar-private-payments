import assert from "node:assert/strict";
import { readFile, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

const sleep = milliseconds => new Promise(resolveWait => setTimeout(resolveWait, milliseconds));

export async function run(ctx) {
  const { key, marker } = ctx;
  await ctx.encrypted(true); await ctx.close();
  const candidateFixture = await ctx.js("const root=await navigator.storage.getDirectory();const pool=await root.getDirectoryHandle('.opfs-sahpool-encrypted');const opaque=await pool.getDirectoryHandle('.opaque');for await(const [,file] of opaque.entries()){const bytes=new Uint8Array(await(await file.getFile()).arrayBuffer());if(new TextDecoder().decode(bytes.slice(0,512)).split('\\0')[0]==='spp.encrypted.db')return Array.from(bytes);}throw Error('candidate fixture missing');");
  async function load() {
    await ctx.load();
    assert(await ctx.js("window.migrationWorkers=[];window.faults=[];window.armed=null;const Original=Worker;window.Worker=class extends Original{constructor(...args){super(...args);migrationWorkers.push(this);this.addEventListener('message',e=>{if(e.data?.migrationFault){e.stopImmediatePropagation();faults.push(e.data.migrationFault);}if(e.data?.migrationArmed){e.stopImmediatePropagation();window.armed=e.data.migrationArmed;}});}};return crossOriginIsolated;"));
  }
  const openMigration = (create = false, supplied = key) => ctx.js("window.migration=await sdk.Storage.openMigration({workerUrl:'/scripts/test-sqlite3mc-migration-worker.js',createNew:arguments[1],keyProvider:async()=>Uint8Array.from(arguments[0])});return await migration.status();", [Array.from(supplied), create]);
  const recoverSetup = (supplied = key) => ctx.js("window.migration=await sdk.Storage.recoverMigrationSetup({workerUrl:'/scripts/test-sqlite3mc-migration-worker.js',keyProvider:async(id,purpose)=>{if(purpose!=='open')throw Error('incorrect purpose');return Uint8Array.from(arguments[0]);}});return await migration.status();", [Array.from(supplied)]);
  async function expectFailure(operation) {
    try { await operation(); } catch { return; }
    assert.fail("operation unexpectedly succeeded");
  }
  async function interruptSetup(fault, recovery = false) {
    const workerUrl = `/scripts/test-sqlite3mc-migration-worker.js?fault=${fault}&target=spp.migration.db`;
    const method = recovery ? "recoverMigrationSetup" : "openMigration";
    await ctx.js("window.faults=[];window.pendingSetup=sdk.Storage[arguments[0]]({workerUrl:arguments[1],createNew:!arguments[2],keyProvider:async()=>Uint8Array.from(arguments[3])}).then(m=>{window.migration=m;return 'ok';}).catch(e=>String(e));return true;", [method, workerUrl, recovery, Array.from(key)]);
    let fired = false;
    for (let tries = 0; tries < 400; tries++) { if ((await ctx.js("return window.faults;")).includes(fault)) { fired = true; break; } await sleep(10); }
    assert(fired, `setup fault did not fire: ${fault}`);
    if (["quota", "flush-error", "setup-retire-error"].includes(fault)) assert.notEqual(await ctx.js("return await window.pendingSetup;"), "ok");
    else await ctx.js("for(const w of migrationWorkers)w.terminate();return true;");
    await load();
  }
  const action = name => ctx.js("return await migration[arguments[0]]();", [name]);
  async function closeMigration() { await ctx.js("await migration.close();window.migration=null;return true;"); }
  async function plaintextFiles() { return (await ctx.snapshot()).filter(file => file.path.startsWith(".opfs-sahpool/")); }
  async function fixture(version) {
    const path = join(ctx.artifacts, `fixture-v${version}-${Date.now()}.db`);
    const state = resolve(ctx.web, "..", "native", "src", "state");
    const database = new DatabaseSync(path);
    database.exec(await readFile(join(state, "schema.sql"), "utf8"));
    if (version === 2) database.exec(await readFile(join(state, "schema_v2_gvk_ciphertext.sql"), "utf8"));
    database.exec(`PRAGMA user_version=${version}`);
    database.prepare("INSERT INTO app_settings(rowid,key,value) VALUES(91,'migration-protected',?)").run(`"${marker}"`);
    database.prepare("INSERT INTO accounts VALUES(19,'synthetic-owner')").run();
    database.prepare("INSERT INTO keypairs VALUES(21,?,?,?,?,?,19)").run(Buffer.from(marker), Buffer.from(marker), Buffer.from(marker), Buffer.from(marker), Buffer.from(marker));
    database.prepare("INSERT INTO sqlite_sequence VALUES('app_user_operations',900)").run();
    database.close();
    const bytes = await readFile(path); await unlink(path);
    return bytes;
  }
  async function setup(version) {
    await load();
    await ctx.js("const root=await navigator.storage.getDirectory();for await(const [name] of root.entries())await root.removeEntry(name,{recursive:true});window.storage=await sdk.Storage.open();return true;");
    await ctx.close();
    const script = "self.onmessage=async e=>{try{const root=await navigator.storage.getDirectory();const pool=await root.getDirectoryHandle('.opfs-sahpool');const opaque=await pool.getDirectoryHandle('.opaque');for await(const [,file] of opaque.entries()){const h=await file.createSyncAccessHandle();try{const header=new Uint8Array(512);h.read(header,{at:0});if(new TextDecoder().decode(header).split('\\0')[0]==='spp.db'){h.truncate(4096);h.write(new Uint8Array(e.data),{at:4096});h.flush();self.postMessage({ok:true});return;}}finally{h.close();}}throw Error('fixture source missing');}catch(error){self.postMessage({error:String(error)});}};";
    assert(await ctx.js("const url=URL.createObjectURL(new Blob([arguments[0]],{type:'text/javascript'}));return await new Promise((resolve,reject)=>{const w=new Worker(url);w.onmessage=e=>{w.terminate();URL.revokeObjectURL(url);e.data.error?reject(Error(e.data.error)):resolve(e.data.ok);};w.onerror=reject;w.postMessage(arguments[1]);});", [script, Array.from(await fixture(version))]));
    return plaintextFiles();
  }
  async function readEncrypted(postWrite = false) {
    await ctx.encrypted();
    assert.match((await ctx.js("return await storage.call({GetSetting:'migration-protected'});" )).Setting, new RegExp(marker));
    if (postWrite) assert.equal((await ctx.js("return await storage.call({GetSetting:'after-activation'});" )).Setting, "true");
    await ctx.close();
  }
  for (const version of [1, 2]) {
    let original = await setup(version);
    await interruptSetup("setup-before-retire");
    assert((await ctx.snapshot()).some(file => file.path.includes(".setup-v1-")));
    assert.equal(await openMigration(), "copying"); await closeMigration();
    assert.deepEqual(await plaintextFiles(), original);
    assert(!(await ctx.snapshot()).some(file => file.path.includes(".setup-")));
    let before = await ctx.snapshot(); await expectFailure(recoverSetup); assert.deepEqual(await ctx.snapshot(), before);
    ctx.checks.push(`schema v${version}: ordinary reopen authenticates committed setup and retires its marker`);
    for (const fault of ["setup-before-marker", "setup-marker-created", "quota", "flush-error", "during-write", "before-commit", "after-commit", "setup-before-retire", "setup-retire-error", "setup-after-retire"]) {
      original = await setup(version); await interruptSetup(fault); before = await ctx.snapshot();
      await expectFailure(() => openMigration(false, Buffer.alloc(32)));
      if (fault !== "setup-before-marker") { await expectFailure(() => recoverSetup(Buffer.alloc(32))); assert.deepEqual(await ctx.snapshot(), before); }
      if (fault === "setup-after-retire") { await expectFailure(recoverSetup); assert.deepEqual(await ctx.snapshot(), before); assert.equal(await openMigration(), "copying"); }
      else { await interruptSetup("during-write", true); const retry = await ctx.snapshot(); await expectFailure(() => recoverSetup(Buffer.alloc(32))); assert.deepEqual(await ctx.snapshot(), retry); assert.equal(await recoverSetup(), "copying"); }
      await closeMigration(); assert.deepEqual(await plaintextFiles(), original); assert(!(await ctx.snapshot()).some(file => file.path.includes(".setup-")));
      before = await ctx.snapshot(); await expectFailure(recoverSetup); assert.deepEqual(await ctx.snapshot(), before);
      await openMigration(); await action("prepare"); await action("activate"); await action("finish"); await closeMigration(); await readEncrypted();
      assert(!(await ctx.snapshot()).some(file => file.protected));
      ctx.checks.push(`schema v${version}: ${fault} during setup and retry interruption preserve key/source and complete migration`);
    }
    for (const kind of ["source", "candidate", "prepared", "active", "aborted"]) {
      original = await setup(version);
      if (["source", "candidate"].includes(kind)) {
        await interruptSetup("during-write");
        if (kind === "source") { await ctx.js("window.storage=await sdk.Storage.open();await storage.call({SetSetting:{key:'changed-setup-source',value_json:'true'}});return true;"); await ctx.close(); }
        else {
          const beforeCreation = await ctx.snapshot(); await expectFailure(() => ctx.encrypted(true)); assert.deepEqual(await ctx.snapshot(), beforeCreation);
          await ctx.js("const root=await navigator.storage.getDirectory();const pool=await root.getDirectoryHandle('.opfs-sahpool-encrypted');const opaque=await pool.getDirectoryHandle('.opaque');const file=await opaque.getFileHandle('test-injected-candidate',{create:true});const writer=await file.createWritable();await writer.write(Uint8Array.from(arguments[0]));await writer.close();return true;", [candidateFixture]);
        }
      } else {
        await openMigration(true); if (kind !== "aborted") await action("prepare"); if (kind === "active") await action("activate"); if (kind === "aborted") await action("abort"); await closeMigration();
      }
      before = await ctx.snapshot(); await expectFailure(recoverSetup); assert.deepEqual(await ctx.snapshot(), before);
      ctx.checks.push(`schema v${version}: initialization recovery refuses ${kind} without mutation`);
    }
  }
  for (const version of [1, 2]) {
    let original = await setup(version);
    assert.equal(await openMigration(true), "copying"); await closeMigration();
    let before = await ctx.snapshot();
    for (const supplied of [Buffer.alloc(32), Buffer.alloc(0), Buffer.alloc(31), Buffer.alloc(33)]) { await expectFailure(() => openMigration(false, supplied)); assert.deepEqual(await ctx.snapshot(), before); }
    assert(await ctx.js("try{await sdk.Storage.openMigration({keyProvider:async()=>{throw Error('provider unavailable')}});return false;}catch{return true;}"));
    assert.deepEqual(await ctx.snapshot(), before);
    assert.equal(await openMigration(), "copying"); assert.equal(await action("prepare"), "prepared"); await closeMigration();
    assert.deepEqual(await plaintextFiles(), original); await load(); assert.equal(await openMigration(), "prepared"); assert.equal(await action("abort"), "aborted"); await closeMigration();
    assert.deepEqual(await plaintextFiles(), original); assert.equal(await openMigration(), "aborted"); assert.equal(await action("restart"), "copying"); assert.equal(await action("prepare"), "prepared");
    await expectFailure(() => ctx.encrypted()); assert.equal(await action("activate"), "active"); await closeMigration(); assert.deepEqual(await plaintextFiles(), original);
    await ctx.encrypted(); await ctx.js("await storage.call({SetSetting:{key:'after-activation',value_json:'true'}});return true;"); await ctx.close();
    await ctx.request("DELETE", `/session/${ctx.sid}`); ctx.sid = null; await ctx.session(); await load();
    assert.equal(await openMigration(), "active"); await expectFailure(() => action("abort")); await closeMigration();
    assert.equal(await openMigration(), "active"); assert.equal(await action("finish"), "complete"); assert.equal(await action("finish"), "complete"); await closeMigration();
    await readEncrypted(true); assert(!(await ctx.snapshot()).some(file => file.protected));
    ctx.checks.push(`schema v${version}: key failures, abort/restart, pool exclusion, browser restart, post-activation writes and plaintext cleanup`);
    original = await setup(version); await openMigration(true); await action("prepare"); await closeMigration();
    await ctx.js("window.storage=await sdk.Storage.open();await storage.call({SetSetting:{key:'intervening-write',value_json:'true'}});return true;"); await ctx.close();
    const changed = await plaintextFiles(); assert.notDeepEqual(changed, original); await openMigration(); await expectFailure(() => action("activate")); await closeMigration();
    assert.deepEqual(await plaintextFiles(), changed); assert.equal(await openMigration(), "prepared"); await action("abort"); await closeMigration();
    ctx.checks.push(`schema v${version}: source changes prevent activation without losing data`);
    const cases = [["quota", "spp.encrypted.db", "prepare", "copying"], ["flush-error", "spp.encrypted.db", "prepare", "copying"], ["during-write", "spp.encrypted.db", "prepare", "copying"], ["before-commit", "spp.migration.db", "activate", "prepared"], ["after-commit", "spp.migration.db", "activate", "active"], ["before-commit", "spp.migration.db", "finish", "active"], ["after-commit", "spp.migration.db", "finish", "cleaning"], ["after-delete", "spp.db", "finish", "cleaning"], ["delete-header-error", "spp.db", "finish", "cleaning"]];
    for (const [fault, target, operation, expected] of cases) {
      original = await setup(version); assert.equal(await openMigration(true), "copying"); if (operation !== "prepare") await action("prepare"); if (operation === "finish") await action("activate");
      await ctx.js("window.armed=null;for(const w of migrationWorkers)w.postMessage({armMigrationFault:{mode:arguments[0],target:arguments[1]}});return true;", [fault, target]);
      let armed = false; for (let tries = 0; tries < 200; tries++) { if (await ctx.js("return window.armed;") === fault) { armed = true; break; } await sleep(10); } assert(armed, "fault was not armed");
      if (["quota", "flush-error", "delete-header-error"].includes(fault)) { await expectFailure(() => action(operation)); await closeMigration(); }
      else {
        await ctx.js("window.pendingMigration=migration[arguments[0]]().catch(e=>String(e));return true;", [operation]);
        let fired = false; for (let tries = 0; tries < 400; tries++) { if ((await ctx.js("return window.faults;")).includes(fault)) { fired = true; break; } await sleep(10); } assert(fired, "fault did not fire");
        await ctx.js("for(const w of migrationWorkers)w.terminate();return true;");
      }
      await load(); before = await ctx.snapshot(); await expectFailure(() => openMigration(false, Buffer.alloc(32))); assert.deepEqual(await ctx.snapshot(), before);
      let state = await openMigration(); assert.equal(state, expected);
      if (["copying", "prepared", "active"].includes(state)) assert.deepEqual(await plaintextFiles(), original);
      if (state === "copying") { await action("prepare"); state = "prepared"; }
      if (state === "prepared") await action("activate");
      assert.equal(await action("finish"), "complete"); await closeMigration(); await readEncrypted(); assert(!(await ctx.snapshot()).some(file => file.protected));
      ctx.checks.push(`schema v${version}: recover ${fault} during ${operation}; wrong key nonmutation and artifact scan passed`);
    }
  }
}
