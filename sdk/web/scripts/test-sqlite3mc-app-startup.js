import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

export async function run(ctx) {
  async function loadApp(mode = null, supplied = ctx.key) {
    await ctx.load();
    await ctx.js("await new Promise((resolve,reject)=>{const script=document.createElement('script');script.type='module';script.src='/test-app-entry.js';script.onload=resolve;script.onerror=()=>reject(Error('app module failed to load'));document.head.append(script);});window.providerCalls=0;window.supplied=Uint8Array.from(arguments[1]);if(arguments[0])appFacade.configureStorageStartup({mode:arguments[0],keyProvider:async(id,purpose)=>{window.providerCalls++;if(id!=='spp.encrypted.db'||purpose!=='open')throw Error('provider context');return window.supplied;}});return true;", [mode, Array.from(supplied)]);
  }
  const openApp = () => ctx.js("const [a,b]=await Promise.all([appFacade.ensureStorage(),appFacade.ensureStorage()]);if(a!==b)throw Error('duplicate AppStorage');window.appStorage=a;return window.workerCount;");
  const refused = () => ctx.js("try{await appFacade.ensureStorage();return false;}catch(e){window.startupError=String(e);return true;}");
  const snapshot = ctx.snapshot;

  await loadApp();
  assert.equal(await openApp(), 1);
  assert.equal(await ctx.js("return await appStorage.getSetting('integration-legacy');"), "legacy-preserved");
  await ctx.js("await appStorage.setBootnodeConfig('https://synthetic.invalid');return true;");
  assert.equal(await ctx.js("return await appStorage.getStoredBootnodeUrl();"), "https://synthetic.invalid");
  assert(await ctx.js("try{appFacade.configureStorageStartup({mode:'encrypted',keyProvider:()=>supplied});return false;}catch{return true;}"));
  ctx.checks.push("app default startup shares one worker and preserves settings API");
  await ctx.load();
  const before = await snapshot();
  if (ctx.args.plaintext_only) {
    for (const mode of ["encrypted", "migrated"]) {
      await loadApp(mode); assert(await refused());
      assert(await ctx.js("return startupError.includes('sqlite3mc feature')&&providerCalls===0&&workerCount===0;"));
      assert.deepEqual(await snapshot(), before);
      ctx.checks.push(`stock app ${mode} startup refuses before key provider without fallback`);
    }
    return;
  }
  await ctx.encrypted(true);
  await ctx.js("await storage.call({SetSetting:{key:'app-protected',value_json:JSON.stringify(arguments[0])}});return true;", [ctx.marker]);
  await ctx.close();
  let baseline = await snapshot();
  for (const [label, supplied] of [["wrong key", randomBytes(32)], ["missing key", Buffer.alloc(0)]]) {
    await loadApp("encrypted", supplied); assert(await refused());
    assert.deepEqual(await snapshot(), baseline);
    assert(await ctx.js("try{appFacade.configureStorageStartup({mode:'plaintext'});return false;}catch{return true;}"));
    await ctx.js("window.supplied=Uint8Array.from(arguments[0]);return true;", [Array.from(ctx.key)]);
    await openApp();
    assert.equal(await ctx.js("return await appStorage.getSetting('app-protected');"), ctx.marker);
    ctx.checks.push(`app ${label} fails without writes or fallback; same-provider retry succeeds`);
    await ctx.load(); baseline = await snapshot();
  }
  await loadApp("encrypted");
  assert.equal(await openApp(), 1);
  assert.equal(await ctx.js("return window.providerCalls;"), 1);
  await ctx.js("await appStorage.setSetting('app-restart',arguments[0]);return true;", [ctx.marker]);
  ctx.checks.push("app encrypted startup shares provider and worker");
  await ctx.request("DELETE", `/session/${ctx.sid}`); ctx.sid = null;
  await ctx.session(); await loadApp("encrypted");
  assert.equal(await openApp(), 1);
  assert.equal(await ctx.js("return await appStorage.getSetting('app-restart');"), ctx.marker);
  ctx.checks.push("app encrypted settings survive full browser restart");
  await ctx.load();
  const encryptedFiles = (await snapshot()).filter(file => file.path.startsWith(".opfs-sahpool-encrypted/"));
  assert(encryptedFiles.length && !encryptedFiles.some(file => file.protected));
  assert.deepEqual((await snapshot()).filter(file => !file.path.startsWith(".opfs-sahpool-encrypted/")), before);
  ctx.checks.push("app encrypted writes preserve plaintext source and expose no protected marker");
  await ctx.js("const root=await navigator.storage.getDirectory();await root.removeEntry('.opfs-sahpool-encrypted',{recursive:true});window.storage=await sdk.Storage.open();await storage.call({SetSetting:{key:'app-protected',value_json:JSON.stringify(arguments[0])}});return true;", [ctx.marker]);
  await ctx.close();
  async function migration(action = null, create = false) {
    await ctx.load();
    return ctx.js("const m=await sdk.Storage.openMigration({createNew:arguments[1],keyProvider:()=>Uint8Array.from(arguments[0])});try{return arguments[2]?await m[arguments[2]]():await m.status();}finally{await m.close();}", [Array.from(ctx.key), create, action]);
  }
  assert.equal(await migration(null, true), "copying");
  for (const [status, action] of [["copying", null], ["prepared", "prepare"], ["aborted", "abort"]]) {
    if (action) assert.equal(await migration(action), status);
    baseline = await snapshot(); await loadApp("migrated"); assert(await refused());
    assert(await ctx.js("return startupError.includes(arguments[0]);", [status]));
    assert.deepEqual(await snapshot(), baseline);
    ctx.checks.push(`app ${status} migration refuses startup without fallback or data changes`);
  }
  assert.equal(await migration("restart"), "copying");
  assert.equal(await migration("prepare"), "prepared");
  assert.equal(await migration("activate"), "active");
  baseline = await snapshot(); await loadApp("migrated", randomBytes(32)); assert(await refused());
  assert.deepEqual(await snapshot(), baseline);
  ctx.checks.push("app migrated startup authenticates control; wrong key leaves OPFS unchanged");
  await loadApp("migrated"); assert.equal(await openApp(), 2);
  assert.equal(await ctx.js("return await appStorage.getSetting('app-protected');"), ctx.marker);
  await ctx.js("await appStorage.setSetting('app-after-activation',arguments[0]);return true;", [ctx.marker]);
  await loadApp("migrated"); assert.equal(await openApp(), 2);
  assert.equal(await ctx.js("return await appStorage.getSetting('app-after-activation');"), ctx.marker);
  ctx.checks.push("app active migration selects encrypted data and preserves post-activation writes");
  assert.equal(await migration("finish"), "complete");
  await loadApp("migrated"); assert.equal(await openApp(), 2);
  assert.equal(await ctx.js("return await appStorage.getSetting('app-after-activation');"), ctx.marker);
  await ctx.load(); assert(!(await snapshot()).some(file => file.protected));
  ctx.checks.push("app completed migration reopens encrypted data after plaintext cleanup");
}
