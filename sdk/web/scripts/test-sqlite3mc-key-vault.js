import assert from "node:assert/strict";

export async function run(ctx) {
  const password = "synthetic correct horse battery";
  const changed = "synthetic updated long password";
  async function load() {
    await ctx.load();
    await ctx.js("window.keys=await import('/js/key-vault.js');window.vault=new keys.DatabaseKeyVault();window.keyStore=new keys.IndexedDbKeyStore();return true;");
  }
  const record = () => ctx.js("return await keyStore.read('spp.encrypted.db');");
  const unlock = supplied => ctx.js("window.unlocked=await vault.unlockPassword(arguments[0]);window.storage=await sdk.Storage.openEncrypted({keyProvider:unlocked.keyProvider});return true;", [supplied]);
  async function close() { await ctx.close(); await ctx.js("unlocked.lock();window.unlocked=null;return true;"); }
  await load();
  await ctx.js("window.unlocked=await vault.createPassword(arguments[0]);window.storage=await sdk.Storage.openEncrypted({createNew:true,keyProvider:unlocked.keyProvider});await storage.call({SetSetting:{key:'wrapped-protected',value_json:JSON.stringify(arguments[1])}});return true;", [password, ctx.marker]);
  await close();
  const before = await ctx.snapshot();
  const wrapped = await record();
  assert(!JSON.stringify(wrapped).includes(password));
  assert(await ctx.js("const r=await keyStore.read('spp.encrypted.db');return r.password.ciphertext.length===64&&r.passkey===null;"));
  ctx.checks.push("password-wrapped random key persisted before encrypted OPFS creation");
  assert(await ctx.js("try{await vault.unlockPassword('wrong password');return false;}catch(e){return e.code==='unlock-failed';}"));
  assert.deepEqual(await ctx.snapshot(), before); assert.deepEqual(await record(), wrapped);
  ctx.checks.push("wrong password leaves IndexedDB envelope and OPFS byte-identical");
  await load(); await unlock(password);
  assert.match((await ctx.js("return await storage.call({GetSetting:'wrapped-protected'});" )).Setting, new RegExp(ctx.marker));
  await close();
  ctx.checks.push("password unlock and encrypted query after page/worker restart");
  await ctx.js("await vault.changePassword(arguments[0],arguments[1]);return true;", [password, changed]);
  assert.deepEqual(await ctx.snapshot(), before);
  assert(await ctx.js("try{await vault.unlockPassword(arguments[0]);return false;}catch(e){return e.code==='unlock-failed';}", [password]));
  ctx.checks.push("password change only rewraps metadata, leaving database bytes unchanged");
  await ctx.request("DELETE", `/session/${ctx.sid}`); ctx.sid = null; await ctx.session();
  await load(); await unlock(changed);
  assert.match((await ctx.js("return await storage.call({GetSetting:'wrapped-protected'});" )).Setting, new RegExp(ctx.marker));
  await close();
  ctx.checks.push("wrapped key and encrypted data survive full browser restart");
  assert(await ctx.js("const [a,b]=await Promise.all([keyStore.read('spp.encrypted.db'),keyStore.read('spp.encrypted.db')]);const next={...a,revision:a.revision+1};await keyStore.write(a.databaseId,next,a);try{await keyStore.write(b.databaseId,{...b,revision:b.revision+1},b);return false;}catch(e){return e.code==='conflict';}"));
  ctx.checks.push("real IndexedDB rejects stale compare-and-swap updates");
  await ctx.js("window.savedRecord=await keyStore.read('spp.encrypted.db');const damaged=structuredClone(savedRecord);damaged.password.ciphertext='A'.repeat(64);await keyStore.write(damaged.databaseId,damaged,savedRecord);return true;");
  assert(await ctx.js("try{await vault.unlockPassword(arguments[0]);return false;}catch(e){return e.code==='unlock-failed';}", [changed]));
  assert.deepEqual(await ctx.snapshot(), before);
  await ctx.js("await keyStore.write(savedRecord.databaseId,savedRecord,await keyStore.read(savedRecord.databaseId));return true;");
  ctx.checks.push("tampered envelope fails without touching encrypted OPFS");
  if (ctx.args.browser === "chromium") {
    const cdp = (command, params) => ctx.request("POST", `/session/${ctx.sid}/goog/cdp/execute`, { cmd: command, params });
    await cdp("WebAuthn.enable", {});
    const authenticator = (await cdp("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } })).authenticatorId;
    await ctx.js("await vault.addPasskey(arguments[0]);return true;", [changed]);
    assert((await record()).passkey !== null);
    await load();
    await ctx.js("window.unlocked=await vault.unlockPasskey();window.storage=await sdk.Storage.openEncrypted({keyProvider:unlocked.keyProvider});return true;");
    assert.match((await ctx.js("return await storage.call({GetSetting:'wrapped-protected'});" )).Setting, new RegExp(ctx.marker));
    await close();
    ctx.checks.push("Chromium actual WebAuthn PRF with virtual authenticator unlocks OPFS after reload");
    await ctx.js("await vault.resetPasswordWithPasskey(arguments[0]);return true;", [password]);
    await unlock(password); await close();
    ctx.checks.push("virtual passkey resets password while preserving encrypted data");
    await ctx.js("await vault.removePasskey(arguments[0]);return true;", [password]);
    await cdp("WebAuthn.removeVirtualAuthenticator", { authenticatorId: authenticator });
  } else {
    await ctx.js("const {fakeCredentials}=await import('/scripts/key-vault-fixture.mjs');window.fake=fakeCredentials(location.origin);window.vault=new keys.DatabaseKeyVault({credentials:fake.credentials});await vault.addPasskey(arguments[0]);window.unlocked=await vault.unlockPasskey();window.storage=await sdk.Storage.openEncrypted({keyProvider:unlocked.keyProvider});return true;", [changed]);
    assert.match((await ctx.js("return await storage.call({GetSetting:'wrapped-protected'});" )).Setting, new RegExp(ctx.marker));
    await close();
    ctx.checks.push("Firefox PRF fixture (not real authenticator) unwraps same key and reads OPFS");
    const baseline = await record();
    assert(await ctx.js("fake.state.fault='cancel-get';try{await vault.unlockPasskey();return false;}catch(e){return e.name==='NotAllowedError';}"));
    assert.deepEqual(await record(), baseline); assert.deepEqual(await ctx.snapshot(), before);
    ctx.checks.push("cancelled passkey leaves password wrapper and OPFS unchanged");
    await ctx.js("await vault.removePasskey(arguments[0]);return true;", [changed]);
  }
  assert.deepEqual(await ctx.snapshot(), before);
  assert(!(await ctx.snapshot()).filter(file => file.path.startsWith(".opfs-sahpool-encrypted/")).some(file => file.protected));
  ctx.checks.push("all wrapping operations preserve data bytes; encrypted artifacts contain no protected marker");
}
