import assert from "node:assert/strict";

export async function run(ctx) {
  const password = "synthetic application password";
  const wait = expression => ctx.js(`for(let i=0;i<300;i++){if(${expression})return true;await new Promise(r=>setTimeout(r,30));}throw Error('UI condition timed out');`);
  async function page(setup = false) {
    await ctx.load();
    await ctx.js("if(arguments[0])history.replaceState(null,'','?storage=encrypted');window.ready=false;await new Promise((resolve,reject)=>{const s=document.createElement('script');s.type='module';s.src='/test-access-entry.js';s.onload=resolve;s.onerror=()=>reject(Error('access entry failed'));document.head.append(s);});window.store=new keyModule.IndexedDbKeyStore();accessUi.startStorageAccess().then(()=>window.ready=true);return true;", [setup]);
    await wait("document.querySelector('#storage-create') && (document.querySelector('dialog').open || window.ready)");
  }
  async function click(name, passwordValue = password, extra = "") {
    await ctx.js(`document.querySelector('#storage-password').value=arguments[0];${extra}document.querySelector('#storage-${name}').click();return true;`, [passwordValue]);
    await wait(`!document.querySelector('#storage-${name}').disabled`);
  }
  await page(true);
  if (ctx.args.plaintext_only) {
    assert(await ctx.js("return !ready && document.querySelector('#storage-create').disabled && document.querySelector('#storage-feedback').textContent.includes('cannot open encrypted');"));
    assert.deepEqual(await ctx.snapshot(), ctx.legacy);
    ctx.checks.push("stock build blocks encrypted setup before creating key or database");
    await page(); assert(await ctx.js("return ready;"));
    ctx.checks.push("stock build retains default plaintext startup");
    return;
  }
  assert(!(await ctx.js("return ready;")));
  await click("create", password, "document.querySelector('#storage-confirm').value=arguments[0];");
  assert(await ctx.js("return !ready && (await store.read('spp.encrypted.db'))!==null && localStorage.getItem('spp.storage-access.v1')==='backup-required' && document.querySelector('#storage-resume').hidden && document.querySelector('#storage-manage').hidden;"));
  ctx.checks.push("setup UI persists wrapped key and creates separate encrypted OPFS before app initialization");
  await click("unlock");
  assert(await ctx.js("return !ready && document.querySelector('#storage-feedback').textContent.includes('backup');"));
  await ctx.js("window.backupText=null;URL.createObjectURL=blob=>{blob.text().then(text=>window.backupText=text);return 'blob:synthetic';};HTMLAnchorElement.prototype.click=function(){};return true;");
  await click("backup"); await wait("window.backupText!==null");
  await ctx.js("sessionStorage.setItem('test-backup',backupText);return true;");
  await click("unlock", "wrong");
  assert(await ctx.js("return !ready && document.querySelector('#storage-feedback').textContent.includes('Incorrect password');"));
  await click("unlock"); await wait("window.ready");
  await ctx.js("window.appStorage=await facade.ensureStorage();await appStorage.setSetting('app-access-protected',arguments[0]);return true;", [ctx.marker]);
  ctx.checks.push("backup required during setup; wrong password rejected; correct password opens app facade");
  await ctx.js("setTimeout(()=>{[...document.querySelectorAll('button')].find(b=>b.textContent==='Lock database').click();},50);return true;");
  await new Promise(resolve => setTimeout(resolve, 500));
  await page(); assert(!(await ctx.js("return ready;")));
  await ctx.js("const input=document.querySelector('#storage-password');input.value=arguments[0];input.focus();return true;", [password]);
  await ctx.request("POST", `/session/${ctx.sid}/actions`, { actions: [{ type: "key", id: "keyboard", actions: [{ type: "keyDown", value: "\ue007" }, { type: "keyUp", value: "\ue007" }] }] });
  await wait("window.ready");
  assert.equal(await ctx.js("return await (await facade.ensureStorage()).getSetting('app-access-protected');"), ctx.marker);
  await ctx.js("await facade.closeStorageForLock();return true;");
  ctx.checks.push("click unlock and Enter unlock both work; lock/reload preserve encrypted application settings");
  if (!ctx.firefox) {
    const cdp = (command, params) => ctx.request("POST", `/session/${ctx.sid}/goog/cdp/execute`, { cmd: command, params });
    await cdp("WebAuthn.enable", {});
    const authenticator = (await cdp("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } })).authenticatorId;
    await ctx.js("[...document.querySelectorAll('button')].find(b=>b.textContent==='Database security').click();return true;");
    await click("enroll");
    assert(await ctx.js("return (await store.read('spp.encrypted.db')).passkey!==null;"));
    await page(); await click("passkey", ""); await wait("window.ready");
    assert.equal(await ctx.js("return await (await facade.ensureStorage()).getSetting('app-access-protected');"), ctx.marker);
    await ctx.js("await facade.closeStorageForLock();return true;");
    await page();
    const replacement = "synthetic replacement password";
    await click("recover", "", `document.querySelector('#storage-new').value='${replacement}';document.querySelector('#storage-new-confirm').value='${replacement}';`);
    assert(await ctx.js("return !ready && document.querySelector('#storage-feedback').textContent.includes('Password reset');"));
    await click("unlock", replacement); await wait("window.ready");
    await ctx.js("await facade.closeStorageForLock();return true;");
    await cdp("WebAuthn.removeVirtualAuthenticator", { authenticatorId: authenticator });
    ctx.checks.push("actual Chromium WebAuthn with virtual PRF authenticator enrolls in UI, unlocks after reload and resets forgotten password while locked");
  }
  await ctx.js("await new Promise((resolve,reject)=>{const r=indexedDB.deleteDatabase('spp-database-key-vault');r.onsuccess=resolve;r.onerror=()=>reject(r.error);});return true;");
  await page();
  assert(await ctx.js("return !ready && !document.querySelector('#storage-restore-section').hidden && document.querySelector('#storage-create').hidden;"));
  await ctx.js("const transfer=new DataTransfer();transfer.items.add(new File([sessionStorage.getItem('test-backup')],'backup.json',{type:'application/json'}));document.querySelector('#storage-file').files=transfer.files;return true;");
  const before = await ctx.snapshot();
  await click("restore", "wrong");
  assert(await ctx.js("return (await store.read('spp.encrypted.db'))===null && !ready;"));
  assert.deepEqual(await ctx.snapshot(), before);
  await click("restore");
  assert(await ctx.js("return (await store.read('spp.encrypted.db'))!==null && !ready;"));
  await click("unlock"); await wait("window.ready");
  assert.equal(await ctx.js("return await (await facade.ensureStorage()).getSetting('app-access-protected');"), ctx.marker);
  await ctx.js("await facade.closeStorageForLock();return true;");
  ctx.checks.push("backup recovery rejects wrong password without mutation and restores access to existing encrypted data");
  const final = await ctx.snapshot();
  assert.deepEqual(final.filter(file => !file.path.startsWith(".opfs-sahpool-encrypted/")), ctx.legacy);
  assert(!final.some(file => file.protected));
  ctx.checks.push("new setup leaves original plaintext database byte-identical and protected data absent from artifacts");
}
