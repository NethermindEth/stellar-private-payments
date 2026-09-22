import assert from "node:assert/strict";

export async function run(ctx) {
  const password = "synthetic migration password";
  const wait = expression => ctx.js(`for(let i=0;i<500;i++){if(${expression})return true;await new Promise(r=>setTimeout(r,30));}throw Error('migration UI timed out');`);
  async function page() {
    await ctx.load();
    await ctx.js("history.replaceState(null,'','?storage=encrypted');window.ready=false;await new Promise((resolve,reject)=>{const s=document.createElement('script');s.type='module';s.src='/test-access-entry.js';s.onload=resolve;s.onerror=reject;document.head.append(s);});accessUi.startStorageAccess().then(()=>window.ready=true);return true;");
    await wait("document.querySelector('#storage-migrate') && document.querySelector('dialog').open");
  }
  async function click(name, supplied = password, extra = "") {
    await ctx.js(`document.querySelector('#storage-password').value=arguments[0];${extra}document.querySelector('#storage-${name}').click();return true;`, [supplied]);
    await wait(`!document.querySelector('#storage-${name}').disabled`);
  }
  async function sourceUnchanged() {
    assert.deepEqual((await ctx.snapshot()).filter(file => file.path.startsWith(".opfs-sahpool/")), ctx.legacy);
  }
  await page();
  if (ctx.args.plaintext_only) {
    assert(await ctx.js("return document.querySelector('#storage-migrate').disabled && !ready;"));
    assert.deepEqual(await ctx.snapshot(), ctx.legacy);
    ctx.checks.push("stock build disables migration before key or OPFS changes");
    return;
  }
  await click("migrate", password, "document.querySelector('#storage-confirm').value=arguments[0];");
  assert(await ctx.js("return localStorage.getItem('spp.storage-access.v1')==='migration-pending' && !ready && document.querySelector('#storage-feedback').textContent.includes('verified');"));
  await sourceUnchanged();
  const before = await ctx.snapshot();
  await ctx.js("localStorage.removeItem('spp.storage-access.v1');return true;");
  await page(); await click("unlock");
  assert(await ctx.js("return !ready && document.querySelector('dialog').open;"));
  assert.deepEqual(await ctx.snapshot(), before);
  await click("migration-recover", "wrong");
  assert.equal(await ctx.js("return localStorage.getItem('spp.storage-access.v1');"), null);
  assert.deepEqual(await ctx.snapshot(), before);
  await click("migration-recover");
  assert(await ctx.js("return localStorage.getItem('spp.storage-access.v1')==='migration-pending' && !ready;"));
  ctx.checks.push("lost selection cannot open an unactivated copy; authenticated recovery restores migration UI without modifying OPFS");
  await click("migration-activate");
  assert(await ctx.js("return document.querySelector('#storage-feedback').textContent.includes('Download your key backup');"));
  await sourceUnchanged();
  await click("migration-abort", "wrong");
  assert(await ctx.js("return document.querySelector('#storage-feedback').textContent.includes('Incorrect password');"));
  await sourceUnchanged();
  await click("migration-abort");
  assert(await ctx.js("return document.querySelector('#storage-feedback').textContent.includes('discarded');"));
  await sourceUnchanged();
  ctx.checks.push("prepare verifies copy without changing source; wrong password and missing backup cannot activate; abort preserves source");
  await page();
  assert(await ctx.js("return document.querySelector('#storage-unlock').hidden && !ready;"));
  await click("migration-prepare");
  assert(await ctx.js("return document.querySelector('#storage-feedback').textContent.includes('verified');"));
  await sourceUnchanged();
  await ctx.js("window.backupText=null;URL.createObjectURL=blob=>{blob.text().then(t=>window.backupText=t);return 'blob:synthetic';};HTMLAnchorElement.prototype.click=function(){};return true;");
  await click("backup"); await wait("window.backupText!==null");
  await click("migration-activate", password, "document.querySelector('#storage-migration-confirm').checked=true;");
  assert(await ctx.js("return localStorage.getItem('spp.storage-access.v1')==='backup-required' && document.querySelector('#storage-feedback').textContent.includes('Migration complete');"));
  await click("unlock"); await wait("window.ready");
  assert.equal(await ctx.js("return await (await facade.ensureStorage()).getSetting('integration-legacy');"), "legacy-preserved");
  await ctx.js("await facade.closeStorageForLock();return true;");
  ctx.checks.push("reload resumes same-key migration; explicit activation and cleanup allow encrypted app startup with original data");
  await page(); await click("unlock"); await wait("window.ready");
  assert.equal(await ctx.js("return await (await facade.ensureStorage()).getSetting('integration-legacy');"), "legacy-preserved");
  await ctx.js("await facade.closeStorageForLock();return true;");
  ctx.checks.push("encrypted migrated app reopens after page and worker restart");
}
