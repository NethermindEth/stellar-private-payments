import assert from "node:assert/strict";

export async function run(ctx) {
  const password = "synthetic wallet UI password";
  let material = null;
  const wait = expression => ctx.js(`for(let i=0;i<400;i++){if(${expression})return true;await new Promise(r=>setTimeout(r,30));}throw Error('wallet UI timed out');`);
  async function page() {
    await ctx.load();
    material = await ctx.js("const f=await import('/scripts/key-vault-fixture.mjs');window.walletFixture=await f.createWalletSigner(arguments[0]);history.replaceState(null,'','?storage=encrypted');window.ready=false;await new Promise((resolve,reject)=>{const s=document.createElement('script');s.type='module';s.src='/test-access-entry.js';s.onload=resolve;s.onerror=reject;document.head.append(s);});accessUi.startStorageAccess().then(()=>window.ready=true);return walletFixture.material;", [material]);
    await wait("document.querySelector('dialog')?.open");
  }
  async function click(name, supplied = password, extra = "") {
    await ctx.js(`document.querySelector('#storage-password').value=arguments[0];${extra}document.querySelector('#storage-${name}').click();return true;`, [supplied]);
    await wait(`!document.querySelector('#storage-${name}').disabled`);
  }
  await page();
  await click("create", password, "document.querySelector('#storage-confirm').value=arguments[0];");
  await ctx.js("URL.createObjectURL=()=> 'blob:synthetic';HTMLAnchorElement.prototype.click=function(){};return true;");
  await click("backup"); await click("unlock"); await wait("window.ready");
  await ctx.js("window.appStorage=await facade.ensureStorage();await appStorage.setSetting('wallet-protected',arguments[0]);[...document.querySelectorAll('button')].find(b=>b.textContent==='Database security').click();return true;", [ctx.marker]);
  await click("wallet-enroll");
  assert(await ctx.js("return walletFixture.state.calls.length===2 && document.querySelector('#storage-feedback').textContent.includes('Wallet unlock added');"));
  await ctx.js("await facade.closeStorageForLock();return true;");
  await page();
  assert(await ctx.js("return !document.querySelector('#storage-wallet').hidden && !ready;"));
  for (const fault of ["account", "signature", "cancel"]) {
    await ctx.js("walletFixture.state.fault=arguments[0];return true;", [fault]);
    const before = await ctx.snapshot();
    await click("wallet", "");
    assert(!(await ctx.js("return ready;")));
    assert.deepEqual(await ctx.snapshot(), before);
  }
  await ctx.js("walletFixture.state.fault=null;return true;");
  await click("wallet", ""); await wait("window.ready");
  assert.equal(await ctx.js("return await (await facade.ensureStorage()).getSetting('wallet-protected');"), ctx.marker);
  ctx.checks.push("synthetic wallet UI enrollment requires two signatures; reload unlock opens encrypted OPFS with original data");
  ctx.checks.push("wrong account, invalid signature and cancellation do not open or modify OPFS");
  await ctx.js("[...document.querySelectorAll('button')].find(b=>b.textContent==='Database security').click();return true;");
  await click("wallet-remove");
  await ctx.js("await facade.closeStorageForLock();return true;");
  await page();
  assert(await ctx.js("return document.querySelector('#storage-wallet').hidden;"));
  await click("unlock"); await wait("window.ready");
  assert.equal(await ctx.js("return await (await facade.ensureStorage()).getSetting('wallet-protected');"), ctx.marker);
  await ctx.js("await facade.closeStorageForLock();return true;");
  ctx.checks.push("wallet removal preserves password recovery and encrypted data");
  const final = await ctx.snapshot();
  assert.deepEqual(final.filter(file => !file.path.startsWith(".opfs-sahpool-encrypted/")), ctx.legacy);
  assert(!final.some(file => file.protected));
  ctx.checks.push("plaintext source unchanged; protected data absent from persistent artifacts");
}
