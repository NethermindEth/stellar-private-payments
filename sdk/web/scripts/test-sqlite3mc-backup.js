import assert from "node:assert/strict";

export async function run(ctx) {
  const password = "synthetic full backup password";
  let savedSnapshot = null;
  async function load() {
    await ctx.load();
    await ctx.js("window.key=Uint8Array.from(arguments[0]);window.snapshotBytes=sessionStorage.getItem('snapshot')?Uint8Array.from(atob(sessionStorage.getItem('snapshot')),c=>c.charCodeAt(0)):null;return true;", [Array.from(ctx.key)]);
    if (savedSnapshot) await ctx.js("window.snapshotBytes=Uint8Array.from(arguments[0]);return true;", [savedSnapshot]);
  }
  const removeTarget = () => ctx.js("const root=await navigator.storage.getDirectory();await root.removeEntry('.opfs-sahpool-encrypted',{recursive:true}).catch(e=>{if(e.name!=='NotFoundError')throw e;});return true;");
  const restore = (extra = "") => ctx.js(`await sdk.Storage.restoreEncrypted(snapshotBytes,{keyProvider:()=>key,${extra}});return true;`);
  async function expectFailure(operation, text) {
    try { await operation(); } catch (error) { if (text) assert.match(String(error), new RegExp(text)); return; }
    assert.fail("operation unexpectedly succeeded");
  }
  if (ctx.args.plaintext_only) {
    assert(await ctx.js("try{await sdk.Storage.restoreEncrypted(new Uint8Array(1024),{keyProvider:()=>{throw Error('provider should not run');}});return false;}catch(e){return String(e).includes('sqlite3mc');}"));
    assert(await ctx.js("try{await sdk.Storage.exportEncrypted({}, {keyProvider:()=>{throw Error('provider should not run');}});return false;}catch(e){return String(e).includes('sqlite3mc');}"));
    ctx.checks.push("stock build refuses encrypted export and restore before requesting key");
    return;
  }
  await load(); await ctx.encrypted(true);
  await ctx.js("await storage.call({SetSetting:{key:'complete-backup-protected',value_json:JSON.stringify(arguments[0])}});window.snapshotBytes=await sdk.Storage.exportEncrypted(storage,{keyProvider:()=>key});sessionStorage.setItem('snapshot',btoa(Array.from(snapshotBytes,b=>String.fromCharCode(b)).join('')));return true;", [ctx.marker]);
  savedSnapshot = await ctx.js("return Array.from(snapshotBytes);");
  assert(await ctx.js("return snapshotBytes.length>=512 && !new TextDecoder().decode(snapshotBytes).includes(arguments[0]);", [ctx.marker]));
  await ctx.close();
  const baseline = await ctx.snapshot();
  await expectFailure(restore, "already exists");
  assert.deepEqual(await ctx.snapshot(), baseline);
  ctx.checks.push("consistent encrypted snapshot exports; existing destination refused without changing files");
  await removeTarget();
  for (const testCase of ["wrong-key", "corruption", "truncation"]) {
    await load();
    assert(await ctx.js("let data=snapshotBytes.slice();let supplied=key.slice();if(arguments[0]==='wrong-key')supplied[0]^=1;else if(arguments[0]==='corruption')data[Math.floor(data.length/2)]^=1;else data=data.slice(0,Math.floor(data.length/2));try{await sdk.Storage.restoreEncrypted(data,{keyProvider:()=>supplied});return false;}catch{return true;}", [testCase]));
    await expectFailure(() => ctx.encrypted());
    await removeTarget();
  }
  ctx.checks.push("wrong key, corrupted pages and truncation rejected before database installation");
  for (const fault of ["quota", "during-write", "after-sync"]) {
    await load();
    await ctx.js("window.faults=[];window.workers=[];const Original=Worker;window.Worker=class extends Original{constructor(...args){super(...args);workers.push(this);this.addEventListener('message',e=>{if(e.data?.migrationFault){e.stopImmediatePropagation();faults.push(e.data.migrationFault);}});}};window.pendingRestore=sdk.Storage.restoreEncrypted(snapshotBytes,{keyProvider:()=>key,workerUrl:'/scripts/test-sqlite3mc-migration-worker.js?fault='+arguments[0]+'&target=spp.encrypted.db'}).then(()=>true,e=>String(e));return true;", [fault]);
    let fired = false;
    for (let tries = 0; tries < 400; tries++) {
      if ((await ctx.js("return faults;")).includes(fault)) { fired = true; break; }
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert(fired, `restore fault did not fire: ${fault}`);
    if (fault === "quota") assert.notEqual(await ctx.js("return await pendingRestore;"), true);
    else await ctx.js("for(const w of workers)w.terminate();return true;");
    if (fault === "during-write") {
      await ctx.request("DELETE", `/session/${ctx.sid}`); ctx.sid = null; await ctx.session();
    }
    await load(); await expectFailure(() => ctx.encrypted());
    assert(await ctx.js("const changed=snapshotBytes.slice();changed[changed.length-1]^=1;try{await sdk.Storage.restoreEncrypted(changed,{keyProvider:()=>key});return false;}catch(e){return String(e).includes('another restore');}"));
    await restore(); await restore(); await ctx.encrypted();
    assert.match((await ctx.js("return await storage.call({GetSetting:'complete-backup-protected'});" )).Setting, new RegExp(ctx.marker));
    await ctx.close();
    await expectFailure(restore, "already exists");
    await removeTarget();
    ctx.checks.push(`${fault}: ordinary open blocked; exact backup retry recovers; replacement disabled after normal open`);
    if (fault === "during-write") ctx.checks.push("interrupted restore resumes across an actual browser-process restart");
  }
  await load(); await restore();
  await ctx.js("window.keys=await import('/js/key-vault.js');window.keyStore=new keys.IndexedDbKeyStore();window.vault=new keys.DatabaseKeyVault();window.session=await vault.createPassword(arguments[0]);return true;", [password]);
  await removeTarget();
  await ctx.js("window.storage=await sdk.Storage.openEncrypted({createNew:true,keyProvider:session.keyProvider});await storage.call({SetSetting:{key:'complete-backup-protected',value_json:JSON.stringify(arguments[0])}});await storage.close();storage.free();session.lock();localStorage.setItem('spp.storage-access.v1','encrypted');return true;", [ctx.marker]);
  const wait = expression => ctx.js(`for(let i=0;i<400;i++){if(${expression})return true;await new Promise(r=>setTimeout(r,25));}throw Error('backup UI timed out: '+document.querySelector('#storage-feedback')?.textContent);`);
  async function page() {
    await load();
    await ctx.js("history.replaceState(null,'','?storage=encrypted');window.ready=false;await new Promise((resolve,reject)=>{const s=document.createElement('script');s.type='module';s.src='/test-access-entry.js';s.onload=resolve;s.onerror=()=>reject(Error('entry failed'));document.head.append(s);});window.store=new keyModule.IndexedDbKeyStore();accessUi.startStorageAccess().then(()=>window.ready=true);return true;");
    await wait("document.querySelector('dialog')?.open");
  }
  async function click(name, supplied = password) {
    await ctx.js(`document.querySelector('#storage-password').value=arguments[0];document.querySelector('#storage-${name}').click();return true;`, [supplied]);
    await wait(`!document.querySelector('#storage-${name}').disabled`);
  }
  await page(); await click("unlock"); await wait("window.ready");
  await ctx.js("[...document.querySelectorAll('button')].find(b=>b.textContent==='Database security').click();URL.createObjectURL=blob=>{blob.arrayBuffer().then(bytes=>sessionStorage.setItem('complete-archive',btoa(Array.from(new Uint8Array(bytes),b=>String.fromCharCode(b)).join(''))));return 'blob:synthetic';};HTMLAnchorElement.prototype.click=function(){};return true;");
  await click("complete-backup"); await wait("sessionStorage.getItem('complete-archive')!==null");
  await ctx.js("await facade.closeStorageForLock();await new Promise((resolve,reject)=>{const r=indexedDB.deleteDatabase('spp-database-key-vault');r.onsuccess=resolve;r.onerror=()=>reject(r.error);});localStorage.removeItem('spp.storage-access.v1');return true;");
  await removeTarget(); await page();
  await ctx.js("const bytes=Uint8Array.from(atob(sessionStorage.getItem('complete-archive')),c=>c.charCodeAt(0));const transfer=new DataTransfer();transfer.items.add(new File([bytes],'complete.sppbackup'));document.querySelector('#storage-complete-file').files=transfer.files;return true;");
  const before = await ctx.snapshot();
  await click("complete-restore", "wrong");
  assert.deepEqual(await ctx.snapshot(), before);
  assert(await ctx.js("return (await store.read('spp.encrypted.db'))===null && !ready;"));
  await click("complete-restore");
  assert(await ctx.js("return !ready && localStorage.getItem('spp.storage-access.v1')==='encrypted';"));
  await click("unlock"); await wait("window.ready");
  assert.equal(await ctx.js("return await (await facade.ensureStorage()).getSetting('complete-backup-protected');"), ctx.marker);
  await ctx.js("await facade.closeStorageForLock();return true;");
  ctx.checks.push("application complete backup restores key and data after simulated site-data loss; wrong password writes nothing");
  const final = await ctx.snapshot();
  assert.deepEqual(final.filter(file => !file.path.startsWith(".opfs-sahpool-encrypted/")), ctx.legacy);
  assert(!final.some(file => file.protected));
  ctx.checks.push("original plaintext namespace unchanged and no protected plaintext in persistent encrypted artifacts");
}
