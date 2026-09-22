"""Complete backups and interruption recovery on synthetic OPFS only."""
import time


def run(ctx):
    js, checks = ctx['js'], ctx['checks']
    password = 'synthetic full backup password'
    saved_snapshot = None

    def load():
        ctx['load']()
        js("window.key=Uint8Array.from(arguments[0]);window.snapshotBytes=sessionStorage.getItem('snapshot')?Uint8Array.from(atob(sessionStorage.getItem('snapshot')),c=>c.charCodeAt(0)):null;return true;", [list(ctx['key'])])
        if saved_snapshot is not None:
            js('window.snapshotBytes=Uint8Array.from(arguments[0]);return true;', [saved_snapshot])

    def remove_target():
        js("const root=await navigator.storage.getDirectory();await root.removeEntry('.opfs-sahpool-encrypted',{recursive:true}).catch(e=>{if(e.name!=='NotFoundError')throw e;});return true;")

    def restore(extra=''):
        return js("await sdk.Storage.restoreEncrypted(snapshotBytes,{keyProvider:()=>key," + extra + "});return true;")

    if ctx['args'].plaintext_only:
        assert js("try{await sdk.Storage.restoreEncrypted(new Uint8Array(1024),{keyProvider:()=>{throw Error('provider should not run');}});return false;}catch(e){return String(e).includes('sqlite3mc');}")
        assert js("try{await sdk.Storage.exportEncrypted({}, {keyProvider:()=>{throw Error('provider should not run');}});return false;}catch(e){return String(e).includes('sqlite3mc');}")
        checks.append('stock build refuses encrypted export and restore before requesting key')
        return

    load()
    ctx['encrypted'](True)
    js("await storage.call({SetSetting:{key:'complete-backup-protected',value_json:JSON.stringify(arguments[0])}});window.snapshotBytes=await sdk.Storage.exportEncrypted(storage,{keyProvider:()=>key});sessionStorage.setItem('snapshot',btoa(Array.from(snapshotBytes,b=>String.fromCharCode(b)).join('')));return true;", [ctx['marker']])
    saved_snapshot = js('return Array.from(snapshotBytes);')
    assert js("return snapshotBytes.length>=512 && !new TextDecoder().decode(snapshotBytes).includes(arguments[0]);", [ctx['marker']])
    ctx['close']()
    baseline = ctx['snapshot']()
    try:
        restore()
        raise AssertionError('existing destination overwritten')
    except RuntimeError as error:
        assert 'already exists' in str(error)
    assert ctx['snapshot']() == baseline
    checks.append('consistent encrypted snapshot exports; existing destination refused without changing files')
    remove_target()
    for case in ['wrong-key', 'corruption', 'truncation']:
        load()
        assert js("let data=snapshotBytes.slice();let supplied=key.slice();if(arguments[0]==='wrong-key')supplied[0]^=1;else if(arguments[0]==='corruption')data[Math.floor(data.length/2)]^=1;else data=data.slice(0,Math.floor(data.length/2));try{await sdk.Storage.restoreEncrypted(data,{keyProvider:()=>supplied});return false;}catch{return true;}", [case])
        # No valid canonical database may be opened after rejection.
        try:
            ctx['encrypted']()
            raise AssertionError('invalid snapshot installed')
        except RuntimeError:
            pass
        remove_target()
    checks.append('wrong key, corrupted pages and truncation rejected before database installation')

    for fault in ['quota', 'during-write', 'after-sync']:
        load()
        js("window.faults=[];window.workers=[];const Original=Worker;window.Worker=class extends Original{constructor(...args){super(...args);workers.push(this);this.addEventListener('message',e=>{if(e.data?.migrationFault){e.stopImmediatePropagation();faults.push(e.data.migrationFault);}});}};window.pendingRestore=sdk.Storage.restoreEncrypted(snapshotBytes,{keyProvider:()=>key,workerUrl:'/scripts/test-sqlite3mc-migration-worker.js?fault='+arguments[0]+'&target=spp.encrypted.db'}).then(()=>true,e=>String(e));return true;", [fault])
        for _ in range(400):
            if fault in js('return faults;'):
                break
            time.sleep(.01)
        else:
            raise AssertionError('restore fault did not fire: ' + fault)
        if fault == 'quota':
            assert js('return await pendingRestore;') is not True
        else:
            js('for(const w of workers)w.terminate();return true;')
        if fault == 'during-write':
            # Retain only the external backup bytes across an actual browser-process restart.
            ctx['request']('DELETE', '/session/' + ctx['sid'])
            ctx['session']()
        load()
        try:
            ctx['encrypted']()
            raise AssertionError('incomplete restore opened normally')
        except RuntimeError:
            pass
        assert js("const changed=snapshotBytes.slice();changed[changed.length-1]^=1;try{await sdk.Storage.restoreEncrypted(changed,{keyProvider:()=>key});return false;}catch(e){return String(e).includes('another restore');}")
        restore()
        # Simulate loss of the first success response / metadata commit: exact retry is allowed.
        restore()
        ctx['encrypted']()
        assert ctx['marker'] in js("return await storage.call({GetSetting:'complete-backup-protected'});")['Setting']
        ctx['close']()
        try:
            restore()
            raise AssertionError('opened database became replaceable')
        except RuntimeError as error:
            assert 'already exists' in str(error)
        remove_target()
        checks.append(f'{fault}: ordinary open blocked; exact backup retry recovers; replacement disabled after normal open')
        if fault == 'during-write':
            checks.append('interrupted restore resumes across an actual browser-process restart')

    # Restore once for the application complete-backup screen.
    load(); restore()
    js("window.keys=await import('/js/key-vault.js');window.keyStore=new keys.IndexedDbKeyStore();window.vault=new keys.DatabaseKeyVault();window.session=await vault.createPassword(arguments[0]);return true;", [password])
    # That vault intentionally has a different random key. Replace only this synthetic
    # source database with one created from the UI vault, never user data.
    remove_target()
    js("window.storage=await sdk.Storage.openEncrypted({createNew:true,keyProvider:session.keyProvider});await storage.call({SetSetting:{key:'complete-backup-protected',value_json:JSON.stringify(arguments[0])}});await storage.close();storage.free();session.lock();localStorage.setItem('spp.storage-access.v1','encrypted');return true;", [ctx['marker']])

    def wait(expression):
        js("for(let i=0;i<400;i++){if(" + expression + ")return true;await new Promise(r=>setTimeout(r,25));}throw Error('backup UI timed out: '+document.querySelector('#storage-feedback')?.textContent);")

    def page():
        load()
        js("history.replaceState(null,'','?storage=encrypted');window.ready=false;await new Promise((resolve,reject)=>{const s=document.createElement('script');s.type='module';s.src='/test-access-entry.js';s.onload=resolve;s.onerror=()=>reject(Error('entry failed'));document.head.append(s);});window.store=new keyModule.IndexedDbKeyStore();accessUi.startStorageAccess().then(()=>window.ready=true);return true;")
        wait("document.querySelector('dialog')?.open")

    def click(name, supplied=password):
        js("document.querySelector('#storage-password').value=arguments[0];document.querySelector('#storage-" + name + "').click();return true;", [supplied])
        wait("!document.querySelector('#storage-" + name + "').disabled")

    page(); click('unlock'); wait('window.ready')
    js("[...document.querySelectorAll('button')].find(b=>b.textContent==='Database security').click();URL.createObjectURL=blob=>{blob.arrayBuffer().then(bytes=>sessionStorage.setItem('complete-archive',btoa(Array.from(new Uint8Array(bytes),b=>String.fromCharCode(b)).join(''))));return 'blob:synthetic';};HTMLAnchorElement.prototype.click=function(){};return true;")
    click('complete-backup')
    wait("sessionStorage.getItem('complete-archive')!==null")
    js("await facade.closeStorageForLock();await new Promise((resolve,reject)=>{const r=indexedDB.deleteDatabase('spp-database-key-vault');r.onsuccess=resolve;r.onerror=()=>reject(r.error);});localStorage.removeItem('spp.storage-access.v1');return true;")
    remove_target()
    page()
    js("const bytes=Uint8Array.from(atob(sessionStorage.getItem('complete-archive')),c=>c.charCodeAt(0));const transfer=new DataTransfer();transfer.items.add(new File([bytes],'complete.sppbackup'));document.querySelector('#storage-complete-file').files=transfer.files;return true;")
    before = ctx['snapshot']()
    click('complete-restore', 'wrong')
    assert ctx['snapshot']() == before
    assert js("return (await store.read('spp.encrypted.db'))===null && !ready;")
    click('complete-restore')
    assert js("return !ready && localStorage.getItem('spp.storage-access.v1')==='encrypted';")
    click('unlock'); wait('window.ready')
    assert js("return await (await facade.ensureStorage()).getSetting('complete-backup-protected');") == ctx['marker']
    js('await facade.closeStorageForLock();return true;')
    checks.append('application complete backup restores key and data after simulated site-data loss; wrong password writes nothing')
    final = ctx['snapshot']()
    assert [f for f in final if not f['path'].startswith('.opfs-sahpool-encrypted/')] == ctx['legacy']
    assert not any(f.get('protected') for f in final)
    checks.append('original plaintext namespace unchanged and no protected plaintext in persistent encrypted artifacts')
