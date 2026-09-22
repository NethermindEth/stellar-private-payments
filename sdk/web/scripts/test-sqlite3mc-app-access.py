"""Application access UI with real key wrapping, facade, IndexedDB and encrypted OPFS."""


def run(ctx):
    js, checks = ctx['js'], ctx['checks']
    password = 'synthetic application password'

    def page(setup=False):
        ctx['load']()
        js("if(arguments[0])history.replaceState(null,'','?storage=encrypted');window.ready=false;await new Promise((resolve,reject)=>{const s=document.createElement('script');s.type='module';s.src='/test-access-entry.js';s.onload=resolve;s.onerror=()=>reject(Error('access entry failed'));document.head.append(s);});window.store=new keyModule.IndexedDbKeyStore();accessUi.startStorageAccess().then(()=>window.ready=true);return true;", [setup])
        wait("document.querySelector('#storage-create') && (document.querySelector('dialog').open || window.ready)")

    def wait(expression):
        js("for(let i=0;i<300;i++){if(" + expression + ")return true;await new Promise(r=>setTimeout(r,30));}throw Error('UI condition timed out');")

    def click(name, password_value=password, extra=''):
        js("document.querySelector('#storage-password').value=arguments[0];" + extra + "document.querySelector('#storage-" + name + "').click();return true;", [password_value])
        wait("!document.querySelector('#storage-" + name + "').disabled")

    page(True)
    if ctx['args'].plaintext_only:
        assert js("return !ready && document.querySelector('#storage-create').disabled && document.querySelector('#storage-feedback').textContent.includes('cannot open encrypted');")
        assert ctx['snapshot']() == ctx['legacy']
        checks.append('stock build blocks encrypted setup before creating key or database')
        page()
        assert js('return ready;')
        checks.append('stock build retains default plaintext startup')
        return

    assert js('return !ready;')
    click('create', extra="document.querySelector('#storage-confirm').value=arguments[0];")
    assert js("return !ready && (await store.read('spp.encrypted.db'))!==null && localStorage.getItem('spp.storage-access.v1')==='backup-required' && document.querySelector('#storage-resume').hidden && document.querySelector('#storage-manage').hidden;")
    checks.append('setup UI persists wrapped key and creates separate encrypted OPFS before app initialization')
    click('unlock')
    assert js("return !ready && document.querySelector('#storage-feedback').textContent.includes('backup');")
    # Capture download content in this synthetic profile, without returning key metadata to the driver.
    js("window.backupText=null;URL.createObjectURL=blob=>{blob.text().then(text=>window.backupText=text);return 'blob:synthetic';};HTMLAnchorElement.prototype.click=function(){};return true;")
    click('backup')
    wait('window.backupText!==null')
    js("sessionStorage.setItem('test-backup',backupText);return true;")
    click('unlock', 'wrong')
    assert js("return !ready && document.querySelector('#storage-feedback').textContent.includes('Incorrect password');")
    click('unlock')
    wait('window.ready')
    js("window.appStorage=await facade.ensureStorage();await appStorage.setSetting('app-access-protected',arguments[0]);return true;", [ctx['marker']])
    checks.append('backup required during setup; wrong password rejected; correct password opens app facade')
    # Actual lock path closes the shared worker then reloads; wait through navigation using WebDriver.
    js("setTimeout(()=>{[...document.querySelectorAll('button')].find(b=>b.textContent==='Lock database').click();},50);return true;")
    import time
    time.sleep(.5)
    page()
    assert js('return !ready;')
    js("const input=document.querySelector('#storage-password');input.value=arguments[0];input.focus();return true;", [password])
    ctx['request']('POST', f"/session/{ctx['sid']}/actions", {'actions': [{
        'type': 'key', 'id': 'keyboard', 'actions': [
            {'type': 'keyDown', 'value': '\ue007'}, {'type': 'keyUp', 'value': '\ue007'},
        ],
    }]})
    wait('window.ready')
    assert js("return await (await facade.ensureStorage()).getSetting('app-access-protected');") == ctx['marker']
    js('await facade.closeStorageForLock();return true;')
    checks.append('click unlock and Enter unlock both work; lock/reload preserve encrypted application settings')

    if not ctx['firefox']:
        def cdp(command, params):
            return ctx['request']('POST', f"/session/{ctx['sid']}/goog/cdp/execute", {'cmd': command, 'params': params})
        cdp('WebAuthn.enable', {})
        authenticator = cdp('WebAuthn.addVirtualAuthenticator', {'options': {
            'protocol': 'ctap2', 'ctap2Version': 'ctap2_1', 'transport': 'internal',
            'hasResidentKey': True, 'hasUserVerification': True, 'isUserVerified': True,
            'automaticPresenceSimulation': True, 'hasPrf': True,
        }})['authenticatorId']
        js("[...document.querySelectorAll('button')].find(b=>b.textContent==='Database security').click();return true;")
        click('enroll')
        assert js("return (await store.read('spp.encrypted.db')).passkey!==null;")
        page()
        click('passkey', '')
        wait('window.ready')
        assert js("return await (await facade.ensureStorage()).getSetting('app-access-protected');") == ctx['marker']
        js('await facade.closeStorageForLock();return true;')
        page()
        replacement = 'synthetic replacement password'
        click('recover', '', "document.querySelector('#storage-new').value='" + replacement + "';document.querySelector('#storage-new-confirm').value='" + replacement + "';")
        assert js("return !ready && document.querySelector('#storage-feedback').textContent.includes('Password reset');")
        click('unlock', replacement)
        wait('window.ready')
        js('await facade.closeStorageForLock();return true;')
        cdp('WebAuthn.removeVirtualAuthenticator', {'authenticatorId': authenticator})
        checks.append('actual Chromium WebAuthn with virtual PRF authenticator enrolls in UI, unlocks after reload and resets forgotten password while locked')

    # Simulate loss of wrapping metadata only, never delete OPFS or the encrypted mode marker.
    js("await new Promise((resolve,reject)=>{const r=indexedDB.deleteDatabase('spp-database-key-vault');r.onsuccess=resolve;r.onerror=()=>reject(r.error);});return true;")
    page()
    assert js("return !ready && !document.querySelector('#storage-restore-section').hidden && document.querySelector('#storage-create').hidden;")
    js("const transfer=new DataTransfer();transfer.items.add(new File([sessionStorage.getItem('test-backup')],'backup.json',{type:'application/json'}));document.querySelector('#storage-file').files=transfer.files;return true;")
    before = ctx['snapshot']()
    click('restore', 'wrong')
    assert js("return (await store.read('spp.encrypted.db'))===null && !ready;")
    assert ctx['snapshot']() == before
    click('restore')
    assert js("return (await store.read('spp.encrypted.db'))!==null && !ready;")
    click('unlock')
    wait('window.ready')
    assert js("return await (await facade.ensureStorage()).getSetting('app-access-protected');") == ctx['marker']
    js('await facade.closeStorageForLock();return true;')
    checks.append('backup recovery rejects wrong password without mutation and restores access to existing encrypted data')
    final = ctx['snapshot']()
    assert [f for f in final if not f['path'].startswith('.opfs-sahpool-encrypted/')] == ctx['legacy']
    assert not any(f.get('protected') for f in final)
    checks.append('new setup leaves original plaintext database byte-identical and protected data absent from artifacts')
