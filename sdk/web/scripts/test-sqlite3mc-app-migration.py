"""Explicit application migration on a synthetic plaintext database."""
def run(ctx):
    js, checks = ctx['js'], ctx['checks']
    password = 'synthetic migration password'

    def wait(expression):
        js("for(let i=0;i<500;i++){if(" + expression + ")return true;await new Promise(r=>setTimeout(r,30));}throw Error('migration UI timed out');")

    def page():
        ctx['load']()
        js("history.replaceState(null,'','?storage=encrypted');window.ready=false;await new Promise((resolve,reject)=>{const s=document.createElement('script');s.type='module';s.src='/test-access-entry.js';s.onload=resolve;s.onerror=reject;document.head.append(s);});accessUi.startStorageAccess().then(()=>window.ready=true);return true;")
        wait("document.querySelector('#storage-migrate') && document.querySelector('dialog').open")

    def click(name, supplied=password, extra=''):
        js("document.querySelector('#storage-password').value=arguments[0];" + extra + "document.querySelector('#storage-" + name + "').click();return true;", [supplied])
        wait("!document.querySelector('#storage-" + name + "').disabled")

    page()
    if ctx['args'].plaintext_only:
        assert js("return document.querySelector('#storage-migrate').disabled && !ready;")
        assert ctx['snapshot']() == ctx['legacy']
        checks.append('stock build disables migration before key or OPFS changes')
        return
    click('migrate', extra="document.querySelector('#storage-confirm').value=arguments[0];")
    assert js("return localStorage.getItem('spp.storage-access.v1')==='migration-pending' && !ready && document.querySelector('#storage-feedback').textContent.includes('verified');")
    def source_unchanged():
        assert [f for f in ctx['snapshot']() if f['path'].startswith('.opfs-sahpool/')] == ctx['legacy']
    source_unchanged()
    # Local selection is only UI metadata; losing it must not expose the copy.
    before = ctx['snapshot']()
    js("localStorage.removeItem('spp.storage-access.v1');return true;")
    page()
    click('unlock')
    assert js("return !ready && document.querySelector('dialog').open;")
    assert ctx['snapshot']() == before
    click('migration-recover', 'wrong')
    assert js("return localStorage.getItem('spp.storage-access.v1')===null;")
    assert ctx['snapshot']() == before
    click('migration-recover')
    assert js("return localStorage.getItem('spp.storage-access.v1')==='migration-pending' && !ready;")
    checks.append('lost selection cannot open an unactivated copy; authenticated recovery restores migration UI without modifying OPFS')
    click('migration-activate')
    assert js("return document.querySelector('#storage-feedback').textContent.includes('Download your key backup');")
    source_unchanged()
    click('migration-abort', 'wrong')
    assert js("return document.querySelector('#storage-feedback').textContent.includes('Incorrect password');")
    source_unchanged()
    click('migration-abort')
    assert js("return document.querySelector('#storage-feedback').textContent.includes('discarded');")
    source_unchanged()
    checks.append('prepare verifies copy without changing source; wrong password and missing backup cannot activate; abort preserves source')
    page()
    assert js("return document.querySelector('#storage-unlock').hidden && !ready;")
    click('migration-prepare')
    assert js("return document.querySelector('#storage-feedback').textContent.includes('verified');")
    source_unchanged()
    # Capture only a synthetic key-envelope download, never user browser data.
    js("window.backupText=null;URL.createObjectURL=blob=>{blob.text().then(t=>window.backupText=t);return 'blob:synthetic';};HTMLAnchorElement.prototype.click=function(){};return true;")
    click('backup')
    wait('window.backupText!==null')
    click('migration-activate', extra="document.querySelector('#storage-migration-confirm').checked=true;")
    assert js("return localStorage.getItem('spp.storage-access.v1')==='backup-required' && document.querySelector('#storage-feedback').textContent.includes('Migration complete');")
    click('unlock')
    wait('window.ready')
    assert js("return await (await facade.ensureStorage()).getSetting('integration-legacy');") == 'legacy-preserved'
    js('await facade.closeStorageForLock();return true;')
    checks.append('reload resumes same-key migration; explicit activation and cleanup allow encrypted app startup with original data')
    page()
    click('unlock')
    wait('window.ready')
    assert js("return await (await facade.ensureStorage()).getSetting('integration-legacy');") == 'legacy-preserved'
    js('await facade.closeStorageForLock();return true;')
    checks.append('encrypted migrated app reopens after page and worker restart')
