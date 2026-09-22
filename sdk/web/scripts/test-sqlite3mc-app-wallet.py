"""Wallet UI with a synthetic Ed25519 signer; does not test the Freighter extension."""
def run(ctx):
    js, checks = ctx['js'], ctx['checks']
    password = 'synthetic wallet UI password'
    material = None
    def wait(expression):
        js("for(let i=0;i<400;i++){if(" + expression + ")return true;await new Promise(r=>setTimeout(r,30));}throw Error('wallet UI timed out');")
    def page():
        nonlocal material
        ctx['load']()
        material = js("const f=await import('/scripts/key-vault-fixture.mjs');window.walletFixture=await f.createWalletSigner(arguments[0]);history.replaceState(null,'','?storage=encrypted');window.ready=false;await new Promise((resolve,reject)=>{const s=document.createElement('script');s.type='module';s.src='/test-access-entry.js';s.onload=resolve;s.onerror=reject;document.head.append(s);});accessUi.startStorageAccess().then(()=>window.ready=true);return walletFixture.material;", [material])
        wait("document.querySelector('dialog')?.open")
    def click(name, supplied=password, extra=''):
        js("document.querySelector('#storage-password').value=arguments[0];" + extra + "document.querySelector('#storage-" + name + "').click();return true;", [supplied])
        wait("!document.querySelector('#storage-" + name + "').disabled")
    page()
    click('create', extra="document.querySelector('#storage-confirm').value=arguments[0];")
    js("URL.createObjectURL=()=> 'blob:synthetic';HTMLAnchorElement.prototype.click=function(){};return true;")
    click('backup'); click('unlock'); wait('window.ready')
    js("window.appStorage=await facade.ensureStorage();await appStorage.setSetting('wallet-protected',arguments[0]);[...document.querySelectorAll('button')].find(b=>b.textContent==='Database security').click();return true;", [ctx['marker']])
    click('wallet-enroll')
    assert js("return walletFixture.state.calls.length===2 && document.querySelector('#storage-feedback').textContent.includes('Wallet unlock added');")
    js('await facade.closeStorageForLock();return true;')
    page()
    assert js("return !document.querySelector('#storage-wallet').hidden && !ready;")
    for fault in ['account', 'signature', 'cancel']:
        js('walletFixture.state.fault=arguments[0];return true;', [fault])
        before = ctx['snapshot']()
        click('wallet', '')
        assert js('return !ready;')
        assert ctx['snapshot']() == before
    js('walletFixture.state.fault=null;return true;')
    click('wallet', ''); wait('window.ready')
    assert js("return await (await facade.ensureStorage()).getSetting('wallet-protected');") == ctx['marker']
    checks.append('synthetic wallet UI enrollment requires two signatures; reload unlock opens encrypted OPFS with original data')
    checks.append('wrong account, invalid signature and cancellation do not open or modify OPFS')
    js("[...document.querySelectorAll('button')].find(b=>b.textContent==='Database security').click();return true;")
    click('wallet-remove')
    js('await facade.closeStorageForLock();return true;')
    page()
    assert js("return document.querySelector('#storage-wallet').hidden;")
    click('unlock'); wait('window.ready')
    assert js("return await (await facade.ensureStorage()).getSetting('wallet-protected');") == ctx['marker']
    js('await facade.closeStorageForLock();return true;')
    checks.append('wallet removal preserves password recovery and encrypted data')
    final = ctx['snapshot']()
    assert [f for f in final if not f['path'].startswith('.opfs-sahpool-encrypted/')] == ctx['legacy']
    assert not any(f.get('protected') for f in final)
    checks.append('plaintext source unchanged; protected data absent from persistent artifacts')
