"""Real application facade startup tests on this runner's synthetic OPFS only."""
import secrets


def run(ctx):
    js, snapshot, key, marker = (ctx[n] for n in ["js", "snapshot", "key", "marker"])
    checks = ctx["checks"]

    def load_app(mode=None, supplied=key):
        ctx["load"]()
        js("await new Promise((resolve,reject)=>{const script=document.createElement('script');script.type='module';script.src='/test-app-entry.js';script.onload=resolve;script.onerror=()=>reject(Error('app module failed to load'));document.head.append(script);});window.providerCalls=0;window.supplied=Uint8Array.from(arguments[1]);if(arguments[0])appFacade.configureStorageStartup({mode:arguments[0],keyProvider:async(id,purpose)=>{window.providerCalls++;if(id!=='spp.encrypted.db'||purpose!=='open')throw Error('provider context');return window.supplied;}});return true;", [mode, list(supplied)])

    def open_app():
        return js("const [a,b]=await Promise.all([appFacade.ensureStorage(),appFacade.ensureStorage()]);if(a!==b)throw Error('duplicate AppStorage');window.appStorage=a;return window.workerCount;")

    def refused():
        return js("try{await appFacade.ensureStorage();return false;}catch(e){window.startupError=String(e);return true;}")

    load_app()
    assert open_app() == 1
    assert js("return await appStorage.getSetting('integration-legacy');") == "legacy-preserved"
    js("await appStorage.setBootnodeConfig('https://synthetic.invalid');return true;")
    assert js("return await appStorage.getStoredBootnodeUrl();") == "https://synthetic.invalid"
    assert js("try{appFacade.configureStorageStartup({mode:'encrypted',keyProvider:()=>supplied});return false;}catch{return true;}")
    checks.append("app default startup shares one worker and preserves settings API")
    ctx["load"]()
    before = snapshot()

    if ctx["args"].plaintext_only:
        for mode in ["encrypted", "migrated"]:
            load_app(mode)
            assert refused()
            assert js("return startupError.includes('sqlite3mc feature')&&providerCalls===0&&workerCount===0;")
            assert snapshot() == before
            checks.append(f"stock app {mode} startup refuses before key provider without fallback")
        return

    ctx["encrypted"](True)
    js("await storage.call({SetSetting:{key:'app-protected',value_json:JSON.stringify(arguments[0])}});return true;", [marker])
    ctx["close"]()
    baseline = snapshot()
    for label, supplied in [("wrong key", secrets.token_bytes(32)), ("missing key", b"")]:
        load_app("encrypted", supplied)
        assert refused()
        assert snapshot() == baseline
        assert js("try{appFacade.configureStorageStartup({mode:'plaintext'});return false;}catch{return true;}")
        # Retry an unlocked provider without reconfiguring or creating a database.
        js("window.supplied=Uint8Array.from(arguments[0]);return true;", [list(key)])
        open_app()
        assert js("return await appStorage.getSetting('app-protected');") == marker
        checks.append(f"app {label} fails without writes or fallback; same-provider retry succeeds")
        ctx["load"]()
        baseline = snapshot()

    load_app("encrypted")
    assert open_app() == 1
    assert js("return window.providerCalls;") == 1
    js("await appStorage.setSetting('app-restart',arguments[0]);return true;", [marker])
    checks.append("app encrypted startup shares provider and worker")
    ctx["request"]("DELETE", "/session/" + ctx["sid"])
    ctx["sid"] = None
    ctx["session"]()
    load_app("encrypted")
    assert open_app() == 1
    assert js("return await appStorage.getSetting('app-restart');") == marker
    checks.append("app encrypted settings survive full browser restart")
    ctx["load"]()
    encrypted_files = [f for f in snapshot() if f["path"].startswith(".opfs-sahpool-encrypted/")]
    assert encrypted_files and not any(f.get("protected", False) for f in encrypted_files)
    assert [f for f in snapshot() if not f["path"].startswith(".opfs-sahpool-encrypted/")] == before
    checks.append("app encrypted writes preserve plaintext source and expose no protected marker")

    # Reuse only the isolated test profile; replace the encrypted fixture with
    # a new synthetic migration. The default source is still the original fixture.
    js("const root=await navigator.storage.getDirectory();await root.removeEntry('.opfs-sahpool-encrypted',{recursive:true});window.storage=await sdk.Storage.open();await storage.call({SetSetting:{key:'app-protected',value_json:JSON.stringify(arguments[0])}});return true;", [marker])
    ctx["close"]()

    def migration(action=None, create=False):
        ctx["load"]()
        return js("const m=await sdk.Storage.openMigration({createNew:arguments[1],keyProvider:()=>Uint8Array.from(arguments[0])});try{return arguments[2]?await m[arguments[2]]():await m.status();}finally{await m.close();}", [list(key), create, action])

    assert migration(create=True) == "copying"
    for status, action in [("copying", None), ("prepared", "prepare"), ("aborted", "abort")]:
        if action:
            assert migration(action) == status
        baseline = snapshot()
        load_app("migrated")
        assert refused()
        assert js("return startupError.includes(arguments[0]);", [status])
        assert snapshot() == baseline
        checks.append(f"app {status} migration refuses startup without fallback or data changes")

    assert migration("restart") == "copying"
    assert migration("prepare") == "prepared"
    assert migration("activate") == "active"
    baseline = snapshot()
    load_app("migrated", secrets.token_bytes(32))
    assert refused()
    assert snapshot() == baseline
    checks.append("app migrated startup authenticates control; wrong key leaves OPFS unchanged")
    load_app("migrated")
    assert open_app() == 2  # control worker released, then data worker
    assert js("return await appStorage.getSetting('app-protected');") == marker
    js("await appStorage.setSetting('app-after-activation',arguments[0]);return true;", [marker])
    load_app("migrated")
    assert open_app() == 2
    assert js("return await appStorage.getSetting('app-after-activation');") == marker
    checks.append("app active migration selects encrypted data and preserves post-activation writes")
    assert migration("finish") == "complete"
    load_app("migrated")
    assert open_app() == 2
    assert js("return await appStorage.getSetting('app-after-activation');") == marker
    ctx["load"]()
    assert not any(f.get("protected", False) for f in snapshot())
    checks.append("app completed migration reopens encrypted data after plaintext cleanup")
