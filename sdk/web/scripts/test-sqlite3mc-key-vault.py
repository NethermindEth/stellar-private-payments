"""Wrapped database-key lifecycle on real IndexedDB + encrypted OPFS."""


def run(ctx):
    js, checks, snapshot = ctx["js"], ctx["checks"], ctx["snapshot"]
    password = "synthetic correct horse battery"
    changed = "synthetic updated long password"

    def load():
        ctx["load"]()
        js("window.keys=await import('/js/key-vault.js');window.vault=new keys.DatabaseKeyVault();window.keyStore=new keys.IndexedDbKeyStore();return true;")

    def record():
        return js("return await keyStore.read('spp.encrypted.db');")

    def unlock(password):
        js("window.unlocked=await vault.unlockPassword(arguments[0]);window.storage=await sdk.Storage.openEncrypted({keyProvider:unlocked.keyProvider});return true;", [password])

    def close():
        ctx["close"]()
        js("unlocked.lock();window.unlocked=null;return true;")

    load()
    js("window.unlocked=await vault.createPassword(arguments[0]);window.storage=await sdk.Storage.openEncrypted({createNew:true,keyProvider:unlocked.keyProvider});await storage.call({SetSetting:{key:'wrapped-protected',value_json:JSON.stringify(arguments[1])}});return true;", [password, ctx["marker"]])
    close()
    before = snapshot()
    wrapped = record()
    assert password not in str(wrapped)
    assert js("const r=await keyStore.read('spp.encrypted.db');return r.password.ciphertext.length===64&&r.passkey===null;")
    checks.append("password-wrapped random key persisted before encrypted OPFS creation")
    assert js("try{await vault.unlockPassword('wrong password');return false;}catch(e){return e.code==='unlock-failed';}")
    assert snapshot() == before and record() == wrapped
    checks.append("wrong password leaves IndexedDB envelope and OPFS byte-identical")
    load()
    unlock(password)
    assert ctx["marker"] in js("return await storage.call({GetSetting:'wrapped-protected'});")["Setting"]
    close()
    checks.append("password unlock and encrypted query after page/worker restart")
    js("await vault.changePassword(arguments[0],arguments[1]);return true;", [password, changed])
    assert snapshot() == before
    assert js("try{await vault.unlockPassword(arguments[0]);return false;}catch(e){return e.code==='unlock-failed';}", [password])
    checks.append("password change only rewraps metadata, leaving database bytes unchanged")
    ctx["request"]("DELETE", "/session/" + ctx["sid"])
    ctx["sid"] = None
    ctx["session"]()
    load()
    unlock(changed)
    assert ctx["marker"] in js("return await storage.call({GetSetting:'wrapped-protected'});")["Setting"]
    close()
    checks.append("wrapped key and encrypted data survive full browser restart")
    original = record()
    assert js("const [a,b]=await Promise.all([keyStore.read('spp.encrypted.db'),keyStore.read('spp.encrypted.db')]);const next={...a,revision:a.revision+1};await keyStore.write(a.databaseId,next,a);try{await keyStore.write(b.databaseId,{...b,revision:b.revision+1},b);return false;}catch(e){return e.code==='conflict';}")
    checks.append("real IndexedDB rejects stale compare-and-swap updates")
    js("window.savedRecord=await keyStore.read('spp.encrypted.db');const damaged=structuredClone(savedRecord);damaged.password.ciphertext='A'.repeat(64);await keyStore.write(damaged.databaseId,damaged,savedRecord);return true;")
    assert js("try{await vault.unlockPassword(arguments[0]);return false;}catch(e){return e.code==='unlock-failed';}", [changed])
    assert snapshot() == before
    js("await keyStore.write(savedRecord.databaseId,savedRecord,await keyStore.read(savedRecord.databaseId));return true;")
    checks.append("tampered envelope fails without touching encrypted OPFS")

    if ctx["args"].browser == "chromium":
        def cdp(command, params):
            return ctx["request"]("POST", f"/session/{ctx['sid']}/goog/cdp/execute", {"cmd": command, "params": params})
        cdp("WebAuthn.enable", {})
        authenticator = cdp("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "internal",
            "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True, "hasPrf": True,
        }})["authenticatorId"]
        js("await vault.addPasskey(arguments[0]);return true;", [changed])
        assert record()["passkey"] is not None
        load()
        js("window.unlocked=await vault.unlockPasskey();window.storage=await sdk.Storage.openEncrypted({keyProvider:unlocked.keyProvider});return true;")
        assert ctx["marker"] in js("return await storage.call({GetSetting:'wrapped-protected'});")["Setting"]
        close()
        checks.append("Chromium actual WebAuthn PRF with virtual authenticator unlocks OPFS after reload")
        js("await vault.resetPasswordWithPasskey(arguments[0]);return true;", [password])
        unlock(password)
        close()
        checks.append("virtual passkey resets password while preserving encrypted data")
        js("await vault.removePasskey(arguments[0]);return true;", [password])
        cdp("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator})
    else:
        # Firefox has no matching CDP PRF virtual authenticator. Exercise the
        # browser crypto/storage path with a labelled fixture, never claim Proton.
        js("const {fakeCredentials}=await import('/scripts/key-vault-fixture.mjs');window.fake=fakeCredentials(location.origin);window.vault=new keys.DatabaseKeyVault({credentials:fake.credentials});await vault.addPasskey(arguments[0]);window.unlocked=await vault.unlockPasskey();window.storage=await sdk.Storage.openEncrypted({keyProvider:unlocked.keyProvider});return true;", [changed])
        assert ctx["marker"] in js("return await storage.call({GetSetting:'wrapped-protected'});")["Setting"]
        close()
        checks.append("Firefox PRF fixture (not real authenticator) unwraps same key and reads OPFS")
        baseline = record()
        assert js("fake.state.fault='cancel-get';try{await vault.unlockPasskey();return false;}catch(e){return e.name==='NotAllowedError';}")
        assert record() == baseline and snapshot() == before
        checks.append("cancelled passkey leaves password wrapper and OPFS unchanged")
        js("await vault.removePasskey(arguments[0]);return true;", [changed])
    assert snapshot() == before
    assert not any(f.get("protected", False) for f in snapshot() if f["path"].startswith('.opfs-sahpool-encrypted/'))
    checks.append("all wrapping operations preserve data bytes; encrypted artifacts contain no protected marker")
