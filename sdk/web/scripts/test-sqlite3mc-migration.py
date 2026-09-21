"""Migration matrix used by test-sqlite3mc.py --migration (synthetic profiles only)."""
import sqlite3
import time


def run(ctx):
    js, snapshot, key, marker = (ctx[n] for n in ["js", "snapshot", "key", "marker"])
    checks = ctx["checks"]

    def load():
        ctx["load"]()
        assert js("window.migrationWorkers=[];window.faults=[];window.armed=null;const Original=Worker;window.Worker=class extends Original{constructor(...args){super(...args);migrationWorkers.push(this);this.addEventListener('message',e=>{if(e.data?.migrationFault){e.stopImmediatePropagation();faults.push(e.data.migrationFault);}if(e.data?.migrationArmed){e.stopImmediatePropagation();window.armed=e.data.migrationArmed;}});}};return crossOriginIsolated;")

    def open_migration(create=False, supplied=key):
        return js("window.migration=await sdk.Storage.openMigration({workerUrl:'/scripts/test-sqlite3mc-migration-worker.js',createNew:arguments[1],keyProvider:async()=>Uint8Array.from(arguments[0])});return await migration.status();", [list(supplied), create])

    def action(name):
        return js("return await migration[arguments[0]]();", [name])

    def close_migration():
        js("await migration.close();window.migration=null;return true;")

    def plaintext_files():
        return [f for f in snapshot() if f["path"].startswith(".opfs-sahpool/")]

    def fixture(version):
        c = sqlite3.connect(":memory:")
        state = ctx["web"].parent / "native/src/state"
        c.executescript((state / "schema.sql").read_text())
        if version == 2:
            c.executescript((state / "schema_v2_gvk_ciphertext.sql").read_text())
        c.execute(f"PRAGMA user_version={version}")
        c.execute("INSERT INTO app_settings(rowid,key,value) VALUES(91,'migration-protected',?)", ['"' + marker + '"'])
        c.execute("INSERT INTO accounts VALUES(19,'synthetic-owner')")
        c.execute("INSERT INTO keypairs VALUES(21,?,?,?,?,?,19)", [marker.encode()] * 5)
        c.execute("INSERT INTO sqlite_sequence VALUES('app_user_operations',900)")
        c.commit()
        data = c.serialize()
        c.close()
        return data

    def setup(version):
        load()
        # This origin and profile were exclusively created by this test runner.
        js("const root=await navigator.storage.getDirectory();for await(const [name] of root.entries())await root.removeEntry(name,{recursive:true});window.storage=await sdk.Storage.open();return true;")
        ctx["close"]()
        # Replace only the synthetic logical spp.db while preserving the SAH
        # mapping header. The production API has no fixture-import RPC.
        script = """self.onmessage=async e=>{try{const root=await navigator.storage.getDirectory();const pool=await root.getDirectoryHandle('.opfs-sahpool');const opaque=await pool.getDirectoryHandle('.opaque');for await(const [,file] of opaque.entries()){const h=await file.createSyncAccessHandle();try{const header=new Uint8Array(512);h.read(header,{at:0});if(new TextDecoder().decode(header).split('\\0')[0]==='spp.db'){h.truncate(4096);h.write(new Uint8Array(e.data),{at:4096});h.flush();self.postMessage({ok:true});return;}}finally{h.close();}}throw Error('fixture source missing');}catch(error){self.postMessage({error:String(error)});}};"""
        assert js("const url=URL.createObjectURL(new Blob([arguments[0]],{type:'text/javascript'}));return await new Promise((resolve,reject)=>{const w=new Worker(url);w.onmessage=e=>{w.terminate();URL.revokeObjectURL(url);e.data.error?reject(Error(e.data.error)):resolve(e.data.ok);};w.onerror=reject;w.postMessage(arguments[1]);});", [script, list(fixture(version))])
        return plaintext_files()

    def expect_error(function):
        try:
            function()
        except RuntimeError:
            return
        raise AssertionError("operation unexpectedly succeeded")

    def read_encrypted(post_write=False):
        ctx["encrypted"]()
        assert marker in js("return await storage.call({GetSetting:'migration-protected'});")["Setting"]
        if post_write:
            assert js("return await storage.call({GetSetting:'after-activation'});")["Setting"] == 'true'
        ctx["close"]()

    for version in [1, 2]:
        original = setup(version)
        assert open_migration(True) == "copying"
        close_migration()
        before = snapshot()
        for supplied in [bytes(32), b"", bytes(31), bytes(33)]:
            expect_error(lambda: open_migration(False, supplied))
            assert snapshot() == before
        assert js("try{await sdk.Storage.openMigration({keyProvider:async()=>{throw Error('provider unavailable')}});return false;}catch{return true;}")
        assert snapshot() == before
        assert open_migration() == "copying"
        assert action("prepare") == "prepared"
        close_migration()
        assert plaintext_files() == original
        load()
        assert open_migration() == "prepared"
        assert action("abort") == "aborted"
        close_migration()
        assert plaintext_files() == original
        assert open_migration() == "aborted"
        assert action("restart") == "copying"
        assert action("prepare") == "prepared"
        # The coordinator owns both pools. Another storage worker must fail.
        expect_error(lambda: ctx["encrypted"]())
        assert action("activate") == "active"
        close_migration()
        assert plaintext_files() == original
        ctx["encrypted"]()
        js("await storage.call({SetSetting:{key:'after-activation',value_json:'true'}});return true;")
        ctx["close"]()
        # Full browser-process restart, retaining the same isolated profile.
        ctx["request"]("DELETE", "/session/" + ctx["sid"])
        ctx["sid"] = None
        ctx["session"]()
        load()
        assert open_migration() == "active"
        expect_error(lambda: action("abort"))
        close_migration()
        assert open_migration() == "active"
        assert action("finish") == "complete"
        assert action("finish") == "complete"
        close_migration()
        read_encrypted(True)
        assert not any(f["protected"] for f in snapshot())
        checks.append(f"schema v{version}: key failures, abort/restart, pool exclusion, browser restart, post-activation writes and plaintext cleanup")

        original = setup(version)
        open_migration(True)
        action("prepare")
        close_migration()
        js("window.storage=await sdk.Storage.open();await storage.call({SetSetting:{key:'intervening-write',value_json:'true'}});return true;")
        ctx["close"]()
        changed = plaintext_files()
        assert changed != original
        open_migration()
        expect_error(lambda: action("activate"))
        close_migration()
        assert plaintext_files() == changed
        assert open_migration() == "prepared"
        action("abort")
        close_migration()
        checks.append(f"schema v{version}: source changes prevent activation without losing data")

        cases = [
            ("quota", "spp.encrypted.db", "prepare", "copying"),
            ("flush-error", "spp.encrypted.db", "prepare", "copying"),
            ("during-write", "spp.encrypted.db", "prepare", "copying"),
            ("before-commit", "spp.migration.db", "activate", "prepared"),
            ("after-commit", "spp.migration.db", "activate", "active"),
            ("before-commit", "spp.migration.db", "finish", "active"),
            ("after-commit", "spp.migration.db", "finish", "cleaning"),
            ("after-delete", "spp.db", "finish", "cleaning"),
            ("delete-header-error", "spp.db", "finish", "cleaning"),
        ]
        for fault, target, operation, expected in cases:
            original = setup(version)
            assert open_migration(True) == "copying"
            if operation != "prepare":
                action("prepare")
            if operation == "finish":
                action("activate")
            js("window.armed=null;for(const w of migrationWorkers)w.postMessage({armMigrationFault:{mode:arguments[0],target:arguments[1]}});return true;", [fault, target])
            for _ in range(200):
                if js("return window.armed;") == fault: break
                time.sleep(.01)
            else: raise AssertionError("fault was not armed")
            if fault in ["quota", "flush-error", "delete-header-error"]:
                expect_error(lambda: action(operation))
                close_migration()
            else:
                js("window.pendingMigration=migration[arguments[0]]().catch(e=>String(e));return true;", [operation])
                for _ in range(400):
                    if fault in js("return window.faults;"): break
                    time.sleep(.01)
                else: raise AssertionError("fault did not fire")
                js("for(const w of migrationWorkers)w.terminate();return true;")
            load()
            before = snapshot()
            expect_error(lambda: open_migration(False, bytes(32)))
            assert snapshot() == before, (version, fault, operation, "wrong key modified OPFS")
            state = open_migration()
            assert state == expected, (version, fault, operation, state)
            if state in ["copying", "prepared", "active"]:
                assert plaintext_files() == original
            if state == "copying": action("prepare"); state = "prepared"
            if state == "prepared": action("activate")
            assert action("finish") == "complete"
            close_migration()
            read_encrypted()
            assert not any(f["protected"] for f in snapshot())
            checks.append(f"schema v{version}: recover {fault} during {operation}; wrong key nonmutation and artifact scan passed")
