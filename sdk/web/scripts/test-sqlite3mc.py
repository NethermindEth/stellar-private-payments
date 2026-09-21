#!/usr/bin/env python3
"""Exercise the built SDK in a fresh, isolated browser profile using WebDriver.

python3 sdk/web/scripts/test-sqlite3mc.py --artifacts /path/to/test-output
Use --plaintext-only against a default build; --browser firefox --driver PATH
selects Firefox/geckodriver. Requires the browser and driver to be installed.
Only synthetic data at an ephemeral localhost origin is used.
"""
import argparse
import functools
import http.server
import json
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--artifacts", type=Path, required=True)
parser.add_argument("--browser", choices=["chromium", "firefox"], default="chromium")
parser.add_argument("--binary")
parser.add_argument("--driver")
parser.add_argument("--plaintext-only", action="store_true")
args = parser.parse_args()
web = Path(__file__).resolve().parents[1]
art = args.artifacts.resolve()
art.mkdir(parents=True, exist_ok=False)
profile = art / "profile"
profile.mkdir()


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args): pass
    def do_GET(self):
        if self.path == "/test.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<!doctype html><title>Storage integration test</title>")
        else:
            super().do_GET()


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(web)))
threading.Thread(target=server.serve_forever, daemon=True).start()
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
firefox = args.browser == "firefox"
driver = args.driver or ("geckodriver" if firefox else "chromedriver")
command = [driver, "--port", str(port), "--host", "127.0.0.1"] if firefox else [driver, f"--port={port}", "--allowed-ips=127.0.0.1"]
log = (art / "driver.log").open("w")
process = subprocess.Popen(command, stdout=log, stderr=log)
url = f"http://127.0.0.1:{port}"
origin = f"http://127.0.0.1:{server.server_port}/test.html"
sid = None
key = secrets.token_bytes(32)
marker = "PROTECTED_OPFS_INTEGRATION_01b8af6d"
checks = []


def request(method, path, value=None):
    data = json.dumps(value).encode() if value is not None else None
    req = urllib.request.Request(url + path, data=data, headers={"Content-Type": "application/json"}, method=method)
    with urllib.request.urlopen(req, timeout=150) as response:
        result = json.load(response)["value"]
    if isinstance(result, dict) and "error" in result:
        raise RuntimeError(result["error"])
    return result


def session():
    global sid
    if firefox:
        caps = {"browserName": "firefox", "moz:firefoxOptions": {"binary": args.binary or "/usr/bin/firefox", "args": ["-headless", "-profile", str(profile)]}}
    else:
        caps = {"browserName": "chrome", "goog:chromeOptions": {"binary": args.binary or "/usr/bin/chromium", "args": ["--headless=new", "--disable-dev-shm-usage", "--disable-background-networking", f"--user-data-dir={profile}"]}}
    result = request("POST", "/session", {"capabilities": {"alwaysMatch": caps}})
    sid = result["sessionId"]
    request("POST", f"/session/{sid}/timeouts", {"script": 120000, "pageLoad": 120000})
    return result["capabilities"].get("browserVersion")


def js(code, values=None):
    result = request("POST", f"/session/{sid}/execute/async", {"script": "const done=arguments[arguments.length-1];(async()=>{" + code + "})().then(x=>done({ok:x})).catch(e=>done({error:String(e)}));", "args": values or []})
    if "error" in result:
        raise RuntimeError(result["error"])
    return result.get("ok")


def load():
    request("POST", f"/session/{sid}/url", {"url": origin})
    js("window.sdk=await import('/js/index.js');await sdk.default();return true;")


def encrypted(create=False, supplied=key):
    return js("const supplied=Uint8Array.from(arguments[0]);try{window.storage=await sdk.Storage.openEncrypted({createNew:arguments[1],keyProvider:async(id,purpose)=>{if(id!=='spp.encrypted.db'||purpose!==(arguments[1]?'create':'open'))throw Error('provider context');return supplied;}});return true;}finally{supplied.fill(0);}", [list(supplied), create])


def close():
    js("await storage.close();storage.free();window.storage=null;return true;")


def snapshot():
    return js("const root=await navigator.storage.getDirectory();const result=[];async function walk(d,path){for await(const [name,h] of d.entries()){if(h.kind==='directory'){await walk(h,path+name+'/');}else{const bytes=new Uint8Array(await(await h.getFile()).arrayBuffer());const hash=await crypto.subtle.digest('SHA-256',bytes);result.push({path:path+name,bytes:bytes.length,sha256:Array.from(new Uint8Array(hash),x=>x.toString(16).padStart(2,'0')).join(''),protected:new TextDecoder().decode(bytes).includes(argumentsMarker)});}}}const argumentsMarker=arguments[0];await walk(root,'');return result.sort((a,b)=>a.path.localeCompare(b.path));", [marker])


try:
    for _ in range(100):
        try:
            request("GET", "/status")
            break
        except Exception:
            time.sleep(.1)
    version = session()
    load()
    js("window.storage=await sdk.Storage.open();await storage.call({SetSetting:{key:'integration-legacy',value_json:JSON.stringify('legacy-preserved')}});return true;")
    close()
    legacy = snapshot()
    load()
    js("window.storage=await sdk.Storage.open();return true;")
    assert js("return await storage.call({GetSetting:'integration-legacy'});")["Setting"] == '"legacy-preserved"'
    close()
    checks.append("plaintext create, close and worker restart")
    if args.plaintext_only:
        try:
            encrypted(True)
            raise AssertionError("default build unexpectedly enables encryption")
        except RuntimeError as error:
            assert "sqlite3mc feature" in str(error)
        checks.append("default build rejects encrypted API")
    else:
        encrypted(True)
        js("await storage.call({SetSetting:{key:'integration-protected',value_json:JSON.stringify(arguments[0])}});window.fork=storage.fork();return true;", [marker])
        assert marker in js("return await fork.call({GetSetting:'integration-protected'});")["Setting"]
        close()
        assert js("try{await fork.call('Ping');return false;}catch{return true;}finally{fork.free();}")
        checks.append("encrypted create, fork and close invalidates forks")
        before = snapshot()
        for label, supplied, create in [("wrong key", secrets.token_bytes(32), False), ("zero key", bytes(32), False), ("missing key", b"", False), ("short key", bytes(31), False), ("long key", bytes(33), False), ("create existing", key, True)]:
            try:
                encrypted(create, supplied)
                raise AssertionError(label + " accepted")
            except RuntimeError:
                pass
            assert snapshot() == before, label + " modified OPFS"
            checks.append(label + " rejects without modifying OPFS")
        assert js("try{await sdk.Storage.openEncrypted({keyProvider:async()=>{throw Error('provider unavailable');}});return false;}catch{return true;}")
        assert snapshot() == before
        checks.append("provider failure leaves OPFS unchanged")
        load()
        encrypted()
        assert marker in js("return await storage.call({GetSetting:'integration-protected'});")["Setting"]
        close()
        checks.append("encrypted worker restart")
        request("DELETE", "/session/" + sid)
        sid = None
        session()
        load()
        encrypted()
        assert marker in js("return await storage.call({GetSetting:'integration-protected'});")["Setting"]
        close()
        checks.append("encrypted browser-process restart")
        final = snapshot()
        encrypted_files = [f for f in final if f["path"].startswith(".opfs-sahpool-encrypted/")]
        assert encrypted_files and not any(f["protected"] for f in encrypted_files)
        assert [f for f in final if not f["path"].startswith(".opfs-sahpool-encrypted/")] == legacy
        checks.append("encrypted artifact scan and original plaintext byte identity")
    result = {"browser": args.browser, "version": version, "checks": checks, "passed": True}
    (art / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
finally:
    if sid:
        try: request("DELETE", "/session/" + sid)
        except Exception: pass
    process.terminate()
    process.wait(timeout=15)
    log.close()
    server.shutdown()
