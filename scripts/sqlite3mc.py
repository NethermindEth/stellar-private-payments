#!/usr/bin/env python3
"""Build pinned SQLite3MC, then run an opt-in Cargo or browser build command.

Examples:
  python3 scripts/sqlite3mc.py -- cargo test -p stellar-private-payments --lib
  python3 scripts/sqlite3mc.py --target x86_64-unknown-linux-musl -- cargo build -p stellar-private-payments --release
  python3 scripts/sqlite3mc.py --target wasm32-unknown-unknown -- bash sdk/web/scripts/build.sh

Requires Python 3.11+, Rust, a target C compiler and ar (clang/llvm-ar for WASM).
Downloads are hash-verified and cached under CARGO_TARGET_DIR. Set
SQLITE3MC_AMALGAMATION_DIR to verified local sources for an offline build.
Compiler selection follows CC_<target>, TARGET_CC, CC (and the equivalent AR).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tomllib
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "2.5.1"
SQLITE = "3.53.4"
SOURCE_HASHES = {
    "sqlite3mc_amalgamation.c": "59e30889a7b0106152e6d4fc3c18ac1592f252cb4defbb0a7e618fdecf1a221c",
    "sqlite3mc_amalgamation.h": "034c22a23268735059850aa22ea79333865c093c90c32287cc03cc606dcbc177",
}
ZIP_HASH = "4125f8ff275ea953dabb3289331b20a0e76d4fc060f57148f4a5df3bf3b0d5e0"
NATIVE_FLAGS = [
    "SQLITE_CORE", "SQLITE_DEFAULT_FOREIGN_KEYS=1", "SQLITE_ENABLE_API_ARMOR",
    "SQLITE_ENABLE_COLUMN_METADATA", "SQLITE_ENABLE_DBSTAT_VTAB", "SQLITE_ENABLE_FTS3",
    "SQLITE_ENABLE_FTS3_PARENTHESIS", "SQLITE_ENABLE_FTS5", "SQLITE_ENABLE_JSON1",
    "SQLITE_ENABLE_LOAD_EXTENSION=1", "SQLITE_ENABLE_MEMORY_MANAGEMENT",
    "SQLITE_ENABLE_RTREE", "SQLITE_ENABLE_STAT4", "SQLITE_SOUNDEX", "SQLITE_THREADSAFE=1",
    "SQLITE_USE_URI", "HAVE_USLEEP=1", "HAVE_ISNAN", "_POSIX_THREAD_SAFE_FUNCTIONS",
    "SQLITE_TEMP_STORE=3",
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(path, expected):
    if digest(path) != expected:
        raise RuntimeError(f"SHA256 mismatch: {path}")


def download(url, path, expected):
    if not path.exists():
        if os.environ.get("CARGO_NET_OFFLINE") == "true":
            raise RuntimeError(f"Offline build needs cached input: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".partial")
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
        verify(temporary, expected)
        temporary.replace(path)
    verify(path, expected)


def sources(cache):
    supplied = os.environ.get("SQLITE3MC_AMALGAMATION_DIR")
    source = Path(supplied).resolve() if supplied else cache / "sources"
    if not supplied and not all((source / n).exists() for n in SOURCE_HASHES):
        name = f"sqlite3mc-{VERSION}-sqlite-{SQLITE}-amalgamation.zip"
        archive = cache / name
        download(f"https://github.com/utelle/SQLite3MultipleCiphers/releases/download/v{VERSION}/{name}", archive, ZIP_HASH)
        source.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as zipped:
            for name in SOURCE_HASHES:
                matches = [p for p in zipped.namelist() if Path(p).name == name]
                if len(matches) != 1:
                    raise RuntimeError(f"Unexpected amalgamation archive: {name}")
                (source / name).write_bytes(zipped.read(matches[0]))
    for name, expected in SOURCE_HASHES.items():
        verify(source / name, expected)
    return source


def wasm_inputs(cache):
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    package = next(p for p in lock["package"] if p["name"] == "sqlite-wasm-rs")
    if package["version"] != "0.5.5" or package["checksum"] != "dc3efc0da82635d7e1ced0053bbbfa8c7ab9645d0bf36ceb4f7127bb85315d75":
        raise RuntimeError("sqlite-wasm-rs changed: review its build/shims before upgrading SQLite3MC")
    name = "sqlite-wasm-rs-0.5.5"
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    archives = sorted((cargo_home / "registry/cache").glob(f"*/{name}.crate"))
    archive = archives[0] if archives else cache / (name + ".crate")
    if not archives:
        download(f"https://static.crates.io/crates/sqlite-wasm-rs/{name}.crate", archive, package["checksum"])
    verify(archive, package["checksum"])
    stage = cache / name
    # Re-extract only the upstream build recipe and C shims, verifying the input
    # every time. No dependency source tree or Rust bindings are patched.
    with tarfile.open(archive) as tar:
        members = [m for m in tar.getmembers() if m.name.startswith(name + "/shim/") or m.name == name + "/build.rs"]
        tar.extractall(cache, members=members, filter="data")
    recipe = (stage / "build.rs").read_text()
    def array(name):
        body = re.search(r"const " + name + r":.*?= \[(.*?)\];", recipe, re.S)
        if body is None:
            raise RuntimeError(f"Missing upstream build array: {name}")
        return re.findall(r'"([^"\n]+)"', body.group(1))
    flags = [x for x in array("FULL_FEATURED") if not x.startswith("-DSQLITE_TEMP_STORE=")]
    flags += ["-DSQLITE_TEMP_STORE=3", "-D__WASM__", "-DARGON2_NO_THREADS"]
    files = [stage / "shim/printf/printf.c"] + [stage / "shim/musl" / p for p in array("C_SOURCE")]
    return stage, flags, files


def tool(kind, target, default):
    for name in [kind + "_" + target, kind + "_" + target.replace("-", "_"), "TARGET_" + kind, kind]:
        if os.environ.get(name):
            return shlex.split(os.environ[name])
    return [default]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("provide a command after --")
    rust = subprocess.check_output(["rustc", "-vV"], text=True)
    host = re.search(r"^host: (.+)$", rust, re.M).group(1)
    target = args.target or host
    if target not in ["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl", "wasm32-unknown-unknown"]:
        parser.error("SQLite3MC is currently qualified for Linux x86_64 GNU/musl and browser WASM")
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
    cache = target_dir / "sqlite3mc" / VERSION
    cache.mkdir(parents=True, exist_ok=True)
    source = sources(cache)
    out = cache / target
    out.mkdir(exist_ok=True)
    wasm = target == "wasm32-unknown-unknown"
    cc = tool("CC", target, "clang" if wasm else ("musl-gcc" if target.endswith("musl") else "cc"))
    ar = tool("AR", target, "llvm-ar" if wasm else "ar")
    if not wasm:
        macros = subprocess.check_output(cc + ["-dM", "-E", "-x", "c", "-"], input="#include <features.h>\n", text=True)
        is_glibc = "#define __GLIBC__ " in macros
        if "#define __x86_64__ " not in macros or is_glibc != target.endswith("gnu"):
            raise RuntimeError(f"C compiler headers do not match {target}; set CC_{target.replace('-', '_')} to the target compiler")
    files = [source / "sqlite3mc_amalgamation.c"]
    flags = ["-O2", "-fPIC", "-ffunction-sections", "-fdata-sections", "-w"]
    if wasm:
        stage, upstream_flags, shims = wasm_inputs(cache)
        files += shims
        flags = ["--target=" + target, "-Oz", "-ffunction-sections", "-fdata-sections", "-w", *upstream_flags,
                 "-DPRINTF_ALIAS_STANDARD_FUNCTION_NAMES_HARD", "-include", str(stage / "shim/wasm-shim.h")]
        for folder in ["shim", "shim/musl/arch/generic", "shim/musl/include"]:
            flags += ["-I", str(stage / folder)]
    else:
        flags += ["-D" + value for value in NATIVE_FLAGS]
    inputs = {str(p): digest(p) for p in files}
    if wasm:
        inputs.update({str(p): digest(p) for p in (stage / "shim").rglob("*") if p.is_file()})
    signature = {"script": digest(Path(__file__)), "target": target, "inputs": inputs, "flags": flags,
                 "cc": cc, "ar": ar, "compiler": subprocess.check_output(cc + ["--version"], text=True),
                 "archiver": subprocess.check_output(ar + ["--version"], text=True)}
    stamp = out / "build.json"
    archive = out / ("libwsqlite3.a" if wasm else "libsqlite3.a")
    previous = json.loads(stamp.read_text()) if stamp.exists() else {}
    if previous.get("inputs") != signature or not archive.exists() or previous.get("sha256") != digest(archive):
        objects = []
        for i, file in enumerate(files):
            obj = out / f"{i:02d}-{file.stem}.o"
            subprocess.run(cc + flags + ["-c", str(file), "-o", str(obj)], check=True)
            objects.append(str(obj))
        archive.unlink(missing_ok=True)
        subprocess.run(ar + ["rcsD", str(archive), *objects], check=True)
        stamp.write_text(json.dumps({"inputs": signature, "sha256": digest(archive)}, indent=2) + "\n")
    env = dict(os.environ, CARGO_TARGET_DIR=str(target_dir), SPP_SQLITE3MC_BUILD=f"{VERSION}:{target}")
    if wasm:
        config = out / "cargo.toml"
        config.write_text('[target.wasm32-unknown-unknown.wsqlite3]\nrustc-link-search = [' + json.dumps(str(out)) + ']\nrustc-link-lib = ["static=wsqlite3"]\n')
        env["SPP_SQLITE3MC_CONFIG"] = str(config)
        if Path(command[0]).name == "cargo":
            command[1:1] = ["--config", str(config)]
    else:
        include = out / "include"
        include.mkdir(exist_ok=True)
        shutil.copyfile(source / "sqlite3mc_amalgamation.h", include / "sqlite3.h")
        pc = out / "pkgconfig"
        pc.mkdir(exist_ok=True)
        (pc / "sqlite3.pc").write_text(f"prefix={out}\nlibdir=${{prefix}}\nincludedir=${{prefix}}/include\nName: SQLite3MC\nDescription: Pinned SQLite3 Multiple Ciphers\nVersion: {SQLITE}\nLibs: -L${{libdir}} -lsqlite3 -lm -ldl -lpthread\nCflags: -I${{includedir}}\n")
        env.update(LIBSQLITE3_SYS_USE_PKG_CONFIG="1", SQLITE3_STATIC="1", SQLITE3_LIB_DIR=str(out),
                   SQLITE3_INCLUDE_DIR=str(include), PKG_CONFIG_LIBDIR=str(pc), PKG_CONFIG_PATH=str(pc), PKG_CONFIG_ALLOW_CROSS="1")
    if Path(command[0]).name == "cargo":
        end = command.index("--") if "--" in command else len(command)
        command[end:end] = ["--features", "sqlite3mc"] + (["--target", target] if target != host else [])
    print(f"SQLite3MC {VERSION}, {target}: {digest(archive)}", flush=True)
    return subprocess.run(command, cwd=ROOT, env=env).returncode


if __name__ == "__main__":
    raise SystemExit(main())
