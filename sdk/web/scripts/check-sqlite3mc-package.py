#!/usr/bin/env python3
"""Verify the staged encryption-enabled npm package; optionally create and inspect its archive.

Default mode checks npm's dry-run file list without copying the large circuit
bundle. --output-directory builds a CI artifact, never publishes it, and checks
the actual tar members. Lifecycle scripts are always disabled.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

REQUIRED = {
    "package.json", "js/index.js", "js/types/api-types.d.ts",
    "js/key-vault.js", "js/types/key-vault.d.ts",
    "dist/stellar_private_payments_web.js", "dist/stellar_private_payments_web_bg.wasm",
    "dist/workers/storage-worker-module.js", "dist/workers/storage-worker-module_bg.wasm",
    "dist/licenses/SQLite3MC.txt", "dist/circuits/NOTICE.txt", "dist/circuits/source-bundle.tar.gz",
}


def package_result(raw):
    result = json.loads(raw)
    # npm 11 returns an array; npm 12 keys the same records by package name.
    packages = list(result.values()) if isinstance(result, dict) else result
    if not isinstance(packages, list) or len(packages) != 1 or not isinstance(packages[0], dict):
        raise ValueError("expected exactly one npm package result")
    package = packages[0]
    if not {"filename", "files"} <= package.keys():
        raise ValueError("npm package result lacks its filename or file list")
    return package


def verify(names, read, notice):
    missing = REQUIRED - names
    if missing:
        raise ValueError(f"encrypted package is missing: {sorted(missing)}")
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "test-sqlite3mc" in name or name.startswith("scripts/"):
            raise ValueError(f"unexpected package entry: {name}")
    if read("dist/licenses/SQLite3MC.txt") != notice:
        raise ValueError("SQLite3MC distribution notice differs from the reviewed source notice")
    bindings = read("dist/stellar_private_payments_web.js").decode()
    for method in ["static openEncrypted(", "static openMigration(", "migrationAction("]:
        if method not in bindings:
            raise ValueError(f"WASM bindings lack {method}; package may contain a legacy plaintext-only build")
    if "recoverMigrationSetup" not in read("js/index.js").decode():
        raise ValueError("JavaScript facade lacks initialization recovery")
    for name in ["dist/stellar_private_payments_web_bg.wasm", "dist/workers/storage-worker-module_bg.wasm"]:
        if read(name)[:4] != b"\0asm":
            raise ValueError(f"invalid WASM artifact: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path)
    args = parser.parse_args()
    web = Path(__file__).resolve().parents[1]
    notice = (web.parents[1] / "vendor/sqlite3mc-NOTICE.txt").read_bytes()
    # Preflight before creating a large archive, including a stock-build rejection.
    verify({name for name in REQUIRED if (web / name).is_file()},
           lambda name: (web / name).read_bytes(), notice)
    listing = package_result(subprocess.check_output(
        ["npm", "pack", "--dry-run", "--ignore-scripts", "--json"], cwd=web, text=True,
    ))
    verify({item["path"] for item in listing["files"]}, lambda name: (web / name).read_bytes(), notice)
    report = {"passed": True, "mode": "dry-run", "files": len(listing["files"])}
    if args.output_directory:
        output = args.output_directory.resolve()
        output.mkdir(parents=True, exist_ok=True)
        packed = package_result(subprocess.check_output(
            ["npm", "pack", "--ignore-scripts", "--json", "--pack-destination", str(output)],
            cwd=web, text=True,
        ))
        filename = packed["filename"]
        if Path(filename).name != filename:
            raise ValueError("npm returned an invalid package filename")
        archive = output / filename
        with tarfile.open(archive, "r:gz") as tar:
            files = {}
            for member in tar.getmembers():
                if not member.isfile() or not member.name.startswith("package/"):
                    raise ValueError(f"unexpected archive member: {member.name}")
                name = member.name.removeprefix("package/")
                if name in files:
                    raise ValueError(f"duplicate archive member: {name}")
                files[name] = member
            def read(name):
                with tar.extractfile(files[name]) as source:
                    return source.read()
            verify(set(files), read, notice)
        with archive.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        report.update(mode="archive", archive=filename, sha256=digest)
        (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
