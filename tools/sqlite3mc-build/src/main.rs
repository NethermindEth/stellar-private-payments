use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use sha2::{Digest, Sha256};

#[path = "../../../sdk/native/sqlite3mc_source.rs"]
mod sqlite3mc_source;

const TARGET: &str = "wasm32-unknown-unknown";

const MUSL_SOURCES: &[&str] = &[
    "string/memchr.c",
    "string/memrchr.c",
    "string/stpcpy.c",
    "string/stpncpy.c",
    "string/strcat.c",
    "string/strchr.c",
    "string/strchrnul.c",
    "string/strcmp.c",
    "string/strcpy.c",
    "string/strcspn.c",
    "string/strlen.c",
    "string/strncat.c",
    "string/strncmp.c",
    "string/strncpy.c",
    "string/strrchr.c",
    "string/strspn.c",
    "stdlib/atoi.c",
    "stdlib/bsearch.c",
    "stdlib/qsort.c",
    "stdlib/qsort_nr.c",
    "stdlib/strtod.c",
    "stdlib/strtol.c",
    "math/__fpclassifyl.c",
    "math/acosh.c",
    "math/asinh.c",
    "math/atanh.c",
    "math/fmodl.c",
    "math/scalbn.c",
    "math/scalbnl.c",
    "math/sqrt.c",
    "math/trunc.c",
    "errno/__errno_location.c",
    "stdio/__toread.c",
    "stdio/__uflow.c",
    "internal/floatscan.c",
    "internal/shgetc.c",
];

const FLAGS: &[&str] = &[
    "-DSQLITE_OS_OTHER",
    "-DSQLITE_USE_URI",
    "-DSQLITE_THREADSAFE=0",
    "-DSQLITE_TEMP_STORE=3",
    "-DSQLITE_DEFAULT_CACHE_SIZE=-16384",
    "-DSQLITE_DEFAULT_PAGE_SIZE=8192",
    "-DSQLITE_OMIT_DEPRECATED",
    "-DSQLITE_OMIT_LOAD_EXTENSION",
    "-DSQLITE_OMIT_SHARED_CACHE",
    "-DSQLITE_ENABLE_UNLOCK_NOTIFY",
    "-DSQLITE_ENABLE_API_ARMOR",
    "-DSQLITE_ENABLE_BYTECODE_VTAB",
    "-DSQLITE_ENABLE_DBPAGE_VTAB",
    "-DSQLITE_ENABLE_DBSTAT_VTAB",
    "-DSQLITE_ENABLE_FTS5",
    "-DSQLITE_ENABLE_MATH_FUNCTIONS",
    "-DSQLITE_ENABLE_OFFSET_SQL_FUNC",
    "-DSQLITE_ENABLE_PREUPDATE_HOOK",
    "-DSQLITE_ENABLE_RTREE",
    "-DSQLITE_ENABLE_SESSION",
    "-DSQLITE_ENABLE_STMTVTAB",
    "-DSQLITE_ENABLE_UNKNOWN_SQL_FUNCTION",
    "-DSQLITE_ENABLE_COLUMN_METADATA",
    "-D__WASM__",
    "-DARGON2_NO_THREADS",
    "-DPRINTF_ALIAS_STANDARD_FUNCTION_NAMES_HARD",
];

fn main() {
    let mut args = env::args_os().skip(1);
    let mut target_dir = None;
    while let Some(arg) = args.next() {
        if arg == "--target-dir" {
            target_dir = args.next().map(PathBuf::from);
        } else {
            panic!("unknown argument: {}", arg.to_string_lossy());
        }
    }
    let target_dir = target_dir
        .or_else(|| env::var_os("CARGO_TARGET_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("target"));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root")
        .to_path_buf();
    let cache = target_dir.join("sqlite3mc");
    let source = sqlite3mc_source::sources(&cache);
    let sqlite_wasm = sqlite_wasm_source(&root);
    let out = cache.join(TARGET);
    fs::create_dir_all(&out).expect("create SQLite3MC output directory");
    let out = fs::canonicalize(out).expect("resolve SQLite3MC output directory");

    let cc = tool("CC", &["clang", "clang-18"]);
    let ar = tool("AR", &["llvm-ar", "llvm-ar-18", "ar"]);
    let shim = sqlite_wasm.join("shim");
    let mut files = vec![
        source.join(sqlite3mc_source::SOURCE_FILES[0]),
        shim.join("printf/printf.c"),
    ];
    files.extend(MUSL_SOURCES.iter().map(|path| shim.join("musl").join(path)));
    let archive = out.join("libwsqlite3.a");
    let stamp = out.join("build.sha256");
    let signature = signature(&files, &cc, &ar);
    if fs::read_to_string(&stamp).ok().as_deref() != Some(&signature) || !archive.is_file() {
        let mut objects = Vec::new();
        for (index, file) in files.iter().enumerate() {
            let object = out.join(format!("{index:02}.o"));
            let mut command = Command::new(&cc);
            command.args([
                "--target=wasm32-unknown-unknown",
                "-Oz",
                "-ffunction-sections",
                "-fdata-sections",
                "-w",
                "-include",
            ]);
            command.arg(shim.join("wasm-shim.h"));
            for include in [
                shim.clone(),
                shim.join("musl/arch/generic"),
                shim.join("musl/include"),
            ] {
                command.arg("-I").arg(include);
            }
            command
                .args(FLAGS)
                .arg("-c")
                .arg(file)
                .arg("-o")
                .arg(&object);
            run(&mut command, "compile SQLite3MC for WASM");
            objects.push(object);
        }
        let _ = fs::remove_file(&archive);
        let mut command = Command::new(&ar);
        command.arg("rcsD").arg(&archive).args(&objects);
        run(&mut command, "archive SQLite3MC for WASM");
        fs::write(&stamp, &signature).expect("write SQLite3MC build stamp");
    }
    fs::write(
        out.join("cargo.toml"),
        format!(
            "[target.wasm32-unknown-unknown]\nrustflags = [{}]\n\n[target.wasm32-unknown-unknown.wsqlite3]\nrustc-link-search = [{}]\nrustc-link-lib = [\"static=wsqlite3\"]\n",
            serde_json::to_string(&format!("-Lnative={}", out.display()))
                .expect("serialize native search path"),
            serde_json::to_string(&out).expect("serialize link path"),
        ),
    ).expect("write Cargo link configuration");
    println!("{}", out.join("cargo.toml").display());
}

fn sqlite_wasm_source(root: &Path) -> PathBuf {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root)
        .output()
        .expect("run cargo metadata");
    assert!(output.status.success(), "cargo metadata failed");
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse cargo metadata");
    metadata["packages"]
        .as_array()
        .expect("Cargo packages")
        .iter()
        .find(|package| package["name"] == "sqlite-wasm-rs" && package["version"] == "0.5.5")
        .and_then(|package| package["manifest_path"].as_str())
        .map(PathBuf::from)
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .expect("locked sqlite-wasm-rs 0.5.5 source; run cargo fetch --locked")
}

fn tool(kind: &str, fallbacks: &[&str]) -> String {
    for key in [
        format!("{kind}_{TARGET}"),
        format!("{kind}_{}", TARGET.replace('-', "_")),
        format!("TARGET_{kind}"),
        kind.into(),
    ] {
        if let Some(value) = env::var_os(key) {
            return value.to_string_lossy().into_owned();
        }
    }
    fallbacks
        .iter()
        .find(|name| {
            Command::new(name)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        })
        .unwrap_or_else(|| panic!("no {} tool found", kind.to_ascii_lowercase()))
        .to_string()
}

fn signature(files: &[PathBuf], cc: &str, ar: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(env!("CARGO_PKG_VERSION"));
    hash.update(cc);
    hash.update(ar);
    hash.update(FLAGS.join("\0"));
    for file in files {
        hash.update(
            fs::read(file).unwrap_or_else(|error| panic!("read {}: {error}", file.display())),
        );
    }
    format!("{}\n", hex::encode(hash.finalize()))
}

fn run(command: &mut Command, action: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("{action}: {error}"));
    assert!(status.success(), "{action} failed with {status}");
}
