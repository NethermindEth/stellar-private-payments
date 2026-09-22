use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

const SQLITE3MC_VERSION: &str = "2.5.1";
const SQLITE_VERSION: &str = "3.53.4";
const SQLITE3MC_ARCHIVE_SHA256: &str =
    "4125f8ff275ea953dabb3289331b20a0e76d4fc060f57148f4a5df3bf3b0d5e0";
const SQLITE3MC_SOURCE_SHA256: &str =
    "59e30889a7b0106152e6d4fc3c18ac1592f252cb4defbb0a7e618fdecf1a221c";
const SQLITE3MC_HEADER_SHA256: &str =
    "034c22a23268735059850aa22ea79333865c093c90c32287cc03cc606dcbc177";

fn main() {
    assert!(
        env::var_os("CARGO_FEATURE_SQLITE3MC").is_some(),
        "SQLite3MC is required; do not disable the sqlite3mc feature"
    );
    println!("cargo:rerun-if-env-changed=SQLITE3MC_AMALGAMATION_DIR");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    if env::var_os("DOCS_RS").is_none()
        && env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("wasm32")
    {
        build_sqlite3mc();
    }
    println!("cargo:rerun-if-changed=src/state/disclaimer.md");
    println!("cargo:rerun-if-changed=circuits.json");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let disclaimer_path = manifest_dir.join("src").join("state").join("disclaimer.md");
    let disclaimer_md =
        fs::read_to_string(&disclaimer_path).expect("read src/state/disclaimer.md for hashing");

    let mut hasher = Sha256::new();
    hasher.update(disclaimer_md.as_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(digest);

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let out = out_dir.join("disclaimer_hash.rs");

    let contents = format!(
        "pub(crate) const CURRENT_DISCLAIMER_HASH_HEX: &str = \"{}\";\n",
        hex
    );
    fs::write(out, contents).expect("write generated disclaimer_hash.rs");
}

fn build_sqlite3mc() {
    let source_dir = if let Some(path) = env::var_os("SQLITE3MC_AMALGAMATION_DIR") {
        PathBuf::from(path)
    } else {
        let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
        let source_dir = out_dir.join(format!("sqlite3mc-{SQLITE3MC_VERSION}"));
        if !source_dir.join("sqlite3mc_amalgamation.c").is_file()
            || !source_dir.join("sqlite3mc_amalgamation.h").is_file()
        {
            download_and_extract(&out_dir, &source_dir);
        }
        source_dir
    };

    verify_source(
        &source_dir,
        "sqlite3mc_amalgamation.c",
        SQLITE3MC_SOURCE_SHA256,
    );
    verify_source(
        &source_dir,
        "sqlite3mc_amalgamation.h",
        SQLITE3MC_HEADER_SHA256,
    );

    let mut build = cc::Build::new();
    build
        .file(source_dir.join("sqlite3mc_amalgamation.c"))
        .include(&source_dir)
        .warnings(false)
        .define("SQLITE_CORE", None)
        .define("SQLITE_DEFAULT_FOREIGN_KEYS", "1")
        .define("SQLITE_ENABLE_API_ARMOR", None)
        .define("SQLITE_ENABLE_COLUMN_METADATA", None)
        .define("SQLITE_ENABLE_DBSTAT_VTAB", None)
        .define("SQLITE_ENABLE_FTS3", None)
        .define("SQLITE_ENABLE_FTS3_PARENTHESIS", None)
        .define("SQLITE_ENABLE_FTS5", None)
        .define("SQLITE_ENABLE_JSON1", None)
        .define("SQLITE_ENABLE_LOAD_EXTENSION", "1")
        .define("SQLITE_ENABLE_MEMORY_MANAGEMENT", None)
        .define("SQLITE_ENABLE_RTREE", None)
        .define("SQLITE_ENABLE_STAT4", None)
        .define("SQLITE_SOUNDEX", None)
        .define("SQLITE_THREADSAFE", "1")
        .define("SQLITE_USE_URI", None)
        .define("HAVE_USLEEP", "1")
        .define("HAVE_ISNAN", None)
        .define("_POSIX_THREAD_SAFE_FUNCTIONS", None)
        .define("SQLITE_TEMP_STORE", "3")
        .compile("sqlite3mc");
}

fn download_and_extract(out_dir: &Path, source_dir: &Path) {
    fs::create_dir_all(source_dir).expect("create SQLite3MC source directory");
    let archive_name =
        format!("sqlite3mc-{SQLITE3MC_VERSION}-sqlite-{SQLITE_VERSION}-amalgamation.zip");
    let archive = out_dir.join(&archive_name);
    let url = format!(
        "https://github.com/utelle/SQLite3MultipleCiphers/releases/download/v{SQLITE3MC_VERSION}/{archive_name}"
    );
    if !archive.is_file() {
        assert!(
            env::var("CARGO_NET_OFFLINE").as_deref() != Ok("true"),
            "offline build needs SQLITE3MC_AMALGAMATION_DIR or cached SQLite3MC sources"
        );
        let partial = out_dir.join(format!("{archive_name}.partial"));
        let status = Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(&partial)
            .arg(&url)
            .status()
            .expect(
                "run curl to download SQLite3MC; install curl or set SQLITE3MC_AMALGAMATION_DIR",
            );
        assert!(status.success(), "failed to download {url}");
        verify_file(&partial, SQLITE3MC_ARCHIVE_SHA256, "SQLite3MC archive");
        fs::rename(partial, &archive).expect("publish verified SQLite3MC archive");
    }
    verify_file(&archive, SQLITE3MC_ARCHIVE_SHA256, "SQLite3MC archive");

    let file = fs::File::open(&archive).expect("open SQLite3MC archive");
    let mut zip = zip::ZipArchive::new(file).expect("read SQLite3MC archive");
    for expected in ["sqlite3mc_amalgamation.c", "sqlite3mc_amalgamation.h"] {
        let index = (0..zip.len())
            .find(|index| {
                zip.by_index(*index)
                    .ok()
                    .and_then(|entry| entry.enclosed_name())
                    .is_some_and(|path| path.file_name().is_some_and(|name| name == expected))
            })
            .unwrap_or_else(|| panic!("{expected} missing from SQLite3MC archive"));
        let mut entry = zip.by_index(index).expect("read SQLite3MC archive entry");
        let mut bytes = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or_default());
        entry
            .read_to_end(&mut bytes)
            .expect("extract SQLite3MC source");
        fs::write(source_dir.join(expected), bytes).expect("write SQLite3MC source");
    }
}

fn verify_source(directory: &Path, name: &str, expected: &str) {
    let path = directory.join(name);
    verify_file(&path, expected, name);
    println!("cargo:rerun-if-changed={}", path.display());
}

fn verify_file(path: &Path, expected: &str, label: &str) {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {label}: {error}"));
    let actual = hex::encode(Sha256::digest(bytes));
    assert_eq!(actual, expected, "{label} SHA-256 mismatch");
}
