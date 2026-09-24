use std::{env, fs, path::PathBuf};

use sha2::{Digest, Sha256};

#[path = "sqlite3mc_source.rs"]
mod sqlite3mc_source;

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
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let source_dir = sqlite3mc_source::sources(&out_dir);
    for name in sqlite3mc_source::SOURCE_FILES {
        println!("cargo:rerun-if-changed={}", source_dir.join(name).display());
    }

    let mut build = cc::Build::new();
    build
        .file(source_dir.join(sqlite3mc_source::SOURCE_FILES[0]))
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
