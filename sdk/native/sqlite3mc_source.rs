//! The pinned SQLite3MC amalgamation and its verified download. Included with
//! `#[path]` by the build script; native and WASM builds share the version
//! and hashes.

use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

const VERSION: &str = "2.5.1";
const SQLITE_VERSION: &str = "3.53.4";
const ARCHIVE_SHA256: &str = "4125f8ff275ea953dabb3289331b20a0e76d4fc060f57148f4a5df3bf3b0d5e0";
const SOURCE_SHA256: &str = "59e30889a7b0106152e6d4fc3c18ac1592f252cb4defbb0a7e618fdecf1a221c";
const HEADER_SHA256: &str = "034c22a23268735059850aa22ea79333865c093c90c32287cc03cc606dcbc177";

/// The amalgamation source and header, in that order.
pub const SOURCE_FILES: [&str; 2] = ["sqlite3mc_amalgamation.c", "sqlite3mc_amalgamation.h"];

/// Directory holding the verified amalgamation: `SQLITE3MC_AMALGAMATION_DIR`
/// when set, otherwise a download cached under `cache`.
pub fn sources(cache: &Path) -> PathBuf {
    let directory = if let Some(path) = env::var_os("SQLITE3MC_AMALGAMATION_DIR") {
        PathBuf::from(path)
    } else {
        let directory = cache.join(format!("sqlite3mc-{VERSION}"));
        if !SOURCE_FILES
            .iter()
            .all(|name| directory.join(name).is_file())
        {
            download_and_extract(cache, &directory);
        }
        directory
    };
    verify(&directory.join(SOURCE_FILES[0]), SOURCE_SHA256);
    verify(&directory.join(SOURCE_FILES[1]), HEADER_SHA256);
    directory
}

fn download_and_extract(cache: &Path, directory: &Path) {
    fs::create_dir_all(directory).expect("create SQLite3MC source directory");
    let name = format!("sqlite3mc-{VERSION}-sqlite-{SQLITE_VERSION}-amalgamation.zip");
    let archive = cache.join(&name);
    let url = format!(
        "https://github.com/utelle/SQLite3MultipleCiphers/releases/download/v{VERSION}/{name}"
    );
    if !archive.is_file() {
        assert!(
            env::var("CARGO_NET_OFFLINE").as_deref() != Ok("true"),
            "offline build needs SQLITE3MC_AMALGAMATION_DIR or cached SQLite3MC sources"
        );
        let partial = cache.join(format!("{name}.partial"));
        let mut response = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("create SQLite3MC download client")
            .get(&url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .unwrap_or_else(|error| panic!("download {url}: {error}"));
        let mut output = fs::File::create(&partial).expect("create SQLite3MC archive download");
        response
            .copy_to(&mut output)
            .unwrap_or_else(|error| panic!("save SQLite3MC download from {url}: {error}"));
        drop(output);
        verify(&partial, ARCHIVE_SHA256);
        fs::rename(partial, &archive).expect("publish verified SQLite3MC archive");
    }
    verify(&archive, ARCHIVE_SHA256);

    let file = fs::File::open(&archive).expect("open SQLite3MC archive");
    let mut zip = zip::ZipArchive::new(file).expect("read SQLite3MC archive");
    for expected in SOURCE_FILES {
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
        fs::write(directory.join(expected), bytes).expect("write SQLite3MC source");
    }
}

fn verify(path: &Path, expected: &str) {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        expected,
        "SHA-256 mismatch: {}",
        path.display()
    );
}
