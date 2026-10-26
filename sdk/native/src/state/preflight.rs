//! Read-only preflight that inspects a database file without letting SQLite
//! recover its rollback journal. Used before a recovery-capable handle opens a
//! file that may be encrypted.
use anyhow::{Result, ensure};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

// The immutable handle is closed before the normal recovery-capable handle
// opens. This is a short preflight under the application's single-owner
// database policy; it must never be used as a long-lived snapshot while another
// writer is active.
pub(crate) fn validation_connection(path: &Path) -> Result<Connection> {
    #[cfg(not(target_arch = "wasm32"))]
    let absolute = std::path::absolute(path)?;
    #[cfg(not(target_arch = "wasm32"))]
    let path = absolute.as_path();
    let path = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("database path must be UTF-8"))?;
    #[cfg(windows)]
    let path = windows_uri_path(path);
    #[cfg(windows)]
    let path = path.as_str();
    Connection::open_with_flags(
        validation_uri(path),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(Into::into)
}

fn validation_uri(path: &str) -> String {
    let encoded: String = path
        .bytes()
        .enumerate()
        .map(|(index, b)| {
            if (b.is_ascii_alphanumeric() || b"/._-~".contains(&b))
                && !(index == 0 && path.starts_with("//"))
            {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!("file:{encoded}?mode=ro&immutable=1")
}

#[cfg(any(windows, test))]
fn windows_uri_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    // Keep UNC and extended-length prefixes as paths, not URI authorities.
    // SQLite's Windows VFS interprets these after URI percent decoding.
    if path.as_bytes().get(1) == Some(&b':') {
        format!("/{path}")
    } else {
        path
    }
}

pub(crate) fn check_header(conn: &Connection) -> Result<()> {
    // schema_version reads the authenticated page-1 header without traversing
    // possibly inconsistent, uncommitted btree pages left by a crash.
    let _: i64 = conn.query_row("PRAGMA schema_version", [], |r| r.get(0))?;
    let pages: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    ensure!(pages > 0, "existing database is empty");
    Ok(())
}

/// Reject a missing, empty or encrypted file before a plaintext handle opens
/// it. Without a key, an encrypted page 1 does not parse as a database.
#[cfg(feature = "unencrypted-storage")]
pub(crate) fn validate_plaintext(path: &Path) -> Result<()> {
    check_header(&validation_connection(path)?)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn windows_validation_paths_preserve_drive_unc_and_literal_characters() {
        for (path, encoded) in [
            (r"C:\wallet\state #%.db", "/C%3A/wallet/state%20%23%25.db"),
            (r"\\server\share\state.db", "%2F/server/share/state.db"),
            (r"\\?\C:\wallet\state.db", "%2F/%3F/C%3A/wallet/state.db"),
        ] {
            assert_eq!(
                validation_uri(&windows_uri_path(path)),
                format!("file:{encoded}?mode=ro&immutable=1")
            );
        }
    }
}
