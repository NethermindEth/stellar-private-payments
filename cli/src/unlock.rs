//! Unlocking the encrypted local database.
//!
//! On a terminal `spp` asks for the password the way `sudo` does: nothing is
//! echoed, a wrong password gets "Sorry, try again." and three misses end the
//! command. Scripts pass `--password-file` (or `SPP_PASSWORD_FILE`) instead.
//!
//! The first run creates the database under a new password. A database left
//! unencrypted by an earlier version is encrypted in place under a new one.

use std::path::Path;

use anyhow::{Context, Result, bail};
use stellar_private_payments::state::{
    SqliteStorage,
    database_key::{DatabaseKey, OpenPurpose},
    encrypted_migration,
    password_vault::{
        self, MIN_PASSWORD_CHARS, PasswordRecord, VaultError, read_password_file,
        validate_new_password,
    },
};
use zeroize::Zeroizing;

const ATTEMPTS: u32 = 3;

type Prompt<'a> = dyn FnMut(&str) -> Result<Zeroizing<String>> + 'a;

/// Unlock the database at `database`, creating or encrypting it if needed.
pub fn unlock(database: &Path, password_file: Option<&Path>) -> Result<DatabaseKey> {
    unlock_with(database, password_file, &mut terminal_prompt)
}

fn terminal_prompt(label: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(label)
        .map(Zeroizing::new)
        .context("no terminal to ask for the database password; pass --password-file <path>")
}

fn unlock_with(
    database: &Path,
    password_file: Option<&Path>,
    prompt: &mut Prompt<'_>,
) -> Result<DatabaseKey> {
    if encrypted_migration::is_plaintext_file(database)? {
        eprintln!(
            "Encrypting local storage. Deleted plaintext, backups and filesystem snapshots may remain recoverable; encryption does not securely erase them."
        );
        return encrypt_existing(database, password_file, prompt);
    }
    match std::fs::metadata(database) {
        Ok(meta) if meta.len() > 0 => open_existing(database, password_file, prompt),
        Ok(_) => {
            // An empty file is all a create that failed early leaves behind;
            // it holds nothing to protect.
            std::fs::remove_file(database)?;
            create(database, password_file, prompt)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create(database, password_file, prompt)
        }
        Err(e) => Err(e).with_context(|| format!("inspect {}", database.display())),
    }
}

fn open_existing(
    database: &Path,
    password_file: Option<&Path>,
    prompt: &mut Prompt<'_>,
) -> Result<DatabaseKey> {
    let key = open_record(&read_record(database)?, password_file, prompt, "Password: ")?;
    // Opening proves the key belongs to this database, not just the record.
    drop(
        SqliteStorage::connect_encrypted(database, &key, OpenPurpose::OpenExisting)
            .with_context(|| format!("open {}", database.display()))?,
    );
    Ok(key)
}

fn read_record(database: &Path) -> Result<PasswordRecord> {
    let record_path = password_vault::record_path(database);
    let json = std::fs::read_to_string(&record_path)
        .with_context(|| format!("read password record {}", record_path.display()))?;
    Ok(PasswordRecord::from_json(&json)?)
}

/// Open `record` with the password from `password_file`, or ask for it with
/// `label` up to [`ATTEMPTS`] times.
fn open_record(
    record: &PasswordRecord,
    password_file: Option<&Path>,
    prompt: &mut Prompt<'_>,
    label: &str,
) -> Result<DatabaseKey> {
    if let Some(file) = password_file {
        return record
            .open(&read_password_file(file)?)
            .map_err(|e| match e {
                VaultError::WrongPassword => {
                    anyhow::anyhow!("the password in {} is wrong", file.display())
                }
                e => e.into(),
            });
    }
    for attempt in 1..=ATTEMPTS {
        match record.open(&prompt(label)?) {
            Ok(key) => return Ok(key),
            Err(VaultError::WrongPassword) if attempt < ATTEMPTS => {
                eprintln!("Sorry, try again.");
            }
            Err(VaultError::WrongPassword) => {}
            Err(e) => return Err(e.into()),
        }
    }
    bail!("{ATTEMPTS} incorrect password attempts")
}

fn create(
    database: &Path,
    password_file: Option<&Path>,
    prompt: &mut Prompt<'_>,
) -> Result<DatabaseKey> {
    let password = new_password(
        password_file,
        prompt,
        &format!(
            "Choose a password for the local database at {}.",
            database.display()
        ),
    )?;
    let key = seal_new_key(database, &password)?;
    drop(
        SqliteStorage::connect_encrypted(database, &key, OpenPurpose::CreateNew)
            .with_context(|| format!("create {}", database.display()))?,
    );
    Ok(key)
}

fn encrypt_existing(
    database: &Path,
    password_file: Option<&Path>,
    prompt: &mut Prompt<'_>,
) -> Result<DatabaseKey> {
    let password = new_password(
        password_file,
        prompt,
        &format!(
            "The local database at {} is not encrypted yet. Choose a password to encrypt it.",
            database.display()
        ),
    )?;
    let key = seal_new_key(database, &password)?;
    encrypted_migration::encrypt_in_place(database, &key)
        .with_context(|| format!("encrypt {}", database.display()))?;
    Ok(key)
}

/// Change the password of the encrypted database at `database`.
///
/// The current password comes from `password_file` or the terminal, the new
/// one from `new_password_file` or the terminal, asked twice. The same
/// database key is sealed again, so the database itself is not rewritten.
pub fn change_password(
    database: &Path,
    password_file: Option<&Path>,
    new_password_file: Option<&Path>,
) -> Result<()> {
    change_password_with(
        database,
        password_file,
        new_password_file,
        &mut terminal_prompt,
    )
}

fn change_password_with(
    database: &Path,
    password_file: Option<&Path>,
    new_password_file: Option<&Path>,
    prompt: &mut Prompt<'_>,
) -> Result<()> {
    anyhow::ensure!(
        database.exists() && !encrypted_migration::is_plaintext_file(database)?,
        "no encrypted database at {}; any other spp command creates or encrypts it",
        database.display()
    );
    let key = open_record(
        &read_record(database)?,
        password_file,
        prompt,
        "Current password: ",
    )?;
    // Re-seal only a key that really opens this database.
    drop(
        SqliteStorage::connect_encrypted(database, &key, OpenPurpose::OpenExisting)
            .with_context(|| format!("open {}", database.display()))?,
    );
    let password = new_password(new_password_file, prompt, "Choose a new password.")?;
    password_vault::write_record(
        &password_vault::record_path(database),
        &PasswordRecord::seal(&key, &password)?,
    )
}

/// Generate the database key and write its password record, before anything
/// uses the key, so the database never exists without a way to unlock it.
fn seal_new_key(database: &Path, password: &str) -> Result<DatabaseKey> {
    let record_path = password_vault::record_path(database);
    match std::fs::symlink_metadata(&record_path) {
        Ok(_) => bail!(
            "refusing to replace existing password record {}; preserve it with its matching database backup, or move it aside explicitly before creating new storage",
            record_path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let key = DatabaseKey::generate()?;
    password_vault::write_record(
        &password_vault::record_path(database),
        &PasswordRecord::seal(&key, password)?,
    )?;
    Ok(key)
}

fn new_password(
    password_file: Option<&Path>,
    prompt: &mut Prompt<'_>,
    intro: &str,
) -> Result<Zeroizing<String>> {
    if let Some(file) = password_file {
        let password = read_password_file(file)?;
        validate_new_password(&password)
            .with_context(|| format!("the password in {} is not usable", file.display()))?;
        return Ok(password);
    }
    eprintln!("{intro}");
    eprintln!("Use at least {MIN_PASSWORD_CHARS} characters; four or more random words work well.");
    for _ in 0..ATTEMPTS {
        let password = prompt("New password: ")?;
        if let Err(e) = validate_new_password(&password) {
            eprintln!("Sorry, {e}.");
            continue;
        }
        if *prompt("Retype new password: ")? != *password {
            eprintln!("Sorry, passwords do not match.");
            continue;
        }
        return Ok(password);
    }
    bail!("no password set after {ATTEMPTS} attempts")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    const PASSWORD: &str = "correct horse battery staple";

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "spp-cli-unlock-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir(&dir).expect("create fixture dir");
            Self(dir)
        }

        fn db(&self) -> PathBuf {
            self.0.join("spp.db")
        }

        fn password_file(&self, contents: &str) -> PathBuf {
            let path = self.0.join("password");
            fs::write(&path, contents).expect("write password file");
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A prompt that answers with `answers` in order and records the labels
    /// it was asked with.
    fn scripted<'a>(
        answers: &'a [&'a str],
        asked: &'a mut Vec<String>,
    ) -> impl FnMut(&str) -> Result<Zeroizing<String>> + 'a {
        let mut answers: VecDeque<&str> = answers.iter().copied().collect();
        move |label| {
            asked.push(label.to_string());
            answers
                .pop_front()
                .map(|answer| Zeroizing::new(answer.to_string()))
                .ok_or_else(|| anyhow::anyhow!("no scripted answer for {label}"))
        }
    }

    #[test]
    fn creating_storage_preserves_an_existing_backup_key_record() -> Result<()> {
        let f = Fixture::new();
        let key = DatabaseKey::generate()?;
        let record_path = password_vault::record_path(&f.db());
        password_vault::write_record(&record_path, &PasswordRecord::seal(&key, PASSWORD)?)?;
        let before = std::fs::read(&record_path)?;
        let file = f.password_file(PASSWORD);
        for plaintext in [false, true] {
            if plaintext {
                drop(SqliteStorage::connect_file(f.db())?);
            }
            let error = unlock_with(&f.db(), Some(&file), &mut |_: &str| unreachable!())
                .expect_err("existing key record must be preserved");
            assert!(
                error
                    .to_string()
                    .contains("refusing to replace existing password record")
            );
            assert_eq!(std::fs::read(&record_path)?, before);
            assert_eq!(
                *PasswordRecord::from_json(&String::from_utf8(before.clone())?)?.open(PASSWORD)?,
                *key
            );
        }
        Ok(())
    }

    #[test]
    fn first_run_asks_twice_and_retries_a_mismatch() -> Result<()> {
        let f = Fixture::new();
        let mut asked = Vec::new();
        let key = unlock_with(
            &f.db(),
            None,
            &mut scripted(
                &["too short", PASSWORD, "typo", PASSWORD, PASSWORD],
                &mut asked,
            ),
        )?;
        assert_eq!(
            asked,
            [
                "New password: ",
                "New password: ",
                "Retype new password: ",
                "New password: ",
                "Retype new password: "
            ]
        );
        assert!(password_vault::record_path(&f.db()).is_file());
        assert!(!encrypted_migration::is_plaintext_file(&f.db())?);
        drop(SqliteStorage::reopen_encrypted(f.db(), &key)?);
        Ok(())
    }

    #[test]
    fn reopening_allows_three_attempts() -> Result<()> {
        let f = Fixture::new();
        let file = f.password_file(PASSWORD);
        unlock_with(&f.db(), Some(&file), &mut |_: &str| unreachable!())?;

        let mut asked = Vec::new();
        assert!(
            unlock_with(
                &f.db(),
                None,
                &mut scripted(&["wrong one", "wrong two", PASSWORD], &mut asked)
            )
            .is_ok()
        );
        assert_eq!(asked.len(), 3);

        let mut asked = Vec::new();
        let error = unlock_with(
            &f.db(),
            None,
            &mut scripted(&["wrong", "wrong", "wrong"], &mut asked),
        )
        .err()
        .map(|e| e.to_string());
        assert_eq!(error.as_deref(), Some("3 incorrect password attempts"));
        Ok(())
    }

    #[test]
    fn password_file_drops_one_trailing_newline() -> Result<()> {
        let f = Fixture::new();
        let file = f.password_file(&format!("{PASSWORD}\n"));
        unlock_with(&f.db(), Some(&file), &mut |_: &str| unreachable!())?;
        let mut asked = Vec::new();
        assert!(unlock_with(&f.db(), None, &mut scripted(&[PASSWORD], &mut asked)).is_ok());

        let wrong = f.password_file("not the password at all");
        let error = unlock_with(&f.db(), Some(&wrong), &mut |_: &str| unreachable!())
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(error.contains("is wrong"), "{error}");
        Ok(())
    }

    #[test]
    fn an_unencrypted_database_is_encrypted_with_its_data() -> Result<()> {
        let f = Fixture::new();
        let mut plain = SqliteStorage::connect_file(f.db())?;
        plain.set_setting_json("explorer", &"https://example.test")?;
        drop(plain);

        let file = f.password_file(PASSWORD);
        let key = unlock_with(&f.db(), Some(&file), &mut |_: &str| unreachable!())?;
        assert!(!encrypted_migration::is_plaintext_file(&f.db())?);
        assert_eq!(
            SqliteStorage::reopen_encrypted(f.db(), &key)?
                .get_setting_json::<String>("explorer")?
                .as_deref(),
            Some("https://example.test")
        );
        Ok(())
    }

    #[test]
    fn changing_the_password_keeps_the_data() -> Result<()> {
        const NEW: &str = "a brand new passphrase for spp";
        let f = Fixture::new();
        let file = f.password_file(PASSWORD);
        let key = unlock_with(&f.db(), Some(&file), &mut |_: &str| unreachable!())?;
        SqliteStorage::reopen_encrypted(f.db(), &key)?.set_setting_json("kept", &"yes")?;
        let before = fs::read(f.db())?;

        let mut asked = Vec::new();
        change_password_with(
            &f.db(),
            None,
            None,
            &mut scripted(&["wrong", PASSWORD, NEW, NEW], &mut asked),
        )?;
        assert_eq!(
            asked,
            [
                "Current password: ",
                "Current password: ",
                "New password: ",
                "Retype new password: "
            ]
        );
        // Only the record changed; the database file is untouched.
        assert_eq!(fs::read(f.db())?, before);

        let mut asked = Vec::new();
        let reopened = unlock_with(&f.db(), None, &mut scripted(&[NEW], &mut asked))?;
        assert_eq!(
            SqliteStorage::reopen_encrypted(f.db(), &reopened)?
                .get_setting_json::<String>("kept")?
                .as_deref(),
            Some("yes")
        );
        let old = unlock_with(&f.db(), Some(&file), &mut |_: &str| unreachable!());
        assert!(old.is_err());
        Ok(())
    }

    #[test]
    fn changing_the_password_needs_the_current_one() -> Result<()> {
        let f = Fixture::new();
        let file = f.password_file(PASSWORD);
        unlock_with(&f.db(), Some(&file), &mut |_: &str| unreachable!())?;
        let record = fs::read(password_vault::record_path(&f.db()))?;

        let mut asked = Vec::new();
        let error = change_password_with(
            &f.db(),
            None,
            None,
            &mut scripted(&["wrong", "wrong", "wrong"], &mut asked),
        )
        .err()
        .map(|e| e.to_string());
        assert_eq!(error.as_deref(), Some("3 incorrect password attempts"));
        assert_eq!(fs::read(password_vault::record_path(&f.db()))?, record);

        let missing = f.0.join("missing.db");
        assert!(
            change_password_with(&missing, Some(&file), Some(&file), &mut |_: &str| {
                unreachable!()
            })
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn an_empty_leftover_file_is_replaced() -> Result<()> {
        let f = Fixture::new();
        fs::write(f.db(), b"")?;
        let file = f.password_file(PASSWORD);
        let key = unlock_with(&f.db(), Some(&file), &mut |_: &str| unreachable!())?;
        drop(SqliteStorage::reopen_encrypted(f.db(), &key)?);
        Ok(())
    }
}
