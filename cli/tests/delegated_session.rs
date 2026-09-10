//! End-to-end checks over the `spp` binary for the two-alias split.
//!
//! These exist because the SDK's own divergent-session tests ship inside the
//! commit that allows a divergent session. A CLI branch built on a base that
//! lacks it carries neither the behaviour nor the test, and every unit test
//! here still passes: nothing below the binary opens a session. So the
//! assertion has to live with the consumer.
//!
//! `stellar` is a fixture script rather than the real CLI, so no keystore,
//! network or funded account is involved.

#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

const OWNER_ADDRESS: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const PAYER_ADDRESS: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ";

/// Answers the four `stellar` subcommands onboarding and a readonly session
/// reach for, and nothing else: an unhandled call fails loudly rather than
/// returning something plausible.
const STELLAR_FIXTURE: &str = r#"#!/usr/bin/env bash
case "$1 $2" in
  "--version "*) echo "stellar 27.0.0" ;;
  "keys public-key")
    case "$3" in
      owner) echo "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF" ;;
      payer) echo "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ" ;;
      *) echo "fixture: unknown alias $3" >&2; exit 1 ;;
    esac ;;
  "message sign")
    # A constant 64-byte Ed25519-shaped signature, base64 encoded.
    echo "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==" ;;
  "network ls")
    printf 'Name: testnet\nRPC url: https://rpc.invalid\nNetwork passphrase: Test SDF Network ; September 2015\n' ;;
  *) echo "fixture: unhandled: $*" >&2; exit 1 ;;
esac
"#;

/// A data dir and a `stellar` fixture, unique per test.
struct Sandbox {
    data_dir: PathBuf,
    stellar: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        static RUN: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "spp-delegated-{label}-{}-{}",
            std::process::id(),
            RUN.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create sandbox root");

        let stellar = root.join("stellar");
        fs::write(&stellar, STELLAR_FIXTURE).expect("write stellar fixture");
        fs::set_permissions(&stellar, fs::Permissions::from_mode(0o755))
            .expect("make the fixture executable");

        let data_dir = root.join("data");
        fs::create_dir_all(&data_dir).expect("create data dir");
        Self { data_dir, stellar }
    }

    fn spp(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_spp"))
            .env("STELLAR_BIN", &self.stellar)
            // The fixture resolves the aliases; an inherited value would make
            // the run depend on the developer's own wallet.
            .env_remove("STELLAR_ACCOUNT")
            .arg("--data-dir")
            .arg(&self.data_dir)
            .args(args)
            .output()
            .expect("run the spp binary")
    }

    fn onboard_owner(&self) {
        let out = self.spp(&[
            "--json",
            "--account",
            "owner",
            "onboard",
            "--accept",
            "--no-register",
        ]);
        assert!(
            out.status.success(),
            "onboarding the owner should succeed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn db(&self) -> PathBuf {
        self.data_dir.join("spp.db")
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The feature itself: notes owned by one account, envelopes signed and paid
/// for by another. This fails on any base whose `Client::account` still
/// refuses a pair that differs, which is the regression it exists to catch.
#[test]
fn a_delegated_session_opens() {
    let sandbox = Sandbox::new("opens");
    sandbox.onboard_owner();

    let out = sandbox.spp(&["--json", "--account", "owner", "--sign-as", "payer", "keys"]);

    assert!(
        out.status.success(),
        "a session owning notes as `owner` and signing as `payer` must open: {}",
        stderr_of(&out)
    );
    // The keys read back are the owner's, not the payer's.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("note_public_key"),
        "the owner's keys should be readable through a delegated session, got: {stdout}"
    );
}

/// Without the flag nothing changes: the same command, same result.
#[test]
fn a_single_alias_session_opens() {
    let sandbox = Sandbox::new("single");
    sandbox.onboard_owner();

    let out = sandbox.spp(&["--json", "--account", "owner", "keys"]);

    assert!(
        out.status.success(),
        "the owner signing for itself must still open a session: {}",
        stderr_of(&out)
    );
}

/// Onboarding is the owner's own errand: the derivation signature is the note
/// secret. A payer is refused before consent is recorded or a key derived, so
/// no database exists afterwards.
#[test]
fn onboarding_refuses_a_payer_before_touching_anything() {
    let sandbox = Sandbox::new("refuse");

    let out = sandbox.spp(&[
        "--account",
        "owner",
        "--sign-as",
        "payer",
        "onboard",
        "--accept",
        "--no-register",
    ]);

    assert!(
        !out.status.success(),
        "onboarding must not run with a payer that is not the owner"
    );
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("cannot stand in for the note owner"),
        "the refusal should name the roles, got: {stderr}"
    );
    assert!(
        !stderr.contains(OWNER_ADDRESS) && !stderr.contains(PAYER_ADDRESS),
        "addresses are Tier-1 and must stay redacted, got: {stderr}"
    );
    assert!(
        !Path::new(&sandbox.db()).exists(),
        "the refusal must land before any local state is written"
    );
}
