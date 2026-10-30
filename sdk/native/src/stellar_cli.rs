//! Thin wrapper over the installed `stellar` CLI binary.
//!
//! Account operations are delegated to the official Stellar CLI so the private
//! payments CLI never handles a raw mnemonic or secret key: identities live in
//! the Stellar CLI's alias store (`stellar keys …`). We shell out for:
//!
//! * resolve an alias to its address ([`public_key`]),
//! * produce the SEP-53 key-derivation signature ([`sign_message`]), and
//! * sign transaction envelopes ([`sign_tx`]), including OS secure-store keys.

use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::{
    chain::Signature,
    types::{KeyDerivationSignature, Sensitive, correlation_id_or_new},
};

/// Env var to override the `stellar` binary path (default: `stellar` on PATH).
const STELLAR_BIN_ENV: &str = "STELLAR_BIN";
const DEFAULT_BIN: &str = "stellar";

fn stellar_bin() -> String {
    std::env::var(STELLAR_BIN_ENV).unwrap_or_else(|_| DEFAULT_BIN.to_string())
}

/// Run `stellar <args…>` (with an optional `--config-dir`) and return trimmed
/// stdout. Info logs go to stderr and are ignored on success.
#[tracing::instrument(
    name = "stellar_cli_run",
    skip_all,
    fields(correlation_id = %correlation_id_or_new())
)]
fn run(args: &[String], config_dir: Option<&Path>) -> Result<Zeroizing<String>> {
    let start = Instant::now();
    let bin = stellar_bin();
    // Full args are Sensitive-wrapped: some call sites (e.g. `message sign`)
    // pass payload/Tier-1 values in args, so they stay redacted by default.
    tracing::info!(
        bin = %bin,
        subcommand = %args.first().map(String::as_str).unwrap_or(""),
        args = ?Sensitive(&args),
        "running external stellar command"
    );
    let mut cmd = Command::new(&bin);
    cmd.args(args);
    if let Some(dir) = config_dir {
        cmd.arg("--config-dir").arg(dir);
    }
    let result = cmd.output().with_context(|| {
        format!(
            "failed to run `{bin}`; install the Stellar CLI (https://stellar.org/cli) \
             or set {STELLAR_BIN_ENV} to its path"
        )
    });
    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    match &result {
        Ok(output) => tracing::debug!(
            exit_status = %output.status,
            stdout_len = output.stdout.len(),
            stderr_len = output.stderr.len(),
            elapsed_ms,
            "external stellar command exited"
        ),
        Err(_) => tracing::debug!(elapsed_ms, "external stellar command failed to start"),
    }
    let output = result?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`{bin} {}` failed: {}",
            args.first().map(String::as_str).unwrap_or(""),
            stderr.trim()
        );
    }
    let stdout = Zeroizing::new(
        String::from_utf8(output.stdout).context("stellar CLI produced non-UTF-8 output")?,
    );
    Ok(Zeroizing::new(stdout.trim().to_string()))
}

/// Resolve an alias to its Stellar address (`G…`) via `stellar keys
/// public-key`.
#[tracing::instrument(
    name = "stellar_public_key",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), alias = ?Sensitive(&alias))
)]
pub fn public_key(alias: &str, config_dir: Option<&Path>) -> Result<String> {
    validate_alias("account", alias)?;
    let args = vec![
        "keys".to_string(),
        "public-key".to_string(),
        alias.to_string(),
    ];
    let address = run(&args, config_dir)?;
    stellar_strkey::ed25519::PublicKey::from_string(&address)
        .context("stellar CLI returned an invalid account address")?;
    Ok(address.to_string())
}

/// Produce the SEP-53 signature of `message` via `stellar message sign`.
///
/// The Stellar CLI prefixes `"Stellar Signed Message:\n"`, SHA-256 hashes, then
/// Ed25519-signs — matching the web app / Freighter derivation exactly. Output
/// is base64 of the 64-byte signature.
#[tracing::instrument(
    name = "stellar_sign_message",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), alias = ?Sensitive(&alias), message_len = message.len())
)]
pub fn sign_message(
    alias: &str,
    message: &str,
    config_dir: Option<&Path>,
) -> Result<KeyDerivationSignature> {
    validate_alias("account", alias)?;
    // The message contents and the produced signature are never logged.
    tracing::info!(
        alias = ?Sensitive(&alias),
        message_len = message.len(),
        "awaiting external signer (may prompt for key)"
    );
    let args = vec![
        "message".to_string(),
        "sign".to_string(),
        message.to_string(),
        "--sign-with-key".to_string(),
        alias.to_string(),
    ];
    let encoded = run(&args, config_dir)?;
    let signature = Signature::from_base64(&encoded)
        .context("decode SEP-53 signature returned by the stellar CLI")?;
    Ok(KeyDerivationSignature(signature.as_bytes().to_vec()))
}

/// Sign an unsigned transaction envelope via `stellar tx sign`.
///
/// Works for identities stored in the config file or OS secure store. The
/// unsigned envelope XDR is passed on stdin; signed envelope XDR is returned
/// from stdout.
#[tracing::instrument(
    name = "stellar_sign_tx",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), alias = ?Sensitive(&alias), xdr_len = tx_xdr.len(), network = %network_passphrase)
)]
pub fn sign_tx(
    alias: &str,
    tx_xdr: &str,
    rpc_url: &str,
    network_passphrase: &str,
    config_dir: Option<&Path>,
) -> Result<String> {
    validate_alias("account", alias)?;
    let start = Instant::now();
    // Host part of the RPC URL (scheme and path stripped); the envelope XDR
    // and the signed XDR output are never logged.
    let rpc_host = rpc_url
        .split("://")
        .nth(1)
        .unwrap_or(rpc_url)
        .split('/')
        .next()
        .unwrap_or("");
    tracing::info!(
        alias = ?Sensitive(&alias),
        xdr_len = tx_xdr.len(),
        network = %network_passphrase,
        rpc_host,
        "awaiting external signer (--auto-sign may block on hardware/secure-store prompt)"
    );
    let bin = stellar_bin();
    let mut cmd = Command::new(&bin);
    cmd.args([
        "tx",
        "sign",
        "--sign-with-key",
        alias,
        "--auto-sign",
        "--rpc-url",
        rpc_url,
        "--network-passphrase",
        network_passphrase,
    ]);
    if let Some(dir) = config_dir {
        cmd.arg("--config-dir").arg(dir);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().with_context(|| {
        format!(
            "failed to run `{bin} tx sign`; install the Stellar CLI (https://stellar.org/cli) \
             or set {STELLAR_BIN_ENV} to its path"
        )
    })?;

    // Dropping stdin at the end of the statement closes it. A write error is
    // held back until the child has been waited for: a signer that rejects its
    // arguments exits without reading, and its stderr says why.
    let written = child
        .stdin
        .take()
        .context("stellar tx sign stdin")?
        .write_all(tx_xdr.as_bytes());

    let result = child.wait_with_output().context("wait for stellar tx sign");
    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    match &result {
        Ok(output) => tracing::debug!(
            exit_status = %output.status,
            stdout_len = output.stdout.len(),
            stderr_len = output.stderr.len(),
            elapsed_ms,
            "external stellar command exited"
        ),
        Err(_) => tracing::debug!(elapsed_ms, "external stellar command failed"),
    }
    let output = result?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`{bin} tx sign --sign-with-key {alias}` failed: {}",
            stderr.trim()
        );
    }
    // A signer that succeeded without reading the whole envelope did not sign
    // it.
    written.context("write transaction XDR to stellar tx sign")?;

    let stdout =
        String::from_utf8(output.stdout).context("stellar CLI produced non-UTF-8 output")?;
    Ok(stdout.trim().to_string())
}

/// A network's connection parameters, resolved from the Stellar CLI.
#[derive(Debug, Clone)]
pub struct StellarNetwork {
    pub rpc_url: String,
    pub passphrase: String,
}

/// Confirm the `stellar` binary is available, returning its version line.
pub fn ensure_installed() -> Result<String> {
    run(&["--version".to_string()], None)
        .map(|output| output.to_string())
        .map_err(|e| {
            anyhow::anyhow!(
                "{e}\n\nInstall the Stellar CLI: https://github.com/stellar/stellar-cli#install"
            )
        })
}

/// Resolve a network's RPC URL and passphrase from the Stellar CLI's own
/// network config (built-in networks like `testnet` and any custom ones added
/// via `stellar network add`), by parsing `stellar network ls --long`.
#[tracing::instrument(
    name = "stellar_network_lookup",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), network = %name)
)]
pub fn network(name: &str, config_dir: Option<&Path>) -> Result<StellarNetwork> {
    let listing = run(
        &[
            "network".to_string(),
            "ls".to_string(),
            "--long".to_string(),
        ],
        config_dir,
    )?;

    // Blocks are separated by blank lines; each has `Name:`, `RPC url:`,
    // `Network passphrase:` fields.
    for block in listing.split("\n\n") {
        let mut block_name = None;
        let mut rpc_url = None;
        let mut passphrase = None;
        for line in block.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("Name:") {
                block_name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("RPC url:") {
                rpc_url = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Network passphrase:") {
                passphrase = Some(v.trim().to_string());
            }
        }
        if block_name.as_deref() != Some(name) {
            continue;
        }
        let (Some(rpc_url), Some(passphrase)) = (rpc_url, passphrase) else {
            bail!("network `{name}` is missing an RPC url or passphrase in the Stellar CLI config");
        };
        if !(rpc_url.starts_with("http://") || rpc_url.starts_with("https://")) {
            bail!(
                "network `{name}` has no usable RPC url (`{rpc_url}`). \
                 Configure one with `stellar network add {name} --rpc-url <URL> --network-passphrase <PHRASE>`"
            );
        }
        return Ok(StellarNetwork {
            rpc_url,
            passphrase,
        });
    }
    bail!(
        "network `{name}` is not known to the Stellar CLI; add it with \
         `stellar network add {name} --rpc-url <URL> --network-passphrase <PHRASE>` \
         or pick another with --network"
    )
}

/// Enforce alias-only usage: reject raw secret keys and seed phrases so secrets
/// never appear on the command line or in config.
///
/// `flag` is the option the value came from (`--account`, `--sign-as`), so the
/// error names the one the user actually typed.
pub fn validate_alias(flag: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.starts_with('-') {
        bail!("{flag} must be a nonempty Stellar CLI alias that does not start with '-'");
    }
    if value.chars().any(char::is_whitespace) {
        bail!(
            "{flag} must be a `stellar keys` alias name, not a seed phrase; \
             register one with `stellar keys add`/`stellar keys generate`"
        );
    }
    if value.len() == 56 && value.starts_with('S') {
        bail!(
            "{flag} must be a `stellar keys` alias name, not a raw secret key; \
             register one with `stellar keys add`"
        );
    }
    Ok(())
}

/// A scripted stand-in for the `stellar` binary, for tests that drive the real
/// shell-out code.
///
/// `STELLAR_BIN` is process-global and unit tests share one process, so a fake
/// holds a lock for as long as it lives and restores the variable on drop.
#[cfg(all(test, unix))]
pub(crate) mod fake {
    use std::{
        ffi::OsString,
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::{Mutex, MutexGuard},
    };

    use super::STELLAR_BIN_ENV;

    static STELLAR_BIN_MUTEX: Mutex<()> = Mutex::new(());

    /// Records its argv (NUL-separated, since arguments may span lines) and
    /// stdin per invocation, then plays back the reply registered for
    /// `<arg1>-<arg2>`, or `default`.
    const SCRIPT: &str = r#"#!/bin/sh
dir='@DIR@'
count=$(cat "$dir/count" 2>/dev/null || echo 0)
n=$((count + 1))
echo "$n" > "$dir/count"
for arg in "$@"; do printf '%s\0' "$arg"; done > "$dir/argv.$n"
[ -e "$dir/ignore-stdin" ] || cat > "$dir/stdin.$n"
reply="$dir/reply/$1-$2"
[ -d "$reply" ] || reply="$dir/reply/default"
cat "$reply/stdout"
cat "$reply/stderr" >&2
exit "$(cat "$reply/code")"
"#;

    /// What the fake prints and how it exits.
    #[derive(Default)]
    pub(crate) struct Reply {
        pub(crate) stdout: Vec<u8>,
        pub(crate) stderr: String,
        pub(crate) code: i32,
    }

    impl Reply {
        pub(crate) fn ok(stdout: impl AsRef<[u8]>) -> Self {
            Self {
                stdout: stdout.as_ref().to_vec(),
                ..Self::default()
            }
        }

        pub(crate) fn failure(stderr: &str) -> Self {
            Self {
                stderr: stderr.to_string(),
                code: 1,
                ..Self::default()
            }
        }
    }

    /// One recorded invocation of the fake.
    pub(crate) struct Call {
        pub(crate) args: Vec<String>,
        pub(crate) stdin: Vec<u8>,
    }

    pub(crate) struct FakeStellar {
        dir: PathBuf,
        previous: Option<OsString>,
        _lock: MutexGuard<'static, ()>,
    }

    impl FakeStellar {
        /// Installs a fake that exits 0 with no output until given replies.
        pub(crate) fn new() -> Self {
            let fake = Self::scratch();
            let bin = fake.bin();
            fs::write(
                &bin,
                SCRIPT.replace("@DIR@", &fake.dir.display().to_string()),
            )
            .expect("write the fake stellar script");
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755))
                .expect("make the fake stellar executable");
            set_stellar_bin(Some(&bin));
            fake.reply("default", Reply::default())
        }

        /// Installs a fake that answers every invocation with `reply`.
        pub(crate) fn replying(reply: Reply) -> Self {
            Self::new().reply("default", reply)
        }

        /// Points `STELLAR_BIN` at a path where no binary exists.
        pub(crate) fn missing() -> Self {
            let fake = Self::scratch();
            set_stellar_bin(Some(&fake.bin()));
            fake
        }

        /// Clears `STELLAR_BIN`. Never run the CLI from this one: whatever
        /// `stellar` is on the PATH would answer.
        pub(crate) fn unset() -> Self {
            let fake = Self::scratch();
            set_stellar_bin(None);
            fake
        }

        /// The reply for invocations whose first two arguments are `key`
        /// joined by `-` (`keys-public-key`); `default` answers the rest.
        pub(crate) fn reply(self, key: &str, reply: Reply) -> Self {
            let dir = self.dir.join("reply").join(key);
            fs::create_dir_all(&dir).expect("create the reply directory");
            fs::write(dir.join("stdout"), &reply.stdout).expect("write the stdout reply");
            fs::write(dir.join("stderr"), &reply.stderr).expect("write the stderr reply");
            fs::write(dir.join("code"), reply.code.to_string()).expect("write the exit code");
            self
        }

        /// Exits without reading stdin, as a CLI that rejects its arguments
        /// before reading the envelope would.
        pub(crate) fn ignoring_stdin(self) -> Self {
            fs::write(self.dir.join("ignore-stdin"), "").expect("write the marker");
            self
        }

        pub(crate) fn bin(&self) -> PathBuf {
            self.dir.join("stellar")
        }

        pub(crate) fn calls(&self) -> Vec<Call> {
            let count: usize = fs::read_to_string(self.dir.join("count"))
                .map_or(0, |count| count.trim().parse().expect("call counter"));
            (1..=count)
                .map(|n| {
                    let argv = fs::read(self.dir.join(format!("argv.{n}"))).expect("recorded argv");
                    let mut args: Vec<&[u8]> = argv.split(|byte| *byte == 0).collect();
                    // Every argument ends in a NUL, so the last piece is empty.
                    args.pop();
                    Call {
                        args: args
                            .into_iter()
                            .map(|arg| String::from_utf8(arg.to_vec()).expect("UTF-8 argument"))
                            .collect(),
                        stdin: fs::read(self.dir.join(format!("stdin.{n}"))).unwrap_or_default(),
                    }
                })
                .collect()
        }

        pub(crate) fn only_call(&self) -> Call {
            let mut calls = self.calls();
            assert_eq!(calls.len(), 1, "expected exactly one stellar invocation");
            calls.remove(0)
        }

        fn scratch() -> Self {
            let lock = STELLAR_BIN_MUTEX
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut suffix = [0u8; 8];
            getrandom::getrandom(&mut suffix).expect("random directory suffix");
            let dir =
                std::env::temp_dir().join(format!("spp-fake-stellar-{}", hex::encode(suffix)));
            fs::create_dir(&dir).expect("create the fake stellar directory");
            Self {
                dir,
                previous: std::env::var_os(STELLAR_BIN_ENV),
                _lock: lock,
            }
        }
    }

    impl Drop for FakeStellar {
        fn drop(&mut self) {
            set_stellar_bin(self.previous.as_deref().map(Path::new));
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[allow(unsafe_code)]
    fn set_stellar_bin(bin: Option<&Path>) {
        // SAFETY: edition 2024 marks environment mutation unsafe because C code
        // may call `getenv` concurrently. Every caller holds
        // `STELLAR_BIN_MUTEX`, so no other test touches this variable,
        // and std's own accessors synchronize with the write.
        unsafe {
            match bin {
                Some(bin) => std::env::set_var(STELLAR_BIN_ENV, bin),
                None => std::env::remove_var(STELLAR_BIN_ENV),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{public_key, sign_message, sign_tx, validate_alias};

    /// Shaped like a raw secret key: 56 characters starting with `S`.
    const SECRET_SHAPED: &str = "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn an_alias_name_is_accepted_for_either_flag() {
        validate_alias("--account", "alice").expect("a plain alias is what both flags want");
        validate_alias("--sign-as", "payer").expect("a plain alias is what both flags want");
    }

    #[test]
    fn empty_and_option_shaped_aliases_are_rejected_by_every_signing_entry_point() {
        for alias in ["", "--help", "-x", "abandon abandon", SECRET_SHAPED] {
            assert!(validate_alias("--storage-account", alias).is_err());
            // Validation must happen before attempting to launch Stellar.
            assert!(
                public_key(alias, None)
                    .expect_err("invalid aliases must fail before launching Stellar")
                    .to_string()
                    .starts_with("account must")
            );
            assert!(
                sign_message(alias, "test", None)
                    .expect_err("invalid aliases must fail before launching Stellar")
                    .to_string()
                    .starts_with("account must")
            );
            assert!(
                sign_tx(alias, "", "", "", None)
                    .expect_err("invalid aliases must fail before launching Stellar")
                    .to_string()
                    .starts_with("account must")
            );
        }
    }

    #[test]
    fn a_seed_phrase_is_reported_against_the_flag_it_came_from() {
        let err = validate_alias("--account", "abandon abandon abandon")
            .expect_err("a seed phrase must never reach the command line");
        assert!(
            err.to_string()
                .starts_with("--account must be a `stellar keys` alias name, not a seed phrase"),
            "got: {err}"
        );

        let err = validate_alias("--sign-as", "abandon abandon abandon")
            .expect_err("a seed phrase must never reach the command line");
        assert!(
            err.to_string()
                .starts_with("--sign-as must be a `stellar keys` alias name, not a seed phrase"),
            "got: {err}"
        );
    }

    #[test]
    fn a_raw_secret_key_is_reported_against_the_flag_it_came_from() {
        let err = validate_alias("--account", SECRET_SHAPED)
            .expect_err("a raw secret key must never reach the command line");
        assert!(
            err.to_string()
                .starts_with("--account must be a `stellar keys` alias name, not a raw secret key"),
            "got: {err}"
        );

        let err = validate_alias("--sign-as", SECRET_SHAPED)
            .expect_err("a raw secret key must never reach the command line");
        assert!(
            err.to_string()
                .starts_with("--sign-as must be a `stellar keys` alias name, not a raw secret key"),
            "got: {err}"
        );
    }

    #[cfg(unix)]
    mod through_a_fake_stellar {
        use std::path::Path;

        use base64::{Engine, engine::general_purpose::STANDARD};

        use crate::stellar_cli::{
            ensure_installed,
            fake::{FakeStellar, Reply},
            network, public_key, run, sign_message, sign_tx, stellar_bin,
        };

        const CONFIG_DIR: &str = "/stellar/config";
        const RPC_URL: &str = "https://rpc.example.test/soroban";
        const PASSPHRASE: &str = "Test SDF Network ; September 2015";
        const XDR: &str = "AAAAAgAAAAB0ZXN0LXVuc2lnbmVkLWVudmVsb3Bl";
        const SIGN_TX_ARGS: [&str; 9] = [
            "tx",
            "sign",
            "--sign-with-key",
            "alice",
            "--auto-sign",
            "--rpc-url",
            RPC_URL,
            "--network-passphrase",
            PASSPHRASE,
        ];
        /// Shaped like `stellar network ls --long`: blank-line-separated
        /// blocks.
        const LISTING: &str = "\
Name: local
RPC url: http://localhost:8000/rpc
Network passphrase: Standalone Network ; February 2017

Name: testnet
RPC url: https://rpc.example.test/testnet
Network passphrase: Test SDF Network ; September 2015

Name: futurenet
RPC url: https://rpc.example.test/futurenet
Network passphrase: Test SDF Future Network ; October 2022
";

        fn args(items: &[&str]) -> Vec<String> {
            items.iter().map(|item| (*item).to_string()).collect()
        }

        fn address() -> String {
            stellar_strkey::ed25519::PublicKey([7; 32])
                .to_string()
                .as_str()
                .to_owned()
        }

        #[test]
        fn the_stellar_bin_override_selects_the_binary_that_runs() {
            let fake = FakeStellar::new();
            assert_eq!(stellar_bin(), fake.bin().display().to_string());
        }

        #[test]
        fn without_an_override_the_stellar_on_the_path_is_used() {
            let _fake = FakeStellar::unset();
            assert_eq!(stellar_bin(), "stellar");
        }

        #[test]
        fn run_passes_the_arguments_in_order_and_no_config_dir_by_default() {
            let fake = FakeStellar::new();
            run(&args(&["keys", "ls", "--long"]), None).expect("the fake exits 0");
            assert_eq!(fake.only_call().args, ["keys", "ls", "--long"]);
        }

        #[test]
        fn run_appends_the_config_dir_after_the_arguments() {
            let fake = FakeStellar::new();
            run(&args(&["keys", "ls"]), Some(Path::new(CONFIG_DIR))).expect("the fake exits 0");
            assert_eq!(
                fake.only_call().args,
                ["keys", "ls", "--config-dir", CONFIG_DIR]
            );
        }

        #[test]
        fn run_returns_stdout_trimmed() {
            let _fake = FakeStellar::replying(Reply::ok("\n  value with spaces \n\n"));
            let output = run(&args(&["keys"]), None).expect("the fake exits 0");
            assert_eq!(*output, "value with spaces");
        }

        #[test]
        fn run_ignores_stderr_when_the_command_succeeds() {
            let _fake = FakeStellar::replying(Reply {
                stdout: b"ok".to_vec(),
                stderr: "info: loaded the config".into(),
                code: 0,
            });
            let output = run(&args(&["keys"]), None).expect("the fake exits 0");
            assert_eq!(*output, "ok");
        }

        #[test]
        fn run_failure_reports_the_subcommand_and_trimmed_stderr_only() {
            let fake = FakeStellar::replying(Reply {
                stdout: b"ignored".to_vec(),
                stderr: "  error: no such alias\n".into(),
                code: 2,
            });
            let err = run(&args(&["keys", "public-key", "alice"]), None)
                .expect_err("a non-zero exit is a failure");
            assert_eq!(
                err.to_string(),
                format!(
                    "`{} keys` failed: error: no such alias",
                    fake.bin().display()
                )
            );
        }

        #[test]
        fn run_rejects_stdout_that_is_not_utf8() {
            let _fake = FakeStellar::replying(Reply::ok([0xff, 0xfe]));
            let err = run(&args(&["keys"]), None).expect_err("stdout must be text");
            assert_eq!(err.to_string(), "stellar CLI produced non-UTF-8 output");
        }

        #[test]
        fn run_names_the_missing_binary_and_how_to_point_at_one() {
            let fake = FakeStellar::missing();
            let message = run(&args(&["keys"]), None)
                .expect_err("there is nothing to run")
                .to_string();
            assert!(
                message.starts_with(&format!("failed to run `{}`;", fake.bin().display())),
                "got: {message}"
            );
            assert!(
                message.contains("set STELLAR_BIN to its path"),
                "got: {message}"
            );
        }

        #[test]
        fn public_key_returns_the_address_the_cli_prints() {
            let fake = FakeStellar::replying(Reply::ok(format!("{}\n", address())));
            assert_eq!(
                public_key("alice", None).expect("a valid address"),
                address()
            );
            assert_eq!(fake.only_call().args, ["keys", "public-key", "alice"]);
        }

        #[test]
        fn public_key_appends_the_config_dir_only_when_given() {
            let fake = FakeStellar::replying(Reply::ok(address()));
            public_key("alice", None).expect("a valid address");
            public_key("alice", Some(Path::new(CONFIG_DIR))).expect("a valid address");
            let calls = fake.calls();
            assert_eq!(calls[0].args, ["keys", "public-key", "alice"]);
            assert_eq!(
                calls[1].args,
                ["keys", "public-key", "alice", "--config-dir", CONFIG_DIR]
            );
        }

        #[test]
        fn public_key_rejects_output_that_is_not_an_account_address() {
            let secret_key = stellar_strkey::ed25519::PrivateKey([7; 32]);
            let secret = stellar_strkey::Unredacted(&secret_key).to_string();
            for output in ["", "not an address", secret.as_str()] {
                let _fake = FakeStellar::replying(Reply::ok(output));
                let err = public_key("alice", None).expect_err("not a G... address");
                assert_eq!(
                    err.to_string(),
                    "stellar CLI returned an invalid account address",
                    "output: {output:?}"
                );
            }
        }

        #[test]
        fn public_key_reports_a_failing_cli() {
            let _fake = FakeStellar::replying(Reply::failure("error: no key named alice"));
            let err = public_key("alice", None).expect_err("the fake exits non-zero");
            assert!(
                err.to_string()
                    .ends_with("failed: error: no key named alice"),
                "got: {err}"
            );
        }

        #[test]
        fn sign_message_decodes_the_base64_signature() {
            let signature = [9u8; 64];
            let _fake =
                FakeStellar::replying(Reply::ok(format!("{}\n", STANDARD.encode(signature))));
            let decoded = sign_message("alice", "hello", None).expect("a 64-byte signature");
            assert_eq!(decoded.0, signature);
        }

        #[test]
        fn sign_message_passes_a_multi_line_message_as_one_argument() {
            let message = "Stellar Private Payments — unlock\nAccount: G...\nSalt: ab";
            let fake = FakeStellar::replying(Reply::ok(STANDARD.encode([9u8; 64])));
            sign_message("alice", message, None).expect("a 64-byte signature");
            assert_eq!(
                fake.only_call().args,
                ["message", "sign", message, "--sign-with-key", "alice"]
            );
        }

        #[test]
        fn sign_message_appends_the_config_dir_only_when_given() {
            let fake = FakeStellar::replying(Reply::ok(STANDARD.encode([9u8; 64])));
            sign_message("alice", "hello", None).expect("a 64-byte signature");
            sign_message("alice", "hello", Some(Path::new(CONFIG_DIR)))
                .expect("a 64-byte signature");
            let calls = fake.calls();
            assert_eq!(
                calls[0].args,
                ["message", "sign", "hello", "--sign-with-key", "alice"]
            );
            assert_eq!(
                calls[1].args,
                [
                    "message",
                    "sign",
                    "hello",
                    "--sign-with-key",
                    "alice",
                    "--config-dir",
                    CONFIG_DIR
                ]
            );
        }

        #[test]
        fn sign_message_rejects_output_that_is_not_base64() {
            let _fake = FakeStellar::replying(Reply::ok("not base64!"));
            let err = sign_message("alice", "hello", None).expect_err("undecodable output");
            assert_eq!(
                err.to_string(),
                "decode SEP-53 signature returned by the stellar CLI"
            );
        }

        #[test]
        fn sign_message_rejects_a_signature_that_is_not_64_bytes() {
            let _fake = FakeStellar::replying(Reply::ok(STANDARD.encode([9u8; 32])));
            let err = sign_message("alice", "hello", None).expect_err("a 32-byte signature");
            assert!(
                format!("{err:#}").contains("signature must be 64 bytes"),
                "got: {err:#}"
            );
        }

        #[test]
        fn sign_message_reports_a_cli_that_refuses_to_sign() {
            let _fake = FakeStellar::replying(Reply::failure("error: signing was cancelled"));
            let err = sign_message("alice", "hello", None).expect_err("the fake exits non-zero");
            assert!(
                err.to_string()
                    .ends_with("failed: error: signing was cancelled"),
                "got: {err}"
            );
        }

        #[test]
        fn sign_tx_pipes_the_unsigned_envelope_on_stdin_and_returns_the_trimmed_signed_one() {
            let fake = FakeStellar::replying(Reply::ok("  SIGNED-XDR\n"));
            let signed =
                sign_tx("alice", XDR, RPC_URL, PASSPHRASE, None).expect("a signed envelope");
            assert_eq!(signed, "SIGNED-XDR");
            assert_eq!(fake.only_call().stdin, XDR.as_bytes());
        }

        #[test]
        fn sign_tx_asks_for_an_auto_sign_by_the_alias_on_the_given_network() {
            let fake = FakeStellar::new();
            sign_tx("alice", XDR, RPC_URL, PASSPHRASE, None).expect("a signed envelope");
            assert_eq!(fake.only_call().args, SIGN_TX_ARGS);
        }

        #[test]
        fn sign_tx_appends_the_config_dir_only_when_given() {
            let fake = FakeStellar::new();
            sign_tx("alice", XDR, RPC_URL, PASSPHRASE, None).expect("a signed envelope");
            sign_tx(
                "alice",
                XDR,
                RPC_URL,
                PASSPHRASE,
                Some(Path::new(CONFIG_DIR)),
            )
            .expect("a signed envelope");
            let calls = fake.calls();
            assert_eq!(calls[0].args, SIGN_TX_ARGS);
            assert_eq!(
                calls[1].args,
                [&SIGN_TX_ARGS[..], &["--config-dir", CONFIG_DIR]].concat()
            );
        }

        #[test]
        fn sign_tx_failure_names_the_binary_the_alias_and_the_trimmed_stderr() {
            let fake = FakeStellar::replying(Reply::failure("  error: ledger is locked\n"));
            let err = sign_tx("alice", XDR, RPC_URL, PASSPHRASE, None)
                .expect_err("the fake exits non-zero");
            assert_eq!(
                err.to_string(),
                format!(
                    "`{} tx sign --sign-with-key alice` failed: error: ledger is locked",
                    fake.bin().display()
                )
            );
        }

        #[test]
        fn sign_tx_reports_the_stderr_of_a_cli_that_exits_without_reading_the_envelope() {
            // Larger than any pipe buffer, so the write cannot finish before
            // the child is gone.
            let envelope = "A".repeat(1024 * 1024);
            let _fake =
                FakeStellar::replying(Reply::failure("error: no key named alice")).ignoring_stdin();
            let err = sign_tx("alice", &envelope, RPC_URL, PASSPHRASE, None)
                .expect_err("the fake exits non-zero");
            assert!(
                err.to_string()
                    .ends_with("failed: error: no key named alice"),
                "got: {err:#}"
            );
        }

        #[test]
        fn sign_tx_does_not_accept_output_from_a_cli_that_exited_without_reading_the_envelope() {
            let envelope = "A".repeat(1024 * 1024);
            let _fake = FakeStellar::replying(Reply::ok("SIGNED-XDR")).ignoring_stdin();
            let err = sign_tx("alice", &envelope, RPC_URL, PASSPHRASE, None)
                .expect_err("a signer that read nothing signed nothing");
            assert_eq!(err.to_string(), "write transaction XDR to stellar tx sign");
        }

        #[test]
        fn sign_tx_rejects_output_that_is_not_utf8() {
            let _fake = FakeStellar::replying(Reply::ok([0xff, 0xfe]));
            let err = sign_tx("alice", XDR, RPC_URL, PASSPHRASE, None).expect_err("not text");
            assert_eq!(err.to_string(), "stellar CLI produced non-UTF-8 output");
        }

        #[test]
        fn sign_tx_names_the_missing_binary_and_how_to_point_at_one() {
            let fake = FakeStellar::missing();
            let message = sign_tx("alice", XDR, RPC_URL, PASSPHRASE, None)
                .expect_err("there is nothing to run")
                .to_string();
            assert!(
                message.starts_with(&format!(
                    "failed to run `{} tx sign`;",
                    fake.bin().display()
                )),
                "got: {message}"
            );
            assert!(
                message.contains("set STELLAR_BIN to its path"),
                "got: {message}"
            );
        }

        #[test]
        fn ensure_installed_returns_the_trimmed_version_output() {
            let fake = FakeStellar::replying(Reply::ok("stellar 28.1.0 (abc123)\n"));
            assert_eq!(
                ensure_installed().expect("the fake exits 0"),
                "stellar 28.1.0 (abc123)"
            );
            assert_eq!(fake.only_call().args, ["--version"]);
        }

        #[test]
        fn ensure_installed_adds_the_install_hint_when_the_binary_is_missing() {
            let _fake = FakeStellar::missing();
            let message = ensure_installed()
                .expect_err("there is nothing to run")
                .to_string();
            assert!(message.starts_with("failed to run `"), "got: {message}");
            assert!(
                message.ends_with(
                    "\n\nInstall the Stellar CLI: https://github.com/stellar/stellar-cli#install"
                ),
                "got: {message}"
            );
        }

        #[test]
        fn ensure_installed_adds_the_install_hint_when_the_binary_fails() {
            let _fake = FakeStellar::replying(Reply::failure("error: broken install"));
            let message = ensure_installed()
                .expect_err("the fake exits non-zero")
                .to_string();
            assert!(
                message.contains("failed: error: broken install"),
                "got: {message}"
            );
            assert!(
                message.ends_with(
                    "Install the Stellar CLI: https://github.com/stellar/stellar-cli#install"
                ),
                "got: {message}"
            );
        }

        #[test]
        fn network_returns_the_rpc_url_and_passphrase_of_the_named_network() {
            let fake = FakeStellar::replying(Reply::ok(LISTING));
            let testnet = network("testnet", None).expect("testnet is listed");
            assert_eq!(testnet.rpc_url, "https://rpc.example.test/testnet");
            assert_eq!(testnet.passphrase, "Test SDF Network ; September 2015");
            assert_eq!(fake.only_call().args, ["network", "ls", "--long"]);
        }

        #[test]
        fn network_reads_the_first_and_last_blocks_of_the_listing() {
            let _fake = FakeStellar::replying(Reply::ok(LISTING));
            assert_eq!(
                network("local", None).expect("local is listed").rpc_url,
                "http://localhost:8000/rpc"
            );
            assert_eq!(
                network("futurenet", None)
                    .expect("futurenet is listed")
                    .passphrase,
                "Test SDF Future Network ; October 2022"
            );
        }

        #[test]
        fn network_appends_the_config_dir_only_when_given() {
            let fake = FakeStellar::replying(Reply::ok(LISTING));
            network("testnet", None).expect("testnet is listed");
            network("testnet", Some(Path::new(CONFIG_DIR))).expect("testnet is listed");
            let calls = fake.calls();
            assert_eq!(calls[0].args, ["network", "ls", "--long"]);
            assert_eq!(
                calls[1].args,
                ["network", "ls", "--long", "--config-dir", CONFIG_DIR]
            );
        }

        #[test]
        fn network_accepts_indented_fields_in_any_order() {
            let _fake = FakeStellar::replying(Reply::ok(
                "Name: custom\n  Network passphrase: My Network\n\tRPC url: https://rpc.example.test/custom\n",
            ));
            let custom = network("custom", None).expect("custom is listed");
            assert_eq!(custom.rpc_url, "https://rpc.example.test/custom");
            assert_eq!(custom.passphrase, "My Network");
        }

        #[test]
        fn network_rejects_a_block_without_a_passphrase() {
            let _fake = FakeStellar::replying(Reply::ok(
                "Name: custom\nRPC url: https://rpc.example.test/custom\n",
            ));
            let err = network("custom", None).expect_err("the passphrase is missing");
            assert_eq!(
                err.to_string(),
                "network `custom` is missing an RPC url or passphrase in the Stellar CLI config"
            );
        }

        #[test]
        fn network_rejects_a_block_without_an_rpc_url() {
            let _fake =
                FakeStellar::replying(Reply::ok("Name: custom\nNetwork passphrase: My Network\n"));
            let err = network("custom", None).expect_err("the RPC url is missing");
            assert_eq!(
                err.to_string(),
                "network `custom` is missing an RPC url or passphrase in the Stellar CLI config"
            );
        }

        #[test]
        fn network_rejects_an_rpc_url_that_is_not_http() {
            for url in ["", "ws://rpc.example.test", "rpc.example.test"] {
                let _fake = FakeStellar::replying(Reply::ok(format!(
                    "Name: custom\nRPC url: {url}\nNetwork passphrase: My Network\n"
                )));
                let message = network("custom", None)
                    .expect_err("only http(s) urls are usable")
                    .to_string();
                assert!(
                    message
                        .starts_with(&format!("network `custom` has no usable RPC url (`{url}`)")),
                    "url {url:?}: {message}"
                );
            }
        }

        #[test]
        fn network_accepts_a_plain_http_rpc_url() {
            let _fake = FakeStellar::replying(Reply::ok(
                "Name: custom\nRPC url: http://localhost:8000/rpc\nNetwork passphrase: My Network\n",
            ));
            assert_eq!(
                network("custom", None).expect("http is usable").rpc_url,
                "http://localhost:8000/rpc"
            );
        }

        #[test]
        fn network_reports_a_name_the_cli_does_not_know() {
            let _fake = FakeStellar::replying(Reply::ok(LISTING));
            let message = network("mainnet", None)
                .expect_err("mainnet is not listed")
                .to_string();
            assert!(
                message.starts_with("network `mainnet` is not known to the Stellar CLI;"),
                "got: {message}"
            );
        }

        #[test]
        fn network_does_not_match_a_name_that_only_shares_a_prefix() {
            let _fake = FakeStellar::replying(Reply::ok(
                "Name: testnet-old\nRPC url: https://rpc.example.test/old\nNetwork passphrase: Old\n",
            ));
            let message = network("testnet", None)
                .expect_err("testnet-old is another network")
                .to_string();
            assert!(
                message.contains("is not known to the Stellar CLI"),
                "got: {message}"
            );
        }

        #[test]
        fn network_reports_a_failing_cli() {
            let _fake = FakeStellar::replying(Reply::failure("error: cannot read the config"));
            let err = network("testnet", None).expect_err("the fake exits non-zero");
            assert!(
                err.to_string()
                    .ends_with("failed: error: cannot read the config"),
                "got: {err}"
            );
        }
    }
}
