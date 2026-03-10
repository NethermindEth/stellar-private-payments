//! CLI tool that wraps `snarkjs` for a Groth16 BN254 trusted setup ceremony.

use anyhow::{Context, Result, anyhow, bail};
use clap::{ArgAction, Parser, Subcommand};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};
use zeroize::{Zeroize, Zeroizing};

/// Parsed command-line arguments.
#[derive(Debug, Parser)]
#[command(
    name = "ceremony-cli",
    about = "Groth16 BN254 ceremony wrapper around snarkjs"
)]
struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    command: Commands,
}

/// Trusted setup ceremony operations.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Create an initial zkey and verify it.
    Init(CeremonyArgs),
    /// Contribute with internally-generated entropy and verify output.
    Contribute(ContributeArgs),
    /// Finalize artifacts in one command (beacon + verification key export).
    Finalize(FinalizeArgs),
}

/// Shared init arguments.
#[derive(Debug, clap::Args)]
struct CeremonyArgs {
    /// Path to the `.r1cs` file. If omitted, auto-discovers
    /// `policy_tx_2_2.r1cs` from the Cargo build output directory.
    #[arg(short = 'c', long = "circuit")]
    circuits: Option<PathBuf>,
    /// Input Powers of Tau file.
    #[arg(short = 'p', long = "ptau")]
    ptau: PathBuf,
    /// Output zkey path.
    #[arg(short = 'o', long = "output")]
    output: PathBuf,
    /// Overwrite output if it exists.
    #[arg(long = "force", action = ArgAction::SetTrue)]
    force: bool,
}

/// Contribution command arguments.
#[derive(Debug, clap::Args)]
struct ContributeArgs {
    /// Input zkey to contribute to.
    #[arg(short = 'z', long = "zkey")]
    zkey: PathBuf,
    /// Path to the `.r1cs` file. If omitted, auto-discovers the compiled
    /// `policy_tx_2_2.r1cs` from the Cargo build output directory.
    #[arg(short = 'c', long = "circuit")]
    circuits: Option<PathBuf>,
    /// Input Powers of Tau file.
    #[arg(short = 'p', long = "ptau")]
    ptau: PathBuf,
    /// Output zkey path with your contribution.
    #[arg(short = 'o', long = "output")]
    output: PathBuf,
    /// Contributor name recorded in the transcript.
    #[arg(long = "name", default_value = "anonymous")]
    name: String,
    /// Overwrite output if it exists.
    #[arg(long = "force", action = ArgAction::SetTrue)]
    force: bool,
}

/// Finalize command arguments.
#[derive(Debug, clap::Args)]
struct FinalizeArgs {
    /// Input zkey to finalize.
    #[arg(short = 'z', long = "zkey")]
    zkey: PathBuf,
    /// Beacon hash in hex.
    #[arg(long = "beacon-hash")]
    beacon_hash: String,
    /// Beacon power parameter.
    #[arg(long = "beacon-power", default_value_t = 10)]
    beacon_power: u32,
    /// Output directory.
    #[arg(short = 'd', long = "out-dir")]
    out_dir: PathBuf,
    /// Output basename.
    #[arg(long = "basename", default_value = "circuit")]
    basename: String,
    /// Overwrite outputs if they exist.
    #[arg(long = "force", action = ArgAction::SetTrue)]
    force: bool,
}

/// Abstraction for command execution.
trait CommandRunner {
    /// Run a program with provided args and ensure success.
    fn run(&self, program: &str, args: &[OsString]) -> Result<()>;
}

/// Default subprocess runner.
struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(&self, program: &str, args: &[OsString]) -> Result<()> {
        let pretty = format_command(program, args);
        println!("[snarkjs-wrapper] running: {pretty}");

        let start = Instant::now();

        let status = Command::new(program)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    anyhow!("`{program}` not found in PATH. Install with: npm install -g {program}")
                } else {
                    anyhow!("failed to start `{pretty}`: {e}")
                }
            })?;

        let elapsed = start.elapsed();
        println!(
            "[snarkjs-wrapper] completed in {:.2}s: {pretty}",
            elapsed.as_secs_f64()
        );

        if !status.success() {
            bail!("command failed with status {status}: {pretty}");
        }

        Ok(())
    }
}

/// Program entrypoint.
fn main() -> Result<()> {
    let cli = Cli::parse();
    execute(cli, &ProcessRunner)
}

/// Executes parsed CLI arguments.
fn execute(cli: Cli, runner: &dyn CommandRunner) -> Result<()> {
    match cli.command {
        Commands::Init(args) => init(args, runner),
        Commands::Contribute(args) => contribute(args, runner),
        Commands::Finalize(args) => finalize(args, runner),
    }
}

/// Runs setup initialization for the selected circuit.
fn init(args: CeremonyArgs, runner: &dyn CommandRunner) -> Result<()> {
    assert_readable_file(&args.ptau, "ptau")?;
    assert_output_allowed(&args.output, args.force)?;

    let circuit = resolve_circuits(&args.circuits)?;

    let cmd = vec![
        OsString::from("groth16"),
        OsString::from("setup"),
        circuit.as_os_str().to_owned(),
        args.ptau.as_os_str().to_owned(),
        args.output.as_os_str().to_owned(),
    ];
    runner.run("snarkjs", &cmd)?;
    print_file_size(&args.output)?;

    let verify_cmd = vec![
        OsString::from("zkey"),
        OsString::from("verify"),
        circuit.as_os_str().to_owned(),
        args.ptau.as_os_str().to_owned(),
        args.output.as_os_str().to_owned(),
    ];
    runner.run("snarkjs", &verify_cmd)?;

    print_next_steps(
        &args.output,
        &["Share the new .zkey with the first contributor to begin the ceremony."],
    );

    Ok(())
}

/// Runs contribution and immediate verification.
fn contribute(args: ContributeArgs, runner: &dyn CommandRunner) -> Result<()> {
    assert_readable_file(&args.zkey, "input zkey")?;
    assert_readable_file(&args.ptau, "ptau")?;
    let circuit = resolve_circuits(&args.circuits)?;

    let preverify_cmd = vec![
        OsString::from("zkey"),
        OsString::from("verify"),
        circuit.as_os_str().to_owned(),
        args.ptau.as_os_str().to_owned(),
        args.zkey.as_os_str().to_owned(),
    ];
    runner.run("snarkjs", &preverify_cmd)?;

    assert_output_allowed(&args.output, args.force)?;

    let entropy = generate_entropy_hex()?;
    let entropy_flag = Zeroizing::new(format!("-e={}", entropy.as_str()));

    let contribute_cmd = vec![
        OsString::from("zkey"),
        OsString::from("contribute"),
        args.zkey.as_os_str().to_owned(),
        args.output.as_os_str().to_owned(),
        OsString::from(format!("--name={}", args.name)),
        OsString::from("-v"),
        OsString::from(entropy_flag.as_str()),
    ];

    runner.run("snarkjs", &contribute_cmd)?;
    print_file_size(&args.output)?;
    drop(entropy_flag);
    drop(entropy);

    let verify_cmd = vec![
        OsString::from("zkey"),
        OsString::from("verify"),
        circuit.as_os_str().to_owned(),
        args.ptau.as_os_str().to_owned(),
        args.output.as_os_str().to_owned(),
    ];
    runner.run("snarkjs", &verify_cmd)?;

    print_next_steps(
        &args.output,
        &[
            "Send only the contributed .zkey to the ceremony coordinator.",
            "Entropy is generated automatically with OS CSPRNG and never printed.",
        ],
    );

    Ok(())
}

/// Finalizes ceremony artifacts in one compact command.
fn finalize(args: FinalizeArgs, runner: &dyn CommandRunner) -> Result<()> {
    assert_readable_file(&args.zkey, "input zkey")?;
    assert_dir_exists(&args.out_dir)?;

    let final_zkey = args.out_dir.join(format!("{}_final.zkey", args.basename));
    let vkey_json = args
        .out_dir
        .join(format!("{}_verification_key.json", args.basename));
    assert_output_allowed(&final_zkey, args.force)?;
    assert_output_allowed(&vkey_json, args.force)?;

    validate_beacon_hash(&args.beacon_hash)?;

    let beacon_cmd = vec![
        OsString::from("zkey"),
        OsString::from("beacon"),
        args.zkey.as_os_str().to_owned(),
        final_zkey.as_os_str().to_owned(),
        OsString::from(args.beacon_hash.clone()),
        OsString::from(args.beacon_power.to_string()),
        OsString::from("-n=Final Beacon phase2"),
    ];
    runner.run("snarkjs", &beacon_cmd)?;
    print_file_size(&final_zkey)?;

    let export_vkey_cmd = vec![
        OsString::from("zkey"),
        OsString::from("export"),
        OsString::from("verificationkey"),
        final_zkey.as_os_str().to_owned(),
        vkey_json.as_os_str().to_owned(),
    ];
    runner.run("snarkjs", &export_vkey_cmd)?;

    print_next_steps(
        &final_zkey,
        &[
            "Publish the final zkey and verification key for public audit.",
            "Record beacon parameters (hash + power) in your ceremony transcript.",
        ],
    );

    Ok(())
}

/// human-readable file size
fn print_file_size(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;
    let bytes = metadata.len();
    let human = format_bytes_human(bytes);
    println!("[info] {}: {human}", path.display());
    Ok(())
}

/// Format byte count
#[allow(clippy::cast_precision_loss)]
fn format_bytes_human(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Formats a command for terminal-safe logging.
fn format_command(program: &str, args: &[OsString]) -> String {
    format_command_with_redactions(program, args, &["-e", "--entropy"])
}

/// Formats a command while redacting values that follow sensitive flags.
fn format_command_with_redactions(
    program: &str,
    args: &[OsString],
    sensitive_flags: &[&str],
) -> String {
    let mut redacted_next = false;
    let mut rendered = Vec::with_capacity(args.len());

    for arg in args {
        if redacted_next {
            rendered.push(String::from("[REDACTED]"));
            redacted_next = false;
            continue;
        }

        let plain = arg.to_string_lossy();
        let plain_owned = plain.into_owned();

        // Handle flag=value format (e.g. -e=secret)
        if let Some(flag) = sensitive_flags
            .iter()
            .find(|f| plain_owned.starts_with(&format!("{f}=")))
        {
            rendered.push(format!("{flag}=[REDACTED]"));
            continue;
        }

        // Handle flag followed by separate value (e.g. -e secret)
        if sensitive_flags.iter().any(|flag| *flag == plain_owned) {
            rendered.push(plain_owned);
            redacted_next = true;
            continue;
        }

        rendered.push(
            shlex::try_quote(&plain_owned).map_or_else(|_| plain_owned.clone(), |q| q.into_owned()),
        );
    }

    format!("{program} {}", rendered.join(" "))
}

/// Resolves a circuit path into the `.r1cs` path expected by snarkjs.
///
/// If the input points to a `.circom` file, this function maps it to the
/// sibling `.r1cs` file with the same basename.
fn resolve_snarkjs_circuit_path(path: &Path) -> Result<PathBuf> {
    assert_readable_file(path, "circuit")?;

    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("circom"))
    {
        let r1cs_path = path.with_extension("r1cs");
        assert_readable_file(&r1cs_path, "compiled circuit (.r1cs)")?;
        return Ok(r1cs_path);
    }

    Ok(path.to_path_buf())
}

/// Default name of the compiled circuit as produced and verified by `cargo
/// build -p circuits --release`.
const DEFAULT_R1CS_NAME: &str = "policy_tx_2_2.r1cs";

/// Resolves the `--circuit` argument. If the user supplied an explicit path it
/// is validated and returned. Otherwise we auto-discover the compiled `.r1cs`
/// from the Cargo build output.
fn resolve_circuits(explicit: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return resolve_snarkjs_circuit_path(path);
    }

    let discovered = discover_r1cs(DEFAULT_R1CS_NAME)?;
    println!("[info] auto-discovered circuit: {}", discovered.display());
    Ok(discovered)
}

/// Searches `target/*/build/circuits-*/out/circuits/` for a compiled `.r1cs`
/// file and returns the best match (release profile preferred, then newest).
fn discover_r1cs(name: &str) -> Result<PathBuf> {
    // Walk up from CWD to find the workspace root (contains Cargo.lock).
    let mut root = std::env::current_dir().context("failed to determine current directory")?;
    loop {
        if root.join("Cargo.lock").is_file() {
            break;
        }
        if !root.pop() {
            bail!(
                "could not find workspace root \
                 (no Cargo.lock in any parent directory)"
            );
        }
    }

    let pattern = root.join(format!("target/*/build/circuits-*/out/circuits/{name}"));
    let pattern_str = pattern.to_string_lossy();
    let mut candidates: Vec<PathBuf> = glob::glob(&pattern_str)
        .with_context(|| format!("invalid glob pattern: {pattern_str}"))?
        .filter_map(|entry| entry.ok())
        .filter(|p| p.is_file())
        .collect();

    if candidates.is_empty() {
        bail!(
            "no compiled circuit `{name}` found.\n\
             Run `cargo build -p circuits --release` first, or pass --circuits <path> explicitly."
        );
    }

    // Prefer release profile, then most recently modified.
    candidates.sort_by(|a, b| {
        let is_release = |p: &Path| p.components().any(|c| c.as_os_str() == "release");
        let mtime = |p: &Path| {
            p.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        };
        match (is_release(a), is_release(b)) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => mtime(b).cmp(&mtime(a)),
        }
    });

    candidates
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("unexpected empty candidate list"))
}

/// Generates contribution entropy with OS CSPRNG and returns hex-encoded
/// material wrapped in zeroizing storage.
fn generate_entropy_hex() -> Result<Zeroizing<String>> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| anyhow!("failed to obtain CSPRNG entropy from OS: {error}"))?;

    let mut entropy = String::with_capacity(
        bytes
            .len()
            .checked_mul(2)
            .ok_or_else(|| anyhow!("failed to get the capacity of the entropy buffer"))?,
    );
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut entropy, "{byte:02x}").context("failed to encode generated entropy")?;
    }

    bytes.zeroize();
    Ok(Zeroizing::new(entropy))
}

/// Checks that a file exists and is not a directory.
fn assert_readable_file(path: &Path, label: &str) -> Result<()> {
    if !path.exists() {
        return Err(anyhow!("{label} path does not exist: {}", path.display()));
    }
    if !path.is_file() {
        return Err(anyhow!("{label} path is not a file: {}", path.display()));
    }
    Ok(())
}

/// Checks that a directory exists.
fn assert_dir_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(anyhow!("directory does not exist: {}", path.display()));
    }
    if !path.is_dir() {
        return Err(anyhow!("path is not a directory: {}", path.display()));
    }
    Ok(())
}

/// Prevents accidental overwrite unless explicitly requested.
fn assert_output_allowed(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "refusing to overwrite existing output `{}`; pass --force to allow",
            path.display()
        ));
    }
    Ok(())
}

/// Basic validation for beacon hash input.
fn validate_beacon_hash(value: &str) -> Result<()> {
    let is_hex = value.chars().all(|c| c.is_ascii_hexdigit());
    if !is_hex || value.len() < 32 {
        return Err(anyhow!(
            "invalid beacon hash. expected hex string of length >= 32, got `{value}`"
        ));
    }
    Ok(())
}

/// Prints contributor guidance after a ceremony step.
fn print_next_steps(zkey_path: &Path, actions: &[&str]) {
    println!("\n=== Ceremony step complete ===");
    println!("Produced zkey artifact: {}", zkey_path.display());
    println!("Next actions:");
    for action in actions {
        println!("  - {action}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Clone, Default)]
    struct MockRunner {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[OsString]) -> Result<()> {
            let entry = format_command(program, args);
            self.calls
                .lock()
                .map_err(|_| anyhow!("failed to lock mock runner"))?
                .push(entry);

            if args.get(1).is_some_and(|v| v == "setup") {
                touch(&PathBuf::from(args[4].clone()))?;
            }
            if args.get(1).is_some_and(|v| v == "contribute") {
                touch(&PathBuf::from(args[3].clone()))?;
            }
            if args.get(1).is_some_and(|v| v == "beacon") {
                touch(&PathBuf::from(args[3].clone()))?;
            }
            if args.get(2).is_some_and(|v| v == "verificationkey") {
                touch(&PathBuf::from(args[4].clone()))?;
            }

            Ok(())
        }
    }

    #[test]
    fn ceremony_e2e_flow() -> Result<()> {
        let temp = temp_dir()?;
        let circuit = temp.join("circuit.r1cs");
        let ptau = temp.join("powers.ptau");
        let zkey0 = temp.join("init.zkey");
        let zkey1 = temp.join("contrib.zkey");
        let out_dir = temp.join("out");
        fs::create_dir_all(&out_dir)?;
        fs::write(&circuit, "circuit")?;
        fs::write(&ptau, "ptau")?;

        let runner = MockRunner::default();

        execute(
            Cli {
                command: Commands::Init(CeremonyArgs {
                    circuits: Some(circuit.clone()),
                    ptau: ptau.clone(),
                    output: zkey0.clone(),
                    force: false,
                }),
            },
            &runner,
        )?;

        execute(
            Cli {
                command: Commands::Contribute(ContributeArgs {
                    zkey: zkey0.clone(),
                    circuits: Some(circuit.clone()),
                    ptau: ptau.clone(),
                    output: zkey1.clone(),
                    name: String::from("alice"),
                    force: false,
                }),
            },
            &runner,
        )?;

        execute(
            Cli {
                command: Commands::Finalize(FinalizeArgs {
                    zkey: zkey1.clone(),
                    beacon_hash: String::from("0123456789abcdef0123456789abcdef"),
                    beacon_power: 10,
                    out_dir: out_dir.clone(),
                    basename: String::from("demo"),
                    force: false,
                }),
            },
            &runner,
        )?;

        let calls = runner
            .calls
            .lock()
            .map_err(|_| anyhow!("failed to lock mock calls"))?
            .clone();

        assert!(calls.iter().any(|line| line.contains("groth16 setup")));
        assert!(calls.iter().any(|line| line.contains("zkey contribute")));
        assert!(calls.iter().any(|line| line.contains("-e=[REDACTED]")));
        assert!(
            calls
                .iter()
                .any(|line| line.contains("zkey verify") && line.contains("init.zkey"))
        );

        assert!(zkey0.exists());
        assert!(zkey1.exists());
        assert!(out_dir.join("demo_final.zkey").exists());
        assert!(out_dir.join("demo_verification_key.json").exists());

        fs::remove_dir_all(&temp)?;
        Ok(())
    }

    fn temp_dir() -> Result<PathBuf> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("clock before unix epoch")?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ceremony-cli-{nanos}"));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn touch(path: &Path) -> Result<()> {
        // fs::write(path, "")?;
        fs::write(path, "mock-zkey-content")?;
        Ok(())
    }
}
