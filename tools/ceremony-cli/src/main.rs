//! CLI tool that wraps `snarkjs` for a Groth16 BN254 trusted setup ceremony.

use anyhow::{Context, Result, anyhow, bail};
use blake2::{Blake2b512, Digest as _};
use clap::{ArgAction, Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs,
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
    /// Convert a final snarkjs zkey into repo deployment key formats.
    ExportDeployment(ExportDeploymentArgs),
}

/// Circuit and Powers of Tau a zkey is built from and verified against.
#[derive(Clone, Debug, clap::Args)]
struct SetupArgs {
    /// Path to the `.r1cs` file. If omitted, auto-discovers the compiled
    /// `policy_tx_2_2_AB.r1cs` from the Cargo build output directory.
    #[arg(short = 'c', long = "circuit")]
    circuits: Option<PathBuf>,
    /// Powers of Tau file.
    #[arg(short = 'p', long = "ptau")]
    ptau: PathBuf,
    /// Circuit lock holding the expected `.r1cs` hashes. If omitted, uses
    /// `deployments/testnet/circuits.json` from the workspace root.
    #[arg(long = "circuits-lock")]
    circuits_lock: Option<PathBuf>,
    /// Accept a ptau that is not one of the Hermez Phase-1 files, e.g. for a
    /// test ceremony.
    #[arg(long = "allow-unpinned-ptau", action = ArgAction::SetTrue)]
    allow_unpinned_ptau: bool,
}

impl SetupArgs {
    /// Checks the ptau file is pinned, resolves the circuit path and checks
    /// the circuit against the lock.
    fn resolve(&self) -> Result<PathBuf> {
        assert_readable_file(&self.ptau, "ptau")?;
        if self.allow_unpinned_ptau {
            println!("[warn] ptau hash not checked; use this only for test ceremonies");
        } else {
            assert_ptau_pinned(&self.ptau)?;
        }
        let circuit = resolve_circuits(&self.circuits)?;
        let lock = match &self.circuits_lock {
            Some(path) => path.clone(),
            None => workspace_root()
                .context("pass --circuits-lock explicitly")?
                .join(DEFAULT_CIRCUITS_LOCK),
        };
        assert_circuit_locked(&circuit, &lock)?;
        Ok(circuit)
    }
}

/// Shared init arguments.
#[derive(Debug, clap::Args)]
struct CeremonyArgs {
    #[command(flatten)]
    setup: SetupArgs,
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
    #[command(flatten)]
    setup: SetupArgs,
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
    #[command(flatten)]
    setup: SetupArgs,
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

/// Export deployment key artifacts from a final ceremony `.zkey`.
#[derive(Debug, clap::Args)]
struct ExportDeploymentArgs {
    /// Final ceremony zkey.
    #[arg(short = 'z', long = "zkey")]
    zkey: PathBuf,
    #[command(flatten)]
    setup: SetupArgs,
    /// Output directory for generated files.
    #[arg(short = 'o', long = "out-dir")]
    out_dir: PathBuf,
    /// Basename used for output files.
    #[arg(long = "basename", default_value = "policy_tx_2_2_AB")]
    basename: String,
    /// Overwrite existing outputs.
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
        Commands::ExportDeployment(args) => export_deployment(args, runner),
    }
}

/// Runs setup initialization for the selected circuit.
fn init(args: CeremonyArgs, runner: &dyn CommandRunner) -> Result<()> {
    let circuit = args.setup.resolve()?;
    assert_output_allowed(&args.output, args.force)?;

    produce_verified(runner, &circuit, &args.setup.ptau, &args.output, |zkey| {
        let cmd = vec![
            OsString::from("groth16"),
            OsString::from("setup"),
            circuit.as_os_str().to_owned(),
            args.setup.ptau.as_os_str().to_owned(),
            zkey.as_os_str().to_owned(),
        ];
        runner.run("snarkjs", &cmd)
    })?;

    print_next_steps(
        &args.output,
        &["Share the new .zkey with the first contributor to begin the ceremony."],
    );

    Ok(())
}

/// Runs contribution and immediate verification.
fn contribute(args: ContributeArgs, runner: &dyn CommandRunner) -> Result<()> {
    assert_readable_file(&args.zkey, "input zkey")?;
    let circuit = args.setup.resolve()?;
    assert_output_allowed(&args.output, args.force)?;

    verify_zkey(runner, &circuit, &args.setup.ptau, &args.zkey)?;

    produce_verified(runner, &circuit, &args.setup.ptau, &args.output, |zkey| {
        let entropy = generate_entropy_hex()?;
        let entropy_flag = Zeroizing::new(format!("-e={}", entropy.as_str()));
        let cmd = vec![
            OsString::from("zkey"),
            OsString::from("contribute"),
            args.zkey.as_os_str().to_owned(),
            zkey.as_os_str().to_owned(),
            OsString::from(format!("--name={}", args.name)),
            OsString::from("-v"),
            OsString::from(entropy_flag.as_str()),
        ];
        runner.run("snarkjs", &cmd)
    })?;

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
    let circuit = args.setup.resolve()?;

    let final_zkey = args.out_dir.join(format!("{}_final.zkey", args.basename));
    let vkey_json = args
        .out_dir
        .join(format!("{}_verification_key.json", args.basename));
    assert_output_allowed(&final_zkey, args.force)?;
    assert_output_allowed(&vkey_json, args.force)?;

    validate_beacon_hash(&args.beacon_hash)?;

    produce_verified(runner, &circuit, &args.setup.ptau, &final_zkey, |zkey| {
        let cmd = vec![
            OsString::from("zkey"),
            OsString::from("beacon"),
            args.zkey.as_os_str().to_owned(),
            zkey.as_os_str().to_owned(),
            OsString::from(args.beacon_hash.clone()),
            OsString::from(args.beacon_power.to_string()),
            OsString::from("-n=Final Beacon phase2"),
        ];
        runner.run("snarkjs", &cmd)
    })?;

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

/// Converts a final snarkjs zkey into the deployment artifacts used by this
/// repo.
fn export_deployment(args: ExportDeploymentArgs, runner: &dyn CommandRunner) -> Result<()> {
    export_deployment::export_deployment(args, runner)
}

/// Verifies a zkey against its circuit and Powers of Tau with
/// `snarkjs zkey verify`.
fn verify_zkey(runner: &dyn CommandRunner, circuit: &Path, ptau: &Path, zkey: &Path) -> Result<()> {
    let cmd = vec![
        OsString::from("zkey"),
        OsString::from("verify"),
        circuit.as_os_str().to_owned(),
        ptau.as_os_str().to_owned(),
        zkey.as_os_str().to_owned(),
    ];
    runner.run("snarkjs", &cmd)
}

/// Runs `produce` to write a zkey next to `output` under a temporary name,
/// verifies it, and only then moves it to `output`. On failure the temporary
/// file is removed, so an unverified zkey never sits at `output`.
fn produce_verified(
    runner: &dyn CommandRunner,
    circuit: &Path,
    ptau: &Path,
    output: &Path,
    produce: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let unverified = output.with_extension("unverified.zkey");
    let result = produce(&unverified)
        .and_then(|()| print_file_size(&unverified))
        .and_then(|()| verify_zkey(runner, circuit, ptau, &unverified))
        .and_then(|()| {
            fs::rename(&unverified, output)
                .with_context(|| format!("failed to move zkey to {}", output.display()))
        });
    if result.is_err() {
        fs::remove_file(&unverified).ok();
    }
    result
}

/// human-readable file size
fn print_file_size(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
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

/// Default name of the compiled circuit produced by `make circuits`.
const DEFAULT_R1CS_NAME: &str = "policy_tx_2_2_AB.r1cs";

/// Circuit lock used when `--circuits-lock` is omitted, relative to the
/// workspace root.
const DEFAULT_CIRCUITS_LOCK: &str = "deployments/testnet/circuits.json";

/// Resolves the `--circuit` argument. If the user supplied an explicit path it
/// is validated and returned. Otherwise we auto-discover the compiled `.r1cs`
/// from `target/circuits-artifacts/`.
fn resolve_circuits(explicit: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return resolve_snarkjs_circuit_path(path);
    }

    let discovered = discover_r1cs(DEFAULT_R1CS_NAME)?;
    println!("[info] auto-discovered circuit: {}", discovered.display());
    Ok(discovered)
}

/// Walks up from the current directory to the workspace root, the first
/// directory holding a `Cargo.lock`.
fn workspace_root() -> Result<PathBuf> {
    let mut root = std::env::current_dir().context("failed to determine current directory")?;
    loop {
        if root.join("Cargo.lock").is_file() {
            return Ok(root);
        }
        if !root.pop() {
            bail!(
                "could not find workspace root \
                 (no Cargo.lock in any parent directory)"
            );
        }
    }
}

/// Searches `target/circuits-artifacts/` for a compiled `.r1cs` file.
fn discover_r1cs(name: &str) -> Result<PathBuf> {
    let path = workspace_root()?
        .join("target/circuits-artifacts")
        .join(name);
    if path.is_file() {
        return Ok(path);
    }

    bail!(
        "no compiled circuit `{name}` found.\n\
         Run `make circuits` first, or pass --circuit <path> explicitly."
    )
}

/// blake2b-512 hashes of the Hermez `powersOfTau28_hez_final_<power>.ptau`
/// files, as published in the snarkjs README.
const HERMEZ_PTAU_BLAKE2B: [(u8, &str); 21] = [
    (
        8,
        "d6a8fb3a04feb600096c3b791f936a578c4e664d262e4aa24beed1b7a9a96aa5eb72864d628db247e9293384b74b36ffb52ca8d148d6e1b8b51e279fdf57b583",
    ),
    (
        9,
        "94f108a80e81b5d932d8e8c9e8fd7f46cf32457e31462deeeef37af1b71c2c1b3c71fb0d9b59c654ec266b042735f50311f9fd1d4cadce47ab234ad163157cb5",
    ),
    (
        10,
        "6cfeb8cda92453099d20120bdd0e8a5c4e7706c2da9a8f09ccc157ed2464d921fd0437fb70db42104769efd7d6f3c1f964bcf448c455eab6f6c7d863e88a5849",
    ),
    (
        11,
        "47c282116b892e5ac92ca238578006e31a47e7c7e70f0baa8b687f0a5203e28ea07bbbec765a98dcd654bad618475d4661bfaec3bd9ad2ed12e7abc251d94d33",
    ),
    (
        12,
        "ded2694169b7b08e898f736d5de95af87c3f1a64594013351b1a796dbee393bd825f88f9468c84505ddd11eb0b1465ac9b43b9064aa8ec97f2b73e04758b8a4a",
    ),
    (
        13,
        "58efc8bf2834d04768a3d7ffcd8e1e23d461561729beaac4e3e7a47829a1c9066d5320241e124a1a8e8aa6c75be0ba66f65bc8239a0542ed38e11276f6fdb4d9",
    ),
    (
        14,
        "eeefbcf7c3803b523c94112023c7ff89558f9b8e0cf5d6cdcba3ade60f168af4a181c9c21774b94fbae6c90411995f7d854d02ebd93fb66043dbb06f17a831c1",
    ),
    (
        15,
        "982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a17b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e",
    ),
    (
        16,
        "6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf43eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125",
    ),
    (
        17,
        "6247a3433948b35fbfae414fa5a9355bfb45f56efa7ab4929e669264a0258976741dfbe3288bfb49828e5df02c2e633df38d2245e30162ae7e3bcca5b8b49345",
    ),
    (
        18,
        "7e6a9c2e5f05179ddfc923f38f917c9e6831d16922a902b0b4758b8e79c2ab8a81bb5f29952e16ee6c5067ed044d7857b5de120a90704c1d3b637fd94b95b13e",
    ),
    (
        19,
        "bca9d8b04242f175189872c42ceaa21e2951e0f0f272a0cc54fc37193ff6648600eaf1c555c70cdedfaf9fb74927de7aa1d33dc1e2a7f1a50619484989da0887",
    ),
    (
        20,
        "89a66eb5590a1c94e3f1ee0e72acf49b1669e050bb5f93c73b066b564dca4e0c7556a52b323178269d64af325d8fdddb33da3a27c34409b821de82aa2bf1a27b",
    ),
    (
        21,
        "9aef0573cef4ded9c4a75f148709056bf989f80dad96876aadeb6f1c6d062391f07a394a9e756d16f7eb233198d5b69407cca44594c763ab4a5b67ae73254678",
    ),
    (
        22,
        "0d64f63dba1a6f11139df765cb690da69d9b2f469a1ddd0de5e4aa628abb28f787f04c6a5fb84a235ec5ea7f41d0548746653ecab0559add658a83502d1cb21b",
    ),
    (
        23,
        "3063a0bd81d68711197c8820a92466d51aeac93e915f5136d74f63c394ee6d88c5e8016231ea6580bec02e25d491f319d92e77f5c7f46a9caa8f3b53c0ea544f",
    ),
    (
        24,
        "fa404d140d5819d39984833ca5ec3632cd4995f81e82db402371a4de7c2eae8687c62bc632a95b0c6aadba3fb02680a94e09174b7233ccd26d78baca2647c733",
    ),
    (
        25,
        "0377d860cdb09a8a31ea1b0b8c04335614c8206357181573bf294c25d5ca7dff72387224fbd868897e6769f7805b3dab02854aec6d69d7492883b5e4e5f35eeb",
    ),
    (
        26,
        "418dee4a74b9592198bd8fd02ad1aea76f9cf3085f206dfd7d594c9e264ae919611b1459a1cc920c2f143417744ba9edd7b8d51e44be9452344a225ff7eead19",
    ),
    (
        27,
        "10ffd99837c512ef99752436a54b9810d1ac8878d368fb4b806267bdd664b4abf276c9cd3c4b9039a1fa4315a0c326c0e8e9e8fe0eb588ffd4f9021bf7eae1a1",
    ),
    (
        28,
        "55c77ce8562366c91e7cda394cf7b7c15a06c12d8c905e8b36ba9cf5e13eb37d1a429c589e8eaba4c591bc4b88a0e2828745a53e170eac300236f5c1a326f41a",
    ),
];

/// Checks that the ptau is one of the Hermez Phase-1 files.
fn assert_ptau_pinned(ptau: &Path) -> Result<()> {
    let mut file =
        fs::File::open(ptau).with_context(|| format!("failed to open ptau {}", ptau.display()))?;
    let mut hasher = Blake2b512::new();
    std::io::copy(&mut file, &mut hasher)
        .with_context(|| format!("failed to read ptau {}", ptau.display()))?;
    let hash = hex::encode(hasher.finalize());

    let (power, _) = HERMEZ_PTAU_BLAKE2B
        .iter()
        .find(|(_, pinned)| *pinned == hash)
        .ok_or_else(|| {
            anyhow!(
                "ptau {} is not a Hermez Phase-1 file (blake2b {hash}); \
                 pass --allow-unpinned-ptau to use it anyway",
                ptau.display()
            )
        })?;
    println!("[info] ptau is Hermez powersOfTau28 power {power}");
    Ok(())
}

/// Checks that the `.r1cs` sha256 matches the hash the lock records for its
/// file stem.
fn assert_circuit_locked(r1cs: &Path, lock: &Path) -> Result<()> {
    let json = fs::read_to_string(lock)
        .with_context(|| format!("failed to read circuit lock {}", lock.display()))?;
    let entries: serde_json::Value = serde_json::from_str(&json)
        .with_context(|| format!("failed to parse circuit lock {}", lock.display()))?;
    let stem = r1cs
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("invalid circuit file name: {}", r1cs.display()))?;
    let want = entries[stem]["r1cs"].as_str().ok_or_else(|| {
        anyhow!(
            "circuit lock {} has no r1cs hash for `{stem}`",
            lock.display()
        )
    })?;

    let bytes =
        fs::read(r1cs).with_context(|| format!("failed to read circuit {}", r1cs.display()))?;
    let got = hex::encode(Sha256::digest(&bytes));
    if got != want {
        bail!(
            "circuit {} does not match {}: expected sha256 {want}, got {got}",
            r1cs.display(),
            lock.display()
        );
    }
    Ok(())
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

mod export_deployment;
mod zkey;

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
    };

    #[derive(Clone, Default)]
    struct MockRunner {
        calls: Arc<Mutex<Vec<String>>>,
        fail_verify: bool,
    }

    impl MockRunner {
        fn calls(&self) -> Result<Vec<String>> {
            Ok(self
                .calls
                .lock()
                .map_err(|_| anyhow!("failed to lock mock calls"))?
                .clone())
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[OsString]) -> Result<()> {
            let entry = format_command(program, args);
            self.calls
                .lock()
                .map_err(|_| anyhow!("failed to lock mock runner"))?
                .push(entry);

            if self.fail_verify && args.get(1).is_some_and(|v| v == "verify") {
                bail!("mock zkey verify failure");
            }

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

    /// Creates placeholder circuit and ptau files, a circuit lock pinning the
    /// circuit, and an empty output dir.
    fn setup_files(temp: &Path) -> Result<(SetupArgs, PathBuf)> {
        let circuit = temp.join("circuit.r1cs");
        let ptau = temp.join("powers.ptau");
        let lock = temp.join("circuits.json");
        let out_dir = temp.join("out");
        fs::create_dir_all(&out_dir)?;
        fs::write(&circuit, "circuit")?;
        fs::write(&ptau, "ptau")?;
        let hash = hex::encode(Sha256::digest("circuit"));
        fs::write(&lock, format!(r#"{{"circuit": {{"r1cs": "{hash}"}}}}"#))?;
        let setup = SetupArgs {
            circuits: Some(circuit),
            ptau,
            circuits_lock: Some(lock),
            allow_unpinned_ptau: true,
        };
        Ok((setup, out_dir))
    }

    /// Runs `init` and returns its result and the runner calls.
    fn run_init(setup: SetupArgs, output: PathBuf) -> Result<(Result<()>, Vec<String>)> {
        let runner = MockRunner::default();
        let result = execute(
            Cli {
                command: Commands::Init(CeremonyArgs {
                    setup,
                    output,
                    force: false,
                }),
            },
            &runner,
        );
        Ok((result, runner.calls()?))
    }

    #[test]
    fn rejects_circuit_not_matching_lock() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (setup, _) = setup_files(temp.path())?;
        let circuit = setup
            .circuits
            .clone()
            .ok_or_else(|| anyhow!("no circuit"))?;
        fs::write(&circuit, "modified circuit")?;

        let (result, calls) = run_init(setup, temp.path().join("init.zkey"))?;

        let err = result.err().ok_or_else(|| anyhow!("expected lock error"))?;
        assert!(err.to_string().contains("does not match"));
        assert!(calls.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_unpinned_ptau() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (setup, _) = setup_files(temp.path())?;
        let setup = SetupArgs {
            allow_unpinned_ptau: false,
            ..setup
        };

        let (result, calls) = run_init(setup, temp.path().join("init.zkey"))?;

        let err = result.err().ok_or_else(|| anyhow!("expected ptau error"))?;
        assert!(err.to_string().contains("not a Hermez Phase-1 file"));
        assert!(calls.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_circuit_missing_from_lock() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (setup, _) = setup_files(temp.path())?;
        let other = temp.path().join("other.r1cs");
        fs::write(&other, "circuit")?;
        let setup = SetupArgs {
            circuits: Some(other),
            ..setup
        };

        let (result, calls) = run_init(setup, temp.path().join("init.zkey"))?;

        let err = result.err().ok_or_else(|| anyhow!("expected lock error"))?;
        assert!(err.to_string().contains("no r1cs hash for `other`"));
        assert!(calls.is_empty());
        Ok(())
    }

    #[test]
    fn ceremony_e2e_flow() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let temp = temp.path();
        let (setup, out_dir) = setup_files(temp)?;
        let zkey0 = temp.join("init.zkey");
        let zkey1 = temp.join("contrib.zkey");

        let runner = MockRunner::default();

        execute(
            Cli {
                command: Commands::Init(CeremonyArgs {
                    setup: setup.clone(),
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
                    setup: setup.clone(),
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
                    setup,
                    beacon_hash: String::from("0123456789abcdef0123456789abcdef"),
                    beacon_power: 10,
                    out_dir: out_dir.clone(),
                    basename: String::from("demo"),
                    force: false,
                }),
            },
            &runner,
        )?;

        let calls = runner.calls()?;

        assert!(calls.iter().any(|line| line.contains("groth16 setup")));
        assert!(calls.iter().any(|line| line.contains("zkey contribute")));
        assert!(calls.iter().any(|line| line.contains("-e=[REDACTED]")));
        assert!(
            calls
                .iter()
                .any(|line| line.contains("zkey verify") && line.contains("init.zkey"))
        );
        assert!(calls.iter().any(
            |line| line.contains("zkey verify") && line.contains("demo_final.unverified.zkey")
        ));

        assert!(zkey0.exists());
        assert!(zkey1.exists());
        assert!(out_dir.join("demo_final.zkey").exists());
        assert!(out_dir.join("demo_verification_key.json").exists());
        Ok(())
    }

    #[test]
    fn failed_verify_leaves_no_zkey() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (setup, _) = setup_files(temp.path())?;
        let output = temp.path().join("init.zkey");
        let runner = MockRunner {
            fail_verify: true,
            ..MockRunner::default()
        };

        let result = execute(
            Cli {
                command: Commands::Init(CeremonyArgs {
                    setup,
                    output: output.clone(),
                    force: false,
                }),
            },
            &runner,
        );

        assert!(result.is_err());
        assert!(!output.exists());
        assert!(!temp.path().join("init.unverified.zkey").exists());
        Ok(())
    }

    /// Runs `export-deployment` on a zkey with the given contents and returns
    /// the result, the runner calls, and the number of files written.
    fn run_export(
        zkey_bytes: &[u8],
        runner: &MockRunner,
    ) -> Result<(Result<()>, Vec<String>, usize)> {
        let temp = tempfile::tempdir()?;
        let (setup, out_dir) = setup_files(temp.path())?;
        let zkey = temp.path().join("final.zkey");
        fs::write(&zkey, zkey_bytes)?;

        let result = execute(
            Cli {
                command: Commands::ExportDeployment(ExportDeploymentArgs {
                    zkey,
                    setup,
                    out_dir: out_dir.clone(),
                    basename: String::from("demo"),
                    force: false,
                }),
            },
            runner,
        );
        let written = fs::read_dir(&out_dir)?.count();
        Ok((result, runner.calls()?, written))
    }

    #[test]
    fn export_deployment_writes_verified_zkey() -> Result<()> {
        let (result, calls, written) =
            run_export(&zkey::tests::valid_zkey(), &MockRunner::default())?;

        result?;
        assert!(calls.iter().any(|line| line.contains("zkey verify")));
        assert_eq!(written, 4);
        Ok(())
    }

    #[test]
    fn export_deployment_requires_verified_zkey() -> Result<()> {
        let runner = MockRunner {
            fail_verify: true,
            ..MockRunner::default()
        };
        let (result, calls, written) = run_export(&zkey::tests::valid_zkey(), &runner)?;

        let err = result
            .err()
            .ok_or_else(|| anyhow!("expected verify error"))?;
        assert!(err.to_string().contains("mock zkey verify failure"));
        assert!(calls.iter().any(|line| line.contains("zkey verify")));
        assert_eq!(written, 0);
        Ok(())
    }

    #[test]
    fn export_deployment_rejects_malformed_zkey() -> Result<()> {
        let (result, calls, written) = run_export(b"mock-zkey-content", &MockRunner::default())?;

        let err = result
            .err()
            .ok_or_else(|| anyhow!("expected parse error"))?;
        assert!(err.to_string().contains("failed to parse snarkjs zkey"));
        assert!(calls.is_empty());
        assert_eq!(written, 0);
        Ok(())
    }

    fn touch(path: &Path) -> Result<()> {
        fs::write(path, "mock-zkey-content")?;
        Ok(())
    }
}
