//! Compiles the Circom circuits and generates their Groth16 key material.
//!
//! Circuit artifacts are central to the safety of the protocol, so they are
//! produced by this dedicated program rather than as a side effect of
//! `cargo build`. Run it through `scripts/build-circuits.sh`.

mod circomlib;
mod compile;
mod discover;
mod keys;
mod manifest;
mod paths;
mod stems;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use manifest::{BuildManifest, FileDigest, KeyEntry, KeyManifest};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Key and graph file suffixes recorded for one stem.
const KEY_SUFFIXES: &[&str] = &[
    "_proving_key.bin",
    "_vk.json",
    "_vk_soroban.bin",
    "_vk_const.rs",
    ".graph.bin",
];

#[derive(Parser)]
#[command(name = "circuit-builder", about, version)]
struct Cli {
    /// The `circuits/` crate directory (default: <workspace root>/circuits).
    #[arg(long, global = true, value_name = "DIR")]
    circuits_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch and pin the circomlib checkout named by circuits/circomlib.lock.
    Vendor,

    /// Apply the circomlib black-box hint patch and leave it in place.
    ///
    /// `compile` patches and restores around itself. Graph regeneration cannot:
    /// `circom-witness-rs` runs the `circom` CLI from its own build script, so
    /// the patch has to be on disk before cargo starts. `make witness-graphs`
    /// brackets its run with this and `patch --undo`.
    Patch {
        /// Restore the pristine files instead of patching.
        #[arg(long)]
        undo: bool,
    },

    /// Compile circuits to r1cs, sym and wasm.
    Compile {
        /// Directory that receives the published artifacts.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,

        /// Also compile the circuits under `src/test/`.
        #[arg(long)]
        include_tests: bool,
    },

    /// Generate Groth16 proving/verifying keys from compiled artifacts.
    Keys {
        /// Directory holding the artifacts written by `compile`.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,

        /// Directory that receives the key files.
        #[arg(long, value_name = "DIR")]
        keys_dir: PathBuf,

        /// Regenerate keys that already exist. Requires a verifier redeploy.
        #[arg(long)]
        force: bool,

        /// Restrict the run to these stems (repeatable; default: all keyed
        /// stems).
        #[arg(long = "circuit", value_name = "STEM")]
        circuits: Vec<String>,
    },

    /// Check artifacts, sources and committed key material against the
    /// manifest.
    Verify {
        /// Directory holding the artifacts written by `compile`.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,

        /// Key directory to check against its committed key manifest.
        #[arg(long, value_name = "DIR")]
        keys_dir: Option<PathBuf>,
    },

    /// Record existing key material against the current R1CS.
    ///
    /// Use after a trusted ceremony, or to bootstrap the key manifest for keys
    /// generated before it existed.
    Snapshot {
        /// Directory holding the artifacts written by `compile`.
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,

        /// Directory holding the key files to record.
        #[arg(long, value_name = "DIR")]
        keys_dir: PathBuf,

        /// How the key material was produced, e.g. `ceremony`. Omit to keep
        /// what each stem already claims.
        #[arg(long)]
        provenance: Option<String>,
    },
}

/// Scratch directory for circom's own output layout, inside `out_dir`.
fn work_dir(out_dir: &Path) -> PathBuf {
    out_dir.join(".work")
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let circuits_dir = match cli.circuits_dir {
        Some(dir) => dir,
        None => paths::default_circuits_dir()?,
    };
    let circuits_dir = circuits_dir
        .canonicalize()
        .with_context(|| format!("resolve {}", circuits_dir.display()))?;

    match cli.command {
        Command::Vendor => circomlib::vendor(&circuits_dir),
        Command::Patch { undo } => {
            let circomlib_path = circuits_dir.join("src/circomlib");
            if undo {
                circomlib::restore_pristine(&circomlib_path)?;
                eprintln!("circomlib restored to pristine");
                Ok(())
            } else {
                circomlib::vendor(&circuits_dir)?;
                circomlib::patch(&circomlib_path)?;
                eprintln!("circomlib patched (run `patch --undo` when done)");
                Ok(())
            }
        }
        Command::Compile {
            out_dir,
            include_tests,
        } => run_compile(&circuits_dir, &out_dir, include_tests),
        Command::Keys {
            out_dir,
            keys_dir,
            force,
            circuits,
        } => run_keys(&out_dir, &keys_dir, force, &circuits),
        Command::Verify { out_dir, keys_dir } => {
            run_verify(&circuits_dir, &out_dir, keys_dir.as_deref())
        }
        Command::Snapshot {
            out_dir,
            keys_dir,
            provenance,
        } => run_snapshot(
            &out_dir,
            &keys_dir,
            &stems::requiring_keys(),
            provenance.as_deref(),
        ),
    }
}

fn run_compile(circuits_dir: &Path, out_dir: &Path, include_tests: bool) -> Result<()> {
    let src_dir = circuits_dir.join("src");
    let work = work_dir(out_dir);
    fs::create_dir_all(&work).with_context(|| format!("create {}", work.display()))?;
    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    circomlib::vendor(circuits_dir)?;
    let _guard = circomlib::RestoreGuard::new_and_patch(&src_dir.join("circomlib"))?;

    let toolchain = manifest::Toolchain {
        circom: paths::circom_version(circuits_dir)?,
        circomlib: circomlib_rev(circuits_dir)?,
        prime: compile::CURVE_ID.to_owned(),
    };
    let version = toolchain.circom.clone();

    // The previous manifest is the only staleness record. It holds a digest of
    // every source each stem reaches, plus the toolchain that compiled them,
    // which is strictly more than file times can tell us. File times are also
    // actively wrong here: the circomlib patch rewrites two files on every run,
    // so anything reaching them always looks newer than its artifacts.
    let manifest_path = out_dir.join(manifest::BUILD_MANIFEST);
    let previous = manifest::load::<BuildManifest>(&manifest_path)
        .ok()
        .filter(|p| p.toolchain == toolchain);

    let mut candidates = discover::find_circom_files(&src_dir, !include_tests);
    candidates.sort();
    if candidates.is_empty() {
        bail!("no circom files found under {}", src_dir.display());
    }

    eprintln!(
        "Checking {} circom files with circom {version}...",
        candidates.len()
    );

    let mut circuits = BTreeMap::new();
    for circom_file in &candidates {
        let stem = circom_file
            .file_stem()
            .context("invalid circom filename")?
            .to_string_lossy()
            .to_string();

        let dependencies = discover::extract_dependencies(circom_file, circuits_dir)?;
        let sources = source_digests(circuits_dir, circom_file, &dependencies)?;
        let artifacts = compile::artifact_paths(&work, &stem);

        // A stem the manifest already lists was an entry point last time, and
        // its sources are unchanged, so it still is. Trusting that avoids
        // re-parsing every circuit on a no-op run.
        let cached = artifacts.r1cs.is_file()
            && artifacts.sym.is_file()
            && artifacts.wasm.is_file()
            && previous
                .as_ref()
                .and_then(|p| p.circuits.get(&stem))
                .is_some_and(|entry| entry.sources == sources);

        if cached {
            eprintln!("  {stem}: up to date");
        } else {
            let Some(archive) = compile::parse(circom_file, &version)? else {
                continue; // a template, not a circuit
            };
            eprintln!("  {stem}: compiling...");
            compile::compile(archive, &stem, &work, &version)?;
        }

        publish(&artifacts, out_dir, &stem)?;
        circuits.insert(
            stem.clone(),
            manifest::CircuitEntry {
                r1cs: FileDigest::of(&out_dir.join(format!("{stem}.r1cs")))?,
                wasm: FileDigest::of(&out_dir.join(format!("{stem}.wasm")))?,
                sources,
            },
        );
    }

    // Written last, so an interrupted run never leaves a manifest claiming more
    // than the directory holds.
    let build = BuildManifest {
        schema: manifest::SCHEMA,
        toolchain,
        circuits,
    };
    manifest::save(&manifest_path, &build)?;

    eprintln!("Artifacts written to {}", out_dir.display());
    Ok(())
}

fn circomlib_rev(circuits_dir: &Path) -> Result<String> {
    let path = circuits_dir.join("circomlib.lock");
    Ok(fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?
        .trim()
        .to_owned())
}

/// Hash the entry point and every `.circom` it reaches, keyed by a path
/// relative to `circuits/`. Vendored circomlib is skipped: the builder patches
/// those files in place, so their bytes on disk differ during a build.
fn source_digests(
    circuits_dir: &Path,
    entry: &Path,
    dependencies: &[PathBuf],
) -> Result<BTreeMap<String, String>> {
    let circomlib_dir = circuits_dir.join("src/circomlib");
    let mut sources = BTreeMap::new();

    for path in std::iter::once(entry).chain(dependencies.iter().map(|p| p.as_path())) {
        if path.starts_with(&circomlib_dir) {
            continue;
        }
        let key = path
            .strip_prefix(circuits_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        sources.insert(key, manifest::sha256_file(path)?);
    }

    Ok(sources)
}

/// Copy the r1cs and wasm into the flat published layout consumers read.
fn publish(artifacts: &compile::Artifacts, out_dir: &Path, stem: &str) -> Result<()> {
    paths::copy_atomic(&artifacts.r1cs, &out_dir.join(format!("{stem}.r1cs")))?;
    paths::copy_atomic(&artifacts.wasm, &out_dir.join(format!("{stem}.wasm")))?;
    Ok(())
}

fn run_keys(out_dir: &Path, keys_dir: &Path, force: bool, only: &[String]) -> Result<()> {
    let work = work_dir(out_dir);
    if !work.is_dir() {
        bail!(
            "no compiled artifacts at {} - run `circuit-builder compile` first",
            work.display()
        );
    }

    let all = stems::requiring_keys();
    let targets: Vec<String> = if only.is_empty() {
        all
    } else {
        for want in only {
            if !all.contains(want) {
                bail!("{want:?} does not take part in Groth16 key generation");
            }
        }
        only.to_vec()
    };

    eprintln!("Generating keys for {} circuits...", targets.len());
    let mut generated = 0usize;
    for stem in &targets {
        if keys::generate(&work, keys_dir, stem, force)? {
            generated = generated.saturating_add(1);
        }
    }
    eprintln!("Done: {generated} of {} regenerated", targets.len());

    if generated > 0 {
        // These keys came from this machine's RNG, so say so even if the stem
        // was previously marked as ceremony output.
        run_snapshot(out_dir, keys_dir, &targets, Some("local"))?;
    }
    Ok(())
}

/// Record the key files present in `keys_dir` against the current R1CS.
///
/// `provenance` of `None` keeps whatever a stem already claims, and records new
/// stems as `local`. Pass `Some` to state it, which is the only way to move a
/// stem between `local` and `ceremony`.
fn run_snapshot(
    out_dir: &Path,
    keys_dir: &Path,
    stems: &[String],
    provenance: Option<&str>,
) -> Result<()> {
    let build: BuildManifest = manifest::load(&out_dir.join(manifest::BUILD_MANIFEST))?;
    let path = keys_dir.join(manifest::KEY_MANIFEST);
    let mut key_manifest: KeyManifest = if path.is_file() {
        manifest::load(&path)?
    } else {
        KeyManifest::empty()
    };

    let mut recorded = 0usize;
    for stem in stems {
        if !keys_dir.join(format!("{stem}_proving_key.bin")).is_file() {
            continue;
        }
        let Some(circuit) = build.circuits.get(stem) else {
            bail!("{stem} has key material but no compiled R1CS in the build manifest");
        };

        let mut files = BTreeMap::new();
        for suffix in KEY_SUFFIXES {
            let name = format!("{stem}{suffix}");
            let file = keys_dir.join(&name);
            if file.is_file() {
                files.insert(name, FileDigest::of(&file)?);
            }
        }

        // A label only means something while it describes the same bytes. If
        // the key files changed, an unstated provenance drops back to `local`
        // rather than letting a `ceremony` label carry over to new material.
        let provenance = match (provenance, key_manifest.circuits.get(stem)) {
            (Some(stated), _) => stated.to_owned(),
            (None, Some(entry)) if entry.files == files => entry.provenance.clone(),
            (None, _) => "local".to_owned(),
        };

        key_manifest.circuits.insert(
            stem.clone(),
            KeyEntry {
                r1cs_sha256: circuit.r1cs.sha256.clone(),
                provenance,
                files,
            },
        );
        recorded = recorded.saturating_add(1);
    }

    manifest::save(&path, &key_manifest)?;
    eprintln!("Recorded {recorded} circuits in {}", path.display());
    Ok(())
}

fn run_verify(circuits_dir: &Path, out_dir: &Path, keys_dir: Option<&Path>) -> Result<()> {
    let build: BuildManifest = manifest::load(&out_dir.join(manifest::BUILD_MANIFEST))?;
    let mut failures = Vec::new();

    let circom = paths::circom_version(circuits_dir)?;
    if build.toolchain.circom != circom {
        failures.push(format!(
            "manifest built with circom {}, this builder links {circom}",
            build.toolchain.circom
        ));
    }
    let circomlib = circomlib_rev(circuits_dir)?;
    if build.toolchain.circomlib != circomlib {
        failures.push(format!(
            "manifest built against circomlib {}, circomlib.lock pins {circomlib}",
            build.toolchain.circomlib
        ));
    }
    if build.toolchain.prime != compile::CURVE_ID {
        failures.push(format!(
            "manifest built over prime {}, this builder uses {}",
            build.toolchain.prime,
            compile::CURVE_ID
        ));
    }

    for (stem, circuit) in &build.circuits {
        check_file(
            out_dir,
            &format!("{stem}.r1cs"),
            &circuit.r1cs,
            &mut failures,
        );
        check_file(
            out_dir,
            &format!("{stem}.wasm"),
            &circuit.wasm,
            &mut failures,
        );

        for (rel, expected) in &circuit.sources {
            match manifest::sha256_file(&circuits_dir.join(rel)) {
                Ok(actual) if actual == *expected => {}
                Ok(_) => failures.push(format!(
                    "{stem}: source {rel} changed since the artifacts were built"
                )),
                Err(e) => failures.push(format!("{stem}: source {rel}: {e}")),
            }
        }
    }

    let mut key_entries = None;
    if let Some(keys_dir) = keys_dir {
        key_entries = Some(verify_keys(&build, keys_dir, &mut failures)?);
    }

    if failures.is_empty() {
        match key_entries {
            Some(keys) => eprintln!(
                "OK: {} circuits and {keys} key entries verified",
                build.circuits.len()
            ),
            None => eprintln!(
                "OK: {} circuits verified (no --keys-dir given, key material unchecked)",
                build.circuits.len()
            ),
        }
        return Ok(());
    }

    for failure in &failures {
        eprintln!("  {failure}");
    }
    bail!("{} verification failure(s)", failures.len())
}

fn verify_keys(
    build: &BuildManifest,
    keys_dir: &Path,
    failures: &mut Vec<String>,
) -> Result<usize> {
    let path = keys_dir.join(manifest::KEY_MANIFEST);
    if !path.is_file() {
        bail!(
            "no key manifest at {} - run `circuit-builder snapshot` to create it",
            path.display()
        );
    }
    let key_manifest: KeyManifest = manifest::load(&path)?;

    // Check the directory against the manifest as well as the other way round.
    // Without this, deleting an entry silently disarms the gate for that stem,
    // and key files added by hand are never checked at all.
    for entry in fs::read_dir(keys_dir).with_context(|| format!("read {}", keys_dir.display()))? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix("_proving_key.bin") else {
            continue;
        };
        if !key_manifest.circuits.contains_key(stem) {
            failures.push(format!(
                "{stem}: {name} is present but has no entry in {}. Run \
                 `circuit-builder snapshot` to record it.",
                manifest::KEY_MANIFEST
            ));
        }
    }

    for (stem, entry) in &key_manifest.circuits {
        let Some(circuit) = build.circuits.get(stem) else {
            failures.push(format!("{stem}: key manifest entry has no compiled R1CS"));
            continue;
        };

        if circuit.r1cs.sha256 != entry.r1cs_sha256 {
            failures.push(format!(
                "{stem}: STALE KEYS. The committed key material was generated against \
                 R1CS {}, but the current R1CS is {}. Proofs made with these keys will \
                 not verify against the current circuit. Either revert the circuit \
                 change, or rotate the keys (`circuit-builder keys --force --circuit \
                 {stem}`) and redeploy the matching on-chain verifier.",
                short(&entry.r1cs_sha256),
                short(&circuit.r1cs.sha256)
            ));
        }

        for (name, expected) in &entry.files {
            check_file(keys_dir, name, expected, failures);
        }
    }

    Ok(key_manifest.circuits.len())
}

fn check_file(dir: &Path, name: &str, expected: &FileDigest, failures: &mut Vec<String>) {
    match FileDigest::of(&dir.join(name)) {
        Ok(actual) if actual == *expected => {}
        Ok(actual) => failures.push(format!(
            "{name}: expected sha256 {} ({} bytes), found {} ({} bytes)",
            short(&expected.sha256),
            expected.len,
            short(&actual.sha256),
            actual.len
        )),
        Err(e) => failures.push(format!("{name}: {e}")),
    }
}

fn short(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}
