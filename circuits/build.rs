//! Build script for compiling Circom circuits
//!
//! This build script automatically compiles all `.circom` files in the `src/`
//! directory into R1CS constraint systems, symbol files and WASM for witness
//! generation.
//!
//! ## Usage
//! The build script runs automatically when you run `cargo build`. It will:
//! 1. Find all `.circom` files in `src/` directory
//! 2. Compile each circuit using the circom compiler
//!
//! To Build the test circuits use `BUILD_TESTS=1 cargo build`
//!
//! The script also generates Groth16 proving and verification keys for selected
//! entry-point circuits (see `GROTH16_KEY_CIRCUITS` below) and outputs them to
//! `testdata/`.
//!
//! The output directory is exposed as en environment variable
//! `std::env::var("CIRCUIT_OUT_DIR")`

use anyhow::{Context, Result, anyhow, bail};
use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use compiler::{
    compiler_interface::{Config, VCP, run_compiler, write_wasm},
    num_bigint::BigInt,
};
use constraint_generation::{BuildConfig, build_circuit};
use constraint_writers::ConstraintExporter;
use program_structure::error_definition::Report;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    string::ToString,
};
use type_analysis::check_types::check_types;

mod build_support;
use build_support::extract_circom_dependencies;

const CURVE_ID: &str = "bn128";
const EXPECTED_GRAPH_CIRCOM_VERSION: &str = "2.2.3";
const EXPECTED_GRAPH_BUILDER_LOCK_SHA256: &str =
    "e5405413f79ac57b0d92952c1dd8f737e609e9a2e93ac950466d8a9ae5c30d67";
const R1CS_CIRCOM_PACKAGES: &[&str] = &[
    "compiler",
    "constraint_generation",
    "constraint_writers",
    "parser",
    "program_structure",
    "type_analysis",
];

/// Circom stems whose Groth16 artifacts live under `testdata/`
/// (`{stem}_proving_key.bin`, etc.). Append here when wiring a new entry-point
/// through the same key-generation path.
const GROTH16_KEY_CIRCUITS: &[&str] = &["policy_tx_2_2", "selectiveDisclosure_1"];

/// Circom stems that must have a checked-in graph artifact for native witness
/// generation.
const GRAPH_WITNESS_CIRCUITS: &[&str] = &["policy_tx_2_2"];

/// `testdata/` filenames (`{stem}{suffix}`) that invalidate the build when
/// changed.
const GROTH16_TESTDATA_SUFFIXES: &[&str] = &["_proving_key.bin", "_vk.json", "_vk_soroban.bin"];

fn circuit_needs_groth16_keys(name: &str) -> bool {
    GROTH16_KEY_CIRCUITS.contains(&name)
}

fn circuit_needs_witness_graph(name: &str) -> bool {
    GRAPH_WITNESS_CIRCUITS.contains(&name)
}

fn publish_dir_path(crate_dir: &Path) -> Result<PathBuf> {
    let workspace_root = crate_dir.parent().unwrap_or(crate_dir);
    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("target"));
    let target_dir = if target_dir.is_absolute() {
        target_dir
    } else {
        workspace_root.join(target_dir)
    };
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    Ok(target_dir.join("circuits-artifacts").join(profile))
}

fn copy(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create directory {}", parent.display()))?;
    }

    let tmp = dst.with_extension(format!("tmp-{}", std::process::id()));
    fs::copy(src, &tmp)
        .with_context(|| format!("Failed to copy {} to {}", src.display(), tmp.display()))?;

    if dst.exists() {
        let _ = fs::remove_file(dst);
    }
    fs::rename(&tmp, dst)
        .with_context(|| format!("Failed to rename {} to {}", tmp.display(), dst.display()))?;
    Ok(())
}

fn publish_circuit_artifacts(
    publish_dir: &Path,
    circuit_name: &str,
    r1cs_file: &Path,
    wasm_file: Option<&Path>,
    graph_file: Option<&Path>,
    graph_manifest_file: Option<&Path>,
) -> Result<()> {
    let r1cs_dst = publish_dir.join(format!("{circuit_name}.r1cs"));
    copy(r1cs_file, &r1cs_dst)?;

    if let Some(wasm_file) = wasm_file
        && wasm_file.exists()
    {
        let wasm_dst = publish_dir.join(format!("{circuit_name}.wasm"));
        copy(wasm_file, &wasm_dst)?;
    }

    if let Some(graph_file) = graph_file
        && graph_file.exists()
    {
        let graph_dst = publish_dir.join(format!("{circuit_name}.graph.bin"));
        copy(graph_file, &graph_dst)?;
    }

    if let Some(graph_manifest_file) = graph_manifest_file
        && graph_manifest_file.exists()
    {
        let graph_manifest_dst = publish_dir.join(format!("{circuit_name}.graph.manifest"));
        copy(graph_manifest_file, &graph_manifest_dst)?;
    }

    Ok(())
}

fn workspace_root(crate_dir: &Path) -> &Path {
    crate_dir.parent().unwrap_or(crate_dir)
}

fn checked_in_graph_path(crate_dir: &Path, circuit_name: &str) -> PathBuf {
    crate_dir
        .join("../deployments/testnet/circuit_keys")
        .join(format!("{circuit_name}.graph.bin"))
}

fn checked_in_graph_manifest_path(crate_dir: &Path, circuit_name: &str) -> PathBuf {
    crate_dir
        .join("../deployments/testnet/circuit_keys")
        .join(format!("{circuit_name}.graph.manifest"))
}

fn required_graph_artifact(
    crate_dir: &Path,
    circuit_name: &str,
    circom_file: &Path,
    dependencies: &[PathBuf],
) -> Result<Option<(PathBuf, PathBuf)>> {
    if !circuit_needs_witness_graph(circuit_name) {
        return Ok(None);
    }

    let graph_path = checked_in_graph_path(crate_dir, circuit_name);
    let manifest_path = checked_in_graph_manifest_path(crate_dir, circuit_name);
    println!("cargo:rerun-if-changed={}", graph_path.display());
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    if !graph_path.exists() {
        bail!(
            "Missing native witness graph for {circuit_name}: {}. Run `tools/witness-graph/generate-policy-graph.sh` and commit the generated artifact.",
            graph_path.display()
        );
    }
    if !manifest_path.exists() {
        bail!(
            "Missing native witness graph manifest for {circuit_name}: {}. Run `tools/witness-graph/generate-policy-graph.sh` and commit the generated manifest.",
            manifest_path.display()
        );
    }

    verify_graph_manifest(
        workspace_root(crate_dir),
        circuit_name,
        &graph_path,
        &manifest_path,
        circom_file,
        dependencies,
    )?;

    Ok(Some((graph_path, manifest_path)))
}

fn verify_graph_manifest(
    workspace_root: &Path,
    circuit_name: &str,
    graph_path: &Path,
    manifest_path: &Path,
    circom_file: &Path,
    dependencies: &[PathBuf],
) -> Result<()> {
    let manifest = parse_graph_manifest(manifest_path)?;
    let actual_graph_hash = sha256_file(graph_path)?;
    if manifest.graph_sha256 != actual_graph_hash {
        bail!(
            "Native witness graph hash mismatch for {circuit_name}: manifest has {}, actual file has {}. Run `tools/witness-graph/generate-policy-graph.sh` and commit both files.",
            manifest.graph_sha256,
            actual_graph_hash
        );
    }

    if manifest.circom_version != EXPECTED_GRAPH_CIRCOM_VERSION {
        bail!(
            "Native witness graph manifest for {circuit_name} was generated with circom {}, expected {}. Run `tools/witness-graph/generate-policy-graph.sh` with the expected circom version.",
            manifest.circom_version,
            EXPECTED_GRAPH_CIRCOM_VERSION
        );
    }

    if manifest.builder_lock_sha256 != EXPECTED_GRAPH_BUILDER_LOCK_SHA256 {
        bail!(
            "Native witness graph manifest for {circuit_name} has graph builder lock hash {}, expected {}. Run `tools/witness-graph/generate-policy-graph.sh` with the expected graph builder dependencies.",
            manifest.builder_lock_sha256,
            EXPECTED_GRAPH_BUILDER_LOCK_SHA256
        );
    }

    let expected_sources = graph_manifest_sources(workspace_root, circom_file, dependencies)?;
    if manifest.source_sha256 != expected_sources {
        let (missing, stale, extra) =
            diff_manifest_sources(&manifest.source_sha256, &expected_sources);
        bail!(
            "Native witness graph manifest is stale for {circuit_name}: {missing} missing, {stale} changed, {extra} extra source entries. Run `tools/witness-graph/generate-policy-graph.sh` and commit the updated graph manifest."
        );
    }

    Ok(())
}

struct GraphManifest {
    graph_sha256: String,
    circom_version: String,
    builder_lock_sha256: String,
    source_sha256: BTreeMap<String, String>,
}

fn parse_graph_manifest(manifest_path: &Path) -> Result<GraphManifest> {
    let contents = fs::read_to_string(manifest_path)
        .with_context(|| format!("Failed to read {}", manifest_path.display()))?;
    let mut version_seen = false;
    let mut graph_sha256 = None;
    let mut circom_version = None;
    let mut builder_lock_sha256 = None;
    let mut source_sha256 = BTreeMap::new();

    for (line_no, line) in contents.lines().enumerate() {
        let line_no = line_no
            .checked_add(1)
            .ok_or_else(|| anyhow!("Graph manifest line number overflow"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed == "version 1" {
            version_seen = true;
            continue;
        }

        if let Some(hash) = trimmed.strip_prefix("graph_sha256 ") {
            graph_sha256 = Some(hash.trim().to_string());
            continue;
        }

        if let Some(version) = trimmed.strip_prefix("circom_version ") {
            circom_version = Some(version.trim().to_string());
            continue;
        }

        if let Some(hash) = trimmed.strip_prefix("builder_lock_sha256 ") {
            builder_lock_sha256 = Some(hash.trim().to_string());
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("source_sha256 ") {
            let (hash, path) = rest
                .split_once(' ')
                .ok_or_else(|| anyhow!("Invalid graph manifest line {line_no}: {trimmed}"))?;
            source_sha256.insert(path.to_string(), hash.to_string());
            continue;
        }

        bail!("Invalid graph manifest line {line_no}: {trimmed}");
    }

    if !version_seen {
        bail!(
            "Graph manifest {} is missing `version 1`",
            manifest_path.display()
        );
    }

    Ok(GraphManifest {
        graph_sha256: graph_sha256.ok_or_else(|| {
            anyhow!(
                "Graph manifest {} is missing graph_sha256",
                manifest_path.display()
            )
        })?,
        circom_version: circom_version.ok_or_else(|| {
            anyhow!(
                "Graph manifest {} is missing circom_version",
                manifest_path.display()
            )
        })?,
        builder_lock_sha256: builder_lock_sha256.ok_or_else(|| {
            anyhow!(
                "Graph manifest {} is missing builder_lock_sha256",
                manifest_path.display()
            )
        })?,
        source_sha256,
    })
}

fn graph_manifest_sources(
    workspace_root: &Path,
    circom_file: &Path,
    dependencies: &[PathBuf],
) -> Result<BTreeMap<String, String>> {
    let mut source_files: Vec<PathBuf> = std::iter::once(circom_file.to_path_buf())
        .chain(dependencies.iter().cloned())
        .chain([
            workspace_root.join("Cargo.lock"),
            workspace_root.join("circuits/Cargo.toml"),
            workspace_root.join("circuits/circomlib.lock"),
            workspace_root.join("circuits/build.rs"),
            workspace_root.join("circuits/build_support.rs"),
            workspace_root.join("tools/witness-graph/generate-policy-graph.sh"),
        ])
        .collect();
    source_files.sort();
    source_files.dedup();

    let mut sources = BTreeMap::new();
    for path in source_files {
        let rel_path = relative_manifest_path(workspace_root, &path)?;
        sources.insert(rel_path, sha256_file(&path)?);
    }
    Ok(sources)
}

fn diff_manifest_sources(
    manifest: &BTreeMap<String, String>,
    expected: &BTreeMap<String, String>,
) -> (usize, usize, usize) {
    let missing = expected
        .keys()
        .filter(|path| !manifest.contains_key(*path))
        .count();
    let stale = expected
        .iter()
        .filter(|(path, hash)| manifest.get(*path).is_some_and(|actual| actual != *hash))
        .count();
    let extra = manifest
        .keys()
        .filter(|path| !expected.contains_key(*path))
        .count();
    (missing, stale, extra)
}

fn relative_manifest_path(workspace_root: &Path, path: &Path) -> Result<String> {
    let absolute = path
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize {}", path.display()))?;
    let relative = absolute
        .strip_prefix(workspace_root.canonicalize()?)
        .with_context(|| {
            format!(
                "Graph manifest source {} is outside workspace {}",
                absolute.display(),
                workspace_root.display()
            )
        })?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    Ok(hex_lower(&digest))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let capacity = bytes
        .len()
        .checked_mul(2)
        .expect("SHA-256 hex output capacity overflow");
    let mut out = String::with_capacity(capacity);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(*byte >> 4)]));
        out.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    out
}

fn main() -> Result<()> {
    println!(
        "cargo:warning=Circuits builder Copyright (C) 2025 Stellar Development Foundation. This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it under certain conditions."
    );
    // === PATH SETUP ===
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace_root = workspace_root(&crate_dir);
    let src_dir = crate_dir.join("src");
    let compiler_version = verify_r1cs_circom_versions()?;

    // Put build artifacts under OUT_DIR/circuits
    let out_dir = PathBuf::from(env::var("OUT_DIR")?).join("circuits");
    fs::create_dir_all(&out_dir).context("Could not create OUT_DIR/circuits")?;

    // Also publish artifacts to a deterministic directory under target/
    let publish_dir = publish_dir_path(&crate_dir)?;
    fs::create_dir_all(&publish_dir)
        .with_context(|| format!("Could not create {}", publish_dir.display()))?;

    // Expose the path to your runtime/tests
    println!("cargo:rustc-env=CIRCUIT_OUT_DIR={}", out_dir.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("Cargo.lock").display()
    );
    println!("cargo:rerun-if-env-changed=BUILD_TESTS");
    println!("cargo:rerun-if-env-changed=REGEN_KEYS");

    // Rerun if testdata key files are missing or changed
    let testdata_dir = crate_dir.join("../testdata");
    for stem in GROTH16_KEY_CIRCUITS {
        for suffix in GROTH16_TESTDATA_SUFFIXES {
            println!(
                "cargo:rerun-if-changed={}",
                testdata_dir.join(format!("{stem}{suffix}")).display()
            );
        }
    }

    // === CIRCOMLIB DEPENDENCY ===
    // Import circomlib library (only if not already present) and pin it to the
    // revision in `circomlib.lock` for reproducible builds.
    println!(
        "cargo:rerun-if-changed={}",
        crate_dir.join("circomlib.lock").display()
    );
    get_circomlib(&crate_dir, &src_dir)?;

    // === FIND CIRCOM FILES ===
    // Find all .circom files with a main component
    let mut circom_files = find_circom_files(&src_dir);

    // Optionally include test circuits when BUILD_TESTS=1
    // This includes both src/test/ and any other test directories (e.g.,
    // circomlib/test/)
    let build_tests = env::var("BUILD_TESTS").is_ok();
    if build_tests {
        println!("cargo:warning=Including test circuits in build...");
        // Re-scan src/ without skipping test directories to include all test circuits
        circom_files = find_circom_files_impl(&src_dir, false);
    } else {
        println!("cargo:warning=Skipping test circuits (set BUILD_TESTS=1 to include)");
    }

    // Skip circom compilation if no files to compile
    if circom_files.is_empty() {
        println!("cargo:warning=No circom files found to compile");
        return Ok(());
    }

    // === COMPILE EACH CIRCUIT ===
    for circom_file in circom_files {
        println!("cargo:rerun-if-changed={}", circom_file.display());

        // Output file
        let out_file = out_dir.join(circom_file.file_stem().context("Invalid circom filename")?);

        // Check if output files already exist and are newer than source
        let r1cs_file = out_file.with_extension("r1cs");
        let sym_file = out_file.with_extension("sym");

        // Hardcoded Values for BN128 (also known as BN254) and only R1CS and SYM
        // compilation
        let prime = BigInt::parse_bytes(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617"
                .as_bytes(),
            10,
        )
        .expect("Can not parse  BN128 prime");
        let flag_no_init = false;

        // === PARSE CIRCUIT ===
        let (mut program_archive, report_warns) = parser::run_parser(
            circom_file.to_string_lossy().to_string(),
            compiler_version.as_str(),
            vec![],
            &prime,
            flag_no_init,
        )
        .map_err(|(file_library, report_errors)| {
            Report::print_reports(&report_errors, &file_library);
            anyhow!("Parser failed to run on {}", circom_file.to_string_lossy())
        })?;
        Report::print_reports(&report_warns, &program_archive.file_library);

        // === CHECK DEPENDENCIES ===
        // We now extract all included files from the parsed circuit and check if
        // rebuild is needed This prevents situations where a circuit is not
        // updated, but its dependencies are
        let dependencies = extract_circom_dependencies(&circom_file, &crate_dir)?;
        for dep_path in &dependencies {
            // Register each dependency file with cargo so it knows to rebuild when they
            // change
            println!("cargo:rerun-if-changed={}", dep_path.display());
        }

        // Get circuit name for key generation check
        let circuit_name = circom_file
            .file_stem()
            .context("Invalid circom filename")?
            .to_string_lossy()
            .to_string();
        let graph_artifacts =
            required_graph_artifact(&crate_dir, &circuit_name, &circom_file, &dependencies)?;
        let graph_file = graph_artifacts
            .as_ref()
            .map(|(graph_path, _)| graph_path.as_path());
        let graph_manifest_file = graph_artifacts
            .as_ref()
            .map(|(_, manifest_path)| manifest_path.as_path());

        let wasm_path = out_dir
            .join("wasm")
            .join(format!("{circuit_name}_js"))
            .join(format!("{circuit_name}.wasm"));

        if r1cs_file.exists() && sym_file.exists() {
            let r1cs_modified = fs::metadata(&r1cs_file)?.modified()?;
            let sym_modified = fs::metadata(&sym_file)?.modified()?;
            let newest_artifact = r1cs_modified.max(sym_modified);

            // Check if any dependency (including the main file) is newer than artifacts
            let needs_rebuild =
                check_dependencies_need_rebuild(&dependencies, &circom_file, newest_artifact)?;

            if !needs_rebuild {
                println!(
                    "cargo:warning=Skipping {} (already compiled, all dependencies up to date)",
                    circom_file.display()
                );

                // Keep deterministic publish directory updated even on "skip" builds.
                if wasm_path.exists() {
                    if let Err(e) = publish_circuit_artifacts(
                        &publish_dir,
                        &circuit_name,
                        &r1cs_file,
                        Some(&wasm_path),
                        graph_file,
                        graph_manifest_file,
                    ) {
                        println!(
                            "cargo:warning=Failed to publish artifacts for {circuit_name}: {e}"
                        );
                    }
                } else {
                    // WASM missing: fall through so we can regenerate it instead of silently
                    // leaving the deterministic directory incomplete.
                    println!(
                        "cargo:warning=WASM missing for {} - recompiling to restore deterministic artifacts",
                        circuit_name
                    );
                }

                // Still check if we need to generate keys for circuits that ship PK/VK under
                // testdata/
                if circuit_needs_groth16_keys(circuit_name.as_str()) && wasm_path.exists() {
                    match generate_keys_if_needed(&crate_dir, &out_dir, &circuit_name, &r1cs_file) {
                        Ok(_) => {}
                        Err(e) => {
                            println!("cargo:warning=Key generation failed: {e}");
                        }
                    }
                    continue;
                }

                if wasm_path.exists() {
                    continue;
                }
            }
        }

        // === TYPECHECK ===
        let report_warns = check_types(&mut program_archive).map_err(|report_errors| {
            Report::print_reports(&report_errors, program_archive.get_file_library());
            anyhow!("{}", report_errors[0].get_message())
        })?;
        Report::print_reports(&report_warns, program_archive.get_file_library());

        // === BUILD CONFIG ===
        // Controls which outputs to generate (R1CS + SYM). The WASM is done later
        let build_config = BuildConfig {
            no_rounds: 1,
            flag_json_sub: false,
            json_substitutions: "Not used".to_string(),
            flag_s: true,
            flag_f: false,
            flag_p: false,
            flag_verbose: false,
            inspect_constraints: false,
            flag_old_heuristics: false,
            prime: CURVE_ID.to_string(),
        };

        // Build the constraint system
        let custom_gates = program_archive.custom_gates;
        let (exporter, vcp) = build_circuit(program_archive, build_config)
            .map_err(|_| anyhow!("Error building circuit"))?;

        // === WRITE R1CS + SYM FILES ===
        generate_output_r1cs(
            out_file
                .with_extension("r1cs")
                .to_str()
                .context("Invalid R1CS generation filename")?,
            exporter.as_ref(),
            custom_gates,
        )
        .expect("R1CS file generation failed");
        generate_output_sym(
            out_file
                .with_extension("sym")
                .to_str()
                .context("Invalid SYM generation filename")?,
            exporter.as_ref(),
        )
        .expect("SYM file generation failed");

        // === WASM GENERATION ===
        let wasm_success = match compile_wasm(&circom_file, &out_dir, vcp) {
            Ok(()) => true,
            Err(e) => {
                println!("cargo:warning=WASM generation failed for {circom_file:?}: {e}");
                false
            }
        };

        if let Err(e) = publish_circuit_artifacts(
            &publish_dir,
            &circuit_name,
            &r1cs_file,
            if wasm_success {
                Some(wasm_path.as_path())
            } else {
                None
            },
            graph_file,
            graph_manifest_file,
        ) {
            println!("cargo:warning=Failed to publish artifacts for {circuit_name}: {e}");
        }

        // === GROTH16 Proving/Verifying key generation ===
        // policy_tx_2_2 and selectiveDisclosure_1 (must match `*.circom` file stem).
        if circuit_needs_groth16_keys(circuit_name.as_str()) {
            if !wasm_success {
                bail!(
                    "Skipping key generation for {} - WASM compilation failed",
                    circuit_name
                );
            } else {
                match generate_keys_if_needed(&crate_dir, &out_dir, &circuit_name, &r1cs_file) {
                    Ok(generated) => {
                        if generated {
                            println!(
                                "cargo:warning=Key generation completed for {}",
                                circuit_name
                            );
                        }
                    }
                    Err(e) => {
                        println!(
                            "cargo:warning=Key generation failed for {}: {}",
                            circuit_name, e
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Check if any dependency file is newer than the build artifacts
///
/// Compares the modification time of the main file and all dependencies
/// against the modification time of the build artifacts to determine if
/// a rebuild is necessary.
///
/// # Arguments
///
/// * `dependencies` - List of dependency file paths
/// * `main_file` - Main Circom file being compiled
/// * `artifact_modified` - Modification time of the newest build artifact
///
/// # Returns
///
/// Returns `Ok(true)` if any file is newer than artifacts (rebuild needed),
/// `Ok(false)` if all files are older or equal (no rebuild needed),
/// or an error if file system operations fail.
fn check_dependencies_need_rebuild(
    dependencies: &[PathBuf],
    main_file: &Path,
    artifact_modified: std::time::SystemTime,
) -> Result<bool> {
    // Combine the main file with dependencies to avoid duplication
    let all_files = std::iter::once(main_file).chain(dependencies.iter().map(|p| p.as_path()));

    for file_path in all_files {
        let modified = fs::metadata(file_path)?.modified()?;
        if modified > artifact_modified {
            println!(
                "cargo:warning=File {} is newer than artifacts, rebuilding...",
                file_path.display()
            );
            return Ok(true);
        }
    }

    Ok(false)
}

/// Recursively find all .circom files with a main component in a directory
///
/// Searches the provided directory and all subdirectories for `.circom` files
/// that contain a main component definition.
///
/// # Arguments
///
/// * `dir` - Directory to search for Circom files
/// * `skip_test_dirs` - If true, skip directories named "test"
///
/// # Returns
///
/// Returns a vector of paths to Circom files that contain a main component.
fn find_circom_files(dir: &Path) -> Vec<PathBuf> {
    find_circom_files_impl(dir, true)
}

/// Internal implementation that allows controlling whether to skip test
/// directories.
fn find_circom_files_impl(dir: &Path, skip_test_dirs: bool) -> Vec<PathBuf> {
    let mut circom_files = Vec::new();

    // Recursively search for .circom files
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "circom") {
                // Check if the file contains a main component
                if has_main_component(&path) {
                    circom_files.push(PathBuf::from("./").join(path));
                }
            } else if path.is_dir() {
                // Skip "test" directories when skip_test_dirs is true
                if skip_test_dirs && path.file_name().is_some_and(|name| name == "test") {
                    continue;
                }
                // Always skip vendored circomlib — it contains its own
                // `component main` entry points (e.g. sha256/main.circom)
                // that would produce colliding artifacts.
                if path.file_name().is_some_and(|name| name == "circomlib") {
                    continue;
                }
                circom_files.extend(find_circom_files_impl(&path, skip_test_dirs));
            }
        }
    } else {
        println!("Failed to read directory: {dir:?}");
    }

    circom_files
}

/// Check if a Circom file contains a main component definition
///
/// Reads the file and searches for the string "component main "
/// to determine if the file defines a main component.
///
/// # Arguments
///
/// * `file_path` - Path to the Circom file to check
///
/// # Returns
///
/// Returns `true` if the file contains a main component, `false` otherwise.
/// Prints a warning if the file cannot be read.
fn has_main_component(file_path: &Path) -> bool {
    match fs::read_to_string(file_path) {
        Ok(content) => {
            let content_lower = content.to_lowercase();

            // Check for component main in the file
            content_lower.contains("component main ")
        }
        Err(e) => {
            println!("cargo:warning=Failed to read file {file_path:?}: {e}");
            false
        }
    }
}

/// Generate and write the R1CS (Rank-1 Constraint System) output file
///
/// Writes the constraint system to a binary R1CS file format.
///
/// # Arguments
///
/// * `file` - Output file name for the R1CS file
/// * `exporter` - Constraint exporter containing the compiled circuit
/// * `custom_gates` - Whether the circuit uses custom gates
///
/// # Returns
///
/// Returns `Ok(())` on success, `Err(())` if writing the file fails.
fn generate_output_r1cs(
    file: &str,
    exporter: &dyn ConstraintExporter,
    custom_gates: bool,
) -> Result<(), ()> {
    if let Ok(()) = exporter.r1cs(file, custom_gates) {
        println!("Written successfully: {file}");
        Ok(())
    } else {
        eprintln!("Could not write the output in the given path");
        Err(())
    }
}

/// Generate and write the symbol table output file
///
/// Writes the symbol table to a file for debugging and constraint inspection.
///
/// # Arguments
///
/// * `file` - Output file path for the symbol file
/// * `exporter` - Constraint exporter containing the compiled circuit
///
/// # Returns
///
/// Returns `Ok(())` on success, `Err(())` if writing fails.
fn generate_output_sym(file: &str, exporter: &dyn ConstraintExporter) -> Result<(), ()> {
    if let Ok(()) = exporter.sym(file) {
        println!("Written successfully: {file}");
        Ok(())
    } else {
        eprintln!("Could not write the output in the given path");
        Err(())
    }
}

/// Parse the Circom compiler version from Cargo.toml
///
/// Searches the Cargo.toml file for the specified package in either
/// `[build-dependencies]` or `[dependencies]` sections and extracts
/// the version tag.
///
/// # Arguments
///
/// * `package_name` - Name of the package to find (e.g., "compiler")
///
/// # Returns
///
/// Returns `Some(String)` with the version tag (with "v" prefix removed)
/// if found, or `None` if the package or version cannot be found.
fn parse_circom_version(package_name: &str) -> Option<String> {
    let cargo_toml = match fs::read_to_string("Cargo.toml") {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Failed to read Cargo.toml: {e}");
            return None;
        }
    };

    // Simple string search approach
    let lines: Vec<&str> = cargo_toml.lines().collect();
    let mut in_build_deps = false;
    let mut in_deps = false;

    for line in lines {
        let trimmed = line.trim();

        if trimmed == "[build-dependencies]" {
            in_build_deps = true;
            in_deps = false;
            continue;
        } else if trimmed == "[dependencies]" {
            in_deps = true;
            in_build_deps = false;
            continue;
        } else if trimmed.starts_with('[') {
            in_build_deps = false;
            in_deps = false;
            continue;
        }

        if (in_build_deps || in_deps) && trimmed.starts_with(package_name) {
            // Look for tag = "..." in this line or continue reading
            if let Some(tag_start) = trimmed.find(r#"tag = ""#) {
                let start_index = tag_start.checked_add(7)?;
                let after_tag = &trimmed[start_index..]; // Skip 'tag = "'
                if let Some(end_quote) = after_tag.find('"') {
                    let tag = &after_tag[..end_quote];
                    return Some(tag.to_string().replace("v", ""));
                }
            }
        }
    }

    None
}

fn verify_r1cs_circom_versions() -> Result<String> {
    let mut compiler_version = None;

    for package_name in R1CS_CIRCOM_PACKAGES {
        let version = parse_circom_version(package_name).with_context(|| {
            format!("Could not parse Circom package version for {package_name}")
        })?;
        if version != EXPECTED_GRAPH_CIRCOM_VERSION {
            bail!(
                "R1CS Circom package {package_name} uses version {version}, expected {EXPECTED_GRAPH_CIRCOM_VERSION}. Keep the Rust Circom compiler inputs aligned with the checked-in witness graph."
            );
        }
        if *package_name == "compiler" {
            compiler_version = Some(version);
        }
    }

    compiler_version.context("Could not parse Circom compiler version")
}

/// Imports the circomlib dependency without adding any Javascript dependency.
///
/// We clone the circomlib repository into the provided repository.
///
/// # Arguments
/// * `directory` - path in which the Circomlib dependency will be cloned.
///
/// # Returns
/// Returns exit status of the import procedure
fn get_circomlib(crate_dir: &Path, src_dir: &Path) -> Result<()> {
    let circomlib_path = src_dir.join("circomlib");
    let locked_rev = fs::read_to_string(crate_dir.join("circomlib.lock"))
        .context("Failed to read circuits/circomlib.lock")?;
    let locked_rev = locked_rev.trim();
    if locked_rev.len() != 40 || !locked_rev.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "Invalid circomlib.lock value (expected 40-char hex SHA): {locked_rev:?}"
        ));
    }

    if circomlib_path.exists() && !circomlib_path.join(".git").exists() {
        // Remove invalid directory and re-initialize.
        fs::remove_dir_all(&circomlib_path)?;
    }

    if !circomlib_path.join(".git").exists() {
        fs::create_dir_all(&circomlib_path)?;
        Command::new("git")
            .arg("-C")
            .arg(&circomlib_path)
            .arg("init")
            .status()
            .map_err(|_| anyhow!("Error initializing circomlib git repository"))?
            .success()
            .then_some(())
            .ok_or_else(|| anyhow!("git init failed for circomlib dependency"))?;

        Command::new("git")
            .arg("-C")
            .arg(&circomlib_path)
            .arg("remote")
            .arg("add")
            .arg("origin")
            .arg("https://github.com/iden3/circomlib.git")
            .status()
            .map_err(|_| anyhow!("Error adding circomlib git remote"))?
            .success()
            .then_some(())
            .ok_or_else(|| anyhow!("git remote add failed for circomlib dependency"))?;
    }

    // If already checked out at the locked rev, do nothing.
    let head_out = Command::new("git")
        .arg("-C")
        .arg(&circomlib_path)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok();
    if let Some(out) = head_out
        && out.status.success()
    {
        let head = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if head == locked_rev {
            ensure_circomlib_clean(&circomlib_path)?;
            println!("cargo:warning=circomlib already at locked revision {locked_rev}");
            return Ok(());
        }
    }

    println!("cargo:warning=Fetching circomlib revision {locked_rev}...");
    let fetch_status = Command::new("git")
        .arg("-C")
        .arg(&circomlib_path)
        .arg("fetch")
        .arg("--depth")
        .arg("1")
        .arg("origin")
        .arg(locked_rev)
        .status()
        .map_err(|_| anyhow!("Error fetching circomlib dependency"))?;
    if !fetch_status.success() {
        return Err(anyhow!("git fetch failed for circomlib dependency"));
    }

    let checkout_status = Command::new("git")
        .arg("-C")
        .arg(&circomlib_path)
        .arg("checkout")
        .arg("--detach")
        .arg("FETCH_HEAD")
        .status()
        .map_err(|_| anyhow!("Error checking out circomlib dependency"))?;
    if !checkout_status.success() {
        return Err(anyhow!("git checkout failed for circomlib dependency"));
    }

    ensure_circomlib_clean(&circomlib_path)?;

    Ok(())
}

fn ensure_circomlib_clean(circomlib_path: &Path) -> Result<()> {
    let status = Command::new("git")
        .arg("-C")
        .arg(circomlib_path)
        .arg("status")
        .arg("--porcelain")
        .output()
        .map_err(|_| anyhow!("Error checking circomlib working tree status"))?;
    if !status.status.success() {
        bail!("git status failed for circomlib dependency");
    }

    if !status.stdout.is_empty() {
        bail!(
            "circuits/src/circomlib has local modifications. Reset it to circuits/circomlib.lock before building so circuit artifacts and witness graph manifests are reproducible."
        );
    }

    Ok(())
}

/// Compile WASM using Rust through Circom library
///
/// Compiles a Circom circuit to WebAssembly format for witness generation.
/// The process involves running the compiler, generating WAT (WebAssembly
/// Text), and converting it to WASM binary format.
///
/// # Arguments
///
/// * `entry_file` - Path to the main Circom circuit file
/// * `out_dir` - Output directory for generated WASM files
/// * `vcp` - Verified Circuit Program structure from the parsed circuit
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if compilation fails.
pub fn compile_wasm(entry_file: &Path, out_dir: &Path, vcp: VCP) -> Result<()> {
    let config = Config {
        produce_input_log: false,
        wat_flag: false,
        no_asm_flag: false,
        sanity_check_style: 0,
        debug_output: false,
    };

    let version = parse_circom_version("compiler")
        .ok_or_else(|| anyhow!("Could not parse Circom compiler version from Cargo.toml"))?;

    let circuit =
        run_compiler(vcp, config, &version).map_err(|e| anyhow!("run_compiler failed: {e:?}"))?;

    let base = entry_file
        .file_stem()
        .ok_or_else(|| anyhow!("Invalid circom filename"))?
        .to_string_lossy()
        .to_string();

    let js_folder = out_dir.join("wasm").join(format!("{base}_js"));
    let wat_file = js_folder.join(format!("{base}.wat"));
    let wasm_file = js_folder.join(format!("{base}.wasm"));

    if js_folder.exists() {
        fs::remove_dir_all(&js_folder)?;
    }
    fs::create_dir_all(&js_folder)?;

    write_wasm(
        &circuit,
        js_folder
            .to_str()
            .expect("Failed to convert js folder path to string"),
        &base,
        wat_file
            .to_str()
            .expect("Failed to convert wat file to str"),
    )
    .map_err(|_| anyhow!("write_wasm failed"))?;

    wat_to_wasm(&wat_file, &wasm_file)?;
    Ok(())
}

/// Convert WAT (WebAssembly Text) to WASM binary format
///
/// Parses a WAT file, encodes it as binary WASM, and writes the result.
/// The original WAT file is removed after successful conversion.
///
/// Modified by the Nethermind team.
/// Original source: https://github.com/iden3/circom/blob/0ecb2c7d154ed8ab72105a9b711815633ca761c5/circom/src/compilation_user.rs#L141
///
/// # Arguments
///
/// * `wat_file` - Path to the input WAT text file
/// * `wasm_file` - Path to the output WASM binary file
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if parsing, encoding, or writing
/// fails.
fn wat_to_wasm(wat_file: &Path, wasm_file: &Path) -> Result<()> {
    use std::{
        fs::File,
        io::{BufWriter, Write},
    };
    use wast::{
        Wat,
        parser::{self, ParseBuffer},
    };

    println!("cargo:warning= ===== wat_file {}...", wat_file.display());

    let wat_contents = fs::read_to_string(wat_file)
        .map_err(|e| anyhow!("read_to_string({}): {e}", wat_file.display()))?;

    // Fix legacy instructions generated by circom
    let wat_contents = wat_contents
        .replace("get_local", "local.get")
        .replace("set_local", "local.set")
        .replace("tee_local", "local.tee")
        .replace("get_global", "global.get")
        .replace("set_global", "global.set")
        // Conversion operators (The slash fix)
        .replace("i32.wrap/i64", "i32.wrap_i64")
        .replace("i64.extend_s/i32", "i64.extend_i32_s")
        .replace("i64.extend_u/i32", "i64.extend_i32_u")
        .replace("f32.convert_s/i32", "f32.convert_i32_s")
        .replace("f64.convert_s/i32", "f64.convert_i32_s")
        // Memory operators
        .replace("grow_memory", "memory.grow")
        .replace("current_memory", "memory.size");

    let buf =
        ParseBuffer::new(&wat_contents).map_err(|e| anyhow!("ParseBuffer::new failed: {e}"))?;

    let wat = parser::parse::<Wat>(&buf).map_err(|e| anyhow!("WAT parse failed: {e}"))?;

    let Wat::Module(mut module) = wat else {
        bail!("WAT {wat_file:?} should be a module");
    };

    let wasm_bytes = module
        .encode()
        .map_err(|e| anyhow!("WASM encode failed: {e}"))?;

    let f = File::create(wasm_file)
        .map_err(|e| anyhow!("File::create({}): {e}", wasm_file.display()))?;
    let mut w = BufWriter::new(f);
    w.write_all(&wasm_bytes)?;
    w.flush()?;

    fs::remove_file(wat_file).expect("Failed to remove WAT");
    Ok(())
}

// Groth16 Key Generation Utility Functions
/// Generate Groth16 proving and verification keys from circuit artifacts.
///
/// Performs a trusted setup for the circuit using random parameters.
///
/// # Arguments
///
/// * `wasm_path` - Path to the compiled WASM file for witness generation
/// * `r1cs_path` - Path to the R1CS constraint system file
///
/// # Returns
///
/// Returns `Ok((ProvingKey, VerifyingKey))` on success.
fn generate_groth16_keys(
    wasm_path: &Path,
    r1cs_path: &Path,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    let cfg =
        CircomConfig::new(wasm_path, r1cs_path).map_err(|e| anyhow!("CircomConfig error: {e}"))?;

    let builder = CircomBuilder::new(cfg);
    let empty = builder.setup();
    let mut rng = thread_rng();

    let (pk, vk) = Groth16::<Bn254, CircomReduction>::circuit_specific_setup(empty, &mut rng)
        .map_err(|e| anyhow!("circuit_specific_setup failed: {e}"))?;

    Ok((pk, vk))
}

/// Check if the essential Groth16 keys exist (the 3 files needed for
/// proving/verification).
///
/// Returns (all_exist, missing_files) where missing_files lists which are
/// absent.
fn check_essential_keys_exist(
    pk_path: &Path,
    vk_path: &Path,
    vk_soroban_path: &Path,
) -> (bool, Vec<&'static str>) {
    let mut missing = Vec::new();
    if !pk_path.exists() {
        missing.push("proving_key.bin");
    }
    if !vk_path.exists() {
        missing.push("vk.json");
    }
    if !vk_soroban_path.exists() {
        missing.push("vk_soroban.bin");
    }
    (missing.is_empty(), missing)
}

/// Check if Groth16 keys need to be regenerated.
///
/// Key regeneration is DANGEROUS after deployment because Groth16
/// keys are generated with random parameters. Regenerating keys will make
/// proofs incompatible with already-deployed contracts.
///
/// Returns (needs_generation, reason) where reason explains why regeneration is
/// needed.
fn check_keys_need_generation(
    pk_path: &Path,
    vk_path: &Path,
    vk_soroban_path: &Path,
    vk_const_path: &Path,
    r1cs_file: &Path,
    force_regen: bool,
) -> (bool, String) {
    // Check if essential key files exist (the 3 needed for proving/verification)
    let (essential_exist, missing) = check_essential_keys_exist(pk_path, vk_path, vk_soroban_path);

    if !essential_exist {
        // Essential files are missing - must generate
        return (
            true,
            format!("Missing essential key files: {}", missing.join(", ")),
        );
    }

    // Essential keys exist. Check if force regeneration was requested.
    if force_regen {
        return (
            true,
            "REGEN_KEYS=1 was set - forcing key regeneration".to_string(),
        );
    }

    // Essential keys exist and no force flag. Check if r1cs is newer (warning
    // only).
    if r1cs_file.exists()
        && let (Ok(r1cs_meta), Ok(pk_meta)) = (fs::metadata(r1cs_file), fs::metadata(pk_path))
        && let (Ok(r1cs_time), Ok(pk_time)) = (r1cs_meta.modified(), pk_meta.modified())
        && r1cs_time > pk_time
    {
        println!(
            "cargo:warning=WARNING: R1CS is newer than keys, but NOT regenerating to avoid breaking deployed contracts."
        );
        println!(
            "cargo:warning=If you need new keys (e.g., circuit changed), run: REGEN_KEYS=1 BUILD_TESTS=1 cargo build"
        );
        println!("cargo:warning=Then REDEPLOY contracts with the new verification key!");
    }

    // Note: vk_const.rs is optional (only for embedding VK in contracts).
    // We don't trigger regeneration just for this file since it would create
    // new incompatible keys. The user must explicitly use REGEN_KEYS=1.
    if !vk_const_path.exists() {
        println!("cargo:warning=Note: vk_const.rs is missing but essential keys exist - skipping");
        println!(
            "cargo:warning=Run REGEN_KEYS=1 BUILD_TESTS=1 cargo build if you need vk_const.rs"
        );
    }

    (
        false,
        "Essential keys exist and REGEN_KEYS not set".to_string(),
    )
}

/// Generate Groth16 keys if they don't exist or REGEN_KEYS=1 is set.
///
/// Set `REGEN_KEYS=1` environment variable to force regeneration (e.g., after
/// circuit changes). Redeployment of contracts will be needed after this.
///
/// # Arguments
///
/// * `crate_dir` - The circuits crate directory
/// * `out_dir` - The output directory containing WASM files
/// * `circuit_name` - Name of the circuit (e.g., `policy_tx_2_2`,
///   `selectiveDisclosure_1`)
/// * `r1cs_file` - Path to the R1CS file for freshness comparison
///
/// # Returns
///
/// Returns `Ok(true)` if keys were generated, `Ok(false)` if skipped,
/// or an error if generation failed critically.
fn generate_keys_if_needed(
    crate_dir: &Path,
    out_dir: &Path,
    circuit_name: &str,
    r1cs_file: &Path,
) -> Result<bool> {
    // Output keys to testdata/
    let keys_dir = crate_dir.join("../testdata");
    fs::create_dir_all(&keys_dir).context("Could not create testdata")?;

    let pk_path = keys_dir.join(format!("{circuit_name}_proving_key.bin"));
    let vk_path = keys_dir.join(format!("{circuit_name}_vk.json"));
    let vk_soroban_path = keys_dir.join(format!("{circuit_name}_vk_soroban.bin"));
    let vk_const_path = keys_dir.join(format!("{circuit_name}_vk_const.rs"));

    // Check for force regeneration flag
    let force_regen = env::var("REGEN_KEYS").is_ok();
    if force_regen {
        println!("cargo:warning=REGEN_KEYS=1 detected - will regenerate keys");
        println!("cargo:warning=WARNING: Remember to REDEPLOY contracts with the new VK!");
    }

    // Check if keys need regeneration
    let (needs_generation, reason) = check_keys_need_generation(
        &pk_path,
        &vk_path,
        &vk_soroban_path,
        &vk_const_path,
        r1cs_file,
        force_regen,
    );

    if !needs_generation {
        println!(
            "cargo:warning=Skipping key generation for {} ({})",
            circuit_name, reason
        );
        return Ok(false);
    }

    println!(
        "cargo:warning=Key generation needed for {}: {}",
        circuit_name, reason
    );

    // Check for WASM file
    let wasm_path = out_dir
        .join("wasm")
        .join(format!("{circuit_name}_js"))
        .join(format!("{circuit_name}.wasm"));

    if !wasm_path.exists() {
        // WASM is required for key generation - this is an error condition
        println!(
            "cargo:warning=ERROR: Cannot generate keys for {} - WASM file not found at {}",
            circuit_name,
            wasm_path.display()
        );
        println!("cargo:warning=This usually happens when:");
        println!("cargo:warning=  1. BUILD_TESTS=1 was not set (run: BUILD_TESTS=1 cargo build)");
        println!("cargo:warning=  2. WASM compilation failed earlier in the build");
        println!(
            "cargo:warning=  3. OUT_DIR was cleaned (try: cargo clean && BUILD_TESTS=1 cargo build)"
        );
        return Err(anyhow!(
            "WASM file not found for key generation: {}",
            wasm_path.display()
        ));
    }

    println!("cargo:warning=Generating Groth16 keys for {circuit_name}...");
    match generate_groth16_keys(&wasm_path, r1cs_file) {
        Ok((pk, vk)) => {
            // Write proving key (binary)
            if let Err(e) = write_proving_key(&pk, &pk_path) {
                println!("cargo:warning=Failed to write proving key: {e}");
            } else {
                println!("cargo:warning=Proving key written to {}", pk_path.display());
            }

            // Write verification key (snarkjs JSON format)
            if let Err(e) = write_verification_key(&vk, &vk_path) {
                println!("cargo:warning=Failed to write verification key JSON: {e}");
            } else {
                println!(
                    "cargo:warning=Verification key (snark JSON) written to {}",
                    vk_path.display()
                );
            }

            // Write verification key for Soroban binary format
            if let Err(e) = write_verification_key_soroban_bin(&vk, &vk_soroban_path) {
                println!("cargo:warning=Failed to write VK Soroban binary: {e}");
            } else {
                println!(
                    "cargo:warning=Verification key (Soroban bin) written to {}",
                    vk_soroban_path.display()
                );
            }

            // Write verification key (const Rust) for potential embedding in contract
            if let Err(e) = write_verification_key_rust_const(&vk, &vk_const_path) {
                println!("cargo:warning=Failed to write VK Rust const: {e}");
            } else {
                println!(
                    "cargo:warning=Verification key (Rust const) written to {}",
                    vk_const_path.display()
                );
            }

            println!(
                "cargo:warning=VK has {} IC points ({} public inputs)",
                vk.gamma_abc_g1.len(),
                vk.gamma_abc_g1.len().saturating_sub(1)
            );

            Ok(true)
        }
        Err(e) => {
            println!("cargo:warning=Failed to generate keys for {circuit_name}: {e}");
            Err(e)
        }
    }
}

/// Write the proving key to a binary file using compressed serialization.
fn write_proving_key(pk: &ProvingKey<Bn254>, path: &Path) -> Result<()> {
    circuit_keys::write_proving_key_bin(pk, path)
}

/// Write the verification key to a JSON file in snarkjs-compatible format.
fn write_verification_key(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
    circuit_keys::write_vk_snarkjs_json(vk, path)
}

/// Write the verification key as a Rust const file for embedding in contracts.
fn write_verification_key_rust_const(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
    circuit_keys::write_vk_rust_const(vk, path)
}

/// Write the verification key as binary Soroban-compatible format.
fn write_verification_key_soroban_bin(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
    circuit_keys::write_vk_soroban_bin(vk, path)
}
