//! Circuit artifact compiler library.
//!
//! Circom sources live under workspace `circuits/`. This crate builds
//! R1CS / WASM / keys / witness graphs. The CLI entrypoint is
//! `bin/compiler.rs`.

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
use regex::Regex;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    string::ToString,
};
use type_analysis::check_types::check_types;

mod witness;

pub use witness::generate_witness_graph;

const CURVE_ID: &str = "bn128";

const SELECTIVE_DISCLOSURE_CIRCUITS: &[&str] = &[
    "selectiveDisclosure_1",
    "selectiveDisclosure_2",
    "selectiveDisclosure_3",
    "selectiveDisclosure_4",
];

/// Policy transaction circuits combined with Global View Key encryption. Each
/// of the 4 ASP policy configs is offered in view-only and traceable modes.
const POLICY_GLOBAL_VIEW_KEY_CIRCUITS: &[&str] = &[
    "policy_tx_gvk_2_2_viewonly",
    "policy_tx_gvk_2_2_traceable",
    "policy_tx_gvk_2_2_A_viewonly",
    "policy_tx_gvk_2_2_A_traceable",
    "policy_tx_gvk_2_2_B_viewonly",
    "policy_tx_gvk_2_2_B_traceable",
    "policy_tx_gvk_2_2_AB_viewonly",
    "policy_tx_gvk_2_2_AB_traceable",
];

fn circuit_needs_groth16_keys(name: &str, groth16_key_circuits: &[String]) -> bool {
    groth16_key_circuits.iter().any(|stem| stem == name)
}

fn groth16_key_circuits() -> Vec<String> {
    // Keep in sync with
    // `stellar_private_payments::types::PolicyFlags::all_stems`.
    let mut circuits = vec![
        "policy_tx_2_2".to_owned(),
        "policy_tx_2_2_A".to_owned(),
        "policy_tx_2_2_B".to_owned(),
        "policy_tx_2_2_AB".to_owned(),
    ];
    circuits.extend(
        SELECTIVE_DISCLOSURE_CIRCUITS
            .iter()
            .map(|stem| (*stem).to_owned()),
    );
    circuits.extend(
        POLICY_GLOBAL_VIEW_KEY_CIRCUITS
            .iter()
            .map(|stem| (*stem).to_owned()),
    );
    circuits
}

pub(crate) fn copy(src: &Path, dst: &Path) -> Result<()> {
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
) -> Result<()> {
    let r1cs_dst = publish_dir.join(format!("{circuit_name}.r1cs"));
    copy(r1cs_file, &r1cs_dst)?;

    if let Some(wasm_file) = wasm_file
        && wasm_file.exists()
    {
        let wasm_dst = publish_dir.join(format!("{circuit_name}.wasm"));
        copy(wasm_file, &wasm_dst)?;
    }

    Ok(())
}

/// Options for [`run`].
#[derive(Debug, Clone)]
pub struct CompileOptions {
    /// Circom package directory (`src/`, `circom.lock`, `circomlib.lock`).
    pub circuits: PathBuf,
    /// Directory for published R1CS/WASM/graphs (and compile intermediates
    /// under `out/`).
    pub out: PathBuf,
    /// Include `.circom` files under directories named `test`.
    pub tests: bool,
    /// Force Groth16 key regeneration even when keys already exist.
    pub regen_keys: bool,
    /// Regenerate witness graphs after a successful compile.
    pub graphs: bool,
}

/// Run the full compile pipeline (circomlib, R1CS/WASM, keys, optional graphs).
pub fn run(opts: CompileOptions) -> Result<()> {
    eprintln!(
        "Circuits builder Copyright (C) 2025 Stellar Development Foundation. This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it under certain conditions."
    );
    let circuits_dir = opts.circuits;
    let src_dir = circuits_dir.join("src");
    let publish_dir = opts.out;
    fs::create_dir_all(&publish_dir)
        .with_context(|| format!("Could not create {}", publish_dir.display()))?;

    // Circom scratch (R1CS/SYM/WASM js folders) under `--out/out`.
    let out_dir = publish_dir.join("out");
    fs::create_dir_all(&out_dir).context("Could not create circuit out dir")?;
    // Local Groth16 keys (gitignored), next to the circuits package.
    let testdata_dir = circuits_dir.join("..").join("testdata");

    let groth16_key_circuits = groth16_key_circuits();

    // === CIRCOMLIB DEPENDENCY ===
    // Import circomlib library (only if not already present) and pin it to the
    // revision in `circomlib.lock` for reproducible builds.
    get_circomlib(&circuits_dir, &src_dir)?;
    // The hints stay on disk after the build
    witness::inject_black_box_hints(&src_dir.join("circomlib"))?;

    // === FIND CIRCOM FILES ===
    // Find all .circom files with a main component
    let mut circom_files = find_circom_files(&src_dir);

    // Optionally include test circuits (`--tests`).
    // This includes both src/test/ and any other test directories (e.g.,
    // circomlib/test/)
    if opts.tests {
        eprintln!("Including test circuits in build...");
        circom_files = find_circom_files_impl(&src_dir, false);
    } else {
        eprintln!("Skipping test circuits (pass --tests to include)");
    }

    // Skip circom compilation if no files to compile
    if circom_files.is_empty() {
        eprintln!("No circom files found to compile");
        return Ok(());
    }

    // === COMPILE EACH CIRCUIT ===
    for circom_file in circom_files {
        // Output file
        let out_file = out_dir.join(circom_file.file_stem().context("Invalid circom filename")?);

        // Check if output files already exist and are newer than source
        let r1cs_file = out_file.with_extension("r1cs");
        let sym_file = out_file.with_extension("sym");

        // Hardcoded Values for BN128 (also known as BN254) and only R1CS and
        // SYM compilation
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
            parse_circom_version("compiler")
                .expect("Could not parse Circom compiler version")
                .as_str(),
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
        // We now extract all included files from the parsed circuit and check
        // if rebuild is needed This prevents situations where a circuit
        // is not updated, but its dependencies are
        let dependencies = extract_circom_dependencies(&circom_file, &circuits_dir)?;

        // Get circuit name for key generation check
        let circuit_name = circom_file
            .file_stem()
            .context("Invalid circom filename")?
            .to_string_lossy()
            .to_string();

        let wasm_path = out_dir
            .join("wasm")
            .join(format!("{circuit_name}_js"))
            .join(format!("{circuit_name}.wasm"));

        if r1cs_file.exists() && sym_file.exists() {
            let r1cs_modified = fs::metadata(&r1cs_file)?.modified()?;
            let sym_modified = fs::metadata(&sym_file)?.modified()?;
            let newest_artifact = r1cs_modified.max(sym_modified);

            // Check if any dependency (including the main file) is newer than
            // artifacts
            let needs_rebuild =
                check_dependencies_need_rebuild(&dependencies, &circom_file, newest_artifact)?;

            if !needs_rebuild {
                eprintln!(
                    "Skipping {} (already compiled, all dependencies up to date)",
                    circom_file.display()
                );

                // Keep deterministic publish directory updated even on "skip"
                // builds.
                if wasm_path.exists() {
                    if let Err(e) = publish_circuit_artifacts(
                        &publish_dir,
                        &circuit_name,
                        &r1cs_file,
                        Some(&wasm_path),
                    ) {
                        eprintln!("Failed to publish artifacts for {circuit_name}: {e}");
                    }
                } else {
                    // WASM missing: fall through so we can regenerate it
                    // instead of silently leaving the
                    // deterministic directory incomplete.
                    eprintln!(
                        "WASM missing for {} - recompiling to restore deterministic artifacts",
                        circuit_name
                    );
                }

                // Still check if we need to generate keys for circuits that
                // ship PK/VK under testdata/
                if circuit_needs_groth16_keys(circuit_name.as_str(), &groth16_key_circuits)
                    && wasm_path.exists()
                {
                    match generate_keys_if_needed(
                        &testdata_dir,
                        &out_dir,
                        &circuit_name,
                        &r1cs_file,
                        opts.regen_keys,
                    ) {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("Key generation failed: {e}");
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
        // Circom --O2. Must match circom-witness-rs graph gen.
        let build_config = BuildConfig {
            no_rounds: usize::MAX,
            flag_json_sub: false,
            json_substitutions: "Not used".to_string(),
            flag_s: false,
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
                eprintln!("WASM generation failed for {circom_file:?}: {e}");
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
        ) {
            eprintln!("Failed to publish artifacts for {circuit_name}: {e}");
        }

        // === GROTH16 Proving/Verifying key generation ===
        if circuit_needs_groth16_keys(circuit_name.as_str(), &groth16_key_circuits) {
            if !wasm_success {
                bail!(
                    "Skipping key generation for {} - WASM compilation failed",
                    circuit_name
                );
            } else {
                match generate_keys_if_needed(
                    &testdata_dir,
                    &out_dir,
                    &circuit_name,
                    &r1cs_file,
                    opts.regen_keys,
                ) {
                    Ok(generated) => {
                        if generated {
                            println!("Key generation completed for {}", circuit_name);
                        }
                    }
                    Err(e) => {
                        eprintln!("Key generation failed for {}: {}", circuit_name, e);
                    }
                }
            }
        }
    }

    if opts.graphs {
        witness::generate_witness_graphs(&circuits_dir, &publish_dir)?;
    }

    Ok(())
}

/// Recursively extract all .circom file dependencies by parsing all include
/// statements
///
/// # Arguments
///
/// * `main_file` - Circom file from where include dependencies will be parsed.
/// * `base_dir` - Base directory to look for other Circom dependencies
fn extract_circom_dependencies(main_file: &Path, base_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut dependencies = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut to_process = vec![main_file.to_path_buf()];

    // Precompute search directories for non-relative includes
    let search_dirs = vec![
        base_dir.to_path_buf(),
        base_dir.join("src"),
        base_dir.join("node_modules"),
    ];

    // Regex for Circom includes
    let include_pattern = Regex::new(r#"^\s*include\s+["']([^"']+)["']"#)?;

    while let Some(current_file) = to_process.pop() {
        if !visited.insert(current_file.clone()) {
            continue;
        }

        let content = fs::read_to_string(&current_file)?;

        for cap in include_pattern.captures_iter(&content) {
            let include_path = cap
                .get(1)
                .expect("No string matching the regex was found")
                .as_str();

            let resolved_path = resolve_include_path(
                include_path,
                current_file.parent().expect("No parent directory found"),
                &search_dirs,
            )?;

            if let Some(path) = resolved_path {
                dependencies.push(path.clone());
                to_process.push(path);
            }
        }
    }

    Ok(dependencies)
}

/// Resolve an include path to an absolute file path
///
/// Handles both relative paths (starting with `./` or `../`) and library paths
/// by searching in the provided search directories.
///
/// # Arguments
///
/// * `include_path` - The include path string from the Circom file
/// * `current_dir` - Directory of the file containing the include statement
/// * `search_dirs` - List of directories to search for non-relative includes
///
/// # Returns
///
/// Returns `Ok(Some(PathBuf))` if the path is found and resolved, `Ok(None)` if
/// not found, or an error if file system operations fail.
fn resolve_include_path(
    include_path: &str,
    current_dir: &Path,
    search_dirs: &[PathBuf],
) -> Result<Option<PathBuf>> {
    // Relative paths
    if include_path.starts_with("./") || include_path.starts_with("../") {
        let path = current_dir.join(include_path);
        if path.exists() {
            return Ok(Some(path.canonicalize()?));
        }
    } else {
        // Search in library directories
        for dir in search_dirs {
            let path = dir.join(include_path);
            if path.exists() {
                return Ok(Some(path.canonicalize()?));
            }
        }
    }

    // Not found
    eprintln!("Warning: Could not resolve include: {include_path}");
    Ok(None)
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
            eprintln!(
                "File {} is newer than artifacts, rebuilding...",
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
            eprintln!("Failed to read file {file_path:?}: {e}");
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

/// Parse the Circom compiler version from this crate's Cargo.toml
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
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let cargo_toml = match fs::read_to_string(&manifest) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Failed to read {}: {e}", manifest.display());
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

/// Imports the circomlib dependency without adding any Javascript dependency.
///
/// We clone the circomlib repository into the provided repository.
///
/// # Arguments
/// * `directory` - path in which the Circomlib dependency will be cloned.
///
/// # Returns
/// Returns exit status of the import procedure
fn get_circomlib(circuits_dir: &Path, src_dir: &Path) -> Result<()> {
    let circomlib_path = src_dir.join("circomlib");
    let locked_rev = fs::read_to_string(circuits_dir.join("circomlib.lock"))
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
            eprintln!("circomlib already at locked revision {locked_rev}");
            return Ok(());
        }
    }

    eprintln!("Fetching circomlib revision {locked_rev}...");
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
        .arg("--force")
        .arg("--detach")
        .arg("FETCH_HEAD")
        .status()
        .map_err(|_| anyhow!("Error checking out circomlib dependency"))?;
    if !checkout_status.success() {
        return Err(anyhow!("git checkout failed for circomlib dependency"));
    }

    witness::inject_black_box_hints(&circomlib_path)?;
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

    eprintln!(" ===== wat_file {}...", wat_file.display());

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
    // Check if essential key files exist (the 3 needed for
    // proving/verification)
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
            "--regen-keys was set - forcing key regeneration".to_string(),
        );
    }

    // Essential keys exist and no force flag. Check if r1cs is newer (warning
    // only).
    if r1cs_file.exists()
        && let (Ok(r1cs_meta), Ok(pk_meta)) = (fs::metadata(r1cs_file), fs::metadata(pk_path))
        && let (Ok(r1cs_time), Ok(pk_time)) = (r1cs_meta.modified(), pk_meta.modified())
        && r1cs_time > pk_time
    {
        eprintln!(
            "WARNING: R1CS is newer than keys, but NOT regenerating to avoid breaking deployed contracts."
        );
        eprintln!(
            "If you need new keys (e.g., circuit changed), run: make circuits TESTS=1 REGEN_KEYS=1"
        );
        eprintln!("Then REDEPLOY contracts with the new verification key!");
    }

    // Note: vk_const.rs is optional (only for embedding VK in contracts).
    // We don't trigger regeneration just for this file since it would create
    // new incompatible keys. The user must explicitly use `--regen-keys`.
    if !vk_const_path.exists() {
        eprintln!("Note: vk_const.rs is missing but essential keys exist - skipping");
        eprintln!("Run `make circuits TESTS=1 REGEN_KEYS=1` if you need vk_const.rs");
    }

    (
        false,
        "Essential keys exist and --regen-keys was not set".to_string(),
    )
}

/// Generate Groth16 keys if they don't exist or `--regen-keys` is set.
///
/// Redeployment of contracts will be needed after forced regeneration.
///
/// # Arguments
///
/// * `testdata_dir` - Directory for generated Groth16 keys
/// * `out_dir` - Scratch dir containing WASM files
/// * `circuit_name` - Name of the circuit (e.g., `policy_tx_2_2_AB`,
///   `selectiveDisclosure_1`)
/// * `r1cs_file` - Path to the R1CS file for freshness comparison
/// * `force_regen` - Force key regeneration even if keys already exist
///
/// # Returns
///
/// Returns `Ok(true)` if keys were generated, `Ok(false)` if skipped,
/// or an error if generation failed critically.
fn generate_keys_if_needed(
    testdata_dir: &Path,
    out_dir: &Path,
    circuit_name: &str,
    r1cs_file: &Path,
    force_regen: bool,
) -> Result<bool> {
    fs::create_dir_all(testdata_dir).context("Could not create testdata")?;

    let pk_path = testdata_dir.join(format!("{circuit_name}_proving_key.bin"));
    let vk_path = testdata_dir.join(format!("{circuit_name}_vk.json"));
    let vk_soroban_path = testdata_dir.join(format!("{circuit_name}_vk_soroban.bin"));
    let vk_const_path = testdata_dir.join(format!("{circuit_name}_vk_const.rs"));

    if force_regen {
        eprintln!("--regen-keys set - will regenerate keys");
        eprintln!("WARNING: Remember to REDEPLOY contracts with the new VK!");
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
        eprintln!("Skipping key generation for {} ({})", circuit_name, reason);
        return Ok(false);
    }

    println!("Key generation needed for {}: {}", circuit_name, reason);

    // Check for WASM file
    let wasm_path = out_dir
        .join("wasm")
        .join(format!("{circuit_name}_js"))
        .join(format!("{circuit_name}.wasm"));

    if !wasm_path.exists() {
        // WASM is required for key generation - this is an error condition
        eprintln!(
            "ERROR: Cannot generate keys for {} - WASM file not found at {}",
            circuit_name,
            wasm_path.display()
        );
        eprintln!("This usually happens when:");
        eprintln!("  1. --tests was not set (run: make circuits TESTS=1)");
        eprintln!("  2. WASM compilation failed earlier in the build");
        eprintln!("  3. circuit artifacts were cleaned (try: make circuits TESTS=1)");
        return Err(anyhow!(
            "WASM file not found for key generation: {}",
            wasm_path.display()
        ));
    }

    eprintln!("Generating Groth16 keys for {circuit_name}...");
    match generate_groth16_keys(&wasm_path, r1cs_file) {
        Ok((pk, vk)) => {
            // Write proving key (binary)
            if let Err(e) = write_proving_key(&pk, &pk_path) {
                eprintln!("Failed to write proving key: {e}");
            } else {
                eprintln!("Proving key written to {}", pk_path.display());
            }

            // Write verification key (snarkjs JSON format)
            if let Err(e) = write_verification_key(&vk, &vk_path) {
                eprintln!("Failed to write verification key JSON: {e}");
            } else {
                eprintln!(
                    "Verification key (snark JSON) written to {}",
                    vk_path.display()
                );
            }

            // Write verification key for Soroban binary format
            if let Err(e) = write_verification_key_soroban_bin(&vk, &vk_soroban_path) {
                eprintln!("Failed to write VK Soroban binary: {e}");
            } else {
                eprintln!(
                    "Verification key (Soroban bin) written to {}",
                    vk_soroban_path.display()
                );
            }

            // Write verification key (const Rust) for potential embedding in
            // contract
            if let Err(e) = write_verification_key_rust_const(&vk, &vk_const_path) {
                eprintln!("Failed to write VK Rust const: {e}");
            } else {
                eprintln!(
                    "Verification key (Rust const) written to {}",
                    vk_const_path.display()
                );
            }

            eprintln!(
                "VK has {} IC points ({} public inputs)",
                vk.gamma_abc_g1.len(),
                vk.gamma_abc_g1.len().saturating_sub(1)
            );

            Ok(true)
        }
        Err(e) => {
            eprintln!("Failed to generate keys for {circuit_name}: {e}");
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
