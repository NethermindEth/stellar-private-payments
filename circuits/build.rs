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
//! The script also generates Groth16 proving and verification
//! keys for the main test circuit (compliant_test) and outputs them to `scripts/testdata/`.
//!
//! The output directory is exposed as en environment variable
//! `std::env::var("CIRCUIT_OUT_DIR")`

use anyhow::{Context, Result, anyhow};
use ark_bn254::{Bn254, Fq, G1Affine, G2Affine};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
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
use serde_json::{Value, json};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    string::ToString,
};
use type_analysis::check_types::check_types;

const CURVE_ID: &str = "bn128";

fn main() -> Result<()> {
    // === PATH SETUP ===
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let src_dir = crate_dir.join("src");

    // Put build artifacts under OUT_DIR/circuits
    let out_dir = PathBuf::from(env::var("OUT_DIR")?).join("circuits");
    fs::create_dir_all(&out_dir).context("Could not create OUT_DIR/circuits")?;

    // Expose the path to your runtime/tests
    println!("cargo:rustc-env=CIRCUIT_OUT_DIR={}", out_dir.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=BUILD_TESTS");

    // === CIRCOMLIB DEPENDENCY ===
    // Import circomlib library (only if not already present)
    get_circomlib(&src_dir)?;

    // === FIND CIRCOM FILES ===
    // Find all .circom files with a main component
    let mut circom_files = find_circom_files(&src_dir);

    // Optionally include test circuits when BUILD_TESTS=1
    let build_tests = env::var("BUILD_TESTS").is_ok();
    if build_tests {
        println!("cargo:warning=Including test circuits in build...");
        circom_files.extend(find_circom_files(&crate_dir.join("src/test")));
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
        // We now extract all included files from the parsed circuit and check if rebuild is needed
        // This prevents situations where a circuit is not updated, but its dependencies are
        let dependencies = extract_circom_dependencies(&circom_file, &crate_dir)?;
        for dep_path in &dependencies {
            // Register each dependency file with cargo so it knows to rebuild when they change
            println!("cargo:rerun-if-changed={}", dep_path.display());
        }

        // Get circuit name for key generation check
        let circuit_name = circom_file
            .file_stem()
            .context("Invalid circom filename")?
            .to_string_lossy()
            .to_string();

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

                // Still check if we need to generate keys for compliant_test
                if circuit_name == "compliant_test" {
                    generate_keys_if_needed(&crate_dir, &out_dir, &circuit_name, &r1cs_file)?;
                }
                continue;
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

        if let Err(e) = compile_wasm(&circom_file, &out_dir, vcp) {
            println!("cargo:warning=Skipping in-process WASM generation for {circom_file:?}: {e}");
        }

        // === GROTH16 Proving/Verifying key generation for test circuits ===
        // For now we only generate keys for the compliant test circuit.
        if circuit_name == "compliant_test" {
            generate_keys_if_needed(&crate_dir, &out_dir, &circuit_name, &r1cs_file)?;
        }
    }

    Ok(())
}

/// Recursively extract all .circom file dependencies by parsing all include statements
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
/// Returns `Ok(Some(PathBuf))` if the path is found and resolved, `Ok(None)` if not found,
/// or an error if file system operations fail.
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
///
/// # Returns
///
/// Returns a vector of paths to Circom files that contain a main component.
fn find_circom_files(dir: &Path) -> Vec<PathBuf> {
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
                circom_files.extend(find_circom_files(&path));
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

/// Imports the circomlib dependency without adding any Javascript dependency.
///
/// We clone the circomlib repository into the provided repository.
///
/// # Arguments
/// * `directory` - path in which the Circomlib dependency will be cloned.
///
/// # Returns
/// Returns exit status of the import procedure
fn get_circomlib(directory: &Path) -> Result<ExitStatus> {
    let circomlib_path = directory.join("circomlib");

    // Check if circomlib already exists and is a valid git repository
    if circomlib_path.exists() {
        // Verify it's a valid git repository by checking for .git directory
        if circomlib_path.join(".git").exists() {
            println!("cargo:warning=circomlib already exists at {circomlib_path:?}");
            return Ok(ExitStatus::default());
        } else {
            // Remove invalid directory and re-clone
            fs::remove_dir_all(&circomlib_path)?;
        }
    }

    // Clone the circomlib repository
    println!("cargo:warning=Cloning circomlib repository...");
    Command::new("git")
        .arg("clone")
        .arg("--depth=1") // Shallow clone to reduce size of build
        .arg("https://github.com/iden3/circomlib.git")
        .arg(&circomlib_path)
        .status()
        .map_err(|_| anyhow!("Error cloning circomlib dependency"))
}

/// Compile WASM using Rust through Circom library
///
/// Compiles a Circom circuit to WebAssembly format for witness generation.
/// The process involves running the compiler, generating WAT (WebAssembly Text),
/// and converting it to WASM binary format.
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
        constraint_assert_disabled_flag: false,
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

    if let Err(e) = wat_to_wasm(&wat_file, &wasm_file) {
        println!("cargo:warning=WAT → WASM compilation failed: {e}");
    }
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
/// Returns `Ok(())` on success, or an error if parsing, encoding, or writing fails.
fn wat_to_wasm(wat_file: &Path, wasm_file: &Path) -> Result<()> {
    use std::{
        fs::File,
        io::{BufWriter, Write},
    };
    use wast::{
        Wat,
        parser::{self, ParseBuffer},
    };

    let wat_contents = fs::read_to_string(wat_file)
        .map_err(|e| anyhow!("read_to_string({}): {e}", wat_file.display()))?;

    let buf =
        ParseBuffer::new(&wat_contents).map_err(|e| anyhow!("ParseBuffer::new failed: {e}"))?;

    let mut wat = parser::parse::<Wat>(&buf).map_err(|e| anyhow!("WAT parse failed: {e}"))?;

    let wasm_bytes = wat
        .module
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

/// Generate Groth16 keys if they don't exist or are older than the R1CS file.
///
/// This function checks if the proving and verification keys exist and are up-to-date.
/// If not, it generates new keys and writes them to the `scripts/testdata/` directory.
///
/// # Arguments
///
/// * `crate_dir` - The circuits crate directory
/// * `out_dir` - The output directory containing WASM files
/// * `circuit_name` - Name of the circuit (e.g., "compliant_test")
/// * `r1cs_file` - Path to the R1CS file for freshness comparison
fn generate_keys_if_needed(
    crate_dir: &Path,
    out_dir: &Path,
    circuit_name: &str,
    r1cs_file: &Path,
) -> Result<()> {
    // Output keys to scripts/testdata/
    let keys_dir = crate_dir.join("../scripts/testdata");
    fs::create_dir_all(&keys_dir).context("Could not create scripts/testdata")?;

    let pk_path = keys_dir.join(format!("{circuit_name}_proving_key.bin"));
    let vk_path = keys_dir.join(format!("{circuit_name}_vk.json"));

    // Check if keys already exist and are newer than the r1cs
    if pk_path.exists() && vk_path.exists() && r1cs_file.exists() {
        let pk_modified = fs::metadata(&pk_path)?.modified()?;
        let vk_modified = fs::metadata(&vk_path)?.modified()?;
        let r1cs_modified = fs::metadata(r1cs_file)?.modified()?;

        if pk_modified > r1cs_modified && vk_modified > r1cs_modified {
            println!(
                "cargo:warning=Skipping key generation for {} (keys up to date)",
                circuit_name
            );
            return Ok(());
        }
    }

    // Generate keys
    let wasm_path = out_dir
        .join("wasm")
        .join(format!("{circuit_name}_js"))
        .join(format!("{circuit_name}.wasm"));

    if !wasm_path.exists() {
        println!(
            "cargo:warning=Skipping key generation for {} (WASM not found at {})",
            circuit_name,
            wasm_path.display()
        );
        return Ok(());
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

            // Write verification key (JSON)
            if let Err(e) = write_verification_key(&vk, &vk_path) {
                println!("cargo:warning=Failed to write verification key: {e}");
            } else {
                println!(
                    "cargo:warning=Verification key written to {}",
                    vk_path.display()
                );
            }
        }
        Err(e) => {
            println!("cargo:warning=Failed to generate keys for {circuit_name}: {e}");
        }
    }

    Ok(())
}

/// Write the proving key to a binary file using compressed serialization.
///
/// # Arguments
///
/// * `pk` - The proving key to serialize
/// * `path` - Output file path
fn write_proving_key(pk: &ProvingKey<Bn254>, path: &Path) -> Result<()> {
    // Serialize to Vec<u8>
    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)
        .map_err(|e| anyhow!("Failed to serialize proving key: {e}"))?;
    fs::write(path, &bytes).context("Failed to write proving key file")?;
    Ok(())
}

/// Write the verification key to a JSON file in snarkjs-compatible format.
///
/// # Arguments
///
/// * `vk` - The verification key to serialize
/// * `path` - Output file path
fn write_verification_key(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
    let vk_json = vk_to_snarkjs_json(vk);
    let json_str = serde_json::to_string_pretty(&vk_json)?;
    fs::write(path, json_str).context("Failed to write verification key")?;
    Ok(())
}

/// Convert an ark-groth16 VerifyingKey to snarkjs-compatible JSON format.
fn vk_to_snarkjs_json(vk: &VerifyingKey<Bn254>) -> Value {
    json!({
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": vk.gamma_abc_g1.len().saturating_sub(1),
        "vk_alpha_1": g1_to_snarkjs(&vk.alpha_g1),
        "vk_beta_2": g2_to_snarkjs(&vk.beta_g2),
        "vk_gamma_2": g2_to_snarkjs(&vk.gamma_g2),
        "vk_delta_2": g2_to_snarkjs(&vk.delta_g2),
        "IC": vk.gamma_abc_g1.iter().map(g1_to_snarkjs).collect::<Vec<_>>()
    })
}

/// Convert a G1Affine point to snarkjs JSON format.
fn g1_to_snarkjs(p: &G1Affine) -> Value {
    json!([fq_to_decimal(&p.x), fq_to_decimal(&p.y), "1"])
}

/// Convert a G2Affine point to snarkjs JSON format.
fn g2_to_snarkjs(p: &G2Affine) -> Value {
    json!([
        [fq_to_decimal(&p.x.c0), fq_to_decimal(&p.x.c1)],
        [fq_to_decimal(&p.y.c0), fq_to_decimal(&p.y.c1)],
        ["1", "0"]
    ])
}

/// Convert an Fq field element to a decimal string.
fn fq_to_decimal(f: &Fq) -> String {
    let bigint = f.into_bigint();
    let bytes = bigint.to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}
