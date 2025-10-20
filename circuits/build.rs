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
//! The output directory is exposed as en environment variable
//! `std::env::var("CIRCUIT_OUT_DIR")`

use anyhow::{Context, Result, anyhow};
use compiler::{
    compiler_interface::{Config, VCP, run_compiler, write_wasm},
    num_bigint::BigInt,
};
use constraint_generation::{BuildConfig, build_circuit};
use constraint_writers::ConstraintExporter;
use program_structure::error_definition::Report;
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

        if r1cs_file.exists() && sym_file.exists() {
            let source_modified = fs::metadata(&circom_file)?.modified()?;
            let r1cs_modified = fs::metadata(&r1cs_file)?.modified()?;
            let sym_modified = fs::metadata(&sym_file)?.modified()?;

            if source_modified < r1cs_modified && source_modified < sym_modified {
                println!(
                    "cargo:warning=Skipping {} (already compiled)",
                    circom_file.display()
                );
                continue;
            }
        }

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
            println!(
                "cargo:warning=Skipping in-process WASM generation for {:?}: {}",
                circom_file, e
            );
        }
    }

    Ok(())
}

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

fn generate_output_sym(file: &str, exporter: &dyn ConstraintExporter) -> Result<(), ()> {
    if let Ok(()) = exporter.sym(file) {
        println!("Written successfully: {file}");
        Ok(())
    } else {
        eprintln!("Could not write the output in the given path");
        Err(())
    }
}

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
                #[allow(clippy::arithmetic_side_effects)]
                let after_tag = &trimmed[tag_start + 7..]; // Skip 'tag = "'
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
            println!(
                "cargo:warning=circomlib already exists at {:?}",
                circomlib_path
            );
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

/// Compile wasm using rust through Circom lib
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

    let js_folder = out_dir.join("wasm").join(format!("{}_js", base));
    let wat_file = js_folder.join(format!("{}.wat", base));
    let wasm_file = js_folder.join(format!("{}.wasm", base));

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
        println!("cargo:warning=WAT → WASM compilation failed: {}", e);
        return Ok(());
    }
    Ok(())
}

/// Convert WAT to WASM
/// Modified by the Nethermind team
/// https://github.com/iden3/circom/blob/0ecb2c7d154ed8ab72105a9b711815633ca761c5/circom/src/compilation_user.rs#L141
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
