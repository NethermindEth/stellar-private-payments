//! Build script for compiling Circom circuits
//!
//! This build script automatically compiles all `.circom` files in the `src/` directory
//! into R1CS constraint systems and symbol files.
//!
//! ## Usage
//! The build script runs automatically when you run `cargo build`. It will:
//! 1. Find all `.circom` files in `src/` directory
//! 2. Compile each circuit using the circom compiler

use anyhow::{anyhow, Context, Result};
use compiler::num_bigint::BigInt;
use constraint_generation::{build_circuit, BuildConfig};
use constraint_writers::ConstraintExporter;
use program_structure::error_definition::Report;
use std::{
    env, fs,
    path::{Path, PathBuf},
    string::ToString,
};
use std::process::{Command, ExitStatus};
use type_analysis::check_types::check_types;

fn main() -> Result<()> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR")?;
    let crate_dir = PathBuf::from(crate_dir);
    let src_dir = crate_dir.join("src");
    let out_dir = crate_dir.join("compiled");

    // Create an output directory
    fs::create_dir_all(&out_dir).expect("Could not create output directory");
    
    // Import circomlib library
    get_circomlib(&src_dir)?;

    // Find all .circom files with a main component
    let circom_files = find_circom_files(&src_dir);

    for circom_file in circom_files {
        // Output file
        let out_file = out_dir.join(circom_file.file_stem().context("Invalid circom filename")?);

        // Hardcoded Values for BN128 (also known as BN254) and only R1CS and SYM compilation
        let prime = BigInt::parse_bytes(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617"
                .as_bytes(),
            10,
        )
        .expect("Can not parse  BN128 prime");
        let flag_no_init = false;

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

        let report_warns = check_types(&mut program_archive).map_err(|report_errors| {
            Report::print_reports(&report_errors, program_archive.get_file_library());
            anyhow!("{}", report_errors[0].get_message())
        })?;
        Report::print_reports(&report_warns, program_archive.get_file_library());

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
            prime: "bn128".to_string(),
        };

        let custom_gates = program_archive.custom_gates;
        let (exporter, _) = build_circuit(program_archive, build_config)
            .map_err(|_| anyhow!("Error building circuit"))?;
        // Generate code
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
    }

    // Tell cargo to rerun if anything changes
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}

fn find_circom_files(dir: &Path) -> Vec<PathBuf> {
    let mut circom_files = Vec::new();

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

fn get_circomlib(directory: &PathBuf) -> Result<ExitStatus> {
    let circomlib_path = directory.join("circomlib");
    
    // Check if circomlib already exists
    if circomlib_path.exists() {
        println!("cargo:warning=circomlib already exists at {:?}", circomlib_path);
        return Ok(ExitStatus::default());
    }
    
    // Clone the circomlib repository
    Command::new("git")
        .arg("clone")
        .arg("https://github.com/iden3/circomlib.git")
        .arg(&circomlib_path)
        .status()
        .map_err(|_| anyhow!("Error cloning circomlib depedency"))
}