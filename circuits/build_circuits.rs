//! Build script for compiling Circom circuits
//!
//! This build script automatically compiles all `.circom` files in the `src/` directory
//! into R1CS constraint systems, WebAssembly files, and symbol files. It also handles
//! the setup of circomlib dependencies and can optionally generate proving and verification
//! keys when the "setup" feature is enabled.
//!
//! ## Usage
//!
//! The build script runs automatically when you run `cargo build`. It will:
//! 1. Set up circomlib dependencies via npm
//! 2. Find all `.circom` files in the `src/` directory
//! 3. Compile each circuit using the circom compiler
//! 4. Generate proving keys if the "setup" feature is enabled
//!
//! ## Requirements
//!
//! - circom compiler must be installed and available in PATH
//! - npm must be installed for dependency management
//! - snarkjs must be installed if using the "setup" feature

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::current_dir().expect("Wrong current directory");
    let src_dir = Path::new("src");
    let compiled_dir = Path::new(&out_dir).join("compiled");

    // Create an output directory
    fs::create_dir_all(&compiled_dir).expect("Could not create output directory");

    // Ensure circomlib dependencies are installed
    setup_circomlib_dependencies();

    // Find all .circom files with a main component in the src folder
    let circom_files = find_circom_files(src_dir);

    for circom_file in circom_files {
        compile_circuit(&circom_file, &compiled_dir);
    }

    #[cfg(feature = "setup")]
    setup_proving_keys(&compiled_dir);
}

fn find_circom_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut circom_files = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "circom") {
                // Check if the file contains a main component
                if has_main_component(&path) {
                    circom_files.push(path);
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

            // Check for main component in the file
            content_lower.contains("component main ")
        }
        Err(e) => {
            println!("cargo:warning=Failed to read file {file_path:?}: {e}");
            false
        }
    }
}

fn setup_circomlib_dependencies() {
    let package_json = Path::new("package.json");
    let node_modules = Path::new("node_modules");

    // Create package.json if it doesn't exist
    if !package_json.exists() {
        let package_content = r#"{
          "name": "circuits-dependencies",
          "version": "1.0.0",
          "dependencies": {
            "circomlib": "^2.0.5"
          }
        }"#;
        fs::write(package_json, package_content).expect("Failed to create package.json");
    }

    // Install dependencies if node_modules doesn't exist or is outdated
    if !node_modules.exists() || is_package_outdated() {
        let status = Command::new("npm")
            .arg("install")
            .arg("--silent")
            .status()
            .expect("Failed to execute npm install. Ensure npm is installed.");

        if !status.success() {
            panic!("npm install failed");
        }
    }

    // Verify circomlib is available
    let circomlib_path = node_modules.join("circomlib");
    if !circomlib_path.exists() {
        panic!("circomlib not found in node_modules");
    }
}

fn is_package_outdated() -> bool {
    let package_json = Path::new("package.json");
    let package_lock = Path::new("package-lock.json");

    if !package_lock.exists() {
        return true;
    }

    let package_modified = package_json
        .metadata()
        .and_then(|m| m.modified())
        .unwrap_or(std::time::UNIX_EPOCH);

    let lock_modified = package_lock
        .metadata()
        .and_then(|m| m.modified())
        .unwrap_or(std::time::UNIX_EPOCH);

    package_modified > lock_modified
}

fn compile_circuit(circom_file: &Path, output_dir: &Path) {
    let file_stem = circom_file
        .file_stem()
        .expect("No Circom file extension")
        .to_str()
        .expect("Filename should be a string");
    let r1cs_path = output_dir.join(format!("{file_stem}.r1cs"));
    let wasm_path = output_dir.join(format!("{file_stem}_js/{file_stem}.wasm"));
    let sym_path = output_dir.join(format!("{file_stem}.sym"));

    // Compile circuit with circomlib include path
    let mut cmd = Command::new("circom");
    cmd.arg(circom_file)
        .arg("--r1cs")
        .arg("--wasm")
        .arg("--sym")
        .arg("--output")
        .arg(output_dir)
        .arg("--prime")
        .arg("bls12381"); // Targeting BLS12-381

    println!("cargo:warning= Running compilation for: {circom_file:?}");
    let status = cmd
        .status()
        .expect("cargo:warning= Failed to execute circom compiler");

    if !status.success() {
        println!("cargo:warning=NOT SUCCESS: {circom_file:?}");
        panic!(
            "cargo:warning= Circuit compilation failed for: {}",
            circom_file.display()
        );
    }

    // Verify outputs exist
    assert!(r1cs_path.exists(), "R1CS file not generated");
    assert!(wasm_path.exists(), "WASM file not generated");
    assert!(sym_path.exists(), "SYM file not generated");
}

#[cfg(feature = "setup")]
fn setup_proving_keys(output_dir: &Path) {
    println!("cargo:warning= Setting up proving keys");
    // Initiate powers of tau
    // Check if the initial power of tau generation was already done.
    let powers_path = output_dir.join("pot_0001.ptau");
    // Set working directory
    env::set_current_dir(output_dir).expect("Wrong output directory");
    if !powers_path.exists() {
        // Generate initial powers of Tau
        let degree = 14; // TODO: Update max required degree to be read from the circuit R1CS
        let status = Command::new("snarkjs")
            .args(["powersoftau", "new", "BLS12381"])
            .arg(degree.to_string())
            .arg("pot_0000.ptau")
            .status()
            .expect("Failed to execute snarkjs ptn new");

        if !status.success() {
            panic!("Powers of Tau generation failed");
        }

        // Make a single mockup contribution to the ceremony
        let status = Command::new("snarkjs")
            .args(["powersoftau", "contribute", "pot_0000.ptau"])
            .arg("pot_0001.ptau")
            .arg("--name=First contribution")
            .status()
            .expect("Failed to execute snarkjs ptn contribute");

        if !status.success() {
            panic!("Powers of Tau contribution failed");
        }
    }

    // Generate proving and verification keys using snarkjs
    let circuits = find_compiled_circuits(output_dir);
    println!("cargo:warning= Found {} compiled circuits", circuits.len());
    for circuit in circuits {
        generate_keys(&circuit, output_dir);
    }
}

#[cfg(feature = "setup")]
fn find_compiled_circuits(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut r1cs_files = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "r1cs") {
                r1cs_files.push(path);
            }
        }
    }

    r1cs_files
}

#[cfg(feature = "setup")]
fn generate_keys(r1cs_file: &Path, output_dir: &Path) {
    let file_stem = r1cs_file
        .file_stem()
        .expect("No R1CS file extension")
        .to_str()
        .expect("Filename should be a string");
    let zkey_path = output_dir.join(format!("{file_stem}.zkey"));
    let vkey_path = output_dir.join(format!("{file_stem}_verification_key.json"));

    if !zkey_path.exists() {
        // This part build on the previous powers of tau ceremony, but it is circuit-specific
        let status = Command::new("snarkjs")
            .args(["powersoftau", "prepare", "phase2", "pot_0001.ptau"])
            .arg("pot_final.ptau") // Powers of tau file
            .status()
            .expect("Failed to execute snarkjs setup");

        if !status.success() {
            panic!(
                "Phase 2 of powers of tau failed for: {}",
                r1cs_file.display()
            );
        }

        // Generate a proving key
        let status = Command::new("snarkjs")
            .args(["groth16", "setup"])
            .arg(r1cs_file)
            .arg("pot_final.ptau")
            .arg(&zkey_path)
            .status()
            .expect("Failed to execute snarkjs setup");
        if !status.success() {
            panic!("Proving key generation failed for: {}", r1cs_file.display());
        }

        // Export verification key
        let status = Command::new("snarkjs")
            .args(["zkey", "export", "verificationkey"])
            .arg(&zkey_path)
            .arg(&vkey_path)
            .status()
            .expect("Failed to export verification key");

        if !status.success() {
            panic!(
                "Verification key export failed for: {}",
                r1cs_file.display()
            );
        }
    }
}
