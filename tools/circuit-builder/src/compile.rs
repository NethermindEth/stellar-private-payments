//! Circom front end: parse, type-check, and emit R1CS / SYM / WASM.

use anyhow::{Context, Result, anyhow, bail};
use compiler::{
    compiler_interface::{Config, VCP, run_compiler, write_wasm},
    num_bigint::BigInt,
};
use constraint_generation::{BuildConfig, build_circuit};
use program_structure::{
    error_code::ReportCode, error_definition::Report, program_archive::ProgramArchive,
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use type_analysis::check_types::check_types;

pub const CURVE_ID: &str = "bn128";

const BN254_PRIME: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Artifacts produced for one circuit inside the work directory.
pub struct Artifacts {
    pub r1cs: PathBuf,
    pub sym: PathBuf,
    pub wasm: PathBuf,
}

/// Where the artifacts for `stem` live under `work_dir`.
pub fn artifact_paths(work_dir: &Path, stem: &str) -> Artifacts {
    Artifacts {
        r1cs: work_dir.join(format!("{stem}.r1cs")),
        sym: work_dir.join(format!("{stem}.sym")),
        wasm: work_dir
            .join("wasm")
            .join(format!("{stem}_js"))
            .join(format!("{stem}.wasm")),
    }
}

/// Parse `circom_file` and report whether it is a circuit entry point.
///
/// `Ok(None)` means the file declares no `component main`, so it is a template
/// that other circuits include rather than a circuit of its own. That verdict
/// comes from the compiler itself: `run_parser` answers with the distinct
/// `NoMainFoundInProject` code, which a substring search over the source cannot
/// distinguish from the same words inside a comment.
pub fn parse(circom_file: &Path, version: &str) -> Result<Option<ProgramArchive>> {
    let prime = BigInt::parse_bytes(BN254_PRIME.as_bytes(), 10).expect("BN254 prime must parse");
    let flag_no_init = false;

    match parser::run_parser(
        circom_file.to_string_lossy().to_string(),
        version,
        vec![],
        &prime,
        flag_no_init,
    ) {
        Ok((program_archive, report_warns)) => {
            Report::print_reports(&report_warns, &program_archive.file_library);
            Ok(Some(program_archive))
        }
        Err((file_library, reports)) => {
            if reports
                .iter()
                .any(|r| matches!(r.get_code(), ReportCode::NoMainFoundInProject))
            {
                return Ok(None);
            }
            Report::print_reports(&reports, &file_library);
            Err(anyhow!("parser failed on {}", circom_file.display()))
        }
    }
}

/// Compile a parsed entry point into `work_dir`.
pub fn compile(
    mut program_archive: ProgramArchive,
    stem: &str,
    work_dir: &Path,
    version: &str,
) -> Result<Artifacts> {
    let out = artifact_paths(work_dir, stem);

    let report_warns = check_types(&mut program_archive).map_err(|report_errors| {
        Report::print_reports(&report_errors, program_archive.get_file_library());
        anyhow!("{}", report_errors[0].get_message())
    })?;
    Report::print_reports(&report_warns, program_archive.get_file_library());

    // Circom --O2. Must match circom-witness-rs graph generation.
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

    let custom_gates = program_archive.custom_gates;
    let (exporter, vcp) = build_circuit(program_archive, build_config)
        .map_err(|_| anyhow!("error building {stem}"))?;

    let r1cs = out.r1cs.to_str().context("invalid R1CS output path")?;
    exporter
        .r1cs(r1cs, custom_gates)
        .map_err(|_| anyhow!("could not write {r1cs}"))?;

    let sym = out.sym.to_str().context("invalid SYM output path")?;
    exporter
        .sym(sym)
        .map_err(|_| anyhow!("could not write {sym}"))?;

    compile_wasm(stem, work_dir, vcp, version)
        .with_context(|| format!("WASM generation failed for {stem}"))?;

    Ok(out)
}

/// Compile the witness generator to WASM through circom's WAT emitter.
fn compile_wasm(stem: &str, work_dir: &Path, vcp: VCP, version: &str) -> Result<()> {
    let config = Config {
        produce_input_log: false,
        wat_flag: false,
        no_asm_flag: false,
        sanity_check_style: 0,
        debug_output: false,
    };

    let circuit =
        run_compiler(vcp, config, version).map_err(|e| anyhow!("run_compiler failed: {e:?}"))?;

    let js_folder = work_dir.join("wasm").join(format!("{stem}_js"));
    let wat_file = js_folder.join(format!("{stem}.wat"));
    let wasm_file = js_folder.join(format!("{stem}.wasm"));

    if js_folder.exists() {
        fs::remove_dir_all(&js_folder)?;
    }
    fs::create_dir_all(&js_folder)?;

    write_wasm(
        &circuit,
        js_folder.to_str().context("invalid js folder path")?,
        stem,
        wat_file.to_str().context("invalid wat file path")?,
    )
    .map_err(|_| anyhow!("write_wasm failed"))?;

    wat_to_wasm(&wat_file, &wasm_file)?;
    Ok(())
}

/// Convert WAT to a WASM binary and remove the WAT.
///
/// Modified by the Nethermind team. Original source:
/// <https://github.com/iden3/circom/blob/0ecb2c7d154ed8ab72105a9b711815633ca761c5/circom/src/compilation_user.rs#L141>
fn wat_to_wasm(wat_file: &Path, wasm_file: &Path) -> Result<()> {
    use std::{
        fs::File,
        io::{BufWriter, Write},
    };
    use wast::{
        Wat,
        parser::{self, ParseBuffer},
    };

    let wat_contents =
        fs::read_to_string(wat_file).with_context(|| format!("read {}", wat_file.display()))?;

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

    let buf = ParseBuffer::new(&wat_contents).map_err(|e| anyhow!("ParseBuffer::new: {e}"))?;
    let wat = parser::parse::<Wat>(&buf).map_err(|e| anyhow!("WAT parse failed: {e}"))?;

    let Wat::Module(mut module) = wat else {
        bail!("WAT {} should be a module", wat_file.display());
    };

    let wasm_bytes = module
        .encode()
        .map_err(|e| anyhow!("WASM encode failed: {e}"))?;

    let f = File::create(wasm_file).with_context(|| format!("create {}", wasm_file.display()))?;
    let mut w = BufWriter::new(f);
    w.write_all(&wasm_bytes)?;
    w.flush()?;

    fs::remove_file(wat_file).with_context(|| format!("remove {}", wat_file.display()))?;
    Ok(())
}
