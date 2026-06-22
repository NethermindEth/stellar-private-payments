#[path = "../build_support.rs"]
mod build_support;

use build_support::{circom_include_path, extract_circom_dependencies};
use std::{fs, path::PathBuf};

#[test]
fn include_parser_finds_includes_after_pragma_lines() {
    let source = [
        "pragma circom 2.2.2;",
        "",
        "include \"./policyTransaction.circom\";",
        "include '../circomlib/circuits/poseidon.circom';",
        "component main = PolicyTransaction();",
    ];

    let includes: Vec<_> = source
        .iter()
        .filter_map(|line| circom_include_path(line))
        .collect();

    assert_eq!(
        includes,
        [
            "./policyTransaction.circom",
            "../circomlib/circuits/poseidon.circom"
        ]
    );
}

#[test]
fn include_parser_ignores_comments_and_similar_identifiers() {
    let source = [
        "// include \"ignored.circom\";",
        "included \"ignored.circom\";",
        "include \"kept.circom\"; // trailing comment",
    ];

    let includes: Vec<_> = source
        .iter()
        .filter_map(|line| circom_include_path(line))
        .collect();

    assert_eq!(includes, ["kept.circom"]);
}

#[test]
fn dependency_extraction_finds_includes_after_pragma_and_transitive() -> anyhow::Result<()> {
    let dir = temp_test_dir("dependency_extraction")?;
    let main = dir.join("main.circom");
    let first = dir.join("first.circom");
    let nested = dir.join("nested.circom");

    fs::write(
        &main,
        [
            "pragma circom 2.2.2;",
            "",
            "include \"./first.circom\";",
            "component main = First();",
        ]
        .join("\n"),
    )?;
    fs::write(
        &first,
        "include \"./nested.circom\";\ntemplate First() {}\n",
    )?;
    fs::write(&nested, "template Nested() {}\n")?;

    let dependencies = extract_circom_dependencies(&main, &dir)?;

    assert_eq!(
        dependencies,
        [first.canonicalize()?, nested.canonicalize()?]
    );

    fs::remove_dir_all(dir)?;
    Ok(())
}

fn temp_test_dir(name: &str) -> anyhow::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "stellar-private-payments-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}
