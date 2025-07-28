# Contributor's guide

## Commit signing

Enable [commit signing](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)

```sh
git config commit.gpgsign true
```

## Prerequisites

* [Rust](https://www.rust-lang.org/tools/install)
* [cargo deny](https://github.com/EmbarkStudios/cargo-deny)
* [typos](https://github.com/crate-ci/typos?tab=readme-ov-file#install)
* [cargo sort](https://github.com/DevinR528/cargo-sort)

## Code quality assurance

Install a pre-push git hook:

```sh
git config core.hooksPath .githooks
```

## Running the Rust Documentation Locally
After cloning the repository, follow the instructions below to run the documentation locally:

```sh
cargo doc
```

Docs for `TODO(template) template_crate`:

```sh
RUSTDOCFLAGS="--html-in-header katex-header.html" cargo doc --no-deps -p template_crate --open
```