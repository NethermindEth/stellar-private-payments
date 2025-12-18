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

## App development

### Prerequisites

* Node.js
* npm
* python3 (for the static server)

The whole app:

```sh
$ make install
$ make serve
```

The Rust part - check compilation

```sh
$ make wasm
```

Prepare a production build (TODO: enable optimizations and minification)

```sh
$ make dist
```