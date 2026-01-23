# Private transactions for Stellar
[![Docs](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/docs.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/docs.yml)
[![Lint](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/linter.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/linter.yml)
[![Build](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/build-and-test.yml)
[![Dependencies](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/dependency-audit.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/dependency-audit.yml)
[![UB](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/ub-detection.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/ub-detection.yml)
[![Coverage](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/coverage.yml/badge.svg)](https://github.com/NethermindEth/stellar-private-transactions/actions/workflows/coverage.yml)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A compliant privacy payment system for the Stellar network.

It uses similar techniques with privacy pools, to create associations sets in order to prove membership or non membership
for a specific deposit and thus regulate the pool.

### Tests
For building the testing circom you need to run

```
BUILD_TESTS=1 cargo build
```

## License

This repository contains **source code** provided under a mixed license structure (Apache 2.0 and GPLv3).

Most of the source code is licensed under the Apache License, Version 2.0. See `LICENSE` for details.

The exception is `circuits/build.rs` which is licensed separately under the GNU Lesser General Public License v3.0. See `circuits/LICENSE` for details.

### Responsibility of Deployers

The `dist/` directory and its contents (including compiled WebAssembly circuits, keys, and bundled JavaScript) are **generated artifacts** produced by the build process. They are not checked into this repository.

If you compile, build, or deploy this project (e.g., hosting the `dist/` folder on a web server), **you become the distributor** of those binary artifacts. It is your responsibility to:
1.  Ensure all generated artifacts comply with their respective licenses (specifically the LGPLv3 requirements for compiled circuits).
2.  Include the appropriate `LICENSE` and `NOTICE` files in your deployment directory.
3.  Make the source code available to your end-users as required by the LGPLv3 (if you are distributing the compiled circuits).

The maintainers of this repository provide the source code "as is" and assume no responsibility for the compliance of downstream builds or deployments.

## Would like to contribute?

see [Contributing](./CONTRIBUTING.md).
