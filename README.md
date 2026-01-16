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

This repository is a mixed-license project.

*Apache 2.0*: The source directories are licensed under the Apache License, Version 2.0. See `LICENSE-APACHE` for details.

*LGPL v3*: The final app distribution (which is the output of the build/compilation process and is in the `dist` directory which is not preserved in the version control) is licensed under *Apache 2.0* except `dist/circuits` which is under the GNU Lesser General Public License v3.0. See `LICENSE-LGPLv3` for details. Also `circuits/build.rs` is licensed under the GNU Lesser General Public License v3.0. See `circuits/LICENSE` for details.

If a directory does not contain a specific license file, it inherits the license of its parent or follows the default project license (*Apache 2.0*).

## Would like to contribute?

see [Contributing](./CONTRIBUTING.md).
