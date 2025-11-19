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

Apache 2.0

## Would like to contribute?

see [Contributing](./CONTRIBUTING.md).
