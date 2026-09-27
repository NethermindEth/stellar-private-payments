[![Crates.io](https://img.shields.io/crates/v/sqlite-wasm-vfs.svg)](https://crates.io/crates/sqlite-wasm-vfs)

Some experimental VFS implementations.


This fork is based on crates.io `sqlite-wasm-vfs` 0.2.0. The SAH changes track
SQLite lock levels, reject a second open handle for the same logical filename,
and flush metadata/header changes so SQLite3MC rollback journals survive abrupt
worker termination. Upstream: https://github.com/Spxg/sqlite-wasm-rs (see the
package repository metadata for the upstream crate location). No upstream PR is
claimed by this repository. Track this fork explicitly when upgrading; removing
the patch requires passing `e2e-freighter/tests/storage/sah-recovery.mjs` as well
as the ordinary encrypted storage tests. Multiple handles to one database are
not supported by this SAH fork.
