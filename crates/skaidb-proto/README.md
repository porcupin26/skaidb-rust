# skaidb-proto

`skaidb-proto` is the binary wire protocol (SCP) between a [skaidb](https://github.com/porcupin26/skaidb) client and server: request and response frames, prepared statements, streamed result chunks, consistency levels and the value encoding. The protocol is specified in the repository's `docs/PROTOCOL.md`.

This crate is an internal building block. Applications use the driver crate
[`skaidb`](https://crates.io/crates/skaidb) (`use skaidb::Client`), which
depends on it and re-exports what a client program needs; the server ships
as packages from the repository's releases. The crate is published from the
[skaidb-rust](https://github.com/porcupin26/skaidb-rust) mirror at the
server's version, and its source of truth is `crates/skaidb-proto` in the
[skaidb](https://github.com/porcupin26/skaidb) monorepo. It is licensed
SSPL-1.0 like the rest of skaidb.
