# skaidb-net

`skaidb-net` is the shared TLS and plaintext transport layer of [skaidb](https://github.com/porcupin26/skaidb): certificate loading, rustls configuration and framed streams used by the server and the drivers alike.

This crate is an internal building block. Applications use the driver crate
[`skaidb`](https://crates.io/crates/skaidb) (`use skaidb::Client`), which
depends on it and re-exports what a client program needs; the server ships
as packages from the repository's releases. The crate is published from the
[skaidb-rust](https://github.com/porcupin26/skaidb-rust) mirror at the
server's version, and its source of truth is `crates/skaidb-net` in the
[skaidb](https://github.com/porcupin26/skaidb) monorepo. It is licensed
SSPL-1.0 like the rest of skaidb.
