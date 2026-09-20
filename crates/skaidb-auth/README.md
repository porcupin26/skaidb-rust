# skaidb-auth

`skaidb-auth` holds the authentication building blocks of [skaidb](https://github.com/porcupin26/skaidb): the SCRAM-SHA-256 client and server exchange, the SHA-256 / HMAC / PBKDF2 primitives it rests on, and credential handling.

This crate is an internal building block. Applications use the driver crate
[`skaidb`](https://crates.io/crates/skaidb) (`use skaidb::Client`), which
depends on it and re-exports what a client program needs; the server ships
as packages from the repository's releases. The crate is published from the
[skaidb-rust](https://github.com/porcupin26/skaidb-rust) mirror at the
server's version, and its source of truth is `crates/skaidb-auth` in the
[skaidb](https://github.com/porcupin26/skaidb) monorepo. It is licensed
SSPL-1.0 like the rest of skaidb.
