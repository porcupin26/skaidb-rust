# skaidb-gssapi

`skaidb-gssapi` wraps [cross-krb5](https://crates.io/crates/cross-krb5) into the Kerberos (SASL GSSAPI) security-context helpers [skaidb](https://github.com/porcupin26/skaidb) uses for client authentication. It compiles only with the `kerberos` feature and links the platform Kerberos library (MIT krb5 on Linux).

This crate is an internal building block. Applications use the driver crate
[`skaidb`](https://crates.io/crates/skaidb) (`use skaidb::Client`), which
depends on it and re-exports what a client program needs; the server ships
as packages from the repository's releases. The crate is published from the
[skaidb-rust](https://github.com/porcupin26/skaidb-rust) mirror at the
server's version, and its source of truth is `crates/skaidb-gssapi` in the
[skaidb](https://github.com/porcupin26/skaidb) monorepo. It is licensed
SSPL-1.0 like the rest of skaidb.
