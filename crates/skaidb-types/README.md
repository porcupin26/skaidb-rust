# skaidb-types

`skaidb-types` is the value model every part of [skaidb](https://github.com/porcupin26/skaidb) shares: the schema-less `Value` and `Document` types (null, bool, int, float, decimal, string, bytes, uuid, timestamp, array, document), the order-preserving key encoding, and the type rules the server and the drivers agree on.

This crate is an internal building block. Applications use the driver crate
[`skaidb`](https://crates.io/crates/skaidb) (`use skaidb::Client`), which
depends on it and re-exports what a client program needs; the server ships
as packages from the repository's releases. The crate is published from the
[skaidb-rust](https://github.com/porcupin26/skaidb-rust) mirror at the
server's version, and its source of truth is `crates/skaidb-types` in the
[skaidb](https://github.com/porcupin26/skaidb) monorepo. It is licensed
SSPL-1.0 like the rest of skaidb.
