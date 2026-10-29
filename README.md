# skaidb Rust driver

The native, synchronous Rust client for [skaidb](https://skaidb.org). It
speaks the binary fast-path protocol directly — SCRAM-SHA-256 or Kerberos
authentication, optional TLS, prepared statements with bound parameters,
pipelined batches, streamed result sets and a connection pool that balances
across the cluster's members — and it is the reference implementation of
the [wire protocol](https://skaidb.org/docs/PROTOCOL.html) that every other
official driver follows.

- Wire protocol specification: <https://skaidb.org/docs/PROTOCOL.html>
- skaidb documentation (SQL, types, clustering, security):
  <https://skaidb.org/docs/>
- Source: <https://github.com/porcupin26/skaidb-rust> (the crate with the
  internal crates it depends on, tagged with the skaidb version); the same
  code lives in `crates/skaidb-driver` of the
  [skaidb](https://github.com/porcupin26/skaidb) repository.

## Install

The crate is on crates.io; its version is the skaidb release it ships and
is tested with:

```toml
[dependencies]
skaidb = "0.330"
```

Kerberos (GSSAPI) logins are behind the `kerberos` feature, which links the
MIT krb5 library through `cross-krb5`. Install the development headers first
(`libkrb5-dev` on Debian/Ubuntu, `krb5-devel` on Fedora/RHEL, bundled on
macOS and Windows) and enable the feature:

```toml
skaidb = { version = "0.330", features = ["kerberos"] }
```

The feature is off by default and never builds on static musl targets.

Inside the skaidb monorepo the same crate is named `skaidb-driver`
(`use skaidb_driver::…`); everything below applies unchanged. Minimum
supported Rust version: 1.93.

## Quick start

```rust
use skaidb::{Client, Response, Value};

fn main() -> Result<(), skaidb::DriverError> {
    let mut client = Client::connect_with("db1:7000", "app", "secret")?
        .with_database("app")?;

    client.execute("CREATE TABLE IF NOT EXISTS people (PRIMARY KEY (id))")?;

    let mut insert = client.prepare("INSERT INTO people (id, name, age) VALUES (?, ?, ?)")?;
    client.execute_prepared(&mut insert, &[Value::Int(1), Value::String("Ada".into()), Value::Int(36)])?;

    match client.execute("SELECT id, name FROM people WHERE age > 30 ORDER BY id")? {
        Response::Rows { columns, rows } => {
            println!("{columns:?}");
            for row in rows {
                println!("{row:?}");
            }
        }
        other => println!("unexpected: {other:?}"),
    }
    Ok(())
}
```

Every call is synchronous and blocks the calling thread. A `Client` is one
connection: use it from one thread at a time, and use a [`Pool`](#connection-pool)
to share connections across threads.

## Connecting

There is no DSN string in Rust; the connect functions take the same options
that other drivers spell in a URL or keyword arguments.

| Other drivers' option | Rust |
|---|---|
| `host` / `port` | the `addr` argument, `"host:port"` |
| `seeds=[...]` | `connect_many(&endpoints, …)` |
| `user` / `password` | the `username` / `password` arguments |
| `database=` | `.with_database("name")` |
| `consistency=` | `set_consistency(…)` or the `*_with(…, consistency)` calls |
| `tls=`, `tls_ca=`, `tls_insecure=`, `tls_server_name=` | `TlsConfig::new(TlsVerify::…, server_name)` passed to `connect_many_tls` |
| `auth_mechanism=gssapi`, `gssapi_spn=` | `connect_gssapi[_tls]` (feature `kerberos`) |

### Signatures

```rust
impl Client {
    /// Anonymous, one endpoint — a server with authentication disabled.
    pub fn connect(addr: impl ToSocketAddrs) -> Result<Client, DriverError>;

    /// SCRAM-SHA-256 to one endpoint. `addr` may resolve to several socket
    /// addresses; all of them are kept as failover targets.
    pub fn connect_with(addr: impl ToSocketAddrs, username: &str, password: &str)
        -> Result<Client, DriverError>;

    /// SCRAM-SHA-256 across a seed list, plaintext.
    pub fn connect_many(endpoints: &[String], username: &str, password: &str)
        -> Result<Client, DriverError>;

    /// SCRAM-SHA-256 across a seed list; `tls = Some(cfg)` wraps every
    /// connection, including failover reconnects, in TLS.
    pub fn connect_many_tls(endpoints: &[String], username: &str, password: &str,
                            tls: Option<TlsConfig>) -> Result<Client, DriverError>;

    /// Kerberos (SASL GSSAPI) instead of a password: `principal` is the
    /// client identity, `target_spn` the node's service principal
    /// (`skaidb/host.example.com@REALM`). Uses the ambient ticket cache.
    pub fn connect_gssapi(endpoints: &[String], principal: &str, target_spn: &str)
        -> Result<Client, DriverError>;
    pub fn connect_gssapi_tls(endpoints: &[String], principal: &str, target_spn: &str,
                              tls: Option<TlsConfig>) -> Result<Client, DriverError>;

    /// Bind the session to a database: runs `USE` now and after every reconnect.
    pub fn with_database(self, database: &str) -> Result<Client, DriverError>;
    pub fn database(&self) -> Option<&str>;

    /// The endpoint the live connection uses; all candidates in preference order.
    pub fn endpoint(&self) -> &str;
    pub fn endpoints(&self) -> &[String];
    /// Merge more failover targets (peers discovered after connecting to a seed).
    pub fn add_endpoints(&mut self, more: &[String]);

    /// Drop the live connection and dial another node (a different one first).
    pub fn reconnect(&mut self) -> Result<(), DriverError>;
}
```

### Endpoint selection and failover

With more than one endpoint the driver measures TCP-connect latency to each
(800 ms probe timeout), dials the nearest reachable one first and keeps the
rest as failover targets; a single endpoint is dialled directly. An endpoint
counts as reachable only when it both connects **and** authenticates — a
node accepting TCP while unhealthy does not swallow the attempt. skaidb is
leaderless, so any member serves any statement.

When a statement hits a transport error (broken pipe, reset, EOF) the
driver dials another endpoint, re-authenticates, re-sends its `Hello`,
re-enters the bound database, re-applies the scan budget and **retries the
statement once**. This is transparent, and it means a non-idempotent
statement can run twice if the node died after applying it but before
answering. `reconnect()` does the same on demand, for a pool or a caller
with its own retry policy. Prepared statements do not survive a reconnect;
see [Prepared statements](#prepared-statements) for how the driver hides
that. A connection from a [balanced pool](#a-pool-balanced-across-members)
re-dials in the pool's order instead — usable members first (random
order), the member it just lost last.

### TLS modes

```rust
use skaidb::{Client, TlsConfig, TlsVerify};

let tls = TlsConfig::new(TlsVerify::CaFile("/etc/skaidb/skai-ca.crt".into()), "skaidb")?;
let seeds = vec!["db1:7000".to_string(), "db2:7000".to_string()];
let mut client = Client::connect_many_tls(&seeds, "app", "secret", Some(tls))?;
```

| `TlsVerify` | Meaning |
|---|---|
| `CaFile(path)` | Trust certificates chaining to this CA file — the cluster CA from `skaidbsh certs gen`. The production mode. |
| `System` | Trust the public-CA roots (Mozilla's bundle, compiled in, identical on every platform) — for servers behind a public certificate. |
| `Insecure` | Encrypt but verify nothing. Self-signed development servers only. |

`server_name` is the SNI and verification name and must match a SAN on
the server certificate. skaidb's own certificates carry `DNS:skaidb`, so
the name is usually `skaidb` rather than the host you dialled. TLS runs on
the same binary port (7000 by default); the server's
`encryption.client_tls` setting (`off`, `opportunistic`, `required`)
decides whether plaintext is still accepted. Passing `None` for `tls` is
plaintext.

### Kerberos

Build with the `kerberos` feature, `kinit` as the client principal, then:

```rust
let tls = TlsConfig::new(TlsVerify::CaFile("/etc/skaidb/skai-ca.crt".into()), "skaidb")?;
let mut client = Client::connect_gssapi_tls(
    &seeds, "alice@EXAMPLE.COM", "skaidb/db1.example.com@EXAMPLE.COM", Some(tls))?;
```

The authenticated identity comes from the ticket, not from `principal`.
Inside TLS the driver binds the GSS context to the server certificate
(RFC 5929 `tls-server-end-point`), so a server that requires channel
binding accepts the login and one that does not ignores it. Without the
feature, `connect_gssapi*` returns `DriverError::Auth("this driver was built
without Kerberos (GSSAPI) support")`.

## Consistency

```rust
pub enum Consistency { One, Quorum, All }

impl Client {
    pub fn set_consistency(&mut self, consistency: Consistency);
}
```

Every read and write carries a consistency level: `One` (a single
replica), `Quorum` (a majority of the replicas — the driver's default) or
`All`. `set_consistency` changes the default for subsequent calls; every
executing call has a `*_with(…, consistency)` twin that overrides it for
one statement. DDL always runs at quorum regardless of the level sent.

```rust
use skaidb::Consistency;
client.set_consistency(Consistency::One);                         // fast local reads
let r = client.execute_with("SELECT count(*) FROM t", Consistency::All)?;
```

## Executing statements

```rust
impl Client {
    pub fn execute(&mut self, sql: &str) -> Result<Response, DriverError>;
    pub fn execute_with(&mut self, sql: &str, consistency: Consistency) -> Result<Response, DriverError>;
}
```

Any statement — DDL, DML, `SELECT`, `CALL`, `SHOW …` — goes through
`execute`. The result is a `Response`:

| Variant | Returned for |
|---|---|
| `Rows { columns: Vec<String>, rows: Vec<Vec<Value>> }` | a result set; cells are positional and match `columns` |
| `Mutation { affected: u64 }` | `INSERT` / `UPDATE` / `DELETE` |
| `Ddl` | a successful DDL statement |
| `ResultSets { sets: Vec<(Vec<String>, Vec<Vec<Value>>)> }` | a `CALL` whose procedure body `EMIT`ted several result sets, in order, the call's final result last |
| `Prepared { id, params }`, `RowsHeader`, `RowsChunk`, `RowsEnd` | protocol frames consumed by `prepare` and `query_stream`; not returned by `execute` |
| `Error(String)` | never returned — the driver converts it into `DriverError::Server` |

Rows are schema-less documents: a column a row does not carry reads as
`Value::Null`. String literals in SQL use single quotes; double quotes are
identifiers.

## Prepared statements

```rust
pub struct Prepared { pub params: u16, /* private id and template */ }

impl Client {
    pub fn prepare(&mut self, sql: &str) -> Result<Prepared, DriverError>;
    pub fn execute_prepared(&mut self, stmt: &mut Prepared, params: &[Value]) -> Result<Response, DriverError>;
    pub fn execute_prepared_with(&mut self, stmt: &mut Prepared, params: &[Value], consistency: Consistency)
        -> Result<Response, DriverError>;
    pub fn execute_batch(&mut self, stmt: &mut Prepared, rows: Vec<Vec<Value>>) -> Result<u64, DriverError>;
}
```

Placeholders are `?`, positional. `prepare` parses the statement on the
server once and returns a handle; `Prepared::params` is the number of
placeholders. Parameters are bound as `Value`s, typed on the wire, so a
string containing a quote or a semicolon is only ever data — never build
SQL from user input when a parameter will do.

```rust
let mut upd = client.prepare("UPDATE people SET age = ? WHERE id = ?")?;
if let Response::Mutation { affected } = client.execute_prepared(&mut upd, &[Value::Int(37), Value::Int(1)])? {
    println!("updated {affected}");
}
```

A handle is valid only on the connection that created it. That is why the
calls take `&mut Prepared`: when a failover happens mid-call, the driver
re-prepares the template on the new connection, updates the handle in
place and retries once, so callers never see a stale id.

`execute_batch` runs one prepared statement once per parameter row in a
single round trip (the `executemany` wire op) and returns the total
affected count. Each row autocommits exactly like a looped
`execute_prepared`; on a failure the server error names the failing row
index and how many rows applied before it, and those earlier rows stay
applied. The whole request must fit one frame (64 MiB).

```rust
let mut ins = client.prepare("INSERT INTO events (id, kind) VALUES (?, ?)")?;
let rows: Vec<Vec<Value>> = (0..1000)
    .map(|i| vec![Value::Int(i), Value::String("click".into())])
    .collect();
let n = client.execute_batch(&mut ins, rows)?;
```

Only `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CALL` and `EXPLAIN` of those
can be prepared; DDL goes through `execute`.

## Pipelining

```rust
impl Client {
    pub fn pipeline(&mut self, stmts: &[&str]) -> Result<Vec<Response>, DriverError>;
    pub fn pipeline_with(&mut self, stmts: &[&str], consistency: Consistency) -> Result<Vec<Response>, DriverError>;
}
```

All statements are written before any response is read, so a batch pays
one round trip of link latency instead of one per statement. They execute
serially, in order, with ordinary session semantics (a `USE` mid-batch
affects the statements after it). Per-statement failures come back
**inline** as `Response::Error(msg)` entries at that statement's index — a
failed statement does not stop the ones after it, and the call itself
returns `Ok`. The whole batch is retried once on a fresh connection if the
node dies mid-flight, with the same idempotency caveat as `execute`.

```rust
let out = client.pipeline(&["INSERT INTO t (id) VALUES (1)", "INSERT INTO t (id) VALUES (1)"])?;
assert!(matches!(out[0], Response::Mutation { .. }));
if let Response::Error(msg) = &out[1] { eprintln!("second insert failed: {msg}"); }
```

## Streaming result sets

```rust
impl Client {
    pub fn query_stream(&mut self, sql: &str) -> Result<RowStream<'_>, DriverError>;
    pub fn query_stream_with(&mut self, sql: &str, consistency: Consistency) -> Result<RowStream<'_>, DriverError>;
    pub fn query_stream_params(&mut self, sql: &str, params: &[Value]) -> Result<RowStream<'_>, DriverError>;
    pub fn query_stream_params_with(&mut self, sql: &str, params: &[Value], consistency: Consistency) -> Result<RowStream<'_>, DriverError>;
}

pub struct RowStream<'a> {
    pub columns: Vec<String>,   // empty for non-row statements
    pub affected: u64,          // set when the statement was a mutation
    // …
}
impl Iterator for RowStream<'_> { type Item = Result<Vec<Value>, DriverError>; }
```

`execute` buffers the whole result set in one frame, which is wrong for a
table scan. `query_stream` receives rows in chunks and holds at most one
chunk in memory, and it is also how a result larger than the server's scan
budget is read at all: the server pages a plain SELECT, and no scan budget
applies to a streamed page. Iterate the stream; each item is one row or the
error that ended the stream. `query_stream_params` binds `?` placeholders
exactly as `execute_prepared` does (`OP_QUERY_STREAM_PARAMS`, servers ≥
0.330); without parameters the request is the original `OP_QUERY_STREAM`,
which every server accepts.

```rust
let mut n = 0u64;
{
    let stream = client.query_stream("SELECT id, doc FROM big ORDER BY id")?;
    for row in stream {
        let row = row?;
        n += 1;
    }
}
println!("{n} rows");

let since = Value::Timestamp(1_700_000_000_000);
for row in client.query_stream_params("SELECT id, ts FROM events WHERE ts >= ?", &[since])? {
    let row = row?;
}
```

**The abandon/drain rule.** A `RowStream` borrows the `Client` exclusively
until it is finished. Dropping it before the end does not cancel the
query: `Drop` reads and discards every remaining frame so the connection
is back at a request boundary for the next call. Breaking out of a loop
over a billion-row scan therefore still costs receiving the whole result.
To abandon a large stream cheaply, drop the `Client` (or the pooled
connection) instead of the stream and open a new one — or bound the query
with `LIMIT` in the first place. Failover applies only to sending the
request; a node dying mid-stream surfaces as an `Err` item and marks the
stream finished, and the caller decides whether to re-run the query (the
next call on the client fails over as usual). Non-row statements yield an
empty stream with `affected` set.

## Streams (change feeds)

A `CREATE STREAM` is an ordinary table (`_stream_<name>`) that logs
changes; the driver polls it with keyset pagination:

```rust
impl Client {
    /// Events after `after` (oldest first) and the cursor to pass next time.
    pub fn stream_poll(&mut self, stream: &str, after: &str, limit: usize)
        -> Result<(Vec<Vec<Value>>, String), DriverError>;
}
```

Each event row is `id, op, k, ts, doc`. Start with an empty cursor, keep
the returned one, and sleep when a poll comes back empty; the cursor
resumes exactly where you stopped, across restarts. For push delivery
subscribe to `$stream/<db>/<name>` with any MQTT client — the events are
identical.

```rust
let mut cursor = String::new();
loop {
    let (events, next) = client.stream_poll("big_orders", &cursor, 500)?;
    for ev in &events { println!("{ev:?}"); }
    cursor = next;
    if events.is_empty() { std::thread::sleep(std::time::Duration::from_millis(500)); }
}
```

## Scan budget

```rust
impl Client {
    pub fn set_scan_budget_rows(&mut self, rows: u64) -> Result<(), DriverError>;
}
```

Runs `SET SCAN BUDGET ROWS n` (`0` = `SET SCAN BUDGET DEFAULT`) and
replays it after every reconnect, so a silent failover cannot revert the
session to node defaults. The budget is tightening-only server-side.

## Connection pool

```rust
pub struct Pool { /* … */ }

impl Pool {
    pub fn builder<S: AsRef<str>>(endpoints: &[S]) -> PoolBuilder;  // balanced across members
    pub fn new<F>(maxsize: usize, make: F) -> Pool                   // connections from a closure
        where F: Fn() -> Result<Client, DriverError> + Send + Sync + 'static;
    pub fn acquire(&self) -> Result<Client, DriverError>;
    pub fn acquire_with_affinity(&self, affinity: &str) -> Result<Client, DriverError>;
    pub fn release(&self, client: Client);
    pub fn with<T, F>(&self, work: F) -> Result<T, DriverError>
        where F: FnOnce(&mut Client) -> Result<T, DriverError>;
    pub fn with_affinity<T, F>(&self, affinity: &str, work: F) -> Result<T, DriverError>
        where F: FnOnce(&mut Client) -> Result<T, DriverError>;
    pub fn idle_len(&self) -> usize;
    pub fn members(&self) -> Vec<PoolMember>;
    pub fn close(&self);
}
```

`Pool` is `Send + Sync`; share it behind an `Arc`. `maxsize` bounds the
connections kept **idle**, not the number checked out: a burst opens extras
and the surplus is dropped on return, so callers never block waiting for a
slot. Idle connections are handed out as-is; a connection the server closed
while it sat idle re-dials itself on first use, so no liveness probe is
needed. `close` (and dropping the pool) drops every idle connection and
makes `acquire` fail; connections checked out at the time are dropped when
returned.

### A pool balanced across members

`Pool::builder` knows the endpoints (the seeds) and how to log in, and
spreads its connections across the cluster's members by the rules every
official driver shares —
[PROTOCOL.md §6.1](https://skaidb.org/docs/PROTOCOL.html#61-balancing-a-pool-across-members).
Nothing is dialed until the first checkout.

```rust
use std::sync::Arc;
use std::time::Duration;
use skaidb::{LoadBalancing, Pool};

let pool = Arc::new(
    Pool::builder(&["db1:7000", "db2:7000", "db3:7000"])
        .credentials("app", "secret")
        .database("app")
        .maxsize(8)
        .load_balancing(LoadBalancing::LeastLatency)
        .discover(true)
        .read_your_writes(Duration::from_secs(2))
        .build()?,
);
let n = pool.with(|c| c.execute("SELECT count(*) FROM t"))?;
pool.with_affinity("user-42", |c| c.execute("UPDATE carts SET n = 3 WHERE id = 42"))?;
let cart = pool.with_affinity("user-42", |c| c.execute("SELECT n FROM carts WHERE id = 42"))?;
```

| Builder method | Default | Meaning |
|---|---|---|
| `credentials(user, password)` / `gssapi(principal, spn)` / `certificate(user)` | anonymous | how every connection logs in (as `connect_many_tls`, `connect_gssapi_tls`, `connect_certificate`) |
| `tls(TlsConfig)` | plaintext | TLS for every connection |
| `database(name)` | none | session database, re-applied after every reconnect |
| `consistency(Consistency)` | `Quorum` | default consistency of every connection |
| `maxsize(n)` | 10 | idle connections kept (at least 1) |
| `load_balancing(LoadBalancing)` | `Random` | `Random`: any idle connection, a new one dials the usable members in random order and sticks to the member it reached. `RoundRobin`: the next usable member in endpoint order. `LeastLatency`: of two usable members picked at random, the one with the lower latency average × (checked-out connections + 1); a member not measured yet, or not in the last 2 s, scores 0, so it is tried |
| `idle_order(IdleOrder)` | `Lifo` | `Lifo`: the most recently returned idle connection first (a quiet pool keeps few sockets warm). `Fifo`: the longest idle first (every idle connection keeps being used, so a server-side idle timeout never finds one) |
| `discover(bool)` | off | learn the members from `SHOW ENDPOINTS` (server ≥ 0.327) |
| `refresh_interval(Duration)` | 60 s | how often discovery re-reads the members (every 5 s while one is `resyncing` or `unreachable`) |
| `read_your_writes(Duration)` | zero (off) | after a write, checkouts under the same affinity key go to the member that took it for this long |
| `eject_errors(n)` | 3 | consecutive transport failures that eject a member (at least 1) |
| `eject_latency_factor(f64)` | 3.0 | eject a member whose latency average is above this × the other members' median (0 disables) |
| `eject_latency_floor(Duration)` | 50 ms | … and more than this above it |
| `eject_backoff(Duration)` | 5 s | how long an ejection lasts, doubled for each repeat |
| `eject_backoff_max(Duration)` | 60 s | the longest ejection; a member healthy this long after a re-admission starts over at the base |

`build()` fails with `NoEndpoint` without endpoints and with an
`InvalidInput` I/O error for an option out of range. `LoadBalancing` and
`IdleOrder` also parse from their names (`"random"`, `"round_robin"`,
`"least_latency"`, `"lifo"`, `"fifo"`) with `str::parse`, for
configuration files.

**Targeting a member.** With a target the pool hands out an idle connection
to it, or dials it; a failed dial falls through to the other usable members
(random order), then to the unusable ones (`resyncing`/`unreachable` before
ejected, the soonest re-admission first). An idle connection to a member
that is no longer usable is closed rather than handed out, and one returned
to the pool is closed instead of kept — as is one a transport error left
broken.

**Latency.** Per member the pool keeps an exponentially weighted average of
round trips (request sent to first response frame): each sample moves it
5 % of the way, no sample counts for more than 10 × the larger of the
average and the ejection floor, and the first sample sets it. One slow
statement barely moves it; a member that stays slow converges within a few
dozen statements.

**Health ejection.** A member is ejected — no new connections, its idle ones
closed — after `eject_errors` consecutive transport failures (a failed
dial, an I/O error mid-request, a capacity refusal; a statement error or a
login refused for its credentials is no member failure), or when, with at
least 10 samples on it and on another usable member, its average is above
`eject_latency_factor` × the median of the other usable members' averages
and more than `eject_latency_floor` above it. When the backoff is up, a
background thread dials the member alone and runs one statement: success
re-admits it with a fresh average and errors cleared (the probe connection
joins the idle set), failure ejects it again for twice as long. The thread
holds the pool weakly, never keeps the process alive, and exits when the
pool is closed or dropped. **The last usable member is never ejected** — a
slow or flaky member beats none.

**Discovery.** With `discover(true)` the pool runs `SHOW ENDPOINTS` on the
first connection it makes to each member whose name it has not learned yet
— the answering member's `local` row names it, so a seed given as a host
name is matched to the endpoint the server reports and never counted
twice — and every `refresh_interval` after that. A listed endpoint the pool
does not know becomes a member; a discovered member missing from a later
listing is dropped; a seed is never dropped (its member leaving the ring
marks it `Unlisted`). Only `ready` members get new connections, and a
member that becomes `ready` again starts with a fresh average. A
standalone server answers no rows and a server older than the statement an
error: either way the pool keeps its seeds and stops asking.

**Read-your-writes.** The member that coordinated a write reads it back at
any consistency, `ONE` included. With a window set, after a write succeeds
on a connection checked out under an affinity key (`acquire_with_affinity`,
`with_affinity` — a user id, a session id), checkouts under the same key go
to that member until the window ends, unless it is ejected or not `ready`.
Checkouts without a key share one pool-wide key. A statement counts as a
write unless its first keyword (after whitespace, comments and opening
parentheses) is `SELECT`, `SHOW`, `EXPLAIN`, `DESCRIBE`, `DESC`, `VALUES`,
`WITH` or `USE`. Derive the key without querying through the same pool: a
helper that checks out a connection and only then computes the key from
something that itself reads the database (a web framework's "current user"
loader) checks out again from inside its own checkout. Take the raw id from
the session or token instead.

**Introspection.** `members()` lists each member in endpoint order:

```rust
pub struct PoolMember {
    pub endpoint: String,           // what the pool dials
    pub canonical: Option<String>,  // its own SHOW ENDPOINTS name, once discovered
    pub state: MemberState,         // Ready, Ejected, Resyncing, Unreachable, Unlisted
    pub latency: Option<Duration>,  // the round-trip average, once measured
    pub in_use: usize,              // connections checked out
    pub idle: usize,                // idle connections
    pub seed: bool,                 // a configured endpoint
}
```

`MemberState::as_str()` gives the spec's names (`ready`, `ejected`,
`resyncing`, `unreachable`, `unlisted`).

### A pool from a closure

`Pool::new` builds connections with the closure you supply, so they inherit
whatever it configures — seeds, TLS, credentials, session database. It
knows nothing about members: the most recently returned idle connection
goes out first, `members()` is empty, and the affinity key of
`acquire_with_affinity` / `with_affinity` is ignored. `new` panics if
`maxsize` is 0.

```rust
use std::sync::Arc;
use skaidb::{Client, Pool};

let eps = vec!["db1:7000".to_string(), "db2:7000".to_string()];
let pool = Arc::new(Pool::new(8, move || {
    Client::connect_many(&eps, "app", "secret")?.with_database("app")
}));
let n = pool.with(|c| c.execute("SELECT count(*) FROM t"))?;
```

## Values and type mapping

`Value` is the driver's parameter and result type; the composite types it
contains are re-exported alongside it.

```rust
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Decimal(Decimal),      // Decimal { mantissa: i128, scale: u32 }; Decimal::new(12345, 2) == 123.45
    String(String),
    Bytes(Vec<u8>),
    Uuid(Uuid),            // Uuid(pub [u8; 16]); Uuid::parse_str("…"), Display prints hyphenated
    Timestamp(i64),        // Unix time in MILLISECONDS
    Array(Vec<Value>),
    Document(Document),    // Document(pub BTreeMap<String, Value>); ::new(), .insert(k, v), .get(k), .get_path("a.b")
}
```

| skaidb type | `Value` | Notes |
|---|---|---|
| `null` | `Null` | a missing field reads as `Null` |
| `bool` | `Bool` | |
| `int64` | `Int(i64)` | |
| `float64` | `Float(f64)` | |
| `decimal` | `Decimal` | exact; `to_f64()` for a lossy view |
| `string` | `String` | UTF-8 |
| `bytes` | `Bytes` | `Display` prints `0x…` hex |
| `uuid` | `Uuid` | 16 raw bytes |
| `timestamp` | `Timestamp(i64)` | milliseconds since the Unix epoch, UTC |
| `array` | `Array` | a vector column is an `Array` of `Float` |
| `document` | `Document` | keys ordered |

Only `int`, `float`, `string`, `bool`, `null`, array and document literals
can be written directly in SQL; `decimal`, `uuid`, `bytes` and `timestamp`
values reach the database as bound parameters (`Value::Decimal(…)`,
`Value::Uuid(…)`, …), which is another reason to prefer prepared statements
over string-built SQL.

`Value` implements `Display` (composite values render as JSON) and has
`type_of() -> ValueType`, `is_null()`, `to_json()` / `Value::from_json`
(via `serde_json`) and `total_cmp` for the database's ordering.

## Errors

```rust
pub enum DriverError {
    Io(std::io::Error),        // transport: connect, read, write, TLS handshake
    Proto(ProtoError),         // a malformed frame from the server
    Server(String),            // the server rejected the statement (its message)
    Auth(String),              // SCRAM/GSSAPI denied, server signature mismatch, feature missing
    NoEndpoint(String),        // no endpoint connected + authenticated (last failure inside)
}
```

`Server` carries the server's error text as-is — syntax errors, unknown
tables, privilege denials, constraint violations, scan-budget refusals,
`"server does not support pipelined requests"` and so on. `Io` is what a
failover has already been attempted for (once): if you see it, both the
original node and every peer failed. `DriverError` implements
`std::error::Error` and `Display`, and converts `From` `io::Error` and
`ProtoError`.

## Transactions

Against a standalone server, `BEGIN` / `COMMIT` / `ROLLBACK` are ordinary
statements sent through `execute` and the transaction is per-connection
session state. **On a cluster there are no transactions: every statement
autocommits** and `BEGIN` is refused. To make several statements atomic on
a cluster, put them in a procedure (`CREATE PROCEDURE … BEGIN … END`) and
`CALL` it — one round trip, and a `CALL p(?)` binds through the normal
prepared path. Because a failover can replay a statement once, make writes
idempotent (`INSERT … ON CONFLICT DO UPDATE`, keyed `UPDATE`s) where a
duplicate would matter.

## Client identification and versions

After authenticating (and after every reconnect) the driver sends a
best-effort `Hello` frame naming itself `rust` with the crate version from
`CARGO_PKG_VERSION`; the pair shows up in the server's `drivers` table
(`client_name`, `client_version`). An older server answers the opcode with
an error, which is ignored.

Feature gates by server version, for clusters not yet on the driver's
release:

| Call | Needs server |
|---|---|
| `prepare` / `execute_prepared` | ≥ 0.17.0 |
| `execute_batch` | ≥ 0.87.0 |
| `pipeline` (tagged requests) | returns `Server("server does not support pipelined requests …")` on older servers |
| `query_stream` | rejected with a server error on older servers; use `execute` |
| `Hello` self-identification | ≥ 0.203.0 (ignored otherwise) |
| `Value` re-exports (`skaidb::{Value, Consistency, Response, ProtoError}`) | driver ≥ 0.290.4; older versions need `skaidb-types` / `skaidb-proto` as direct dependencies |

The driver's version is the skaidb version: driver `X.Y.Z` is the one
shipped and tested with server `X.Y.Z`, and the protocol is backward
compatible, so a newer driver talks to an older server (minus the gated
calls above) and vice versa.

## Examples

The `examples/` directory of the crate holds:

- `basic_usage.rs` — DDL, prepared inserts, queries, updates, error handling.
- `bench.rs` — a multi-threaded load generator over one-shot and prepared
  statements (`cargo run --release --example bench -- <addr> <user> <pass> <mode> <ops> <threads>`).
- `abench.rs` — a barrier-started, time-boxed load generator with optional TLS
  (`--tls-ca` / `--tls-insecure`), used for the encryption A/B benchmark.

## License

SSPL-1.0, the same license as skaidb. See `LICENSE`.
