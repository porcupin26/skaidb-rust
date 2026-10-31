//! skaidb client driver (SPEC §7).
//!
//! A synchronous client over the binary fast-path protocol ([`skaidb_proto`]).
//! A [`Client`] holds one or more candidate endpoints: on connect it prefers the
//! **nearest reachable** node (lowest TCP-connect latency) and keeps the rest as
//! failover targets. If the live connection drops mid-session, [`Client::execute`]
//! transparently reconnects to another endpoint and retries once, so a single
//! node dying does not take the session down when peers are available.
//!
//! A [`Pool`] built with [`Pool::builder`] balances its connections across
//! the cluster's members (policies, health ejection, member discovery and
//! read-your-writes affinity — docs/PROTOCOL.md §6.1).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use skaidb_auth::scram;
use skaidb_proto::{
    auth_message, decode_tagged_response, encode_tagged_request, read_frame, write_frame,
    AuthChallenge, AuthFinish, AuthMechanism, AuthOutcome, AuthStart, ClientRequest, Request,
};

// The types a caller needs to use the driver, re-exported so a project
// depends on this crate alone: `Value` (parameters and result cells) and
// the composite types inside it, plus the consistency level and the
// response shape every call returns. Without these, `Client::execute`
// returned a `Response` the caller could only name by adding
// `skaidb-proto` as a second dependency.
pub use skaidb_proto::{Consistency, ProtoError, Response};
pub use skaidb_types::{Decimal, Document, Uuid, Value, ValueType};

/// How long to wait for the latency probe TCP connect before giving up on an
/// endpoint's ordering (it is still retained as a last-resort failover target).
const PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// Errors surfaced by the driver.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error("connection error: {0}")]
    Io(#[from] io::Error),
    #[error("protocol error: {0}")]
    Proto(#[from] ProtoError),
    #[error("server error: {0}")]
    Server(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("no endpoint reachable: {0}")]
    NoEndpoint(String),
}

/// The prefix of an `AuthOutcome::Denied` reason that is a CAPACITY
/// refusal, not rejected credentials: the server is at
/// `server.max_connections` and the slot this connection landed in is
/// reserved for the superuser (docs/PROTOCOL.md, "Connection lifecycle").
pub const CAPACITY_DENIAL_PREFIX: &str = "too many connections:";

/// The error for an `AuthOutcome::Denied`: an authentication failure,
/// except a capacity refusal, which is a refused CONNECTION
/// ([`DriverError::Io`], `ConnectionRefused`) — retried and failed over
/// like any other, and never mistaken for bad credentials by a pool.
fn denied(reason: String) -> DriverError {
    if reason.starts_with(CAPACITY_DENIAL_PREFIX) {
        DriverError::Io(io::Error::new(io::ErrorKind::ConnectionRefused, reason))
    } else {
        DriverError::Auth(reason)
    }
}

/// A statement prepared on the server via [`Client::prepare`]: parse once,
/// execute many times with different parameter bindings. Holds the template
/// text so the driver can re-prepare transparently after a failover.
#[derive(Debug, Clone)]
pub struct Prepared {
    id: u32,
    /// How many `?` parameters the statement expects.
    pub params: u16,
    sql: String,
}

/// A synchronous connection to a skaidb cluster, with failover across endpoints.
#[derive(Debug)]
pub struct Client {
    /// Candidate endpoints (`host:port`), retained for reconnection.
    endpoints: Vec<String>,
    username: String,
    password: String,
    /// When set, authenticate with Kerberos (GSSAPI) to this target service
    /// principal instead of SCRAM; `password` is unused. Retained so failover
    /// reconnects re-authenticate the same way.
    gssapi_spn: Option<String>,
    /// Authenticate with the TLS client certificate (EXTERNAL) instead of a
    /// password; retained so failover reconnects do the same.
    cert_auth: bool,
    /// The endpoint the live `stream` is connected to.
    connected: String,
    stream: skaidb_net::Stream,
    /// Client-TLS settings applied to every (re)connect; `None` = plaintext.
    tls: Option<TlsConfig>,
    default_consistency: Consistency,
    /// Session database, re-applied after every reconnect (see
    /// [`Client::with_database`]). `None` leaves the server default.
    database: Option<String>,
    /// Session scan-budget ROWS override, replayed on reconnect like the
    /// database (`0` = none). Tightening-only server-side, so replaying it
    /// can never widen anything.
    scan_budget_rows: u64,
    /// The balanced pool this connection belongs to (see [`Pool::builder`]):
    /// told each round trip's latency, each transport failure and each
    /// write, and asked for the dial order when the connection re-dials.
    /// `None` outside such a pool.
    link: Option<PoolLink>,
}

/// Client-side TLS settings for a [`Client`]: the built rustls config plus the
/// SNI/verification name. Build with [`TlsConfig::new`].
#[derive(Clone)]
pub struct TlsConfig {
    cfg: Arc<rustls::ClientConfig>,
    server_name: String,
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConfig")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

/// How the driver verifies the server's certificate.
#[derive(Debug, Clone)]
pub enum TlsVerify {
    /// Trust server certs chaining to this CA file (the cluster CA).
    CaFile(String),
    /// Trust the public-CA roots (Mozilla's bundle, compiled in) — for
    /// servers behind certificates from a public CA.
    System,
    /// Skip verification — self-signed/dev only. INSECURE.
    Insecure,
}

impl TlsConfig {
    /// Build a client-TLS config. `server_name` is the SNI/verification name
    /// (the SAN on the server's cert — `skaidb` for certs from
    /// `skaidbsh certs gen`).
    pub fn new(verify: TlsVerify, server_name: &str) -> Result<TlsConfig, DriverError> {
        let v = match verify {
            TlsVerify::CaFile(p) => skaidb_net::ClientVerify::CaFile(p),
            TlsVerify::System => skaidb_net::ClientVerify::WebpkiDefaults,
            TlsVerify::Insecure => skaidb_net::ClientVerify::Insecure,
        };
        let cfg = skaidb_net::client_config(v, None)
            .map_err(|e| DriverError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
        Ok(TlsConfig {
            cfg,
            server_name: server_name.to_string(),
        })
    }

    /// [`TlsConfig::new`] that also presents a client certificate (PEM
    /// `cert_file` + `key_file`) — the credential for
    /// [`Client::connect_certificate`], and accepted by any server that
    /// requests one.
    pub fn with_client_cert(
        verify: TlsVerify,
        server_name: &str,
        cert_file: &str,
        key_file: &str,
    ) -> Result<TlsConfig, DriverError> {
        let v = match verify {
            TlsVerify::CaFile(p) => skaidb_net::ClientVerify::CaFile(p),
            TlsVerify::System => skaidb_net::ClientVerify::WebpkiDefaults,
            TlsVerify::Insecure => skaidb_net::ClientVerify::Insecure,
        };
        let cfg = skaidb_net::client_config(v, Some((cert_file, key_file)))
            .map_err(|e| DriverError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
        Ok(TlsConfig {
            cfg,
            server_name: server_name.to_string(),
        })
    }
}

impl Client {
    /// Connect anonymously to a single endpoint (server with auth disabled).
    pub fn connect(addr: impl ToSocketAddrs) -> Result<Client, DriverError> {
        Client::connect_with(addr, "anonymous", "")
    }

    /// Connect and authenticate to a single endpoint (SCRAM-SHA-256).
    ///
    /// `addr` may resolve to several socket addresses; all are kept as failover
    /// targets. For an explicit multi-node list use [`Client::connect_many`].
    pub fn connect_with(
        addr: impl ToSocketAddrs,
        username: &str,
        password: &str,
    ) -> Result<Client, DriverError> {
        let endpoints: Vec<String> = addr
            .to_socket_addrs()?
            .map(|a| a.to_string())
            .collect();
        if endpoints.is_empty() {
            return Err(DriverError::NoEndpoint("address did not resolve".into()));
        }
        Client::connect_many(&endpoints, username, password)
    }

    /// Connect across multiple candidate endpoints, preferring the nearest
    /// reachable one and keeping the others for failover. At least one endpoint
    /// must accept the connection and authenticate.
    pub fn connect_many(
        endpoints: &[String],
        username: &str,
        password: &str,
    ) -> Result<Client, DriverError> {
        Client::connect_many_tls(endpoints, username, password, None)
    }

    /// [`Client::connect_many`] with client-side TLS. `tls = None` is plaintext
    /// (identical to `connect_many`); `Some(cfg)` wraps every connection —
    /// including failover reconnects — in TLS.
    pub fn connect_many_tls(
        endpoints: &[String],
        username: &str,
        password: &str,
        tls: Option<TlsConfig>,
    ) -> Result<Client, DriverError> {
        Client::connect_mode(endpoints, username, password, None, false, tls)
    }

    /// Connect authenticating with Kerberos (SASL GSSAPI) instead of a
    /// password. `principal` is the client identity presented in the handshake
    /// (the authenticated identity actually comes from the Kerberos ticket);
    /// `target_spn` is the skaidb node's service principal, e.g.
    /// `skaidb/host.example.com@REALM`. Uses the ambient ticket cache — run
    /// `kinit` first. Requires a driver built with the `kerberos` feature.
    /// `tls = None` is plaintext; `Some(cfg)` wraps every (re)connect in TLS
    /// (recommended — GSSAPI provides authentication, TLS the confidentiality).
    pub fn connect_gssapi_tls(
        endpoints: &[String],
        principal: &str,
        target_spn: &str,
        tls: Option<TlsConfig>,
    ) -> Result<Client, DriverError> {
        Client::connect_mode(endpoints, principal, "", Some(target_spn.to_string()), false, tls)
    }

    /// Authenticate with the TLS client certificate (SASL EXTERNAL): the
    /// server maps the certificate's subject Common Name to a user, with no
    /// password. `tls` must present a certificate
    /// ([`TlsConfig::with_client_cert`]) and the server must run with
    /// `auth.x509_enabled`. `username` is optional — empty, or it must equal
    /// the certificate's Common Name.
    pub fn connect_certificate(
        endpoints: &[String],
        username: &str,
        tls: TlsConfig,
    ) -> Result<Client, DriverError> {
        Client::connect_mode(endpoints, username, "", None, true, Some(tls))
    }

    /// Plaintext [`Client::connect_gssapi_tls`].
    pub fn connect_gssapi(
        endpoints: &[String],
        principal: &str,
        target_spn: &str,
    ) -> Result<Client, DriverError> {
        Client::connect_gssapi_tls(endpoints, principal, target_spn, None)
    }

    /// Shared connect path: order endpoints by latency and dial each until one
    /// authenticates, via SCRAM (`gssapi_spn = None`) or GSSAPI (`Some(spn)`).
    fn connect_mode(
        endpoints: &[String],
        username: &str,
        password: &str,
        gssapi_spn: Option<String>,
        cert_auth: bool,
        tls: Option<TlsConfig>,
    ) -> Result<Client, DriverError> {
        let ordered = order_by_latency(&dedup(endpoints));
        if ordered.is_empty() {
            return Err(DriverError::NoEndpoint("no endpoints given".into()));
        }
        let login = Login {
            username: username.to_string(),
            password: password.to_string(),
            gssapi_spn,
            cert_auth,
            tls,
        };
        Client::open(ordered, &login, None)
    }

    /// Dial `ordered` in turn until one endpoint connects and authenticates.
    /// Inside a balanced pool (`link`), each failed dial that says something
    /// about the member's health is reported to the pool.
    fn open(ordered: Vec<String>, login: &Login, link: Option<PoolLink>) -> Result<Client, DriverError> {
        let mut last = String::new();
        for ep in &ordered {
            let dialed = dial(
                ep,
                &login.username,
                &login.password,
                login.gssapi_spn.as_deref(),
                login.cert_auth,
                login.tls.as_ref(),
            );
            match dialed {
                Ok(stream) => {
                    let mut link = link;
                    if let Some(l) = &mut link {
                        l.member = ep.clone();
                    }
                    return Ok(Client {
                        endpoints: ordered.clone(),
                        username: login.username.clone(),
                        password: login.password.clone(),
                        gssapi_spn: login.gssapi_spn.clone(),
                        cert_auth: login.cert_auth,
                        connected: ep.clone(),
                        stream,
                        tls: login.tls.clone(),
                        default_consistency: Consistency::Quorum,
                        database: None,
                        scan_budget_rows: 0,
                        link,
                    }
                    .said_hello());
                }
                Err(e) => {
                    if let Some(l) = &link {
                        if member_fault(&e) {
                            l.pool.failed(ep);
                        }
                    }
                    last = format!("{ep}: {e}");
                }
            }
        }
        Err(DriverError::NoEndpoint(last))
    }

    /// The endpoint the live connection is using (the chosen / failed-over node).
    pub fn endpoint(&self) -> &str {
        &self.connected
    }

    /// All candidate endpoints, in current preference order.
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// Merge additional failover endpoints into the pool (e.g. peers discovered
    /// from the cluster after connecting to a seed). Duplicates are ignored and
    /// the live connection is left untouched.
    pub fn add_endpoints(&mut self, more: &[String]) {
        for e in more {
            if !self.endpoints.contains(e) {
                self.endpoints.push(e.clone());
            }
        }
    }

    /// Set the consistency level used by [`Client::execute`].
    pub fn set_consistency(&mut self, consistency: Consistency) {
        self.default_consistency = consistency;
    }

    /// Execute a statement at the default consistency.
    /// Poll a stream's log once, returning events after `after` (oldest
    /// first) together with the position to pass next time.
    ///
    /// A dependency-free helper: streams are ordinary tables, so this is a
    /// keyset-paged read. Call it in a loop, keeping the returned cursor —
    /// it resumes exactly where you stopped, across restarts. An empty
    /// result means "nothing new"; sleep and call again.
    ///
    /// For push delivery subscribe to `$stream/<db>/<name>` with any MQTT
    /// client instead; the events are identical.
    ///
    /// ```no_run
    /// # use skaidb::Client;
    /// # let mut client = Client::connect("h:7000")?;
    /// let mut cursor = String::new();
    /// loop {
    ///     let (events, next) = client.stream_poll("big_orders", &cursor, 500)?;
    ///     for ev in &events { println!("{ev:?}"); }
    ///     cursor = next;
    ///     if events.is_empty() { std::thread::sleep(std::time::Duration::from_millis(500)); }
    /// }
    /// # Ok::<(), skaidb::DriverError>(())
    /// ```
    pub fn stream_poll(
        &mut self,
        stream: &str,
        after: &str,
        limit: usize,
    ) -> Result<(Vec<Vec<Value>>, String), DriverError> {
        let log = format!("_stream_{stream}");
        let sql = if after.is_empty() {
            format!("SELECT id, op, k, ts, doc FROM {log} ORDER BY id LIMIT {limit}")
        } else {
            format!(
                "SELECT id, op, k, ts, doc FROM {log} WHERE id > '{}' ORDER BY id LIMIT {limit}",
                after.replace('\'', "''")
            )
        };
        let rows = match self.execute(&sql)? {
            Response::Rows { rows, .. } => rows,
            _ => Vec::new(),
        };
        let next = rows
            .last()
            .and_then(|r| r.first())
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_else(|| after.to_string());
        Ok((rows, next))
    }

    /// Bind this client to `database` — the equivalent of every other
    /// driver's `database=` connect option, which Rust lacked.
    ///
    /// The `USE` runs now and again after every reconnect. That second part is
    /// the point: a failover that silently dropped the session back to the
    /// default database would send subsequent statements to the wrong tables.
    ///
    /// ```no_run
    /// # use skaidb::Client;
    /// # let eps = vec!["h1:7000".to_string()];
    /// let client = Client::connect_many(&eps, "u", "p")?.with_database("app")?;
    /// # Ok::<(), skaidb::DriverError>(())
    /// ```
    pub fn with_database(mut self, database: &str) -> Result<Client, DriverError> {
        self.use_database(database)?;
        Ok(self)
    }

    /// Bind (or rebind) the session database on a live client: `USE` now,
    /// and again after every failover. A refusal (unknown database, no
    /// privilege) leaves the previous binding and the connection as they
    /// were.
    pub fn use_database(&mut self, database: &str) -> Result<(), DriverError> {
        let previous = self.database.replace(database.to_string());
        if let Err(e) = self.apply_database() {
            self.database = previous;
            return Err(e);
        }
        Ok(())
    }

    /// The session database, if one was bound.
    pub fn database(&self) -> Option<&str> {
        self.database.as_deref()
    }

    /// Issue `USE` for the bound database on the CURRENT connection. Sends
    /// through `roundtrip` rather than `execute`, so a failure here cannot
    /// recurse back into reconnect. The name is identifier-quoted, so a
    /// database whose name needs quoting still works.
    fn apply_database(&mut self) -> Result<(), DriverError> {
        let Some(db) = self.database.clone() else {
            return Ok(());
        };
        let sql = format!("USE \"{}\"", db.replace('"', "\"\""));
        self.roundtrip(&ClientRequest::Query {
            sql,
            consistency: self.default_consistency,
        })?;
        Ok(())
    }

    /// Best-effort self-identification (`Hello`): fills the server's
    /// `drivers` table `client_name`/`client_version` columns. An old
    /// server rejects the opcode with an error, which is IGNORED —
    /// identity is telemetry, never load-bearing.
    fn said_hello(mut self) -> Client {
        self.send_hello();
        self
    }

    fn send_hello(&mut self) {
        let req = ClientRequest::Hello {
            client_name: "rust".into(),
            client_version: env!("CARGO_PKG_VERSION").into(),
        };
        // Sent outside `roundtrip`: identification is no statement, so it
        // is no latency sample for a balanced pool either.
        if write_frame(&mut self.stream, &req.encode()).is_ok() {
            let _ = read_frame(&mut self.stream);
        }
    }

    /// Set (and remember) the session's tightening-only scan-row budget:
    /// executes `SET SCAN BUDGET ROWS <n>` now and REPLAYS it after every
    /// reconnect — without the replay, a silent reconnect reverts the
    /// session to node defaults with nothing in the logs. `0` clears
    /// (`SET SCAN BUDGET DEFAULT`).
    pub fn set_scan_budget_rows(&mut self, rows: u64) -> Result<(), DriverError> {
        let sql = if rows == 0 {
            "SET SCAN BUDGET DEFAULT".to_string()
        } else {
            format!("SET SCAN BUDGET ROWS {rows}")
        };
        self.roundtrip(&ClientRequest::Query {
            sql,
            consistency: self.default_consistency,
        })?;
        self.scan_budget_rows = rows;
        Ok(())
    }

    fn apply_scan_budget(&mut self) -> Result<(), DriverError> {
        if self.scan_budget_rows == 0 {
            return Ok(());
        }
        let sql = format!("SET SCAN BUDGET ROWS {}", self.scan_budget_rows);
        self.roundtrip(&ClientRequest::Query {
            sql,
            consistency: self.default_consistency,
        })?;
        Ok(())
    }

    pub fn execute(&mut self, sql: &str) -> Result<Response, DriverError> {
        self.execute_with(sql, self.default_consistency)
    }

    /// Execute a statement at an explicit consistency level. If the live
    /// connection has dropped, fail over to another endpoint and retry once.
    pub fn execute_with(
        &mut self,
        sql: &str,
        consistency: Consistency,
    ) -> Result<Response, DriverError> {
        let out = match self.try_execute(sql, consistency) {
            // A broken pipe / reset / EOF means the node went away — try a peer.
            Err(DriverError::Io(_)) => {
                self.reconnect()?;
                self.try_execute(sql, consistency)
            }
            other => other,
        };
        if out.is_ok() {
            self.observe_statement(sql);
        }
        out
    }

    /// One attempt over the current stream (no reconnect).
    fn try_execute(
        &mut self,
        sql: &str,
        consistency: Consistency,
    ) -> Result<Response, DriverError> {
        let req = Request {
            sql: sql.to_string(),
            consistency,
        };
        let started = Instant::now();
        let frame = write_frame(&mut self.stream, &req.encode())
            .and_then(|()| read_frame(&mut self.stream));
        let payload = self.observed(started, frame)?;
        match Response::decode(&payload)? {
            Response::Error(msg) => Err(DriverError::Server(msg)),
            other => Ok(other),
        }
    }

    /// Execute a batch of statements **pipelined** at the default
    /// consistency: all requests are written before any response is read, so
    /// the whole batch pays one round-trip of link latency instead of one
    /// per statement. See [`Client::pipeline_with`].
    pub fn pipeline(&mut self, stmts: &[&str]) -> Result<Vec<Response>, DriverError> {
        self.pipeline_with(stmts, self.default_consistency)
    }

    /// Pipelined batch execution at an explicit consistency.
    ///
    /// Statements execute on the server serially, in order, with ordinary
    /// session semantics (a `USE` mid-batch affects the statements after
    /// it). Responses are correlated by request id, and per-statement
    /// failures come back **inline** as [`Response::Error`] entries — a
    /// failed statement does not stop the ones after it. The whole batch is
    /// retried once on a fresh connection if the node dies mid-flight (same
    /// idempotency caveat as [`Client::execute_with`]). Servers older than
    /// the tagged-request opcode fail the batch with "server too old".
    pub fn pipeline_with(
        &mut self,
        stmts: &[&str],
        consistency: Consistency,
    ) -> Result<Vec<Response>, DriverError> {
        if stmts.is_empty() {
            return Ok(Vec::new());
        }
        let out = match self.try_pipeline(stmts, consistency) {
            Err(DriverError::Io(_)) => {
                self.reconnect()?;
                self.try_pipeline(stmts, consistency)
            }
            other => other,
        };
        if let Ok(responses) = &out {
            for (sql, resp) in stmts.iter().zip(responses) {
                if !matches!(resp, Response::Error(_)) {
                    self.observe_statement(sql);
                }
            }
        }
        out
    }

    /// One pipelined attempt over the current stream (no reconnect).
    fn try_pipeline(
        &mut self,
        stmts: &[&str],
        consistency: Consistency,
    ) -> Result<Vec<Response>, DriverError> {
        // Write every request before reading anything: the requests queue in
        // the server's receive buffer and are answered back-to-back.
        let started = Instant::now();
        let mut buf = Vec::new();
        for (i, sql) in stmts.iter().enumerate() {
            buf.clear();
            encode_tagged_request(
                i as u32,
                &ClientRequest::Query {
                    sql: (*sql).to_string(),
                    consistency,
                },
                &mut buf,
            );
            let sent = write_frame(&mut self.stream, &buf);
            self.transport(sent)?;
        }
        let mut out: Vec<Option<Response>> = (0..stmts.len()).map(|_| None).collect();
        for n in 0..stmts.len() {
            let frame = read_frame(&mut self.stream);
            // The first response frame ends the batch's round trip.
            let payload = if n == 0 {
                self.observed(started, frame)?
            } else {
                self.transport(frame)?
            };
            let (id, resp) = decode_tagged_response(&payload)?;
            let Some(id) = id else {
                // An untagged response to a tagged request: the server
                // predates pipelining and answered with a plain error.
                return Err(DriverError::Server(
                    "server does not support pipelined requests (upgrade the server)".into(),
                ));
            };
            match out.get_mut(id as usize) {
                Some(slot @ None) => *slot = Some(resp),
                _ => {
                    return Err(DriverError::Server(format!(
                        "unexpected response id {id} in pipeline"
                    )))
                }
            }
        }
        // Every slot filled exactly once (ids 0..n, each seen once).
        Ok(out.into_iter().map(|r| r.expect("all ids seen")).collect())
    }

    /// Parse `sql` (which may contain `?` placeholders) once on the server
    /// and cache it on this connection. Execute it any number of times with
    /// [`Client::execute_prepared`], paying no per-call parse.
    pub fn prepare(&mut self, sql: &str) -> Result<Prepared, DriverError> {
        let req = ClientRequest::Prepare {
            sql: sql.to_string(),
        };
        match self.roundtrip(&req) {
            Err(DriverError::Io(_)) => {
                self.reconnect()?;
                self.roundtrip(&req)
            }
            other => other,
        }
        .and_then(|resp| match resp {
            Response::Prepared { id, params } => Ok(Prepared {
                id,
                params,
                sql: sql.to_string(),
            }),
            other => Err(DriverError::Server(format!(
                "unexpected response to Prepare: {other:?}"
            ))),
        })
    }

    /// Execute a prepared statement at the default consistency.
    pub fn execute_prepared(
        &mut self,
        stmt: &mut Prepared,
        params: &[Value],
    ) -> Result<Response, DriverError> {
        self.execute_prepared_with(stmt, params, self.default_consistency)
    }

    /// Execute a prepared statement at an explicit consistency. Prepared ids
    /// are per-connection, so on failover the statement is transparently
    /// re-prepared on the new connection (updating `stmt`) and retried once.
    pub fn execute_prepared_with(
        &mut self,
        stmt: &mut Prepared,
        params: &[Value],
        consistency: Consistency,
    ) -> Result<Response, DriverError> {
        let req = ClientRequest::Execute {
            id: stmt.id,
            params: params.to_vec(),
            consistency,
        };
        let out = match self.roundtrip(&req) {
            Err(DriverError::Io(_)) => {
                self.reconnect()?;
                *stmt = self.prepare(&stmt.sql)?;
                self.roundtrip(&ClientRequest::Execute {
                    id: stmt.id,
                    params: params.to_vec(),
                    consistency,
                })
            }
            other => other,
        };
        if out.is_ok() {
            self.observe_statement(&stmt.sql);
        }
        out
    }

    /// Execute a prepared statement once per parameter row in a single
    /// round-trip (the `executemany` wire op) at the default consistency.
    /// Returns the total affected count. Each row autocommits like a looped
    /// `execute_prepared`; on a failure the server error names the row and
    /// earlier rows stay applied.
    pub fn execute_batch(
        &mut self,
        stmt: &mut Prepared,
        rows: Vec<Vec<Value>>,
    ) -> Result<u64, DriverError> {
        let consistency = self.default_consistency;
        let req = ClientRequest::ExecuteBatch {
            id: stmt.id,
            rows: rows.clone(),
            consistency,
        };
        let resp = match self.roundtrip(&req) {
            Err(DriverError::Io(_)) => {
                self.reconnect()?;
                *stmt = self.prepare(&stmt.sql)?;
                self.roundtrip(&ClientRequest::ExecuteBatch {
                    id: stmt.id,
                    rows,
                    consistency,
                })
            }
            other => other,
        }?;
        match resp {
            Response::Mutation { affected } => {
                self.observe_statement(&stmt.sql);
                Ok(affected)
            }
            Response::Error(e) => Err(DriverError::Server(e)),
            other => Err(DriverError::Server(format!(
                "unexpected response to ExecuteBatch: {other:?}"
            ))),
        }
    }

    /// One request/response round-trip over the current stream (no reconnect).
    fn roundtrip(&mut self, req: &ClientRequest) -> Result<Response, DriverError> {
        let started = Instant::now();
        let frame = write_frame(&mut self.stream, &req.encode())
            .and_then(|()| read_frame(&mut self.stream));
        let payload = self.observed(started, frame)?;
        match Response::decode(&payload)? {
            Response::Error(msg) => Err(DriverError::Server(msg)),
            other => Ok(other),
        }
    }

    // ---- what a pooled connection reports to its pool -------------------

    /// A request's transport outcome, reported to the balanced pool that
    /// owns this connection (if any): the round trip from `started` to the
    /// first response frame, or the failure.
    fn observed<T>(&mut self, started: Instant, frame: io::Result<T>) -> Result<T, DriverError> {
        match frame {
            Ok(v) => {
                if let Some(link) = &mut self.link {
                    link.broken = false;
                    let pool = link.pool.clone();
                    pool.round_trip(link, &self.connected, started.elapsed());
                }
                Ok(v)
            }
            Err(e) => self.transport(Err(e)),
        }
    }

    /// A transport step with no latency to report: on failure the socket is
    /// unusable until a re-dial, and the member it reached gets a strike.
    fn transport<T>(&mut self, r: io::Result<T>) -> Result<T, DriverError> {
        r.map_err(|e| {
            if let Some(link) = &mut self.link {
                link.broken = true;
                link.pool.failed(&self.connected);
            }
            DriverError::Io(e)
        })
    }

    /// A statement succeeded: a pool with read-your-writes on remembers
    /// which member took a write.
    fn observe_statement(&self, sql: &str) {
        if let Some(link) = &self.link {
            if link.out && link.pool.read_your_writes() && is_write(sql) {
                link.pool.wrote(link.affinity.clone(), &self.connected);
            }
        }
    }

    /// Run a query whose result arrives as a stream of row chunks, at the
    /// default consistency. See [`Client::query_stream_with`].
    pub fn query_stream(&mut self, sql: &str) -> Result<RowStream<'_>, DriverError> {
        self.query_stream_with(sql, self.default_consistency)
    }

    /// Run a query whose result arrives as a stream of row chunks, so the
    /// client never holds more than one chunk in memory — use this for result
    /// sets too large to buffer. Non-row statements yield an empty stream
    /// (check [`RowStream::affected`]); a `CALL` whose body `EMIT`s result
    /// sets yields its first set, and [`RowStream::next_result_set`] walks
    /// the rest.
    ///
    /// The returned [`RowStream`] borrows the connection exclusively until it
    /// is drained or dropped (dropping it reads and discards the rest of the
    /// stream). Failover applies only to sending the request; an endpoint
    /// dying mid-stream surfaces as an error from the iterator, and the caller
    /// decides whether to re-run the query. Servers older than the
    /// `QueryStream` opcode reject it with a server error; use
    /// [`Client::execute`] against those.
    pub fn query_stream_with(
        &mut self,
        sql: &str,
        consistency: Consistency,
    ) -> Result<RowStream<'_>, DriverError> {
        self.query_stream_params_with(sql, &[], consistency)
    }

    /// [`Client::query_stream`] with `params` bound to the statement's `?`
    /// placeholders, in order — a bound range streams exactly like a
    /// written one (the server binds them as `execute_prepared` does). At
    /// the default consistency; see [`Client::query_stream_params_with`].
    pub fn query_stream_params(
        &mut self,
        sql: &str,
        params: &[Value],
    ) -> Result<RowStream<'_>, DriverError> {
        self.query_stream_params_with(sql, params, self.default_consistency)
    }

    /// [`Client::query_stream_with`] with bound parameters. Parameters
    /// travel in `OP_QUERY_STREAM_PARAMS` (servers ≥ 0.330); without any,
    /// the request is the original `OP_QUERY_STREAM`, so a parameterless
    /// stream still works against older servers.
    pub fn query_stream_params_with(
        &mut self,
        sql: &str,
        params: &[Value],
        consistency: Consistency,
    ) -> Result<RowStream<'_>, DriverError> {
        let req = ClientRequest::QueryStream {
            sql: sql.to_string(),
            params: params.to_vec(),
            consistency,
        };
        let mut started = Instant::now();
        let sent = write_frame(&mut self.stream, &req.encode());
        if self.transport(sent).is_err() {
            // The node died since the last use — fail over before the stream
            // starts, like execute() does.
            self.reconnect()?;
            started = Instant::now();
            let sent = write_frame(&mut self.stream, &req.encode());
            self.transport(sent)?;
        }
        let frame = read_frame(&mut self.stream);
        let payload = self.observed(started, frame)?;
        let resp = Response::decode(&payload)?;
        if matches!(
            resp,
            Response::RowsHeader { .. }
                | Response::Mutation { .. }
                | Response::Ddl
                | Response::ResultSets { .. }
        ) {
            self.observe_statement(sql);
        }
        match resp {
            Response::Error(msg) => Err(DriverError::Server(msg)),
            Response::RowsHeader { columns } => Ok(RowStream {
                client: self,
                columns,
                affected: 0,
                chunk: Vec::new().into_iter(),
                more: Vec::new().into_iter(),
                done: false,
            }),
            // Non-row statement: a single ordinary response ends the exchange.
            Response::Mutation { affected } => Ok(RowStream {
                client: self,
                columns: Vec::new(),
                affected,
                chunk: Vec::new().into_iter(),
                more: Vec::new().into_iter(),
                done: true,
            }),
            Response::Ddl => Ok(RowStream {
                client: self,
                columns: Vec::new(),
                affected: 0,
                chunk: Vec::new().into_iter(),
                more: Vec::new().into_iter(),
                done: true,
            }),
            // A CALL whose body EMITted: every set in ONE ordinary frame,
            // streamed or not — the frame `execute` receives, decoded by the
            // same `Response::decode`. The exchange is over, so the stream
            // owns nothing: the first set is current and
            // [`RowStream::next_result_set`] walks the rest.
            Response::ResultSets { sets } => {
                let mut sets = sets.into_iter();
                let (columns, rows) = sets.next().unwrap_or_default();
                Ok(RowStream {
                    client: self,
                    columns,
                    affected: 0,
                    chunk: rows.into_iter(),
                    more: sets,
                    done: true,
                })
            }
            other => Err(DriverError::Server(format!(
                "unexpected response to QueryStream: {other:?}"
            ))),
        }
    }

    /// Re-establish the connection after a failure, preferring a *different*
    /// node than the one that just died, then falling back to any reachable one.
    ///
    /// Called automatically when a statement hits a transport error; public so
    /// a pool (or a caller that owns its own retry policy) can recycle a
    /// connection deliberately, as the Python driver's `reconnect()` allows.
    /// Re-authenticates and re-enters the bound database
    /// ([`Client::with_database`]); prepared statements do not survive, since
    /// a statement id is only valid on the connection that created it.
    pub fn reconnect(&mut self) -> Result<(), DriverError> {
        let ordered = match &self.link {
            // Pooled: the pool's current order — usable members first, the
            // member this connection just lost last.
            Some(link) => link.pool.dial_order(&self.connected),
            None => {
                let mut ordered = order_by_latency(&self.endpoints);
                // Try endpoints other than the one that just failed first.
                ordered.sort_by_key(|e| *e == self.connected);
                ordered
            }
        };
        let mut last = String::new();
        for ep in &ordered {
            match dial(
                ep,
                &self.username,
                &self.password,
                self.gssapi_spn.as_deref(),
                self.cert_auth,
                self.tls.as_ref(),
            ) {
                Ok(stream) => {
                    self.stream = stream;
                    self.connected = ep.clone();
                    self.endpoints = ordered;
                    if let Some(link) = &mut self.link {
                        // The connection now counts against the member it
                        // reached.
                        link.broken = false;
                        let pool = link.pool.clone();
                        pool.moved(link, &self.connected);
                    }
                    // Re-identify, re-enter the session database and
                    // re-tighten the scan budget before anything else runs
                    // on this socket.
                    self.send_hello();
                    self.apply_database()?;
                    self.apply_scan_budget()?;
                    return Ok(());
                }
                Err(e) => {
                    if let Some(link) = &self.link {
                        if member_fault(&e) {
                            link.pool.failed(ep);
                        }
                    }
                    last = format!("{ep}: {e}");
                }
            }
        }
        Err(DriverError::NoEndpoint(last))
    }
}

/// A streamed result set from [`Client::query_stream`]: iterate to receive
/// rows chunk by chunk. Holds at most one chunk in memory. Borrows the
/// [`Client`] exclusively; dropping the stream early drains the remaining
/// frames so the connection stays usable.
///
/// A `CALL` whose procedure body `EMIT`s result sets is answered with all of
/// them in one frame, streamed or not: the stream starts on the first set
/// and [`RowStream::next_result_set`] walks the rest.
#[derive(Debug)]
pub struct RowStream<'a> {
    client: &'a mut Client,
    /// Column names of the result set (empty for non-row statements).
    pub columns: Vec<String>,
    /// Rows affected, when the statement turned out to be a mutation.
    pub affected: u64,
    chunk: std::vec::IntoIter<Vec<Value>>,
    /// The sets after the current one, of a `CALL` whose body `EMIT`ted.
    more: std::vec::IntoIter<(Vec<String>, Vec<Vec<Value>>)>,
    done: bool,
}

impl RowStream<'_> {
    /// Advance to the next result set of a multi-set reply: a `CALL` whose
    /// procedure body `EMIT`s result sets is answered with all of them in
    /// one frame, even to a stream request, and the stream starts on the
    /// first. [`RowStream::columns`] and the iteration then describe the next
    /// set. `false` when there is no further set — always, for a streamed
    /// result.
    pub fn next_result_set(&mut self) -> bool {
        match self.more.next() {
            Some((columns, rows)) => {
                self.columns = columns;
                self.chunk = rows.into_iter();
                true
            }
            None => false,
        }
    }

    /// Fetch the next frame after the current chunk ran dry.
    fn next_frame(&mut self) -> Result<(), DriverError> {
        let frame = read_frame(&mut self.client.stream);
        let payload = self.client.transport(frame)?;
        match Response::decode(&payload)? {
            Response::RowsChunk { rows } => self.chunk = rows.into_iter(),
            Response::RowsEnd => self.done = true,
            Response::Error(msg) => {
                self.done = true;
                return Err(DriverError::Server(msg));
            }
            other => {
                self.done = true;
                return Err(DriverError::Server(format!(
                    "unexpected frame in row stream: {other:?}"
                )));
            }
        }
        Ok(())
    }
}

impl Iterator for RowStream<'_> {
    type Item = Result<Vec<Value>, DriverError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(row) = self.chunk.next() {
                return Some(Ok(row));
            }
            if self.done {
                return None;
            }
            if let Err(e) = self.next_frame() {
                // An I/O error also marks the stream finished: the connection
                // is broken and the next client call will fail over.
                self.done = true;
                return Some(Err(e));
            }
        }
    }
}

impl Drop for RowStream<'_> {
    fn drop(&mut self) {
        // Read out any frames the server is still sending, so the connection
        // is positioned at a request boundary for the next call. On error the
        // socket is broken anyway and the client will reconnect on next use.
        while !self.done {
            if self.next_frame().is_err() {
                break;
            }
        }
    }
}

/// Open a TCP connection to `endpoint` and run the client handshake — GSSAPI
/// when `gssapi_spn` is set, the client certificate when `cert_auth`,
/// otherwise SCRAM.
fn dial(
    endpoint: &str,
    username: &str,
    password: &str,
    gssapi_spn: Option<&str>,
    cert_auth: bool,
    tls: Option<&TlsConfig>,
) -> Result<skaidb_net::Stream, DriverError> {
    let tcp = TcpStream::connect(endpoint)?;
    tcp.set_nodelay(true).ok();
    let mut stream = match tls {
        Some(t) => skaidb_net::connect_tls(tcp, t.cfg.clone(), &t.server_name)?,
        None => skaidb_net::Stream::Plain(tcp),
    };
    match gssapi_spn {
        Some(spn) => handshake_gssapi(&mut stream, username, spn)?,
        None if cert_auth => handshake_external(&mut stream, username)?,
        None => handshake(&mut stream, username, password)?,
    }
    Ok(stream)
}

/// Client side of EXTERNAL: announce the mechanism and read the outcome —
/// the certificate presented during the TLS handshake is the credential.
fn handshake_external<S: io::Read + io::Write>(
    stream: &mut S,
    username: &str,
) -> Result<(), DriverError> {
    write_frame(
        stream,
        &AuthStart {
            username: username.to_string(),
            client_nonce: String::new(),
            mechanism: AuthMechanism::External,
        }
        .encode(),
    )?;
    match AuthOutcome::decode(&read_frame(stream)?)? {
        AuthOutcome::Ok { .. } => Ok(()),
        AuthOutcome::Denied { reason } => Err(denied(reason)),
    }
}

/// Client side of the GSSAPI handshake: announce the mechanism, send the first
/// GSS token, then shuttle `AuthToken` frames until the server replies with an
/// `AuthOutcome`. Uses the ambient ticket cache (run `kinit`). Built only with
/// the `kerberos` feature.
#[cfg(feature = "kerberos")]
fn handshake_gssapi(
    stream: &mut skaidb_net::Stream,
    username: &str,
    target_spn: &str,
) -> Result<(), DriverError> {
    use skaidb_gssapi::{ClientHandshake, ClientStep};
    use skaidb_proto::AuthToken;

    // Inside TLS, bind the GSS context to the server certificate we just
    // verified (RFC 5929 tls-server-end-point): a server configured to
    // require bindings then accepts, and one that is not ignores them.
    let bindings = stream
        .peer_certificate_der()
        .map(|der| skaidb_net::tls_server_end_point(&der));

    static NONCE: AtomicU64 = AtomicU64::new(0);
    let client_nonce = format!(
        "c{}.{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    );
    let (client, token0) = ClientHandshake::new(target_spn, None, bindings.as_deref())
        .map_err(|e| DriverError::Auth(format!("gssapi init failed (did you kinit?): {e}")))?;
    write_frame(
        stream,
        &AuthStart {
            username: username.to_string(),
            client_nonce,
            mechanism: AuthMechanism::Gssapi,
        }
        .encode(),
    )?;
    write_frame(stream, &AuthToken { token: token0 }.encode())?;

    let mut client = Some(client);
    loop {
        let frame = read_frame(stream)?;
        if let Ok(tok) = AuthToken::decode(&frame) {
            let c = client
                .take()
                .ok_or_else(|| DriverError::Auth("gssapi: unexpected server token".into()))?;
            match c.step(&tok.token).map_err(|e| DriverError::Auth(e.to_string()))? {
                ClientStep::Continue { next, token } => {
                    client = Some(next);
                    write_frame(stream, &AuthToken { token }.encode())?;
                }
                ClientStep::Done { token } => {
                    if let Some(token) = token {
                        write_frame(stream, &AuthToken { token }.encode())?;
                    }
                }
            }
        } else if let Ok(outcome) = AuthOutcome::decode(&frame) {
            return match outcome {
                AuthOutcome::Ok { .. } => Ok(()),
                AuthOutcome::Denied { reason } => Err(denied(reason)),
            };
        } else {
            return Err(DriverError::Auth("gssapi: unexpected handshake frame".into()));
        }
    }
}

#[cfg(not(feature = "kerberos"))]
fn handshake_gssapi(
    _stream: &mut skaidb_net::Stream,
    _username: &str,
    _target_spn: &str,
) -> Result<(), DriverError> {
    Err(DriverError::Auth(
        "this driver was built without Kerberos (GSSAPI) support".into(),
    ))
}

/// Remove duplicate endpoints while preserving the caller's order.
fn dedup(endpoints: &[String]) -> Vec<String> {
    let mut seen = Vec::new();
    for e in endpoints {
        if !seen.contains(e) {
            seen.push(e.clone());
        }
    }
    seen
}

/// Order endpoints by ascending TCP-connect latency (nearest first). Endpoints
/// that fail the probe sink to the back but are retained as failover targets. A
/// single endpoint is returned as-is (no probe needed).
fn order_by_latency(endpoints: &[String]) -> Vec<String> {
    if endpoints.len() <= 1 {
        return endpoints.to_vec();
    }
    let mut scored: Vec<(Option<Duration>, String)> = endpoints
        .iter()
        .map(|e| (probe(e), e.clone()))
        .collect();
    scored.sort_by(|a, b| match (a.0, b.0) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    scored.into_iter().map(|(_, e)| e).collect()
}

/// Measure TCP-connect latency to an endpoint, or `None` if it can't be reached.
fn probe(endpoint: &str) -> Option<Duration> {
    let addr = endpoint.to_socket_addrs().ok()?.next()?;
    let start = Instant::now();
    TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).ok()?;
    Some(start.elapsed())
}

/// Process-global cache of derived SCRAM `SaltedPassword`s, keyed by
/// (password, salt, iterations). The PBKDF2 derivation is deliberately
/// expensive (15k HMAC iterations at the default — tens of ms on small
/// CPUs) and its output is identical for every connection authenticating
/// the same credential against the same stored salt, so pools and
/// reconnects pay it once instead of per connection. The cache holds
/// password-equivalent secrets, but so does the process (the password
/// itself is in memory); bounded small since real processes use a handful
/// of credentials.
fn cached_salted_password(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    use std::collections::HashMap;
    use std::sync::Mutex;
    /// (password, salt, iterations) → derived SaltedPassword.
    type SaltedCache = HashMap<(String, Vec<u8>, u32), [u8; 32]>;
    static CACHE: Mutex<Option<SaltedCache>> = Mutex::new(None);

    let key = (password.to_string(), salt.to_vec(), iterations);
    if let Some(hit) = CACHE
        .lock()
        .ok()
        .and_then(|c| c.as_ref().and_then(|m| m.get(&key).copied()))
    {
        return hit;
    }
    // Derive outside the lock: a herd of first connections computes it in
    // parallel rather than serializing behind one derivation.
    let salted = scram::salted_password(password, salt, iterations);
    if let Ok(mut guard) = CACHE.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        if map.len() >= 64 {
            map.clear(); // crude bound; real processes hold a handful of creds
        }
        map.insert(key, salted);
    }
    salted
}

/// Run the client side of the SCRAM handshake. When `password` is non-empty,
/// the server's signature is verified for mutual authentication.
fn handshake<S: io::Read + io::Write>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<(), DriverError> {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let client_nonce = format!(
        "c{}.{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    );

    let start = AuthStart {
        username: username.to_string(),
        client_nonce: client_nonce.clone(),
        // This handshake helper speaks SCRAM; GSSAPI has its own client path.
        mechanism: AuthMechanism::ScramSha256,
    };
    write_frame(stream, &start.encode())?;

    let challenge = AuthChallenge::decode(&read_frame(stream)?)?;
    let am = auth_message(
        username,
        &client_nonce,
        &challenge.server_nonce,
        &challenge.salt,
        challenge.iterations,
    );
    // One PBKDF2 per (credential, salt) per process — not two per
    // connection: the proof and the server-signature check share the
    // derived key, and the cache shares it across connections.
    let salted = cached_salted_password(password, &challenge.salt, challenge.iterations);
    let proof = scram::client_proof_salted(&salted, &am);
    write_frame(
        stream,
        &AuthFinish {
            client_proof: proof,
        }
        .encode(),
    )?;

    match AuthOutcome::decode(&read_frame(stream)?)? {
        AuthOutcome::Ok { server_signature } => {
            if !password.is_empty() {
                let expected = scram::server_signature_salted(&salted, &am);
                if expected != server_signature {
                    return Err(DriverError::Auth("server signature mismatch".into()));
                }
            }
            Ok(())
        }
        AuthOutcome::Denied { reason } => Err(denied(reason)),
    }
}

// ---- connection pool ------------------------------------------------------

/// A thread-safe pool of [`Client`] connections.
///
/// `maxsize` bounds the connections kept **idle**, not the number checked out:
/// a burst creates extras and the surplus is dropped on return, so callers
/// never block waiting for a slot. There are two ways to build one:
///
/// - [`Pool::builder`]: the pool knows the endpoints and credentials and
///   balances its connections across the cluster's members by the rules
///   every official driver shares (docs/PROTOCOL.md §6.1) — a
///   [`LoadBalancing`] policy, an [`IdleOrder`], health ejection with a
///   background re-probe, member discovery through `SHOW ENDPOINTS`, and
///   read-your-writes affinity ([`Pool::acquire_with_affinity`]).
/// - [`Pool::new`]: connections are built by the closure you supply, so they
///   inherit whatever it configures — seed list, TLS, credentials, session
///   database; the most recently returned idle connection is handed out
///   first and the pool knows nothing about members.
///
/// ```no_run
/// # use skaidb::{LoadBalancing, Pool};
/// let pool = Pool::builder(&["h1:7000", "h2:7000", "h3:7000"])
///     .credentials("app", "secret")
///     .database("app")
///     .maxsize(8)
///     .load_balancing(LoadBalancing::LeastLatency)
///     .discover(true)
///     .build()?;
/// let rows = pool.with(|c| c.execute("SELECT count(*) FROM t"))?;
/// # Ok::<(), skaidb::DriverError>(())
/// ```
///
/// ```no_run
/// # use skaidb::{Client, Pool};
/// let eps = vec!["h1:7000".to_string(), "h2:7000".to_string()];
/// let pool = Pool::new(8, move || {
///     Client::connect_many(&eps, "app", "secret")?.with_database("app")
/// });
/// let rows = pool.with(|c| c.execute("SELECT count(*) FROM t"))?;
/// # Ok::<(), skaidb::DriverError>(())
/// ```
pub struct Pool {
    inner: PoolInner,
}

enum PoolInner {
    /// [`Pool::new`]: connections from a closure.
    Factory {
        maxsize: usize,
        // Boxed so the pool is usable from any thread that can see it.
        make: Box<dyn Fn() -> Result<Client, DriverError> + Send + Sync>,
        idle: Mutex<Vec<Client>>,
        closed: Mutex<bool>,
    },
    /// [`Pool::builder`]: balanced across members. Shared with every
    /// connection it hands out (they report to it) and, weakly, with its
    /// background thread.
    Balanced(Arc<Balancer>),
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            PoolInner::Factory { maxsize, idle, .. } => f
                .debug_struct("Pool")
                .field("maxsize", maxsize)
                .field("idle", &idle.lock().map(|v| v.len()).unwrap_or(0))
                .finish_non_exhaustive(),
            PoolInner::Balanced(b) => f
                .debug_struct("Pool")
                .field("maxsize", &b.opts.maxsize)
                .field("load_balancing", &b.opts.load_balancing)
                .field("idle", &b.lock().idle.len())
                .finish_non_exhaustive(),
        }
    }
}

impl Pool {
    /// Create a pool that opens connections with `make`.
    ///
    /// # Panics
    /// If `maxsize` is 0.
    pub fn new<F>(maxsize: usize, make: F) -> Pool
    where
        F: Fn() -> Result<Client, DriverError> + Send + Sync + 'static,
    {
        assert!(maxsize >= 1, "maxsize must be >= 1");
        Pool {
            inner: PoolInner::Factory {
                maxsize,
                make: Box::new(make),
                idle: Mutex::new(Vec::new()),
                closed: Mutex::new(false),
            },
        }
    }

    /// Start building a pool balanced across the members reachable from
    /// `endpoints` (the seeds, `host:port`). See [`PoolBuilder`].
    pub fn builder<S: AsRef<str>>(endpoints: &[S]) -> PoolBuilder {
        PoolBuilder {
            endpoints: endpoints.iter().map(|e| e.as_ref().to_string()).collect(),
            login: Login {
                username: "anonymous".into(),
                password: String::new(),
                gssapi_spn: None,
                cert_auth: false,
                tls: None,
            },
            database: None,
            consistency: Consistency::Quorum,
            options: PoolOptions::default(),
        }
    }

    /// Check out a connection, reusing an idle one when possible.
    ///
    /// Idle connections are handed out as-is: `Client` re-dials by itself when
    /// a statement hits a dead socket, so a connection the server closed while
    /// it sat idle recovers on first use rather than needing a liveness probe
    /// here. A balanced pool hands out an idle connection to the member its
    /// policy picks, or dials that member (falling back to the others).
    pub fn acquire(&self) -> Result<Client, DriverError> {
        match &self.inner {
            PoolInner::Factory { make, idle, closed, .. } => {
                if *closed.lock().map_err(|_| DriverError::NoEndpoint("pool poisoned".into()))? {
                    return Err(DriverError::NoEndpoint("pool is closed".into()));
                }
                let reused = idle
                    .lock()
                    .map_err(|_| DriverError::NoEndpoint("pool poisoned".into()))?
                    .pop();
                match reused {
                    Some(c) => Ok(c),
                    None => make(),
                }
            }
            PoolInner::Balanced(b) => b.checkout(None),
        }
    }

    /// [`Pool::acquire`] under an affinity key — a user id, a session id.
    /// With [`PoolBuilder::read_your_writes`] set, after a write succeeds on
    /// a connection checked out under a key, checkouts under the same key go
    /// to the member that took it until the window ends (that member reads
    /// the write back at any consistency, `ONE` included). Checkouts without
    /// a key share one pool-wide key. A [`Pool::new`] pool ignores the key.
    ///
    /// Derive the key without querying through the same pool — take the raw
    /// id from the session or token. A helper that checks out a connection
    /// and only then computes the key from something that itself reads the
    /// database (a web framework's "current user" loader) checks out again
    /// from inside its own checkout.
    pub fn acquire_with_affinity(&self, affinity: &str) -> Result<Client, DriverError> {
        match &self.inner {
            PoolInner::Factory { .. } => self.acquire(),
            PoolInner::Balanced(b) => b.checkout(Some(affinity)),
        }
    }

    /// Return a connection, dropping it if the pool is closed or full. A
    /// balanced pool also drops a connection a transport error left broken,
    /// one whose member is ejected, not `ready` or gone, and one it did not
    /// hand out.
    pub fn release(&self, client: Client) {
        match &self.inner {
            PoolInner::Factory { maxsize, idle, closed, .. } => {
                let closed = closed.lock().map(|c| *c).unwrap_or(true);
                if closed {
                    return;
                }
                if let Ok(mut idle) = idle.lock() {
                    if idle.len() < *maxsize {
                        idle.push(client);
                    }
                }
            }
            PoolInner::Balanced(b) => b.checkin(client),
        }
    }

    /// Run `work` with a checked-out connection, returning it either way.
    pub fn with<T, F>(&self, work: F) -> Result<T, DriverError>
    where
        F: FnOnce(&mut Client) -> Result<T, DriverError>,
    {
        let mut client = self.acquire()?;
        let out = work(&mut client);
        self.release(client);
        out
    }

    /// [`Pool::with`] under an affinity key (see
    /// [`Pool::acquire_with_affinity`]).
    pub fn with_affinity<T, F>(&self, affinity: &str, work: F) -> Result<T, DriverError>
    where
        F: FnOnce(&mut Client) -> Result<T, DriverError>,
    {
        let mut client = self.acquire_with_affinity(affinity)?;
        let out = work(&mut client);
        self.release(client);
        out
    }

    /// Idle connections currently retained.
    pub fn idle_len(&self) -> usize {
        match &self.inner {
            PoolInner::Factory { idle, .. } => idle.lock().map(|v| v.len()).unwrap_or(0),
            PoolInner::Balanced(b) => b.lock().idle.len(),
        }
    }

    /// The members as a balanced pool sees them, in endpoint order, for
    /// monitoring. Empty for a [`Pool::new`] pool, which knows no members.
    pub fn members(&self) -> Vec<PoolMember> {
        match &self.inner {
            PoolInner::Factory { .. } => Vec::new(),
            PoolInner::Balanced(b) => b.members(),
        }
    }

    /// Close the pool and drop every idle connection. Checked-out connections
    /// are dropped when they are returned. A balanced pool's background
    /// thread exits. Dropping the pool closes it.
    pub fn close(&self) {
        match &self.inner {
            PoolInner::Factory { idle, closed, .. } => {
                if let Ok(mut c) = closed.lock() {
                    *c = true;
                }
                if let Ok(mut idle) = idle.lock() {
                    idle.clear();
                }
            }
            PoolInner::Balanced(b) => b.close(),
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.close();
    }
}

/// How a balanced [`Pool`] picks the member for a checkout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadBalancing {
    /// Any idle connection; a new connection dials the usable members in
    /// random order, and each connection sticks to the member it reached.
    #[default]
    Random,
    /// The next usable member in endpoint order.
    RoundRobin,
    /// Of two usable members picked at random, the one with the lower
    /// latency average × (checked-out connections + 1). A member not
    /// measured yet, or not in the last 2 s, scores 0, so it is tried.
    LeastLatency,
}

impl LoadBalancing {
    /// The policy's name: `random`, `round_robin` or `least_latency`.
    pub fn as_str(&self) -> &'static str {
        match self {
            LoadBalancing::Random => "random",
            LoadBalancing::RoundRobin => "round_robin",
            LoadBalancing::LeastLatency => "least_latency",
        }
    }
}

impl std::fmt::Display for LoadBalancing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LoadBalancing {
    type Err = DriverError;

    /// Parse a policy name; anything else is an `InvalidInput` error.
    fn from_str(s: &str) -> Result<LoadBalancing, DriverError> {
        match s {
            "random" => Ok(LoadBalancing::Random),
            "round_robin" => Ok(LoadBalancing::RoundRobin),
            "least_latency" => Ok(LoadBalancing::LeastLatency),
            other => Err(invalid(format!(
                "unknown load_balancing {other:?} (use \"random\", \"round_robin\" or \"least_latency\")"
            ))),
        }
    }
}

/// Which idle connection a balanced [`Pool`] hands out first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdleOrder {
    /// The most recently returned, so a quiet pool keeps few sockets warm.
    #[default]
    Lifo,
    /// The longest idle, so every idle connection keeps being used and a
    /// server-side idle timeout never finds one.
    Fifo,
}

impl IdleOrder {
    /// The order's name: `lifo` or `fifo`.
    pub fn as_str(&self) -> &'static str {
        match self {
            IdleOrder::Lifo => "lifo",
            IdleOrder::Fifo => "fifo",
        }
    }
}

impl std::fmt::Display for IdleOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for IdleOrder {
    type Err = DriverError;

    /// Parse an idle order name; anything else is an `InvalidInput` error.
    fn from_str(s: &str) -> Result<IdleOrder, DriverError> {
        match s {
            "lifo" => Ok(IdleOrder::Lifo),
            "fifo" => Ok(IdleOrder::Fifo),
            other => Err(invalid(format!("unknown idle_order {other:?} (use \"lifo\" or \"fifo\")"))),
        }
    }
}

/// A member's state as a balanced [`Pool`] sees it ([`Pool::members`]).
/// Only `Ready` members get new connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberState {
    /// In rotation.
    Ready,
    /// Taken out by the pool (consecutive transport failures, or latency
    /// far above the other members') until a probe re-admits it.
    Ejected,
    /// Backfilling, as discovery reports it: answers correctly but slower.
    Resyncing,
    /// Its circuit breaker is open on the member that answered discovery.
    Unreachable,
    /// A configured endpoint whose member left the ring.
    Unlisted,
}

impl MemberState {
    /// The state's name: `ready`, `ejected`, `resyncing`, `unreachable` or
    /// `unlisted`.
    pub fn as_str(&self) -> &'static str {
        match self {
            MemberState::Ready => "ready",
            MemberState::Ejected => "ejected",
            MemberState::Resyncing => "resyncing",
            MemberState::Unreachable => "unreachable",
            MemberState::Unlisted => "unlisted",
        }
    }
}

impl std::fmt::Display for MemberState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One member as a balanced [`Pool`] sees it ([`Pool::members`]).
#[derive(Debug, Clone, PartialEq)]
pub struct PoolMember {
    /// The endpoint the pool dials.
    pub endpoint: String,
    /// The member's own name from `SHOW ENDPOINTS`, once discovered.
    pub canonical: Option<String>,
    pub state: MemberState,
    /// The round-trip latency average; `None` until measured.
    pub latency: Option<Duration>,
    /// Connections checked out.
    pub in_use: usize,
    /// Idle connections.
    pub idle: usize,
    /// A configured endpoint (discovery never drops it).
    pub seed: bool,
}

/// Builds a balanced [`Pool`] ([`Pool::builder`]): the seeds, how every
/// connection logs in, and the balancing options of docs/PROTOCOL.md §6.1.
/// Nothing is dialed until the first checkout.
///
/// | Option | Default |
/// |---|---|
/// | [`maxsize`](PoolBuilder::maxsize) | 10 idle connections |
/// | [`load_balancing`](PoolBuilder::load_balancing) | [`LoadBalancing::Random`] |
/// | [`idle_order`](PoolBuilder::idle_order) | [`IdleOrder::Lifo`] |
/// | [`discover`](PoolBuilder::discover) | off |
/// | [`refresh_interval`](PoolBuilder::refresh_interval) | 60 s |
/// | [`read_your_writes`](PoolBuilder::read_your_writes) | zero (off) |
/// | [`eject_errors`](PoolBuilder::eject_errors) | 3 |
/// | [`eject_latency_factor`](PoolBuilder::eject_latency_factor) | 3.0 |
/// | [`eject_latency_floor`](PoolBuilder::eject_latency_floor) | 50 ms |
/// | [`eject_backoff`](PoolBuilder::eject_backoff) | 5 s |
/// | [`eject_backoff_max`](PoolBuilder::eject_backoff_max) | 60 s |
#[derive(Clone)]
pub struct PoolBuilder {
    endpoints: Vec<String>,
    login: Login,
    database: Option<String>,
    consistency: Consistency,
    options: PoolOptions,
}

impl std::fmt::Debug for PoolBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No password: a builder ends up in logs.
        f.debug_struct("PoolBuilder")
            .field("endpoints", &self.endpoints)
            .field("username", &self.login.username)
            .field("database", &self.database)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl PoolBuilder {
    /// Log in with SCRAM-SHA-256 (the default is `anonymous`, for a server
    /// with authentication disabled).
    pub fn credentials(mut self, username: &str, password: &str) -> PoolBuilder {
        self.login.username = username.to_string();
        self.login.password = password.to_string();
        self.login.gssapi_spn = None;
        self.login.cert_auth = false;
        self
    }

    /// Log in with Kerberos (SASL GSSAPI), as
    /// [`Client::connect_gssapi_tls`] does.
    pub fn gssapi(mut self, principal: &str, target_spn: &str) -> PoolBuilder {
        self.login.username = principal.to_string();
        self.login.password = String::new();
        self.login.gssapi_spn = Some(target_spn.to_string());
        self.login.cert_auth = false;
        self
    }

    /// Log in with the TLS client certificate (SASL EXTERNAL), as
    /// [`Client::connect_certificate`] does; [`PoolBuilder::tls`] must
    /// present one. `username` is empty or the certificate's Common Name.
    pub fn certificate(mut self, username: &str) -> PoolBuilder {
        self.login.username = username.to_string();
        self.login.password = String::new();
        self.login.gssapi_spn = None;
        self.login.cert_auth = true;
        self
    }

    /// Wrap every connection in TLS.
    pub fn tls(mut self, tls: TlsConfig) -> PoolBuilder {
        self.login.tls = Some(tls);
        self
    }

    /// Bind every connection to `database` (see [`Client::with_database`]).
    pub fn database(mut self, database: &str) -> PoolBuilder {
        self.database = Some(database.to_string());
        self
    }

    /// The default consistency of every connection (`QUORUM` by default).
    pub fn consistency(mut self, consistency: Consistency) -> PoolBuilder {
        self.consistency = consistency;
        self
    }

    /// Idle connections kept (default 10; must be at least 1).
    pub fn maxsize(mut self, maxsize: usize) -> PoolBuilder {
        self.options.maxsize = maxsize;
        self
    }

    /// The member a checkout goes to (default [`LoadBalancing::Random`]).
    pub fn load_balancing(mut self, policy: LoadBalancing) -> PoolBuilder {
        self.options.load_balancing = policy;
        self
    }

    /// Which idle connection goes out first (default [`IdleOrder::Lifo`]).
    pub fn idle_order(mut self, order: IdleOrder) -> PoolBuilder {
        self.options.idle_order = order;
        self
    }

    /// Learn the members from `SHOW ENDPOINTS` (server ≥ 0.327; default
    /// off): on the first connection made to each member whose name is not
    /// known yet, and every [`refresh_interval`](PoolBuilder::refresh_interval)
    /// after that. Members joining the cluster are added, members that left
    /// it dropped (a seed is kept, marked `Unlisted`), and members reported
    /// `resyncing` or `unreachable` get no new connections until they are
    /// `ready` again. A standalone server (no rows) or one older than the
    /// statement (an error) keeps the seeds and stops discovery.
    pub fn discover(mut self, on: bool) -> PoolBuilder {
        self.options.discover = on;
        self
    }

    /// How often discovery re-reads the members (default 60 s; every 5 s
    /// at most while a listed member is `resyncing` or `unreachable`).
    pub fn refresh_interval(mut self, every: Duration) -> PoolBuilder {
        self.options.refresh_interval = every;
        self
    }

    /// How long after a write checkouts under the same affinity key go to
    /// the member that took it (default zero: off). See
    /// [`Pool::acquire_with_affinity`].
    pub fn read_your_writes(mut self, window: Duration) -> PoolBuilder {
        self.options.read_your_writes = window;
        self
    }

    /// Consecutive transport failures (a failed dial, an I/O error
    /// mid-request, a capacity refusal) that eject a member (default 3; at
    /// least 1). A statement error, or a login refused for its credentials,
    /// is no member failure.
    pub fn eject_errors(mut self, n: u32) -> PoolBuilder {
        self.options.eject_errors = n;
        self
    }

    /// Eject a member whose latency average (with at least 10 samples on it
    /// and on another usable member) is above `factor` × the median of the
    /// other usable members' averages and more than
    /// [`eject_latency_floor`](PoolBuilder::eject_latency_floor) above it
    /// (default 3.0; 0 disables latency ejection). The fastest of a member's
    /// first three round trips seeds its average, so a statement that stalls
    /// in the application itself cannot get a healthy member ejected.
    pub fn eject_latency_factor(mut self, factor: f64) -> PoolBuilder {
        self.options.eject_latency_factor = factor;
        self
    }

    /// See [`eject_latency_factor`](PoolBuilder::eject_latency_factor)
    /// (default 50 ms). It also caps how much one slow round trip counts.
    pub fn eject_latency_floor(mut self, floor: Duration) -> PoolBuilder {
        self.options.eject_latency_floor = floor;
        self
    }

    /// How long an ejection lasts before a background probe dials the member
    /// alone and runs one statement — success re-admits it, failure ejects
    /// it again (default 5 s, doubled for each repeat).
    pub fn eject_backoff(mut self, backoff: Duration) -> PoolBuilder {
        self.options.eject_backoff = backoff;
        self
    }

    /// The longest an ejection lasts (default 60 s); a member that stays
    /// healthy this long after a re-admission starts over at
    /// [`eject_backoff`](PoolBuilder::eject_backoff).
    pub fn eject_backoff_max(mut self, max: Duration) -> PoolBuilder {
        self.options.eject_backoff_max = max;
        self
    }

    /// Build the pool. Fails without endpoints (`NoEndpoint`) or with an
    /// option out of range (`Io` / `InvalidInput`).
    pub fn build(self) -> Result<Pool, DriverError> {
        let seeds = dedup(&self.endpoints);
        if seeds.is_empty() {
            return Err(DriverError::NoEndpoint("no endpoints given".into()));
        }
        let o = &self.options;
        if o.maxsize < 1 {
            return Err(invalid("maxsize must be >= 1"));
        }
        if o.eject_errors < 1 {
            return Err(invalid("eject_errors must be >= 1"));
        }
        if !(o.eject_latency_factor.is_finite() && o.eject_latency_factor >= 0.0) {
            return Err(invalid("eject_latency_factor must be a finite number >= 0"));
        }
        let members = seeds.into_iter().map(|ep| (ep, Member::new(true))).collect();
        let balancer = Balancer {
            opts: self.options,
            login: self.login,
            database: self.database,
            consistency: self.consistency,
            state: Mutex::new(BalancerState {
                members,
                idle: Vec::new(),
                rr: usize::MAX,
                affinity: HashMap::new(),
                discovery_off: false,
                next_refresh: Instant::now(),
                closed: false,
                maintainer: None,
                rng: Rng::new(),
            }),
        };
        Ok(Pool {
            inner: PoolInner::Balanced(Arc::new(balancer)),
        })
    }
}

fn invalid(msg: impl Into<String>) -> DriverError {
    DriverError::Io(io::Error::new(io::ErrorKind::InvalidInput, msg.into()))
}

/// How a connection logs in — kept by a balanced pool so every connection it
/// dials authenticates the same way.
#[derive(Debug, Clone)]
struct Login {
    username: String,
    password: String,
    gssapi_spn: Option<String>,
    cert_auth: bool,
    tls: Option<TlsConfig>,
}

/// A balanced pool's options (see [`PoolBuilder`] for each).
#[derive(Debug, Clone)]
struct PoolOptions {
    maxsize: usize,
    load_balancing: LoadBalancing,
    idle_order: IdleOrder,
    discover: bool,
    refresh_interval: Duration,
    read_your_writes: Duration,
    eject_errors: u32,
    eject_latency_factor: f64,
    eject_latency_floor: Duration,
    eject_backoff: Duration,
    eject_backoff_max: Duration,
}

impl Default for PoolOptions {
    fn default() -> PoolOptions {
        PoolOptions {
            maxsize: 10,
            load_balancing: LoadBalancing::Random,
            idle_order: IdleOrder::Lifo,
            discover: false,
            refresh_interval: Duration::from_secs(60),
            read_your_writes: Duration::ZERO,
            eject_errors: 3,
            eject_latency_factor: 3.0,
            eject_latency_floor: Duration::from_millis(50),
            eject_backoff: Duration::from_secs(5),
            eject_backoff_max: Duration::from_secs(60),
        }
    }
}

// Latency EWMA: the fastest of a member's first round trips seeds it (a round
// trip is only ever lengthened — by the member, the network or this process
// stalling — so a slow first statement cannot set it); then each round trip
// moves it 5% toward it, and no sample counts for more than 10x the larger of
// the current average and the ejection floor — one slow query does not eject
// a healthy member, a member that stays slow is ejected within a few dozen
// statements.
const EWMA_SEED_SAMPLES: usize = 3;
const EWMA_WEIGHT: f64 = 0.05;
const EWMA_CLAMP: f64 = 10.0;
/// Round trips a member (and at least one other) needs before its average
/// can eject it.
const EWMA_MIN_SAMPLES: u32 = 10;
/// least_latency: a member whose last round trip is older than this scores
/// 0, so a lightly loaded pool keeps re-measuring every member instead of
/// settling forever on whichever answered fastest once.
const STALE_SAMPLE: Duration = Duration::from_secs(2);
/// How often the background thread checks for members due a re-probe or a
/// discovery refresh.
const MAINTAIN_TICK: Duration = Duration::from_millis(250);
/// Discovery refresh while a listed member is not ready: a member is often
/// `unreachable` or `resyncing` only for seconds (a peer's circuit breaker
/// right after it restarts), and waiting a whole refresh interval to let it
/// back in leaves the load on the others.
const REFRESH_NOT_READY: Duration = Duration::from_secs(5);
/// Read-your-writes keys remembered before expired ones are swept.
const AFFINITY_CAP: usize = 4096;
/// Dials a checkout makes when member discovery keeps breaking the fresh
/// connection (every member just went away) before it gives up.
const CHECKOUT_ATTEMPTS: usize = 3;

/// Leading keywords of statements that never write: everything else counts
/// as a write for read-your-writes affinity (a read taken for a write only
/// keeps the caller on its member a little longer).
const READ_KEYWORDS: [&str; 8] = ["select", "show", "explain", "describe", "desc", "values", "with", "use"];

/// Whether `sql` counts as a write: its first keyword, after whitespace,
/// `--` / `/* */` comments and opening parentheses, is not a read keyword.
fn is_write(sql: &str) -> bool {
    let b = sql.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_whitespace() || b[i] == b'(' {
            i += 1;
        } else if b[i..].starts_with(b"--") {
            i = b[i..].iter().position(|&c| c == b'\n').map_or(b.len(), |j| i + j + 1);
        } else if b[i..].starts_with(b"/*") {
            i = b[i + 2..]
                .windows(2)
                .position(|w| w == b"*/")
                .map_or(b.len(), |j| i + 2 + j + 2);
        } else {
            break;
        }
    }
    let end = b[i..]
        .iter()
        .position(|c| !(c.is_ascii_alphabetic() || *c == b'_'))
        .map_or(b.len(), |j| i + j);
    let word = &sql[i..end];
    !READ_KEYWORDS.iter().any(|k| word.eq_ignore_ascii_case(k))
}

/// Whether a failed dial says something about the member's health: a
/// transport or protocol failure does — a capacity refusal included, which
/// [`denied`] turns into an `Io` error. A login refused for its credentials
/// (or a server signature that does not verify) is the caller's problem.
fn member_fault(e: &DriverError) -> bool {
    matches!(e, DriverError::Io(_) | DriverError::Proto(_))
}

/// One member as a balanced pool sees it; its endpoint is the map key.
#[derive(Debug)]
struct Member {
    /// Configured: discovery never drops it.
    seed: bool,
    /// Its own `SHOW ENDPOINTS` name, once learned.
    canonical: Option<String>,
    /// What discovery last said: `Ready`, `Resyncing`, `Unreachable` or
    /// `Unlisted` (never `Ejected` — that is `ejected_until`).
    listed: MemberState,
    /// Round-trip average, in seconds.
    ewma: Option<f64>,
    /// Round trips before the average is seeded.
    firsts: Vec<f64>,
    samples: u32,
    last_sample: Option<Instant>,
    /// Consecutive transport failures.
    errors: u32,
    /// `None` = admitted.
    ejected_until: Option<Instant>,
    ejections: u32,
    readmitted_at: Option<Instant>,
    in_use: usize,
    probing: bool,
}

impl Member {
    fn new(seed: bool) -> Member {
        Member {
            seed,
            canonical: None,
            listed: MemberState::Ready,
            ewma: None,
            firsts: Vec::new(),
            samples: 0,
            last_sample: None,
            errors: 0,
            ejected_until: None,
            ejections: 0,
            readmitted_at: None,
            in_use: 0,
            probing: false,
        }
    }

    /// Measure the member afresh (a re-admission, back to ready).
    fn reset_latency(&mut self) {
        self.ewma = None;
        self.firsts.clear();
        self.samples = 0;
    }

    /// New connections may go to it.
    fn usable(&self) -> bool {
        self.ejected_until.is_none() && self.listed == MemberState::Ready
    }

    /// least_latency's score: latency × (checked-out connections + 1). A
    /// member never measured, or not lately, scores 0, so it is tried and
    /// measured.
    fn score(&self, now: Instant) -> f64 {
        match (self.ewma, self.last_sample) {
            (Some(ewma), Some(at)) if now.duration_since(at) <= STALE_SAMPLE => {
                ewma * (self.in_use as f64 + 1.0)
            }
            _ => 0.0,
        }
    }
}

/// A balanced pool: its fixed settings and its mutable state.
struct Balancer {
    opts: PoolOptions,
    login: Login,
    database: Option<String>,
    consistency: Consistency,
    state: Mutex<BalancerState>,
}

struct BalancerState {
    /// By endpoint (sorted: round-robin order and `members()` order).
    members: BTreeMap<String, Member>,
    /// Idle connections, the most recently returned last.
    idle: Vec<Client>,
    /// Round-robin position (starts so the first checkout takes index 0).
    rr: usize,
    /// Read-your-writes: affinity key → (member, window end).
    affinity: HashMap<Option<String>, (String, Instant)>,
    /// The server does not answer `SHOW ENDPOINTS` with members.
    discovery_off: bool,
    next_refresh: Instant,
    closed: bool,
    /// The background thread, once started (to wake it on close).
    maintainer: Option<std::thread::Thread>,
    rng: Rng,
}

/// A pooled connection's tie to its balanced pool.
struct PoolLink {
    pool: Arc<Balancer>,
    /// The member this connection counts against: the one it reached.
    member: String,
    /// Checked out, so counted in the member's `in_use`.
    out: bool,
    /// The checkout's affinity key (read-your-writes).
    affinity: Option<String>,
    /// A transport failure left the socket unusable: dropped on return
    /// instead of kept idle.
    broken: bool,
}

impl PoolLink {
    fn new(pool: Arc<Balancer>) -> PoolLink {
        PoolLink {
            pool,
            member: String::new(),
            out: false,
            affinity: None,
            broken: false,
        }
    }
}

impl std::fmt::Debug for PoolLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolLink")
            .field("member", &self.member)
            .field("out", &self.out)
            .finish_non_exhaustive()
    }
}

impl Drop for PoolLink {
    fn drop(&mut self) {
        // Dropped while checked out instead of returned: the pool stops
        // counting it against its member. (An idle or returned connection
        // is never `out`, so dropping one under the pool's lock is safe.)
        if self.out {
            self.pool.closed_out(&self.member);
        }
    }
}

impl Balancer {
    fn lock(&self) -> MutexGuard<'_, BalancerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn read_your_writes(&self) -> bool {
        !self.opts.read_your_writes.is_zero()
    }

    // -- checkout / checkin --

    fn checkout(self: &Arc<Self>, affinity: Option<&str>) -> Result<Client, DriverError> {
        for _ in 0..CHECKOUT_ATTEMPTS {
            let (idle, stale, order) = {
                let mut guard = self.lock();
                let st = &mut *guard;
                if st.closed {
                    return Err(DriverError::NoEndpoint("pool is closed".into()));
                }
                let target = self.pick(st, affinity);
                let (idle, stale) = self.take_idle(st, target.as_deref());
                let order = match idle {
                    Some(_) => Vec::new(),
                    None => self.order(st, target.as_deref(), None),
                };
                (idle, stale, order)
            };
            // Connections to members no longer usable close outside the lock.
            drop(stale);
            let mut client = match idle {
                Some(c) => c,
                None => {
                    let mut c = self.dial(order, true)?;
                    self.discover_through(&mut c);
                    if c.link.as_ref().is_some_and(|l| l.broken) {
                        continue;
                    }
                    c
                }
            };
            if let Some(link) = client.link.as_mut() {
                if let Some(m) = self.lock().members.get_mut(&link.member) {
                    m.in_use += 1;
                }
                link.out = true;
                link.affinity = affinity.map(str::to_string);
            }
            return Ok(client);
        }
        Err(DriverError::NoEndpoint(
            "every new connection broke during member discovery".into(),
        ))
    }

    fn checkin(&self, mut client: Client) {
        let mut guard = self.lock();
        let st = &mut *guard;
        let keep = match client.link.as_mut() {
            Some(link) if std::ptr::eq(Arc::as_ptr(&link.pool), self) => {
                let usable = match st.members.get_mut(&link.member) {
                    Some(m) => {
                        if link.out {
                            m.in_use = m.in_use.saturating_sub(1);
                        }
                        m.usable()
                    }
                    None => false,
                };
                link.out = false;
                !st.closed && !link.broken && usable && st.idle.len() < self.opts.maxsize
            }
            // Not one of ours: never kept.
            _ => false,
        };
        if keep {
            st.idle.push(client);
            return;
        }
        drop(guard);
        drop(client);
    }

    fn members(&self) -> Vec<PoolMember> {
        let st = self.lock();
        let mut idle: HashMap<&str, usize> = HashMap::new();
        for c in &st.idle {
            if let Some(link) = &c.link {
                *idle.entry(link.member.as_str()).or_default() += 1;
            }
        }
        st.members
            .iter()
            .map(|(ep, m)| PoolMember {
                endpoint: ep.clone(),
                canonical: m.canonical.clone(),
                state: if m.ejected_until.is_some() {
                    MemberState::Ejected
                } else {
                    m.listed
                },
                latency: m.ewma.and_then(|s| Duration::try_from_secs_f64(s).ok()),
                in_use: m.in_use,
                idle: idle.get(ep.as_str()).copied().unwrap_or(0),
                seed: m.seed,
            })
            .collect()
    }

    fn close(&self) {
        let (idle, maintainer) = {
            let mut st = self.lock();
            st.closed = true;
            (std::mem::take(&mut st.idle), st.maintainer.take())
        };
        if let Some(t) = maintainer {
            t.unpark();
        }
        drop(idle);
    }

    // -- choosing a member (callers hold the lock) --

    /// The member this checkout should go to, or `None` for "any" (the
    /// random policy, or no usable member at all).
    fn pick(&self, st: &mut BalancerState, affinity: Option<&str>) -> Option<String> {
        if self.read_your_writes() {
            let key = affinity.map(str::to_string);
            if let Some((ep, until)) = st.affinity.get(&key).cloned() {
                match st.members.get(&ep) {
                    Some(m) if Instant::now() < until => {
                        if m.usable() {
                            return Some(ep);
                        }
                    }
                    _ => {
                        st.affinity.remove(&key);
                    }
                }
            }
        }
        if self.opts.load_balancing == LoadBalancing::Random {
            return None;
        }
        let usable: Vec<&String> = st.members.iter().filter(|(_, m)| m.usable()).map(|(ep, _)| ep).collect();
        if usable.is_empty() {
            return None;
        }
        if self.opts.load_balancing == LoadBalancing::RoundRobin {
            st.rr = st.rr.wrapping_add(1) % usable.len();
            return Some(usable[st.rr].clone());
        }
        if usable.len() == 1 {
            return Some(usable[0].clone());
        }
        let i = st.rng.below(usable.len());
        let mut j = st.rng.below(usable.len() - 1);
        if j >= i {
            j += 1;
        }
        let now = Instant::now();
        let (a, b) = (usable[i], usable[j]);
        let pick = if st.members[a].score(now) <= st.members[b].score(now) { a } else { b };
        Some(pick.clone())
    }

    /// Remove and return an idle connection (to `target`, or to any usable
    /// member, in idle order), plus the idle connections found to belong to
    /// members no longer usable (to close outside the lock).
    fn take_idle(&self, st: &mut BalancerState, target: Option<&str>) -> (Option<Client>, Vec<Client>) {
        let n = st.idle.len();
        let mut found = None;
        let mut stale = Vec::new();
        for k in 0..n {
            let i = if self.opts.idle_order == IdleOrder::Fifo { k } else { n - 1 - k };
            let ep = st.idle[i].link.as_ref().map_or("", |l| l.member.as_str());
            match st.members.get(ep) {
                Some(m) if m.usable() => {
                    if target.is_none_or(|t| t == ep) {
                        found = Some(i);
                        break;
                    }
                }
                _ => stale.push(i),
            }
        }
        if stale.is_empty() {
            return (found.map(|i| st.idle.remove(i)), Vec::new());
        }
        let (mut picked, mut dropped, mut kept) = (None, Vec::new(), Vec::with_capacity(n));
        for (i, c) in std::mem::take(&mut st.idle).into_iter().enumerate() {
            if Some(i) == found {
                picked = Some(c);
            } else if stale.contains(&i) {
                dropped.push(c);
            } else {
                kept.push(c);
            }
        }
        st.idle = kept;
        (picked, dropped)
    }

    /// Endpoints to dial, best first: `first`, the other usable members in
    /// random order, then the rest (resyncing/unreachable before ejected, the
    /// soonest re-admission first) — a dial never has nowhere to go while
    /// any member is configured. `exclude` (the member a connection just
    /// lost) goes last.
    fn order(&self, st: &mut BalancerState, first: Option<&str>, exclude: Option<&str>) -> Vec<String> {
        let mut usable = Vec::new();
        let mut rest = Vec::new();
        for (ep, m) in &st.members {
            if Some(ep.as_str()) == first {
                continue;
            }
            if m.usable() {
                usable.push(ep.clone());
            } else {
                rest.push((m.ejected_until, ep.clone()));
            }
        }
        st.rng.shuffle(&mut usable);
        rest.sort_by_key(|(until, _)| (until.is_some(), *until));
        let mut eps: Vec<String> = first
            .map(str::to_string)
            .into_iter()
            .chain(usable)
            .chain(rest.into_iter().map(|(_, ep)| ep))
            .collect();
        if let Some(x) = exclude {
            if eps.len() > 1 {
                if let Some(pos) = eps.iter().position(|e| e == x) {
                    let e = eps.remove(pos);
                    eps.push(e);
                }
            }
        }
        eps
    }

    /// Dial a connection across `order` with the pool's login, consistency
    /// and database. `pooled` ties it to the pool (failed dials reported); a
    /// probe dials untied.
    fn dial(self: &Arc<Self>, order: Vec<String>, pooled: bool) -> Result<Client, DriverError> {
        let link = pooled.then(|| PoolLink::new(self.clone()));
        let mut client = Client::open(order, &self.login, link)?;
        client.default_consistency = self.consistency;
        if let Some(db) = &self.database {
            client.use_database(db)?;
        }
        Ok(client)
    }

    // -- what connections report (any thread) --

    /// A pooled connection re-dialing: the pool's order, the member it lost
    /// last.
    fn dial_order(&self, lost: &str) -> Vec<String> {
        let mut st = self.lock();
        self.order(&mut st, None, Some(lost))
    }

    /// A pooled connection re-dialed and reached `connected`.
    fn moved(&self, link: &mut PoolLink, connected: &str) {
        let mut st = self.lock();
        reattribute(&mut st, link, connected);
    }

    fn round_trip(self: &Arc<Self>, link: &mut PoolLink, connected: &str, elapsed: Duration) {
        let mut guard = self.lock();
        let st = &mut *guard;
        reattribute(st, link, connected);
        let floor = self.opts.eject_latency_floor.as_secs_f64();
        let Some(m) = st.members.get_mut(connected) else {
            return;
        };
        let sample = elapsed.as_secs_f64();
        match m.ewma {
            None => {
                m.firsts.push(sample);
                if m.firsts.len() >= EWMA_SEED_SAMPLES {
                    m.ewma = m.firsts.drain(..).reduce(f64::min);
                }
            }
            Some(avg) => m.ewma = Some(avg + EWMA_WEIGHT * (sample.min(EWMA_CLAMP * avg.max(floor)) - avg)),
        }
        m.errors = 0;
        m.samples = m.samples.saturating_add(1);
        m.last_sample = Some(Instant::now());
        // Only a measured member still in rotation: round trips finishing on
        // connections checked out before an ejection must not eject it again
        // (and so double its backoff).
        let factor = self.opts.eject_latency_factor;
        let Some(ewma) = m.ewma else {
            return;
        };
        if !m.usable() || m.samples < EWMA_MIN_SAMPLES || factor <= 0.0 {
            return;
        }
        let mut others: Vec<f64> = st
            .members
            .iter()
            .filter(|(ep, o)| ep.as_str() != connected && o.usable() && o.samples >= EWMA_MIN_SAMPLES)
            .filter_map(|(_, o)| o.ewma)
            .collect();
        if others.is_empty() {
            return;
        }
        others.sort_by(f64::total_cmp);
        let median = others[(others.len() - 1) / 2];
        if ewma > factor * median && ewma - median > floor {
            self.eject(st, connected);
        }
    }

    fn failed(self: &Arc<Self>, ep: &str) {
        let mut guard = self.lock();
        let st = &mut *guard;
        let Some(m) = st.members.get_mut(ep) else {
            return;
        };
        m.errors = m.errors.saturating_add(1);
        if m.errors >= self.opts.eject_errors && m.ejected_until.is_none() {
            self.eject(st, ep);
        }
    }

    fn closed_out(&self, member: &str) {
        if let Some(m) = self.lock().members.get_mut(member) {
            m.in_use = m.in_use.saturating_sub(1);
        }
    }

    fn wrote(&self, affinity: Option<String>, connected: &str) {
        let now = Instant::now();
        let mut st = self.lock();
        if st.affinity.len() >= AFFINITY_CAP {
            st.affinity.retain(|_, (_, until)| *until > now);
        }
        st.affinity
            .insert(affinity, (connected.to_string(), now + self.opts.read_your_writes));
    }

    // -- ejection and re-admission --

    /// Take `ep` out of rotation (caller holds the lock) — unless it is the
    /// last usable member: a slow or flaky member beats none.
    fn eject(self: &Arc<Self>, st: &mut BalancerState, ep: &str) {
        if !st.members.iter().any(|(k, o)| k != ep && o.usable()) {
            return;
        }
        let now = Instant::now();
        let Some(m) = st.members.get_mut(ep) else {
            return;
        };
        if m.readmitted_at.is_none_or(|t| now.duration_since(t) > self.opts.eject_backoff_max) {
            m.ejections = 0; // healthy for a while: start the backoff over
        }
        m.ejections = m.ejections.saturating_add(1);
        m.ejected_until = Some(now + self.backoff_for(m.ejections));
        self.ensure_maintainer(st);
    }

    fn backoff_for(&self, ejections: u32) -> Duration {
        let doublings = 2u32.saturating_pow(ejections.saturating_sub(1));
        self.opts
            .eject_backoff
            .saturating_mul(doublings)
            .min(self.opts.eject_backoff_max)
    }

    /// Start the background thread (caller holds the lock): it re-probes
    /// ejected members and refreshes discovery.
    fn ensure_maintainer(self: &Arc<Self>, st: &mut BalancerState) {
        if st.maintainer.is_some() || st.closed {
            return;
        }
        let pool = Arc::downgrade(self);
        let spawned = std::thread::Builder::new()
            .name("skaidb-pool".into())
            .spawn(move || maintain(&pool));
        // Without a thread an ejected member stays out until the next
        // ejection or discovery tries again.
        if let Ok(handle) = spawned {
            st.maintainer = Some(handle.thread().clone());
        }
    }

    /// One pass of the background thread; false once the pool is closed.
    fn tick(self: &Arc<Self>) -> bool {
        let now = Instant::now();
        let (due, refresh) = {
            let mut guard = self.lock();
            let st = &mut *guard;
            if st.closed {
                return false;
            }
            let mut due = Vec::new();
            for (ep, m) in st.members.iter_mut() {
                if m.ejected_until.is_some_and(|t| now >= t) && !m.probing {
                    m.probing = true;
                    due.push(ep.clone());
                }
            }
            (due, self.opts.discover && !st.discovery_off && now >= st.next_refresh)
        };
        for ep in &due {
            self.probe(ep);
        }
        if refresh {
            self.refresh();
        }
        true
    }

    /// Dial `ep` alone and run one statement: success re-admits it (the probe
    /// connection joins the idle set), failure ejects it again for twice as
    /// long.
    fn probe(self: &Arc<Self>, ep: &str) {
        let probed = self
            .dial(vec![ep.to_string()], false)
            .and_then(|mut c| c.try_execute("SHOW DATABASES", self.consistency).map(|_| c));
        let mut guard = self.lock();
        let st = &mut *guard;
        let room = st.idle.len() < self.opts.maxsize;
        let closed = st.closed;
        let Some(m) = st.members.get_mut(ep) else {
            return; // dropped by discovery meanwhile
        };
        m.probing = false;
        match probed {
            Ok(mut client) if !closed => {
                m.ejected_until = None;
                m.errors = 0;
                m.reset_latency();
                m.readmitted_at = Some(Instant::now());
                if room {
                    let mut link = PoolLink::new(self.clone());
                    link.member = ep.to_string();
                    client.link = Some(link);
                    st.idle.push(client);
                }
            }
            _ => {
                m.ejections = m.ejections.saturating_add(1);
                m.ejected_until = Some(Instant::now() + self.backoff_for(m.ejections));
            }
        }
    }

    // -- discovery --

    /// Run discovery on a freshly dialed connection when the member it
    /// reached has not named itself yet (once per member, so seeds given as
    /// host names are matched to the endpoints the server reports).
    fn discover_through(self: &Arc<Self>, client: &mut Client) {
        if !self.opts.discover {
            return;
        }
        {
            let mut st = self.lock();
            if st.discovery_off {
                return;
            }
            match st.members.get(client.endpoint()) {
                Some(m) if m.canonical.is_none() => {}
                _ => return,
            }
            self.ensure_maintainer(&mut st);
        }
        self.list_through(client);
    }

    fn refresh(self: &Arc<Self>) {
        match self.checkout(None) {
            Ok(mut client) => {
                self.list_through(&mut client);
                self.checkin(client);
            }
            Err(_) => self.lock().next_refresh = Instant::now() + self.opts.refresh_interval,
        }
    }

    fn list_through(&self, client: &mut Client) {
        let listing = client.execute("SHOW ENDPOINTS");
        let mut st = self.lock();
        match listing {
            Ok(Response::Rows { rows, .. }) if !rows.is_empty() => {
                self.fold_listing(&mut st, client.endpoint(), &rows);
            }
            // A standalone server (no rows), or one that predates the
            // statement (an error): keep the seeds and stop asking.
            Ok(_) | Err(DriverError::Server(_)) => st.discovery_off = true,
            // A transport failure: the next refresh tries again.
            Err(_) => {}
        }
    }

    /// Fold a `SHOW ENDPOINTS` answer from the member at `dialed` into the
    /// members and schedule the next refresh — sooner while a listed member
    /// is not ready.
    fn fold_listing(&self, st: &mut BalancerState, dialed: &str, rows: &[Vec<Value>]) {
        apply_listing(&mut st.members, dialed, rows);
        let mut every = self.opts.refresh_interval;
        if st
            .members
            .values()
            .any(|m| matches!(m.listed, MemberState::Resyncing | MemberState::Unreachable))
        {
            every = every.min(REFRESH_NOT_READY);
        }
        st.next_refresh = Instant::now() + every;
    }
}

/// The connection behind `link` reached `connected` (caller holds the lock):
/// a re-dial mid-checkout moves its count to that member.
fn reattribute(st: &mut BalancerState, link: &mut PoolLink, connected: &str) {
    if link.member == connected {
        return;
    }
    if link.out {
        if let Some(old) = st.members.get_mut(&link.member) {
            old.in_use = old.in_use.saturating_sub(1);
        }
        if let Some(new) = st.members.get_mut(connected) {
            new.in_use += 1;
        }
    }
    link.member = connected.to_string();
}

/// Fold `SHOW ENDPOINTS` rows (`endpoint`, `state`, `local`) answered by the
/// member at `dialed` into `members`.
fn apply_listing(members: &mut BTreeMap<String, Member>, dialed: &str, rows: &[Vec<Value>]) {
    let mut listed: Vec<(String, MemberState)> = Vec::new();
    for row in rows {
        let (Some(Value::String(endpoint)), Some(Value::String(state))) = (row.first(), row.get(1)) else {
            continue;
        };
        // A state this driver does not know reads as ready.
        let state = match state.as_str() {
            "resyncing" => MemberState::Resyncing,
            "unreachable" => MemberState::Unreachable,
            _ => MemberState::Ready,
        };
        match listed.iter_mut().find(|(e, _)| e == endpoint) {
            Some(slot) => slot.1 = state,
            None => listed.push((endpoint.clone(), state)),
        }
        if matches!(row.get(2), Some(Value::Bool(true))) {
            if let Some(me) = members.get_mut(dialed) {
                me.canonical = Some(endpoint.clone());
            }
        }
    }
    // A member reported under the name of one already known (a seed given
    // as a host name) is that member, not a new one.
    let mut by_name: HashMap<String, String> = HashMap::new();
    for (ep, m) in members.iter() {
        if let Some(name) = &m.canonical {
            if m.seed || !by_name.contains_key(name) {
                by_name.insert(name.clone(), ep.clone());
            }
        }
    }
    // A duplicate of a seed goes.
    members.retain(|ep, m| m.canonical.as_ref().is_none_or(|name| by_name.get(name) == Some(ep)));
    let mut seen = HashSet::new();
    for (endpoint, state) in listed {
        let ep = match by_name.get(&endpoint) {
            Some(ep) => ep.clone(),
            None => {
                let m = members.entry(endpoint.clone()).or_insert_with(|| Member::new(false));
                m.canonical = Some(endpoint.clone());
                endpoint
            }
        };
        let Some(m) = members.get_mut(&ep) else {
            continue;
        };
        if state == MemberState::Ready && m.listed != MemberState::Ready {
            // Back in rotation: measured afresh, like a re-admission.
            m.reset_latency();
            m.errors = 0;
        }
        m.listed = state;
        seen.insert(ep);
    }
    members.retain(|ep, m| {
        if seen.contains(ep) || (m.seed && m.canonical.is_none()) {
            true // listed, or a seed not identified yet
        } else if m.seed {
            m.listed = MemberState::Unlisted; // configured, but no longer a member
            true
        } else {
            false
        }
    });
}

/// A balanced pool's background thread: re-probes ejected members and
/// refreshes discovery every [`MAINTAIN_TICK`]. It holds the pool only
/// weakly and exits once the pool is closed (closing wakes it) or gone, so
/// it never keeps anything alive — and a process never waits for it at exit.
fn maintain(pool: &Weak<Balancer>) {
    loop {
        std::thread::park_timeout(MAINTAIN_TICK);
        let Some(balancer) = pool.upgrade() else {
            return;
        };
        if !balancer.tick() {
            return;
        }
    }
}

/// A small xorshift generator for member choice: balancing needs an order
/// that differs between pools and checkouts, not cryptographic randomness.
#[derive(Debug)]
struct Rng(u64);

impl Rng {
    fn new() -> Rng {
        use std::hash::BuildHasher;
        // RandomState is randomly keyed per process (and per instance).
        Rng(std::collections::hash_map::RandomState::new().hash_one(Instant::now()) | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform-enough in `0..n` (`n > 0`).
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i + 1);
            v.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_keeps_first_occurrence_order() {
        let eps = ["b:1".to_string(), "a:1".to_string(), "b:1".to_string()];
        assert_eq!(dedup(&eps), vec!["b:1".to_string(), "a:1".to_string()]);
        assert!(dedup(&[]).is_empty());
    }

    #[test]
    fn single_endpoint_is_not_probed() {
        // A lone endpoint comes back as-is even when nothing listens on it,
        // so a one-node connect never pays the probe timeout.
        let eps = ["127.0.0.1:1".to_string()];
        assert_eq!(order_by_latency(&eps), eps.to_vec());
    }

    #[test]
    fn unreachable_endpoints_sink_but_are_kept() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let live = listener.local_addr().unwrap().to_string();
        // Port 1 on loopback is refused immediately (no 800 ms wait).
        let eps = ["127.0.0.1:1".to_string(), live.clone()];
        let ordered = order_by_latency(&eps);
        assert_eq!(ordered, vec![live, "127.0.0.1:1".to_string()]);
    }

    #[test]
    fn no_endpoints_is_an_error_not_a_hang() {
        match Client::connect_many(&[], "u", "p") {
            Err(DriverError::NoEndpoint(msg)) => assert!(msg.contains("no endpoints")),
            other => panic!("expected NoEndpoint, got {other:?}"),
        }
    }

    #[test]
    fn refused_endpoint_reports_the_last_failure() {
        let eps = ["127.0.0.1:1".to_string()];
        match Client::connect_many(&eps, "u", "p") {
            Err(DriverError::NoEndpoint(msg)) => assert!(msg.starts_with("127.0.0.1:1: ")),
            other => panic!("expected NoEndpoint, got {other:?}"),
        }
    }

    #[test]
    fn tls_config_builds_for_every_verify_mode() {
        for v in [TlsVerify::Insecure, TlsVerify::System] {
            let cfg = TlsConfig::new(v, "skaidb").expect("config");
            assert_eq!(cfg.server_name, "skaidb");
            assert!(format!("{cfg:?}").contains("skaidb"));
        }
        // A CA path that does not exist is an InvalidInput I/O error.
        match TlsConfig::new(TlsVerify::CaFile("/nonexistent/ca.crt".into()), "skaidb") {
            Err(DriverError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput),
            other => panic!("expected Io(InvalidInput), got {other:?}"),
        }
    }

    #[test]
    fn errors_display_their_source() {
        let e = DriverError::Server("boom".into());
        assert_eq!(e.to_string(), "server error: boom");
        let e: DriverError = ProtoError::Malformed("short").into();
        assert_eq!(e.to_string(), "protocol error: malformed message: short");
        let e: DriverError = io::Error::new(io::ErrorKind::BrokenPipe, "pipe").into();
        assert_eq!(e.to_string(), "connection error: pipe");
    }

    #[test]
    fn closed_pool_refuses_without_dialing() {
        let pool = Pool::new(2, || {
            panic!("the factory must not run once the pool is closed")
        });
        pool.close();
        assert_eq!(pool.idle_len(), 0);
        match pool.acquire() {
            Err(DriverError::NoEndpoint(msg)) => assert_eq!(msg, "pool is closed"),
            other => panic!("expected a closed-pool error, got {other:?}"),
        }
        assert!(format!("{pool:?}").contains("maxsize: 2"));
    }

    #[test]
    fn pool_factory_errors_pass_through() {
        let pool = Pool::new(1, || Err(DriverError::Auth("denied".into())));
        match pool.with(|_| Ok(())) {
            Err(DriverError::Auth(msg)) => assert_eq!(msg, "denied"),
            other => panic!("expected Auth, got {other:?}"),
        }
    }

    /// A `Denied` whose reason is the server's capacity refusal is a
    /// refused connection (retried, failed over), not an authentication
    /// failure; every other reason stays one.
    #[test]
    fn a_capacity_denial_is_a_connection_error_not_an_auth_failure() {
        let capacity = "too many connections: server.max_connections is reached and the \
                        remaining slots are reserved for the superuser; retry shortly or use \
                        another node";
        match denied(capacity.to_string()) {
            DriverError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
                assert!(e.to_string().contains("reserved for the superuser"));
            }
            other => panic!("expected a connection error, got {other:?}"),
        }
        match denied("invalid credentials".to_string()) {
            DriverError::Auth(msg) => assert_eq!(msg, "invalid credentials"),
            other => panic!("expected Auth, got {other:?}"),
        }
    }

    #[test]
    #[should_panic(expected = "maxsize must be >= 1")]
    fn pool_rejects_zero_size() {
        let _ = Pool::new(0, || Err(DriverError::NoEndpoint(String::new())));
    }

    #[test]
    fn hello_version_is_the_package_version() {
        // The Hello frame reports CARGO_PKG_VERSION; it must be a real
        // semver triple, never a stale literal.
        let v = env!("CARGO_PKG_VERSION");
        let parts: Vec<&str> = v.split('.').collect();
        assert_eq!(parts.len(), 3, "{v}");
        assert!(parts.iter().all(|p| p.parse::<u64>().is_ok()), "{v}");
    }

    #[test]
    fn pool_and_client_cross_threads() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<Client>();
        assert_send::<Pool>();
        assert_sync::<Pool>();
        assert_send::<Prepared>();
        assert_send::<TlsConfig>();
        assert_send::<PoolBuilder>();
        assert_send::<PoolMember>();
    }

    // ---- balanced pool internals (the wire behaviour is in
    // tests/load_balancing.rs, against fake members) ----

    fn balancer(pool: &Pool) -> &Arc<Balancer> {
        match &pool.inner {
            PoolInner::Balanced(b) => b,
            PoolInner::Factory { .. } => panic!("not a balanced pool"),
        }
    }

    fn rows(listing: &[(&str, &str, bool)]) -> Vec<Vec<Value>> {
        listing
            .iter()
            .map(|(ep, state, local)| {
                vec![
                    Value::String((*ep).into()),
                    Value::String((*state).into()),
                    Value::Bool(*local),
                ]
            })
            .collect()
    }

    #[test]
    fn statement_classification() {
        for sql in [
            "SELECT 1",
            "  select 1",
            "(SELECT 1)",
            "-- c\nSHOW TABLES",
            "/* x */ EXPLAIN SELECT 1",
            "WITH a AS (SELECT 1) SELECT * FROM a",
            "DESCRIBE t",
            "desc t",
            "VALUES (1)",
            "use app",
        ] {
            assert!(!is_write(sql), "{sql}");
        }
        for sql in [
            "INSERT INTO t VALUES (1)",
            "update t set a = 1",
            "DELETE FROM t",
            "CREATE TABLE t (id INT PRIMARY KEY)",
            "COMMIT",
            "CALL p()",
            "selectx",
            "-- only a comment",
            "/* unterminated",
            "",
        ] {
            assert!(is_write(sql), "{sql}");
        }
    }

    #[test]
    fn a_refused_login_is_not_a_member_fault() {
        assert!(!member_fault(&DriverError::Auth("invalid credentials".into())));
        assert!(!member_fault(&DriverError::Auth("server signature mismatch".into())));
        assert!(!member_fault(&DriverError::Server("no such table".into())));
        // A capacity refusal is the member being full.
        assert!(member_fault(&denied("too many connections: 500".into())));
        assert!(member_fault(&DriverError::Io(io::Error::from(io::ErrorKind::ConnectionRefused))));
        assert!(member_fault(&DriverError::Proto(ProtoError::Malformed("short"))));
    }

    #[test]
    fn policy_and_idle_order_names_round_trip() {
        for p in [LoadBalancing::Random, LoadBalancing::RoundRobin, LoadBalancing::LeastLatency] {
            assert_eq!(p.as_str().parse::<LoadBalancing>().unwrap(), p);
        }
        for o in [IdleOrder::Lifo, IdleOrder::Fifo] {
            assert_eq!(o.to_string().parse::<IdleOrder>().unwrap(), o);
        }
        assert_eq!(LoadBalancing::default(), LoadBalancing::Random);
        assert_eq!(IdleOrder::default(), IdleOrder::Lifo);
        match "nearest".parse::<LoadBalancing>() {
            Err(DriverError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert!("random".parse::<IdleOrder>().is_err());
        assert_eq!(MemberState::Unlisted.to_string(), "unlisted");
    }

    #[test]
    fn the_builder_refuses_bad_options() {
        let eps = ["127.0.0.1:1"];
        let invalid = |r: Result<Pool, DriverError>| match r {
            Err(DriverError::Io(e)) => e.kind() == io::ErrorKind::InvalidInput,
            _ => false,
        };
        assert!(invalid(Pool::builder(&eps).maxsize(0).build()));
        assert!(invalid(Pool::builder(&eps).eject_errors(0).build()));
        assert!(invalid(Pool::builder(&eps).eject_latency_factor(f64::NAN).build()));
        assert!(invalid(Pool::builder(&eps).eject_latency_factor(-1.0).build()));
        let none: [&str; 0] = [];
        assert!(matches!(Pool::builder(&none).build(), Err(DriverError::NoEndpoint(_))));
        // Building dials nothing: an unreachable seed is fine until checkout.
        let pool = Pool::builder(&eps).credentials("u", "p").build().unwrap();
        let members = pool.members();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].endpoint, "127.0.0.1:1");
        assert_eq!(members[0].state, MemberState::Ready);
        assert!(members[0].seed && members[0].latency.is_none());
        assert!(!format!("{:?}", Pool::builder(&eps).credentials("u", "secret")).contains("secret"));
    }

    #[test]
    fn a_factory_pool_knows_no_members() {
        let pool = Pool::new(1, || Err(DriverError::NoEndpoint(String::new())));
        assert!(pool.members().is_empty());
    }

    #[test]
    fn the_backoff_doubles_up_to_its_max() {
        let pool = Pool::builder(&["a:1"])
            .eject_backoff(Duration::from_secs(5))
            .eject_backoff_max(Duration::from_secs(60))
            .build()
            .unwrap();
        let b = balancer(&pool);
        let secs: Vec<u64> = (1..=6).map(|n| b.backoff_for(n).as_secs()).collect();
        assert_eq!(secs, [5, 10, 20, 40, 60, 60]);
        assert_eq!(b.backoff_for(u32::MAX), Duration::from_secs(60));
    }

    #[test]
    fn least_latency_re_measures_a_member_it_has_not_used_lately() {
        let pool = Pool::builder(&["a:1", "b:1"])
            .load_balancing(LoadBalancing::LeastLatency)
            .build()
            .unwrap();
        let b = balancer(&pool);
        let mut st = b.lock();
        let now = Instant::now();
        let a = st.members.get_mut("a:1").unwrap();
        a.ewma = Some(0.001);
        a.last_sample = Some(now);
        let slow = st.members.get_mut("b:1").unwrap();
        slow.ewma = Some(0.020);
        slow.last_sample = Some(now);
        assert!((0..20).all(|_| b.pick(&mut st, None).as_deref() == Some("a:1")));
        // b's average goes stale: it scores 0 and is tried again.
        st.members.get_mut("b:1").unwrap().last_sample = now.checked_sub(Duration::from_secs(3));
        assert!((0..20).all(|_| b.pick(&mut st, None).as_deref() == Some("b:1")));
    }

    #[test]
    fn an_ejected_member_is_not_ejected_again_by_late_round_trips() {
        let pool = Pool::builder(&["a:1", "b:1", "c:1"])
            .eject_latency_floor(Duration::from_millis(20))
            .eject_backoff(Duration::from_secs(30))
            .build()
            .unwrap();
        let b = balancer(&pool);
        {
            let mut st = b.lock();
            for (ep, avg) in [("a:1", 0.0001), ("b:1", 0.05), ("c:1", 0.0001)] {
                let m = st.members.get_mut(ep).unwrap();
                m.ewma = Some(avg);
                m.samples = 20;
            }
        }
        let mut link = PoolLink::new(b.clone());
        link.member = "b:1".into();
        b.round_trip(&mut link, "b:1", Duration::from_millis(50));
        let (ejections, until) = {
            let st = b.lock();
            (st.members["b:1"].ejections, st.members["b:1"].ejected_until)
        };
        assert_eq!(ejections, 1);
        assert!(until.is_some());
        // Slow round trips still finishing on connections to b checked out
        // before the ejection.
        for _ in 0..5 {
            b.round_trip(&mut link, "b:1", Duration::from_millis(50));
        }
        let st = b.lock();
        assert_eq!((st.members["b:1"].ejections, st.members["b:1"].ejected_until), (1, until));
    }

    #[test]
    fn a_listing_with_a_member_not_ready_refreshes_sooner() {
        let pool = Pool::builder(&["a:1"])
            .discover(true)
            .refresh_interval(Duration::from_secs(60))
            .build()
            .unwrap();
        let b = balancer(&pool);
        let mut st = b.lock();
        let resyncing = rows(&[("a:1", "ready", true), ("b:1", "ready", false), ("c:1", "resyncing", false)]);
        b.fold_listing(&mut st, "a:1", &resyncing);
        assert!(st.next_refresh <= Instant::now() + REFRESH_NOT_READY);
        let ready = rows(&[("a:1", "ready", true), ("b:1", "ready", false), ("c:1", "ready", false)]);
        b.fold_listing(&mut st, "a:1", &ready);
        assert!(st.next_refresh > Instant::now() + Duration::from_secs(50));
        let unreachable = rows(&[("a:1", "ready", true), ("b:1", "unreachable", false), ("c:1", "ready", false)]);
        b.fold_listing(&mut st, "a:1", &unreachable);
        assert!(st.next_refresh <= Instant::now() + REFRESH_NOT_READY);
    }

    #[test]
    fn a_member_back_to_ready_is_measured_afresh() {
        let mut members = BTreeMap::new();
        members.insert("a:1".to_string(), Member::new(true));
        apply_listing(&mut members, "a:1", &rows(&[("a:1", "ready", true), ("c:1", "resyncing", false)]));
        assert_eq!(members["c:1"].listed, MemberState::Resyncing);
        let c = members.get_mut("c:1").unwrap();
        c.ewma = Some(9.9);
        c.samples = 50;
        c.errors = 2;
        apply_listing(&mut members, "a:1", &rows(&[("a:1", "ready", true), ("c:1", "ready", false)]));
        let c = &members["c:1"];
        assert_eq!((c.listed, c.ewma, c.samples, c.errors), (MemberState::Ready, None, 0, 0));
        // A ready member staying ready keeps its average.
        members.get_mut("c:1").unwrap().ewma = Some(0.5);
        apply_listing(&mut members, "a:1", &rows(&[("a:1", "ready", true), ("c:1", "ready", false)]));
        assert_eq!(members["c:1"].ewma, Some(0.5));
    }

    #[test]
    fn a_listing_keeps_seeds_and_matches_them_by_name() {
        let mut members = BTreeMap::new();
        members.insert("db1:7000".to_string(), Member::new(true));
        members.insert("db9:7000".to_string(), Member::new(true));
        // The seed db1 answers as 10.0.0.1; a discovered member of that
        // name would be a duplicate of it.
        members.insert("10.0.0.1:7000".to_string(), {
            let mut m = Member::new(false);
            m.canonical = Some("10.0.0.1:7000".into());
            m
        });
        let listing = rows(&[("10.0.0.1:7000", "ready", true), ("10.0.0.2:7000", "ready", false)]);
        apply_listing(&mut members, "db1:7000", &listing);
        let keys: Vec<&str> = members.keys().map(String::as_str).collect();
        assert_eq!(keys, ["10.0.0.2:7000", "db1:7000", "db9:7000"]);
        assert_eq!(members["db1:7000"].canonical.as_deref(), Some("10.0.0.1:7000"));
        // db9 is not identified yet: kept as it is.
        assert_eq!(members["db9:7000"].listed, MemberState::Ready);
        // db9 identifies itself, then leaves the ring: kept, unlisted; a
        // discovered member that leaves is dropped.
        members.get_mut("db9:7000").unwrap().canonical = Some("10.0.0.9:7000".into());
        apply_listing(&mut members, "db1:7000", &rows(&[("10.0.0.1:7000", "ready", true)]));
        let keys: Vec<&str> = members.keys().map(String::as_str).collect();
        assert_eq!(keys, ["db1:7000", "db9:7000"]);
        assert_eq!(members["db9:7000"].listed, MemberState::Unlisted);
        assert_eq!(members["db1:7000"].listed, MemberState::Ready);
    }
}
