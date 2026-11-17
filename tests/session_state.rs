//! The state of a session across connections (docs/PROTOCOL.md §6, rules 7
//! and 9 to 15): what a connection that replaces a lost one is given back,
//! when a connection is replaced at all, and what a pool hands its next
//! borrower — through the public API, against a scripted peer.
//!
//! The peer keeps what a server keeps for each connection — its database,
//! its consistency override, its scan budget, its open transaction — and
//! records every statement with the connection it arrived on, so a test
//! reads off both what a statement ran under and what was sent to get
//! there. A `SELECT` answers one row describing its session ([`Ran`]).

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use skaidb::{
    Client, Consistency, DriverError, LoadBalancing, MemberState, Pool, Response, TlsConfig,
    TlsVerify, Value,
};
use skaidb_proto::{
    decode_client_request, read_frame, tag_response, write_frame, AuthChallenge, AuthFinish,
    AuthOutcome, AuthStart, ClientRequest,
};

const SELECT: &str = "SELECT count(*) FROM notes";

fn insert(id: i64) -> String {
    format!("INSERT INTO notes (id) VALUES ({id})")
}

/// One connection as the peer keeps it.
#[derive(Default)]
struct Session {
    /// A second handle on the socket, for the test to shut down. `None`
    /// once the peer has let the socket go.
    socket: Option<TcpStream>,
    database: String,
    consistency: Option<String>,
    scan_budget: Option<String>,
    /// The rows inserted in the open transaction; `None` with none open.
    pending: Option<Vec<i64>>,
    /// The statements received, in order.
    statements: Vec<String>,
    /// Bytes received in all (under TLS: of plaintext).
    received: usize,
    /// `received` when the peer shut down its sending side.
    half_closed_at: Option<usize>,
    /// Leave the `Hello` unread and wait for `reset`: closing a socket
    /// with unread data is how a peer resets a connection.
    resets: bool,
    reset: bool,
    /// The client's end of stream was read, or the socket failed.
    ended: bool,
}

#[derive(Default)]
struct World {
    sessions: Vec<Session>,
    databases: HashSet<String>,
    /// The rows committed.
    rows: Vec<i64>,
    /// Answer `SET CONSISTENCY DEFAULT` as a server before 0.349 does.
    old_server: bool,
    /// A statement the connection is closed under, unanswered (once).
    lose_under: Option<String>,
    /// Statements answered with an error: text → message.
    refuse: HashMap<String, String>,
    /// Close new connections before the handshake.
    refuse_connections: bool,
    /// The next connection is one the peer will reset (`Session::resets`).
    reset_next: bool,
    stopped: bool,
}

/// A scripted skaidb server on a loopback port.
struct Peer {
    endpoint: String,
    world: Arc<Mutex<World>>,
}

/// The peer's side of a connection, counting what it receives.
struct Counted {
    stream: skaidb_net::Stream,
    world: Arc<Mutex<World>>,
    serial: usize,
}

impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.stream.read(buf)?;
        self.world.lock().unwrap().sessions[self.serial].received += n;
        Ok(n)
    }
}

impl Write for Counted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl Peer {
    fn new() -> Peer {
        Peer::start(None)
    }

    /// A peer that speaks TLS with the certificate and key in these files.
    fn tls(cert: &str, key: &str) -> Peer {
        Peer::start(Some(skaidb_net::server_config(cert, key).expect("server TLS config")))
    }

    fn start(tls: Option<Arc<rustls::ServerConfig>>) -> Peer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let world = Arc::new(Mutex::new(World {
            databases: ["default", "app", "other"].into_iter().map(String::from).collect(),
            ..World::default()
        }));
        let shared = world.clone();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let serial = {
                    let mut w = shared.lock().unwrap();
                    if w.stopped {
                        return;
                    }
                    if w.refuse_connections {
                        continue; // dropped: closed before the handshake
                    }
                    let resets = std::mem::take(&mut w.reset_next);
                    w.sessions.push(Session {
                        socket: conn.try_clone().ok(),
                        database: "default".into(),
                        resets,
                        ..Session::default()
                    });
                    w.sessions.len() - 1
                };
                let (world, tls) = (shared.clone(), tls.clone());
                thread::spawn(move || {
                    let _ = serve(&world, serial, conn, tls);
                    world.lock().unwrap().sessions[serial].ended = true;
                });
            }
        });
        Peer { endpoint, world }
    }

    fn world(&self) -> MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    fn connect(&self) -> Client {
        Client::connect(self.endpoint.as_str()).expect("connect")
    }

    /// Connections accepted so far.
    fn sessions(&self) -> usize {
        self.world().sessions.len()
    }

    /// The statements connection `serial` received, in order.
    fn statements(&self, serial: usize) -> Vec<String> {
        self.world().sessions[serial].statements.clone()
    }

    /// How often `sql` arrived, on any connection.
    fn arrived(&self, sql: &str) -> usize {
        self.world().sessions.iter().flat_map(|s| &s.statements).filter(|s| *s == sql).count()
    }

    fn refuse(&self, sql: &str, message: &str) {
        self.world().refuse.insert(sql.into(), message.into());
    }

    fn allow(&self, sql: &str) {
        self.world().refuse.remove(sql);
    }

    /// The peer goes away from connection `serial`, as a member that
    /// restarts does: both directions are shut down.
    fn close(&self, serial: usize) {
        if let Some(socket) = &self.world().sessions[serial].socket {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    /// [`Peer::close`] while the client is idle, with the time for the
    /// close to reach it.
    fn lose(&self, serial: usize) {
        self.close(serial);
        settle();
    }

    /// The peer shuts down only its SENDING side of connection `serial`
    /// and keeps reading: the client reads an end of stream, and its
    /// writes succeed — what a connection closed by a peer far away looks
    /// like until the reset comes back.
    fn half_close(&self, serial: usize) {
        {
            let mut w = self.world();
            let session = &mut w.sessions[serial];
            session.half_closed_at = Some(session.received);
            let _ = session.socket.as_ref().expect("socket").shutdown(Shutdown::Write);
        }
        settle();
    }

    /// How many bytes connection `serial` received after its half-close —
    /// counted once the client has closed its end, so nothing is on its
    /// way any more.
    fn after_half_close(&self, serial: usize) -> usize {
        self.wait_ended(serial);
        let w = self.world();
        let session = &w.sessions[serial];
        session.received - session.half_closed_at.expect("the connection was not half-closed")
    }

    /// Wait for the client to close its end of connection `serial`.
    fn wait_ended(&self, serial: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.world().sessions[serial].ended {
            assert!(Instant::now() < deadline, "the client never closed connection {serial}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Reset connection `serial` (one accepted under `reset_next`) while
    /// the client is idle.
    fn reset(&self, serial: usize) {
        self.world().sessions[serial].reset = true;
        self.wait_ended(serial);
        settle();
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        {
            let mut w = self.world();
            w.stopped = true;
            for session in &w.sessions {
                if let Some(socket) = &session.socket {
                    let _ = socket.shutdown(Shutdown::Both);
                }
            }
        }
        // Wake the accept loop so it sees `stopped` and lets the port go.
        let _ = TcpStream::connect(&self.endpoint);
    }
}

/// The time a close takes to reach the client on loopback, generously.
fn settle() {
    thread::sleep(Duration::from_millis(100));
}

fn serve(
    world: &Arc<Mutex<World>>,
    serial: usize,
    tcp: TcpStream,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = match tls {
        Some(cfg) => skaidb_net::accept_tls(tcp, cfg)?,
        None => skaidb_net::Stream::Plain(tcp),
    };
    let mut s = Counted {
        stream,
        world: world.clone(),
        serial,
    };
    // SCRAM with whatever proof arrives: the clients here log in as
    // `anonymous`, whose empty password verifies no server signature.
    let start = AuthStart::decode(&read_frame(&mut s)?)?;
    let challenge = AuthChallenge {
        salt: b"session-state".to_vec(),
        iterations: 1,
        server_nonce: format!("{}peer", start.client_nonce),
    };
    write_frame(&mut s, &challenge.encode())?;
    AuthFinish::decode(&read_frame(&mut s)?)?;
    write_frame(&mut s, &AuthOutcome::Ok { server_signature: [0; 32] }.encode())?;
    if world.lock().unwrap().sessions[serial].resets {
        // The Hello is acknowledged with most of it unread; the close
        // that follows, with that still in the receive buffer, is a reset.
        s.read_exact(&mut [0u8; 4])?;
        write_frame(&mut s, &Response::Ddl.encode())?;
        while !world.lock().unwrap().sessions[serial].reset {
            thread::sleep(Duration::from_millis(5));
        }
        world.lock().unwrap().sessions[serial].socket = None;
        return Ok(());
    }
    // The statements prepared on this connection: an id is an index here.
    let mut prepared: Vec<String> = Vec::new();
    loop {
        let frame = read_frame(&mut s)?;
        let (tag, request) = decode_client_request(&frame)?;
        let mut w = world.lock().unwrap();
        // What arrives after the half-close is counted and not answered.
        if w.sessions[serial].half_closed_at.is_some() {
            continue;
        }
        let answered = match request {
            ClientRequest::Hello { .. } | ClientRequest::Close { .. } => Some(vec![Response::Ddl]),
            ClientRequest::Query { sql, consistency } => {
                answer(&mut w, serial, &sql, consistency).map(|r| vec![r])
            }
            ClientRequest::Prepare { sql } => {
                let params = sql.matches('?').count() as u16;
                prepared.push(sql);
                Some(vec![Response::Prepared {
                    id: prepared.len() as u32 - 1,
                    params,
                }])
            }
            ClientRequest::Execute { id, params, consistency } => {
                let sql = bound(&prepared[id as usize], &params);
                answer(&mut w, serial, &sql, consistency).map(|r| vec![r])
            }
            ClientRequest::ExecuteBatch { id, rows, consistency } => {
                let mut affected = 0;
                for params in &rows {
                    let sql = bound(&prepared[id as usize], params);
                    if answer(&mut w, serial, &sql, consistency).is_some() {
                        affected += 1;
                    }
                }
                Some(vec![Response::Mutation { affected }])
            }
            ClientRequest::QueryStream { sql, consistency, .. } => {
                answer(&mut w, serial, &sql, consistency).map(|r| match r {
                    Response::Rows { columns, rows } => vec![
                        Response::RowsHeader { columns },
                        Response::RowsChunk { rows },
                        Response::RowsEnd,
                    ],
                    other => vec![other],
                })
            }
        };
        let Some(responses) = answered else {
            // Lost under the statement: no answer, and the socket goes.
            if let Some(socket) = &w.sessions[serial].socket {
                let _ = socket.shutdown(Shutdown::Both);
            }
            return Ok(());
        };
        drop(w);
        for response in responses {
            let mut out = Vec::new();
            if let Some(id) = tag {
                tag_response(&mut out, id);
            }
            out.extend_from_slice(&response.encode());
            write_frame(&mut s, &out)?;
        }
    }
}

/// A prepared statement's text with its parameters written in.
fn bound(sql: &str, params: &[Value]) -> String {
    let mut out = sql.to_string();
    for p in params {
        let text = match p {
            Value::Int(n) => n.to_string(),
            other => format!("{other:?}"),
        };
        out = out.replacen('?', &text, 1);
    }
    out
}

/// The peer's answer to one statement on connection `serial`; `None` when
/// the connection is to be closed under it instead.
fn answer(world: &mut World, serial: usize, sql: &str, level: Consistency) -> Option<Response> {
    world.sessions[serial].statements.push(sql.to_string());
    if world.lose_under.as_deref() == Some(sql) {
        world.lose_under = None;
        return None;
    }
    // The statement as a server reads it: `--` comments and one trailing
    // `;` dropped, keywords in any case. (No statement here has a `--`
    // inside a quoted name.)
    let text: Vec<&str> = sql.lines().map(|l| l.split("--").next().unwrap_or("")).collect();
    let text = text.join(" ");
    let words: Vec<&str> = text.trim().trim_end_matches(';').split_whitespace().collect();
    let upper: Vec<String> = words.iter().map(|w| w.to_ascii_uppercase()).collect();
    let upper: Vec<&str> = upper.iter().map(String::as_str).collect();
    if let Some(message) = world.refuse.get(sql) {
        // A refused COMMIT has ended the transaction too.
        if upper.first() == Some(&"COMMIT") {
            world.sessions[serial].pending = None;
        }
        return Some(Response::Error(message.clone()));
    }
    let old_server = world.old_server;
    let committed = world.rows.len() as i64;
    let session = &mut world.sessions[serial];
    Some(match upper.as_slice() {
        ["USE", _] | ["USE", "DATABASE", _] => {
            let name = words[words.len() - 1].trim_matches('"').replace("\"\"", "\"");
            if world.databases.contains(&name) {
                session.database = name;
                Response::Ddl
            } else {
                Response::Error(format!("unknown database: {name}"))
            }
        }
        ["SET", "CONSISTENCY", "DEFAULT"] if old_server => Response::Error(
            "parse error: SET CONSISTENCY takes ONE, QUORUM, or ALL — found \"DEFAULT\"".into(),
        ),
        ["SET", "CONSISTENCY", "DEFAULT"] => {
            session.consistency = None;
            Response::Ddl
        }
        ["SET", "CONSISTENCY", level] => {
            session.consistency = Some((*level).to_string());
            Response::Ddl
        }
        ["SET", "SCAN", "BUDGET", "DEFAULT"] => {
            session.scan_budget = None;
            Response::Ddl
        }
        ["SET", "SCAN", "BUDGET", budget @ ..] => {
            session.scan_budget = Some(budget.join(" "));
            Response::Ddl
        }
        ["BEGIN", ..] => {
            if session.pending.is_some() {
                Response::Error("a transaction is already open".into())
            } else {
                session.pending = Some(Vec::new());
                Response::Ddl
            }
        }
        ["COMMIT"] | ["COMMIT", "TRANSACTION"] => match session.pending.take() {
            Some(rows) => {
                world.rows.extend(rows);
                Response::Ddl
            }
            None => Response::Error("no transaction open".into()),
        },
        ["ROLLBACK"] | ["ROLLBACK", "TRANSACTION"] => {
            session.pending = None;
            Response::Ddl
        }
        ["INSERT", ..] => {
            let digits: String = sql.rsplit('(').next().unwrap_or("").chars().filter(char::is_ascii_digit).collect();
            let id = digits.parse().unwrap_or(0);
            match &mut session.pending {
                Some(rows) => rows.push(id),
                None => world.rows.push(id),
            }
            Response::Mutation { affected: 1 }
        }
        ["SELECT", ..] => Response::Rows {
            columns: ["conn", "database", "consistency", "scan_budget", "level", "rows"]
                .into_iter()
                .map(String::from)
                .collect(),
            rows: vec![vec![
                Value::Int(serial as i64),
                Value::String(session.database.clone()),
                session.consistency.clone().map_or(Value::Null, Value::String),
                session.scan_budget.clone().map_or(Value::Null, Value::String),
                Value::String(format!("{level:?}")),
                Value::Int(committed),
            ]],
        },
        // The balanced pool's probe and its discovery: a standalone server.
        ["SHOW", ..] => Response::Rows {
            columns: vec!["name".into()],
            rows: Vec::new(),
        },
        _ => Response::Ddl,
    })
}

/// What a `SELECT` ran under, as the peer answered it.
#[derive(Debug, Clone, PartialEq)]
struct Ran {
    /// The connection it arrived on (the peer's serial, from 0).
    conn: usize,
    database: String,
    consistency: Option<String>,
    scan_budget: Option<String>,
    /// The consistency level its request carried.
    level: String,
    /// The rows committed when it ran.
    rows: i64,
}

impl Ran {
    /// The connection, and the state of its session.
    fn session(&self) -> (usize, &str, Option<&str>, Option<&str>) {
        (self.conn, &self.database, self.consistency.as_deref(), self.scan_budget.as_deref())
    }
}

fn ran_of(response: Response) -> Ran {
    let text = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => panic!("unexpected cell {other:?}"),
    };
    let int = |v: &Value| match v {
        Value::Int(n) => *n,
        other => panic!("unexpected cell {other:?}"),
    };
    match response {
        Response::Rows { rows, .. } => {
            let row = &rows[0];
            Ran {
                conn: int(&row[0]) as usize,
                database: text(&row[1]).expect("database"),
                consistency: text(&row[2]),
                scan_budget: text(&row[3]),
                level: text(&row[4]).expect("level"),
                rows: int(&row[5]),
            }
        }
        other => panic!("unexpected response {other:?}"),
    }
}

/// Run the `SELECT` and say what it ran under.
fn ran(client: &mut Client) -> Ran {
    ran_of(client.execute(SELECT).expect("SELECT"))
}

fn try_ran(client: &mut Client) -> Result<Ran, DriverError> {
    client.execute(SELECT).map(ran_of)
}

/// A pool of `maxsize` connections to `peer`, from a closure that
/// configures nothing.
fn plain_pool(peer: &Peer, maxsize: usize) -> Pool {
    let endpoint = peer.endpoint.clone();
    Pool::new(maxsize, move || Client::connect(endpoint.as_str()))
}

fn server_error(e: &DriverError) -> &str {
    match e {
        DriverError::Server(message) => message,
        other => panic!("expected a server error, got {other:?}"),
    }
}

/// The message of the driver's connection error.
fn lost(e: &DriverError) -> String {
    match e {
        DriverError::Io(e) => e.to_string(),
        other => panic!("expected a connection error, got {other:?}"),
    }
}

// ---- H: session settings survive a re-dial -----------------------------------

/// `SET CONSISTENCY` and `SET SCAN BUDGET` sent as statements are the
/// session's, like the database a `USE` entered: the connection that
/// replaces a lost one gets them before the statement — after the
/// database, the consistency, then the scan budget. They used to be lost
/// with the connection: a scan the application had bounded ran unbounded,
/// and a read asked for at `ALL` ran at the request's default.
#[test]
fn settings_sent_as_statements_are_put_back_on_a_replaced_connection() {
    let peer = Peer::new();
    let mut c = peer.connect();
    c.execute("USE app").unwrap();
    c.execute("SET CONSISTENCY ALL").unwrap();
    c.execute("set scan budget rows 1; -- one row is plenty").unwrap();
    assert_eq!(ran(&mut c).session(), (0, "app", Some("ALL"), Some("ROWS 1")));
    peer.lose(0);
    assert_eq!(ran(&mut c).session(), (1, "app", Some("ALL"), Some("ROWS 1")));
    assert_eq!(
        peer.statements(1),
        ["USE \"app\"", "SET CONSISTENCY ALL", "set scan budget rows 1", SELECT]
    );
    // The last one of each kind is the one kept.
    c.execute("SET CONSISTENCY ONE").unwrap();
    c.execute("SET SCAN BUDGET BYTES 4096 ROWS 9").unwrap();
    peer.lose(1);
    assert_eq!(ran(&mut c).session(), (2, "app", Some("ONE"), Some("BYTES 4096 ROWS 9")));
    assert_eq!(
        peer.statements(2),
        ["USE \"app\"", "SET CONSISTENCY ONE", "SET SCAN BUDGET BYTES 4096 ROWS 9", SELECT]
    );
}

/// `… DEFAULT` clears the setting on the server, and the driver's note of
/// it: a new connection is not given a setting the application took back.
#[test]
fn a_setting_cleared_with_default_is_not_put_back() {
    let peer = Peer::new();
    let mut c = peer.connect();
    c.execute("SET CONSISTENCY ALL").unwrap();
    c.execute("SET SCAN BUDGET ROWS 1").unwrap();
    c.execute("SET CONSISTENCY DEFAULT").unwrap();
    c.execute("Set  Scan Budget\n default ;").unwrap();
    peer.lose(0);
    assert_eq!(ran(&mut c).session(), (1, "default", None, None));
    assert_eq!(peer.statements(1), [SELECT]);
    // A setting the server refused was never the session's.
    peer.refuse("SET CONSISTENCY SOME", "parse error: SET CONSISTENCY takes ONE, QUORUM, ALL, or DEFAULT");
    assert!(c.execute("SET CONSISTENCY SOME").is_err());
    peer.lose(1);
    assert_eq!(ran(&mut c).session(), (2, "default", None, None));
    assert_eq!(peer.statements(2), [SELECT]);
}

/// A setting the new connection refuses fails the statement with that
/// error, and the next one too: no statement runs under other settings
/// than the application set.
#[test]
fn a_setting_the_new_connection_refuses_fails_the_statement() {
    let peer = Peer::new();
    let mut c = peer.connect();
    c.execute("SET SCAN BUDGET ROWS 1").unwrap();
    peer.refuse("SET SCAN BUDGET ROWS 1", "permission denied: SET SCAN BUDGET");
    peer.lose(0);
    for _ in 0..2 {
        let err = try_ran(&mut c).unwrap_err();
        assert_eq!(server_error(&err), "permission denied: SET SCAN BUDGET");
    }
    assert_eq!(peer.arrived(SELECT), 0, "the statement ran without its scan budget");
    // Taken again, the setting is back and the statement runs under it.
    peer.allow("SET SCAN BUDGET ROWS 1");
    assert_eq!(ran(&mut c).scan_budget.as_deref(), Some("ROWS 1"));
}

/// `set_scan_budget_rows` and a `SET SCAN BUDGET` statement are one
/// setting: the later of the two is what a new connection gets, once.
#[test]
fn the_typed_scan_budget_and_the_statement_are_one_setting() {
    let peer = Peer::new();
    let mut c = peer.connect();
    // The statement after the method.
    c.set_scan_budget_rows(5).unwrap();
    c.execute("SET SCAN BUDGET ROWS 1").unwrap();
    peer.lose(0);
    assert_eq!(ran(&mut c).scan_budget.as_deref(), Some("ROWS 1"));
    assert_eq!(peer.statements(1), ["SET SCAN BUDGET ROWS 1", SELECT]);
    // The method after the statement.
    c.set_scan_budget_rows(7).unwrap();
    peer.lose(1);
    assert_eq!(ran(&mut c).scan_budget.as_deref(), Some("ROWS 7"));
    assert_eq!(peer.statements(2), ["SET SCAN BUDGET ROWS 7", SELECT]);
    // What the method set, cleared by a statement.
    c.execute("SET SCAN BUDGET DEFAULT").unwrap();
    peer.lose(2);
    assert_eq!(ran(&mut c).scan_budget, None);
    assert_eq!(peer.statements(3), [SELECT]);
    // What a statement set, cleared by the method.
    c.execute("SET SCAN BUDGET BYTES 4096").unwrap();
    c.set_scan_budget_rows(0).unwrap();
    peer.lose(3);
    assert_eq!(ran(&mut c).scan_budget, None);
    assert_eq!(peer.statements(4), [SELECT]);
}

/// A statement in a pipeline sets the session's state as it does alone.
#[test]
fn settings_in_a_pipeline_are_noted() {
    let peer = Peer::new();
    let mut c = peer.connect();
    peer.refuse("SET CONSISTENCY SOME", "parse error");
    let answers = c
        .pipeline(&["USE app", "SET CONSISTENCY ALL", "SET CONSISTENCY SOME", "SET SCAN BUDGET ROWS 3"])
        .unwrap();
    assert!(matches!(answers[2], Response::Error(_)));
    peer.lose(0);
    assert_eq!(ran(&mut c).session(), (1, "app", Some("ALL"), Some("ROWS 3")));
}

/// A pooled connection replaced while its borrower holds it keeps what
/// that borrower set.
#[test]
fn a_pooled_connection_replaced_under_its_borrower_keeps_the_borrowers_settings() {
    let peer = Peer::new();
    let pool = Pool::builder(&[peer.endpoint.as_str()]).database("app").build().unwrap();
    let mut c = pool.acquire().unwrap();
    c.execute("SET CONSISTENCY ALL").unwrap();
    c.execute("SET SCAN BUDGET ROWS 1").unwrap();
    peer.lose(0);
    assert_eq!(ran(&mut c).session(), (1, "app", Some("ALL"), Some("ROWS 1")));
    pool.release(c);
}

// ---- I: a connection closed while it was idle costs no statement -------------

/// The peer closed the connection while the client was idle, and the
/// client's writes still succeed (a half-close: what a restart looks like
/// over a real network until the reset comes back). The statement runs on
/// a second connection, and nothing of it was written on the dead one — a
/// look at the socket found it closed first. The driver used to write the
/// statement there and send it again after the read failed.
#[test]
fn a_connection_half_closed_while_idle_gets_no_statement() {
    let peer = Peer::new();
    let mut c = peer.connect();
    assert_eq!(ran(&mut c).conn, 0);
    // A read.
    peer.half_close(0);
    assert_eq!(ran(&mut c).conn, 1);
    assert_eq!(peer.after_half_close(0), 0, "the SELECT was written on the closed connection");
    // A write, likewise: sent once, on the new connection.
    peer.half_close(1);
    c.execute(&insert(1)).unwrap();
    assert_eq!(peer.after_half_close(1), 0, "the INSERT was written on the closed connection");
    assert_eq!(peer.statements(2), [insert(1)]);
    let after = ran(&mut c);
    assert_eq!((after.conn, after.rows), (2, 1));
}

/// Every kind of request looks first: a prepare, a prepared execute and
/// its batch, a pipeline, a stream.
#[test]
fn every_kind_of_request_looks_at_the_connection_first() {
    let peer = Peer::new();
    let mut c = peer.connect();
    let text = "INSERT INTO notes (id) VALUES (?)";
    let mut stmt = c.prepare(text).unwrap();
    peer.half_close(0);
    c.execute_prepared(&mut stmt, &[Value::Int(1)]).unwrap();
    assert_eq!(peer.after_half_close(0), 0, "execute_prepared");
    assert_eq!(peer.statements(1), [insert(1)]);

    peer.half_close(1);
    assert_eq!(c.execute_batch(&mut stmt, vec![vec![Value::Int(2)], vec![Value::Int(3)]]).unwrap(), 2);
    assert_eq!(peer.after_half_close(1), 0, "execute_batch");

    peer.half_close(2);
    let answers = c.pipeline(&[&insert(4), &insert(5)]).unwrap();
    assert_eq!(answers.len(), 2);
    assert_eq!(peer.after_half_close(2), 0, "pipeline");
    assert_eq!(peer.statements(3), [insert(4), insert(5)]);

    peer.half_close(3);
    let rows: Vec<Vec<Value>> = c.query_stream(SELECT).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(peer.after_half_close(3), 0, "query_stream");

    peer.half_close(4);
    c.prepare("INSERT INTO notes (id, v) VALUES (?, ?)").unwrap();
    assert_eq!(peer.after_half_close(4), 0, "prepare");

    peer.half_close(5);
    c.use_database("app").unwrap();
    assert_eq!(peer.after_half_close(5), 0, "use_database");
    peer.half_close(6);
    c.set_scan_budget_rows(2).unwrap();
    assert_eq!(peer.after_half_close(6), 0, "set_scan_budget_rows");
    let after = ran(&mut c);
    assert_eq!(after.session(), (7, "app", None, Some("ROWS 2")));
    assert_eq!(after.rows, 5);
}

/// A reset instead of a clean close: the same outcome.
#[test]
fn a_connection_reset_while_idle_costs_no_statement() {
    let peer = Peer::new();
    peer.world().reset_next = true;
    let mut c = peer.connect();
    peer.reset(0);
    assert_eq!(ran(&mut c).conn, 1);
    c.execute(&insert(1)).unwrap();
    assert_eq!(peer.arrived(&insert(1)), 1);
    assert_eq!(peer.sessions(), 2);
}

/// A pool hands out no connection that died while it sat idle: the
/// checkout itself gives a live one, and nothing is written on the dead
/// one.
#[test]
fn a_pool_hands_out_no_connection_that_died_while_idle() {
    let peer = Peer::new();
    let pool = plain_pool(&peer, 2);
    assert_eq!(pool.with(|c| Ok(ran(c).conn)).unwrap(), 0);
    assert_eq!(pool.idle_len(), 1);
    peer.half_close(0);
    let mut c = pool.acquire().unwrap();
    assert_eq!(peer.sessions(), 2, "the checkout handed out the connection the peer had closed");
    assert_eq!(pool.idle_len(), 0);
    assert_eq!(ran(&mut c).conn, 1);
    assert_eq!(peer.after_half_close(0), 0);
    pool.release(c);
    assert_eq!(pool.idle_len(), 1);
}

/// The same for a pool balanced across members: the dead idle connection
/// is dropped, counted against no checkout, and a live one handed out.
#[test]
fn a_balanced_pool_hands_out_no_connection_that_died_while_idle() {
    let peer = Peer::new();
    let pool = Pool::builder(&[peer.endpoint.as_str()]).maxsize(4).build().unwrap();
    // Four idle connections, all closed by the peer while idle: more than
    // the dials a checkout allows itself.
    let held: Vec<Client> = (0..4).map(|_| pool.acquire().unwrap()).collect();
    for c in held {
        pool.release(c);
    }
    assert_eq!(pool.idle_len(), 4);
    for serial in 0..4 {
        peer.half_close(serial);
    }
    let mut c = pool.acquire().unwrap();
    assert_eq!(peer.sessions(), 5, "the checkout handed out a connection the peer had closed");
    assert_eq!(ran(&mut c).conn, 4);
    for serial in 0..4 {
        assert_eq!(peer.after_half_close(serial), 0);
    }
    let member = &pool.members()[0];
    assert_eq!((member.in_use, member.idle, member.state), (1, 0, MemberState::Ready));
    pool.release(c);
    assert_eq!(pool.members()[0].idle, 1);
}

/// Inside the transaction helper nothing changes (rule 7): a connection
/// found closed there is a lost transaction, not one to replace. The
/// statements of the body fail with the connection error, none is written
/// anywhere, and the helper reports that nothing was committed.
#[test]
fn the_helper_does_not_replace_a_connection_found_closed_in_its_transaction() {
    let peer = Peer::new();
    let mut c = peer.connect();
    let mut errors = Vec::new();
    let err = c
        .transaction(3, |c| {
            c.execute(&insert(1))?;
            peer.half_close(0);
            // A body that catches its errors and goes on.
            errors.push(lost(&c.execute(&insert(2)).unwrap_err()));
            errors.push(lost(&c.execute(&insert(3)).unwrap_err()));
            Ok(())
        })
        .unwrap_err();
    assert_eq!(peer.after_half_close(0), 0, "a statement was written on the closed connection");
    assert_eq!(peer.sessions(), 1, "the transaction was carried to a new connection");
    assert!(errors.iter().all(|e| e.contains("inside a transaction")), "{errors:?}");
    assert!(lost(&err).contains("nothing was committed"), "{err}");
    // Outside, the client dials again; no row of the transaction exists.
    let after = ran(&mut c);
    assert_eq!((after.conn, after.rows), (1, 0));
    assert_eq!(peer.statements(1), [SELECT]);
}

/// The opening statement of a transaction dials like any other statement:
/// nothing is open yet.
#[test]
fn the_opening_statement_replaces_a_connection_closed_while_idle() {
    let peer = Peer::new();
    let mut c = peer.connect();
    peer.half_close(0);
    c.transaction(1, |c| c.execute(&insert(1)).map(|_| ())).unwrap();
    assert_eq!(peer.after_half_close(0), 0);
    assert_eq!(peer.statements(1), ["BEGIN".to_string(), insert(1), "COMMIT".to_string()]);
    assert_eq!(ran(&mut c).rows, 1);
}

/// A certificate and key for the TLS peer, made by the `openssl` binary
/// (the driver has no code that makes one). `None` without one.
fn certificate() -> Option<(String, String)> {
    static SERIAL: AtomicUsize = AtomicUsize::new(0);
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "session-state-tls-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).ok()?;
    let cert = dir.join("cert.pem").to_string_lossy().into_owned();
    let key = dir.join("key.pem").to_string_lossy().into_owned();
    let made = std::process::Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"])
        .args(["-days", "2", "-subj", "/CN=skaidb", "-addext", "subjectAltName=DNS:skaidb"])
        .args(["-keyout", &key, "-out", &cert])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    made.success().then_some((cert, key))
}

/// Under TLS the look is at the transport: a live connection is not taken
/// for a dead one because of what TLS itself sends after the handshake
/// (session tickets), and one the peer closed while idle is replaced
/// before anything is written on it.
#[test]
fn under_tls_the_look_is_at_the_transport() {
    let Some((cert, key)) = certificate() else {
        eprintln!("skipped: no `openssl` binary to make a certificate with");
        return;
    };
    let peer = Peer::tls(&cert, &key);
    let tls = TlsConfig::new(TlsVerify::Insecure, "skaidb").unwrap();
    let mut c = Client::connect_many_tls(std::slice::from_ref(&peer.endpoint), "anonymous", "", Some(tls)).unwrap();
    // Live, and idle between statements: one connection.
    for _ in 0..3 {
        assert_eq!(ran(&mut c).conn, 0);
        settle();
    }
    c.execute("SET SCAN BUDGET ROWS 1").unwrap();
    peer.half_close(0);
    c.execute(&insert(1)).unwrap();
    assert_eq!(peer.after_half_close(0), 0, "the INSERT was written on the closed connection");
    assert_eq!(peer.statements(1), ["SET SCAN BUDGET ROWS 1".to_string(), insert(1)]);
    // The peer going away altogether, likewise.
    peer.lose(1);
    let after = ran(&mut c);
    assert_eq!((after.conn, after.rows), (2, 1));
    std::fs::remove_dir_all(std::path::Path::new(&cert).parent().unwrap()).ok();
}

// ---- J: a pool hands every borrower its own session state --------------------

/// One borrower's `USE`, `SET SCAN BUDGET` and `SET CONSISTENCY` are not
/// the next borrower's: the pool puts the connection back — in `default`,
/// the database a pool that names none starts every connection in — before
/// it is handed out again.
#[test]
fn a_pool_puts_back_what_its_borrower_changed() {
    let peer = Peer::new();
    let pool = plain_pool(&peer, 1);
    pool.with(|c| {
        c.execute("USE other")?;
        c.execute("SET SCAN BUDGET ROWS 1")?;
        c.execute("SET CONSISTENCY ALL")?;
        Ok(())
    })
    .unwrap();
    let next = pool.with(|c| Ok(ran(c))).unwrap();
    assert_eq!(next.session(), (0, "default", None, None));
    assert_eq!(
        peer.statements(0),
        [
            "USE other",
            "SET SCAN BUDGET ROWS 1",
            "SET CONSISTENCY ALL",
            "USE \"default\"",
            "SET SCAN BUDGET DEFAULT",
            "SET CONSISTENCY DEFAULT",
            SELECT
        ]
    );
}

/// The settings alone — the borrower stayed in the pool's database — are
/// put back too. They used to stay on the connection for whoever borrowed
/// it next: a read at another consistency, a scan refused for a budget
/// nobody in sight had set.
#[test]
fn a_borrowers_settings_do_not_reach_the_next_borrower() {
    let peer = Peer::new();
    let endpoint = peer.endpoint.clone();
    let pool = Pool::new(1, move || Client::connect(endpoint.as_str())?.with_database("app"));
    pool.with(|c| {
        c.execute("SET SCAN BUDGET ROWS 1")?;
        c.execute("SET CONSISTENCY ALL").map(|_| ())
    })
    .unwrap();
    assert_eq!(pool.with(|c| Ok(ran(c))).unwrap().session(), (0, "app", None, None));
    // One setting changed: one statement to put it back.
    pool.with(|c| c.set_scan_budget_rows(3)).unwrap();
    assert_eq!(pool.with(|c| Ok(ran(c))).unwrap().session(), (0, "app", None, None));
    assert_eq!(
        peer.statements(0)[3..],
        ["SET SCAN BUDGET DEFAULT", "SET CONSISTENCY DEFAULT", SELECT, "SET SCAN BUDGET ROWS 3", "SET SCAN BUDGET DEFAULT", SELECT]
    );
    // And the database of a pool that names one.
    pool.with(|c| c.execute("USE other").map(|_| ())).unwrap();
    assert_eq!(pool.with(|c| Ok(ran(c))).unwrap().session(), (0, "app", None, None));
}

/// A borrower that changed nothing costs no round trip.
#[test]
fn a_borrower_that_changed_nothing_costs_no_round_trip() {
    let peer = Peer::new();
    let pool = plain_pool(&peer, 1);
    for _ in 0..3 {
        pool.with(|c| Ok(ran(c))).unwrap();
    }
    // A setting set and taken back by its borrower is no change either.
    pool.with(|c| {
        c.execute("SET CONSISTENCY ALL")?;
        c.execute("SET CONSISTENCY DEFAULT")?;
        c.execute("USE default").map(|_| ())
    })
    .unwrap();
    pool.with(|c| Ok(ran(c))).unwrap();
    assert_eq!(
        peer.statements(0),
        [SELECT, SELECT, SELECT, "SET CONSISTENCY ALL", "SET CONSISTENCY DEFAULT", "USE default", SELECT]
    );
}

/// A connection that cannot be put back is closed instead of pooled: a
/// server before 0.349 refuses `SET CONSISTENCY DEFAULT`, and the next
/// borrower gets a new connection rather than the override.
#[test]
fn a_connection_an_older_server_cannot_put_back_is_closed() {
    let peer = Peer::new();
    peer.world().old_server = true;
    let pool = plain_pool(&peer, 1);
    pool.with(|c| c.execute("SET CONSISTENCY ALL").map(|_| ())).unwrap();
    assert_eq!(pool.idle_len(), 0);
    peer.wait_ended(0);
    assert_eq!(pool.with(|c| Ok(ran(c))).unwrap().session(), (1, "default", None, None));
    assert_eq!(pool.idle_len(), 1);
}

/// A transaction a borrower left open is rolled back before the next
/// borrower gets the connection: its statements commit on their own, not
/// in a transaction nobody will ever commit.
#[test]
fn a_transaction_a_borrower_left_open_is_rolled_back() {
    let peer = Peer::new();
    let pool = plain_pool(&peer, 1);
    pool.with(|c| {
        c.execute("BEGIN")?;
        c.execute(&insert(1)).map(|_| ())
    })
    .unwrap();
    pool.with(|c| c.execute(&insert(2)).map(|_| ())).unwrap();
    let next = pool.with(|c| Ok(ran(c))).unwrap();
    assert_eq!((next.conn, next.rows), (0, 1), "the next borrower's INSERT is in the open transaction");
    assert_eq!(peer.world().rows, [2]);
    assert_eq!(peer.statements(0), ["BEGIN".to_string(), insert(1), "ROLLBACK".to_string(), insert(2), SELECT.to_string()]);
    // The ROLLBACK comes first, the rest of the state after it.
    pool.with(|c| {
        c.execute("USE other")?;
        c.execute("begin atomic").map(|_| ())
    })
    .unwrap();
    assert_eq!(pool.with(|c| Ok(ran(c))).unwrap().session(), (0, "default", None, None));
    assert_eq!(peer.statements(0)[7..9], ["ROLLBACK", "USE \"default\""]);
}

/// The notes go back with the connection: one re-dialed for the next
/// borrower is given the pool's state, not the last borrower's.
#[test]
fn a_re_dial_for_the_next_borrower_restores_the_pools_state() {
    let peer = Peer::new();
    let endpoint = peer.endpoint.clone();
    let pool = Pool::new(1, move || Client::connect(endpoint.as_str())?.with_database("app"));
    pool.with(|c| {
        c.execute("USE other")?;
        c.execute("SET SCAN BUDGET ROWS 1")?;
        c.execute("SET CONSISTENCY ALL").map(|_| ())
    })
    .unwrap();
    // The next borrower holds the connection when it is lost.
    let mut c = pool.acquire().unwrap();
    assert_eq!(ran(&mut c).session(), (0, "app", None, None));
    peer.lose(0);
    assert_eq!(ran(&mut c).session(), (1, "app", None, None));
    assert_eq!(peer.statements(1), ["USE \"app\"", SELECT]);
    pool.release(c);
}

/// What the pool's own closure set on a connection is the pool's state:
/// that is what a borrower's change is put back to.
#[test]
fn what_a_pools_closure_set_is_the_pools_state() {
    let peer = Peer::new();
    let endpoint = peer.endpoint.clone();
    let pool = Pool::new(1, move || {
        let mut c = Client::connect(endpoint.as_str())?;
        c.set_scan_budget_rows(100)?;
        c.execute("SET CONSISTENCY ONE")?;
        c.set_consistency(Consistency::All);
        Ok(c)
    });
    pool.with(|c| {
        c.execute("SET SCAN BUDGET ROWS 1")?;
        c.execute("SET CONSISTENCY DEFAULT")?;
        c.set_consistency(Consistency::One);
        Ok(())
    })
    .unwrap();
    let next = pool.with(|c| Ok(ran(c))).unwrap();
    assert_eq!(next.session(), (0, "default", Some("ONE"), Some("ROWS 100")));
    assert_eq!(next.level, "All");
    assert_eq!(
        peer.statements(0),
        [
            "SET SCAN BUDGET ROWS 100",
            "SET CONSISTENCY ONE",
            "SET SCAN BUDGET ROWS 1",
            "SET CONSISTENCY DEFAULT",
            "SET SCAN BUDGET ROWS 100",
            "SET CONSISTENCY ONE",
            SELECT
        ]
    );
}

/// The level a borrower gave `set_consistency` is its own too: the next
/// borrower's requests carry the pool's.
#[test]
fn a_borrowers_consistency_level_is_not_the_next_borrowers() {
    let peer = Peer::new();
    let pool = Pool::builder(&[peer.endpoint.as_str()]).consistency(Consistency::All).build().unwrap();
    let first = pool
        .with(|c| {
            c.set_consistency(Consistency::One);
            Ok(ran(c))
        })
        .unwrap();
    assert_eq!(first.level, "One");
    let next = pool.with(|c| Ok(ran(c))).unwrap();
    assert_eq!((next.conn, next.level.as_str()), (0, "All"));
    // No statement puts it back: the level travels with each request.
    assert_eq!(peer.statements(0), [SELECT, SELECT]);
}

/// A pool balanced across members does the same.
#[test]
fn a_balanced_pool_puts_back_what_its_borrower_changed() {
    let peer = Peer::new();
    let pool = Pool::builder(&[peer.endpoint.as_str()]).maxsize(1).build().unwrap();
    pool.with(|c| {
        c.execute("USE other")?;
        c.execute("SET SCAN BUDGET ROWS 1")?;
        c.execute("SET CONSISTENCY ALL")?;
        c.execute("BEGIN").map(|_| ())
    })
    .unwrap();
    assert_eq!(pool.with(|c| Ok(ran(c))).unwrap().session(), (0, "default", None, None));
    assert_eq!(
        peer.statements(0)[4..],
        ["ROLLBACK", "USE \"default\"", "SET SCAN BUDGET DEFAULT", "SET CONSISTENCY DEFAULT", SELECT]
    );
    // With a database of its own, and against a server that cannot clear
    // the override: closed, and the member's counts stay right.
    let pool = Pool::builder(&[peer.endpoint.as_str()]).database("app").maxsize(1).build().unwrap();
    pool.with(|c| c.execute("USE other").map(|_| ())).unwrap();
    assert_eq!(pool.with(|c| Ok(ran(c))).unwrap().session(), (1, "app", None, None));
    peer.world().old_server = true;
    pool.with(|c| c.execute("SET CONSISTENCY ALL").map(|_| ())).unwrap();
    let member = &pool.members()[0];
    assert_eq!((member.in_use, member.idle), (0, 0));
    assert_eq!(pool.with(|c| Ok(ran(c))).unwrap().session(), (2, "app", None, None));
}

/// A connection the pool's probe made, which joins the idle set when it
/// re-admits a member, is put back like one a checkout dialed. (It was
/// handed out with no state of the pool to go back to, so a borrower's
/// `USE` stayed on it.)
#[test]
fn a_connection_the_probe_made_is_put_back_too() {
    let (a, b) = (Peer::new(), Peer::new());
    b.world().refuse_connections = true;
    let pool = Pool::builder(&[a.endpoint.as_str(), b.endpoint.as_str()])
        .load_balancing(LoadBalancing::RoundRobin)
        .database("app")
        .eject_errors(1)
        .eject_backoff(Duration::from_millis(100))
        .build()
        .unwrap();
    let state_of_b = |pool: &Pool| pool.members().into_iter().find(|m| m.endpoint == b.endpoint).unwrap();
    for _ in 0..4 {
        pool.with(|c| Ok(ran(c))).unwrap();
    }
    assert_eq!(state_of_b(&pool).state, MemberState::Ejected);
    // b is back: the probe re-admits it, and its connection joins the idle set.
    b.world().refuse_connections = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !(state_of_b(&pool).state == MemberState::Ready && state_of_b(&pool).idle == 1) {
        assert!(Instant::now() < deadline, "the probe never re-admitted b");
        thread::sleep(Duration::from_millis(10));
    }
    // Every borrower that lands on b moves it; none finds it moved.
    let mut on_b = 0;
    for _ in 0..6 {
        pool.with(|c| {
            if c.endpoint() == b.endpoint {
                on_b += 1;
                assert_eq!(ran(c).database, "app", "an earlier borrower's USE");
                c.execute("USE other")?;
            }
            Ok(())
        })
        .unwrap();
    }
    assert!(on_b >= 2, "{on_b} checkouts reached b");
    assert_eq!(b.sessions(), 1, "b's connection was replaced instead of put back");
}

// ---- K: a USE is never held hostage by the database it leaves ----------------

/// The session's database was dropped while the connection was down. No
/// statement runs anywhere else — each fails at the new connection's `USE`
/// — but the `USE` that leaves it is sent without entering it first, and
/// decides the session's database as usual. The noted settings are put
/// back before it.
#[test]
fn a_use_is_not_held_hostage_by_the_database_it_leaves() {
    let peer = Peer::new();
    let mut c = peer.connect();
    c.execute("USE app").unwrap();
    c.execute("SET CONSISTENCY ALL").unwrap();
    peer.world().databases.remove("app");
    peer.lose(0);
    for _ in 0..2 {
        let err = try_ran(&mut c).unwrap_err();
        assert_eq!(server_error(&err), "unknown database: app");
    }
    assert_eq!(peer.arrived(SELECT), 0, "the statement ran in another database");
    c.execute("USE other").unwrap();
    assert_eq!(c.database(), Some("other"));
    let last = peer.sessions() - 1;
    assert_eq!(peer.statements(last), ["SET CONSISTENCY ALL", "USE other"]);
    assert_eq!(ran(&mut c).session(), (last, "other", Some("ALL"), None));
}

/// The `USE` is the first statement after the loss, as a statement and
/// through `use_database`.
#[test]
fn a_use_that_finds_the_connection_gone_does_not_enter_the_old_database() {
    let peer = Peer::new();
    let mut c = peer.connect();
    c.execute("USE app").unwrap();
    peer.world().databases.remove("app");
    peer.lose(0);
    c.execute("USE other -- app is gone").unwrap();
    assert_eq!(peer.statements(1), ["USE other -- app is gone"]);
    assert_eq!(ran(&mut c).session(), (1, "other", None, None));

    peer.world().databases.remove("other");
    peer.lose(1);
    c.use_database("default").unwrap();
    assert_eq!(peer.statements(2), ["USE \"default\""]);
    assert_eq!(ran(&mut c).session(), (2, "default", None, None));
    assert_eq!(c.database(), Some("default"));
}

/// A `USE` the new connection refuses leaves a session that is in neither
/// database: the next statement does not run there, it runs in the
/// database the driver has noted.
#[test]
fn a_use_refused_on_a_new_connection_leaves_no_session_in_another_database() {
    let peer = Peer::new();
    let mut c = peer.connect();
    c.execute("USE app").unwrap();
    peer.lose(0);
    let err = c.execute("USE nowhere").unwrap_err();
    assert_eq!(server_error(&err), "unknown database: nowhere");
    assert_eq!(c.database(), Some("app"));
    assert_eq!(ran(&mut c).database, "app");
    // The same through `use_database`, which keeps the previous binding.
    peer.lose(peer.sessions() - 1);
    assert!(c.use_database("nowhere").is_err());
    assert_eq!(c.database(), Some("app"));
    assert_eq!(ran(&mut c).database, "app");
}

// ---- L: a hand-written transaction is a transaction --------------------------

/// A transaction the application opens with a `BEGIN` statement lives on
/// its connection like the helper's. Lost with it, the rest is not
/// carried to a new connection, where each statement would commit on its
/// own: every statement fails with the connection error and none is sent,
/// the `COMMIT` fails saying nothing was committed, and the statement
/// after it dials as usual.
#[test]
fn a_transaction_begun_by_a_statement_is_not_carried_to_a_new_connection() {
    let peer = Peer::new();
    let mut c = peer.connect();
    c.execute("BEGIN").unwrap();
    c.execute(&insert(1)).unwrap();
    peer.lose(0);
    for id in [2, 3] {
        let err = c.execute(&insert(id)).unwrap_err();
        assert!(lost(&err).contains("inside a transaction"), "{err}");
    }
    let err = c.execute("COMMIT").unwrap_err();
    assert!(lost(&err).contains("nothing was committed"), "{err}");
    assert_eq!(peer.sessions(), 1, "the transaction was carried to a new connection");
    assert_eq!(peer.statements(0), ["BEGIN".to_string(), insert(1)]);
    // Over: the next statement runs on a new connection, and no row exists.
    let after = ran(&mut c);
    assert_eq!((after.conn, after.rows), (1, 0));
    c.execute(&insert(4)).unwrap();
    assert_eq!(peer.world().rows, [4]);
}

/// The same when the connection is lost under a statement of the
/// transaction: that statement is not sent again.
#[test]
fn a_statement_a_transaction_is_lost_under_is_not_sent_again() {
    let peer = Peer::new();
    let mut c = peer.connect();
    c.execute("begin transaction; -- by hand").unwrap();
    c.execute(&insert(1)).unwrap();
    peer.world().lose_under = Some(insert(2));
    let err = c.execute(&insert(2)).unwrap_err();
    assert!(lost(&err).contains("inside a transaction"), "{err}");
    let err = c.execute(&insert(3)).unwrap_err();
    assert!(lost(&err).contains("inside a transaction"), "{err}");
    // A prepared statement, a pipeline and a stream are statements too.
    assert!(lost(&c.prepare("INSERT INTO notes (id) VALUES (?)").unwrap_err()).contains("inside a transaction"));
    assert!(lost(&c.pipeline(&[&insert(5)]).unwrap_err()).contains("inside a transaction"));
    assert!(lost(&c.query_stream(SELECT).map(|_| ()).unwrap_err()).contains("inside a transaction"));
    assert!(lost(&c.reconnect().unwrap_err()).contains("inside a transaction"));
    assert_eq!(peer.sessions(), 1);
    assert_eq!(peer.arrived(&insert(2)), 1);
    assert_eq!(peer.arrived(&insert(3)), 0);
    // ROLLBACK ends it here, with success and without a statement: the
    // server discarded the transaction with the connection.
    assert!(matches!(c.execute("ROLLBACK;").unwrap(), Response::Ddl));
    assert_eq!(peer.sessions(), 1);
    let after = ran(&mut c);
    assert_eq!((after.conn, after.rows), (1, 0));
    assert_eq!(peer.statements(1), [SELECT]);
}

/// Lost under the `COMMIT` itself, the outcome is unknown — the server
/// may have applied it before its reply went missing — and the error says
/// so. The `COMMIT` is not sent again, and the transaction is over.
#[test]
fn a_commit_the_connection_is_lost_under_has_an_unknown_outcome() {
    let peer = Peer::new();
    let mut c = peer.connect();
    c.execute("BEGIN").unwrap();
    c.execute(&insert(1)).unwrap();
    peer.world().lose_under = Some("COMMIT".into());
    let err = c.execute("COMMIT").unwrap_err();
    assert!(lost(&err).contains("outcome is unknown"), "{err}");
    assert!(!lost(&err).contains("nothing was committed"), "{err}");
    assert_eq!(peer.arrived("COMMIT"), 1);
    assert_eq!(ran(&mut c).conn, 1);
    // Lost under the ROLLBACK, the transaction is gone either way.
    c.execute("BEGIN").unwrap();
    peer.world().lose_under = Some("ROLLBACK".into());
    assert!(matches!(c.execute("ROLLBACK").unwrap(), Response::Ddl));
    assert_eq!(peer.arrived("ROLLBACK"), 1);
    assert_eq!(ran(&mut c).conn, 2);
}

/// Without a loss nothing changes, and whatever answers the `COMMIT` or
/// the `ROLLBACK` ends the transaction: afterwards a lost connection is
/// replaced as outside any transaction.
#[test]
fn a_transaction_by_hand_ends_with_its_commit_or_rollback() {
    let peer = Peer::new();
    let mut c = peer.connect();
    c.execute("BEGIN").unwrap();
    c.execute(&insert(1)).unwrap();
    c.execute("COMMIT").unwrap();
    assert_eq!(peer.world().rows, [1]);
    peer.lose(0);
    assert_eq!(ran(&mut c).conn, 1);

    c.execute("BEGIN ATOMIC").unwrap();
    c.execute(&insert(2)).unwrap();
    c.execute("rollback transaction").unwrap();
    peer.lose(1);
    assert_eq!(ran(&mut c).conn, 2);

    // A COMMIT the server refuses has ended the transaction too.
    c.execute("BEGIN").unwrap();
    c.execute(&insert(3)).unwrap();
    peer.refuse("COMMIT", "transaction conflict: row 3 changed");
    assert!(c.execute("COMMIT").unwrap_err().is_transaction_conflict());
    peer.allow("COMMIT");
    peer.lose(2);
    let after = ran(&mut c);
    assert_eq!((after.conn, after.rows), (3, 1));

    // A BEGIN the server refuses opened nothing.
    peer.refuse("BEGIN", "transactions are not enabled");
    assert!(c.execute("BEGIN").is_err());
    peer.lose(3);
    assert_eq!(ran(&mut c).conn, 4);
}

/// The helper's transaction is noted once, by the helper and by its
/// `BEGIN` alike: when it returns — committed, rolled back or lost —
/// nothing is left open, and a lost connection is replaced again.
#[test]
fn the_helper_leaves_no_transaction_noted() {
    let peer = Peer::new();
    let mut c = peer.connect();
    c.transaction(1, |c| c.execute(&insert(1)).map(|_| ())).unwrap();
    peer.lose(0);
    assert_eq!(ran(&mut c).conn, 1);

    // An error from the body: rolled back.
    let err = c
        .transaction(1, |c| {
            c.execute(&insert(2))?;
            Err::<(), _>(DriverError::Server("the body gave up".into()))
        })
        .unwrap_err();
    assert_eq!(server_error(&err), "the body gave up");
    peer.lose(1);
    assert_eq!(ran(&mut c).conn, 2);

    // Lost under a statement of the body: its error is the one returned,
    // and nothing is sent after it — on this connection or a new one.
    peer.world().lose_under = Some(insert(3));
    let err = c.transaction(3, |c| c.execute(&insert(3)).map(|_| ())).unwrap_err();
    assert!(lost(&err).contains("inside a transaction"), "{err}");
    assert_eq!(peer.sessions(), 3);
    assert_eq!(peer.statements(2), [SELECT.to_string(), "BEGIN".to_string(), insert(3)]);
    let after = ran(&mut c);
    assert_eq!((after.conn, after.rows), (3, 1));

    // Lost under the helper's COMMIT: unknown, and said so.
    peer.world().lose_under = Some("COMMIT".into());
    let err = c.transaction(3, |c| c.execute(&insert(4)).map(|_| ())).unwrap_err();
    assert!(lost(&err).contains("outcome is unknown"), "{err}");
    assert_eq!(peer.arrived("COMMIT"), 2);
    assert_eq!(ran(&mut c).conn, 4);

    // A conflict is still run again, each run in a transaction of its own.
    peer.refuse("COMMIT", "transaction conflict: row 5 changed");
    let mut runs = 0;
    let err = c
        .transaction(2, |c| {
            runs += 1;
            c.execute(&insert(5)).map(|_| ())
        })
        .unwrap_err();
    assert!(err.is_transaction_conflict());
    assert_eq!(runs, 2);
    peer.allow("COMMIT");
    peer.lose(4);
    assert_eq!(ran(&mut c).conn, 5);
}

/// A statement sent as a stream is read like one sent through `execute`:
/// its `USE` is the session's, its `BEGIN` opens a transaction, and the
/// `ROLLBACK` of one lost with its connection is answered here.
#[test]
fn statements_sent_as_streams_change_the_session_too() {
    let peer = Peer::new();
    let mut c = peer.connect();
    drop(c.query_stream("USE app").unwrap());
    peer.world().databases.remove("app");
    peer.lose(0);
    // The USE that leaves the database dials without entering it, and the
    // connection it dialed is the session's from then on.
    drop(c.query_stream("USE other").unwrap());
    assert_eq!(peer.statements(1), ["USE other"]);
    assert_eq!(ran(&mut c).session(), (1, "other", None, None));

    drop(c.query_stream("BEGIN").unwrap());
    peer.lose(1);
    assert!(lost(&c.query_stream(&insert(1)).map(|_| ()).unwrap_err()).contains("inside a transaction"));
    assert_eq!(c.query_stream("ROLLBACK").unwrap().count(), 0);
    assert_eq!(peer.sessions(), 2);
    assert_eq!(ran(&mut c).session(), (2, "other", None, None));
}
