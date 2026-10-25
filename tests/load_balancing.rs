//! Pool load balancing (docs/PROTOCOL.md §6.1): policies, idle order, health
//! ejection and re-admission, member discovery (`SHOW ENDPOINTS`) and
//! read-your-writes affinity — through the public API, against fake members
//! that each serve many connections.

use std::collections::HashSet;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use skaidb_auth::scram::{salted_password, server_signature_salted};
use skaidb::{
    DriverError, IdleOrder, LoadBalancing, MemberState, Pool, PoolBuilder, Response, Value,
};
use skaidb_proto::{
    auth_message, decode_client_request, read_frame, write_frame, AuthChallenge, AuthFinish,
    AuthOutcome, AuthStart, ClientRequest,
};

const USER: &str = "lb";
const PASSWORD: &str = "lb-secret";
const SALT: &[u8] = b"skaidb-lb-test-salt";
const ITERATIONS: u32 = 4096;

fn salted() -> [u8; 32] {
    static SALTED: OnceLock<[u8; 32]> = OnceLock::new();
    *SALTED.get_or_init(|| salted_password(PASSWORD, SALT, ITERATIONS))
}

/// A `SHOW ENDPOINTS` answer: (endpoint, state, local) per member.
type Listing = Vec<(String, String, bool)>;
/// What a member answers `SHOW ENDPOINTS` with (`None`: an error).
type ListingFn = Mutex<Option<Box<dyn Fn() -> Listing + Send>>>;

#[derive(Default)]
struct Knobs {
    /// Delay before answering a `SELECT`, in ms.
    delay_ms: AtomicU64,
    /// Close each new connection before the handshake.
    refuse: AtomicBool,
    /// Deny each login (bad credentials, or a capacity refusal).
    deny: Mutex<Option<String>>,
    /// Answer `SHOW ENDPOINTS` with a parse error.
    old_server: AtomicBool,
    listing: ListingFn,
    statements: Mutex<Vec<String>>,
    /// Connections closed by `refuse` (counted after the close).
    refused: AtomicUsize,
    /// Serial of the next connection served.
    serial: AtomicU64,
    closed: AtomicBool,
}

/// A fake skaidb member: SCRAM on every connection, then `SELECT …`
/// answers one row (member name, connection serial) after `delay`, `SHOW
/// ENDPOINTS` answers `listing`, `SHOW DATABASES` (the pool's probe) answers
/// no rows, anything else is a one-row mutation.
struct Member {
    name: &'static str,
    port: u16,
    endpoint: String,
    knobs: Arc<Knobs>,
}

impl Member {
    fn new(name: &'static str) -> Member {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let knobs = Arc::new(Knobs::default());
        let k = knobs.clone();
        thread::spawn(move || {
            for conn in listener.incoming() {
                if k.closed.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(conn) = conn else { continue };
                if k.refuse.load(Ordering::SeqCst) {
                    drop(conn);
                    k.refused.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                let k = k.clone();
                thread::spawn(move || {
                    let _ = serve(name, &k, conn);
                });
            }
        });
        Member {
            name,
            port,
            endpoint: format!("127.0.0.1:{port}"),
            knobs,
        }
    }

    fn delay(&self, ms: u64) {
        self.knobs.delay_ms.store(ms, Ordering::SeqCst);
    }

    fn refuse(&self, on: bool) {
        self.knobs.refuse.store(on, Ordering::SeqCst);
    }

    fn refused(&self) -> usize {
        self.knobs.refused.load(Ordering::SeqCst)
    }

    fn asked(&self, sql: &str) -> usize {
        self.knobs.statements.lock().unwrap().iter().filter(|s| *s == sql).count()
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        self.knobs.closed.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees `closed` and lets the port go.
        let _ = TcpStream::connect(&self.endpoint);
    }
}

fn serve(name: &str, k: &Knobs, mut s: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let start = AuthStart::decode(&read_frame(&mut s)?)?;
    let server_nonce = format!("{}lb", start.client_nonce);
    let challenge = AuthChallenge {
        salt: SALT.to_vec(),
        iterations: ITERATIONS,
        server_nonce: server_nonce.clone(),
    };
    write_frame(&mut s, &challenge.encode())?;
    AuthFinish::decode(&read_frame(&mut s)?)?;
    if let Some(reason) = k.deny.lock().unwrap().clone() {
        write_frame(&mut s, &AuthOutcome::Denied { reason }.encode())?;
        return Ok(());
    }
    let am = auth_message(&start.username, &start.client_nonce, &server_nonce, SALT, ITERATIONS);
    let server_signature = server_signature_salted(&salted(), &am);
    write_frame(&mut s, &AuthOutcome::Ok { server_signature }.encode())?;
    let serial = k.serial.fetch_add(1, Ordering::SeqCst) as i64;
    loop {
        let req = read_frame(&mut s)?;
        let sql = match decode_client_request(&req)? {
            (None, ClientRequest::Query { sql, .. }) => sql,
            // Hello and anything else: an ack.
            _ => {
                write_frame(&mut s, &Response::Ddl.encode())?;
                continue;
            }
        };
        k.statements.lock().unwrap().push(sql.clone());
        let resp = if sql == "SHOW ENDPOINTS" {
            match &*k.listing.lock().unwrap() {
                Some(listing) if !k.old_server.load(Ordering::SeqCst) => Response::Rows {
                    columns: vec!["endpoint".into(), "state".into(), "local".into()],
                    rows: listing()
                        .into_iter()
                        .map(|(ep, state, local)| {
                            vec![Value::String(ep), Value::String(state), Value::Bool(local)]
                        })
                        .collect(),
                },
                _ => Response::Error("parse error: expected TABLES, found ENDPOINTS".into()),
            }
        } else if sql == "SHOW DATABASES" {
            Response::Rows {
                columns: vec!["name".into()],
                rows: Vec::new(),
            }
        } else if sql.starts_with("SELECT") {
            let ms = k.delay_ms.load(Ordering::SeqCst);
            if ms > 0 {
                thread::sleep(Duration::from_millis(ms));
            }
            Response::Rows {
                columns: vec!["member".into(), "conn".into()],
                rows: vec![vec![Value::String(name.into()), Value::Int(serial)]],
            }
        } else {
            Response::Mutation { affected: 1 }
        };
        write_frame(&mut s, &resp.encode())?;
    }
}

fn three() -> [Member; 3] {
    [Member::new("a"), Member::new("b"), Member::new("c")]
}

fn builder(members: &[&Member]) -> PoolBuilder {
    let eps: Vec<&str> = members.iter().map(|m| m.endpoint.as_str()).collect();
    Pool::builder(&eps).credentials(USER, PASSWORD)
}

/// The member and connection serial a `SELECT` reached.
fn select(client: &mut skaidb::Client) -> Result<(String, i64), DriverError> {
    match client.execute("SELECT member()")? {
        Response::Rows { rows, .. } => match (&rows[0][0], &rows[0][1]) {
            (Value::String(name), Value::Int(conn)) => Ok((name.clone(), *conn)),
            other => panic!("unexpected row {other:?}"),
        },
        other => panic!("unexpected response {other:?}"),
    }
}

fn who(pool: &Pool) -> String {
    pool.with(select).expect("checkout").0
}

fn who_for(pool: &Pool, affinity: &str) -> String {
    pool.with_affinity(affinity, select).expect("checkout").0
}

fn state(pool: &Pool, member: &Member) -> MemberState {
    pool.members()
        .into_iter()
        .find(|m| m.endpoint == member.endpoint)
        .unwrap_or_else(|| panic!("{} is not a member", member.endpoint))
        .state
}

fn wait_for(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn distinct(names: impl IntoIterator<Item = String>) -> usize {
    names.into_iter().collect::<HashSet<_>>().len()
}

// ---- policies ---------------------------------------------------------------

#[test]
fn round_robin_rotates_over_every_member() {
    let [a, b, c] = three();
    let pool = builder(&[&a, &b, &c]).load_balancing(LoadBalancing::RoundRobin).build().unwrap();
    let served: Vec<String> = (0..9).map(|_| who(&pool)).collect();
    let mut sorted = served.clone();
    sorted.sort();
    assert_eq!(sorted, ["a", "a", "a", "b", "b", "b", "c", "c", "c"]);
    // Strict rotation: three in a row are three different members.
    for triple in served.chunks(3) {
        assert_eq!(distinct(triple.to_vec()), 3, "{served:?}");
    }
}

#[test]
fn least_latency_prefers_the_faster_member() {
    let [a, b, _c] = three();
    b.delay(20);
    let pool = builder(&[&a, &b])
        .load_balancing(LoadBalancing::LeastLatency)
        .eject_latency_factor(0.0)
        .build()
        .unwrap();
    let served: Vec<String> = (0..60).map(|_| who(&pool)).collect();
    let on_a = served.iter().filter(|s| *s == "a").count();
    assert!(on_a > 48, "{served:?}");
    assert!(on_a < 60, "b was measured at least once: {served:?}");
}

#[test]
fn least_latency_re_measures_a_member_it_has_not_used_lately() {
    let [a, b, _c] = three();
    b.delay(20);
    let pool = builder(&[&a, &b])
        .load_balancing(LoadBalancing::LeastLatency)
        .eject_latency_factor(0.0)
        .build()
        .unwrap();
    for _ in 0..20 {
        who(&pool);
    }
    // b is slow, then recovers: once b's average goes stale (2 s) an idle
    // pool asks b again instead of never.
    b.delay(0);
    thread::sleep(Duration::from_millis(2100));
    let served: Vec<String> = (0..3).map(|_| who(&pool)).collect();
    assert!(served.iter().any(|s| s == "b"), "{served:?}");
}

#[test]
fn the_random_policy_reuses_one_connection() {
    let [a, b, c] = three();
    let pool = builder(&[&a, &b, &c]).build().unwrap();
    // One connection, reused: random never targets a member.
    assert_eq!(distinct((0..5).map(|_| who(&pool))), 1);
    assert_eq!(pool.idle_len(), 1);
}

#[test]
fn unknown_policies_are_refused() {
    assert!("nearest".parse::<LoadBalancing>().is_err());
    assert!("random".parse::<IdleOrder>().is_err());
    assert_eq!("least_latency".parse::<LoadBalancing>().unwrap(), LoadBalancing::LeastLatency);
    assert_eq!("fifo".parse::<IdleOrder>().unwrap(), IdleOrder::Fifo);
}

// ---- idle order ---------------------------------------------------------------

/// Check out three connections to one member, return them in order, and
/// report their serials.
fn three_returned(pool: &Pool) -> Vec<i64> {
    let mut held: Vec<_> = (0..3).map(|_| pool.acquire().unwrap()).collect();
    let serials: Vec<i64> = held.iter_mut().map(|c| select(c).unwrap().1).collect();
    let m = &pool.members()[0];
    assert_eq!((m.in_use, m.idle), (3, 0));
    for c in held {
        pool.release(c);
    }
    let m = &pool.members()[0];
    assert_eq!((m.in_use, m.idle), (0, 3));
    serials
}

#[test]
fn lifo_hands_out_the_most_recently_returned() {
    let a = Member::new("a");
    let pool = builder(&[&a]).build().unwrap();
    let serials = three_returned(&pool);
    let mut c = pool.acquire().unwrap();
    assert_eq!(select(&mut c).unwrap().1, serials[2]);
}

#[test]
fn fifo_hands_out_the_longest_idle() {
    let a = Member::new("a");
    let pool = builder(&[&a]).idle_order(IdleOrder::Fifo).build().unwrap();
    let serials = three_returned(&pool);
    let mut held: Vec<_> = (0..3).map(|_| pool.acquire().unwrap()).collect();
    let got: Vec<i64> = held.iter_mut().map(|c| select(c).unwrap().1).collect();
    assert_eq!(got, serials);
}

#[test]
fn a_connection_dropped_while_checked_out_stops_counting() {
    let a = Member::new("a");
    let pool = builder(&[&a]).build().unwrap();
    let c = pool.acquire().unwrap();
    assert_eq!(pool.members()[0].in_use, 1);
    drop(c);
    assert_eq!((pool.members()[0].in_use, pool.members()[0].idle), (0, 0));
}

// ---- health ejection ---------------------------------------------------------

#[test]
fn a_failing_member_is_ejected_then_readmitted_by_the_probe() {
    let [a, b, c] = three();
    b.refuse(true);
    let pool = builder(&[&a, &b, &c])
        .load_balancing(LoadBalancing::RoundRobin)
        .eject_errors(2)
        .eject_backoff(Duration::from_millis(300))
        .build()
        .unwrap();
    let served: Vec<String> = (0..12).map(|_| who(&pool)).collect();
    assert!(!served.iter().any(|s| s == "b"), "{served:?}");
    assert_eq!(state(&pool, &b), MemberState::Ejected);
    // Healthy again: the background probe re-admits it after the backoff.
    b.refuse(false);
    wait_for("the probe to re-admit b", Duration::from_secs(5), || {
        state(&pool, &b) == MemberState::Ready
    });
    let served: Vec<String> = (0..6).map(|_| who(&pool)).collect();
    assert!(served.iter().any(|s| s == "b"), "{served:?}");
}

#[test]
fn a_probe_that_fails_doubles_the_backoff() {
    let [a, b, c] = three();
    b.refuse(true);
    let pool = builder(&[&a, &b, &c])
        .load_balancing(LoadBalancing::RoundRobin)
        .eject_errors(1)
        .eject_backoff(Duration::from_millis(200))
        .build()
        .unwrap();
    for _ in 0..6 {
        who(&pool);
    }
    assert_eq!(state(&pool, &b), MemberState::Ejected);
    let before = b.refused();
    wait_for("the probe", Duration::from_secs(5), || b.refused() > before);
    // The probe failed (the connection was closed before `refused` counted
    // it): b stays out for twice the base backoff from then.
    let failed = Instant::now();
    b.refuse(false);
    assert_eq!(state(&pool, &b), MemberState::Ejected);
    wait_for("the second probe", Duration::from_secs(5), || state(&pool, &b) == MemberState::Ready);
    assert!(failed.elapsed() >= Duration::from_millis(380), "{:?}", failed.elapsed());
}

#[test]
fn a_consistently_slow_member_is_ejected() {
    let [a, b, c] = three();
    b.delay(50);
    let pool = builder(&[&a, &b, &c])
        .load_balancing(LoadBalancing::RoundRobin)
        .eject_latency_floor(Duration::from_millis(20))
        .eject_backoff(Duration::from_secs(30))
        .build()
        .unwrap();
    for _ in 0..45 {
        who(&pool);
    }
    assert_eq!(state(&pool, &b), MemberState::Ejected);
    let served: Vec<String> = (0..6).map(|_| who(&pool)).collect();
    assert!(!served.iter().any(|s| s == "b"), "{served:?}");
}

#[test]
fn one_slow_statement_does_not_eject_a_member() {
    let [a, b, c] = three();
    let pool = builder(&[&a, &b, &c])
        .load_balancing(LoadBalancing::RoundRobin)
        .eject_latency_floor(Duration::from_millis(50))
        .build()
        .unwrap();
    for _ in 0..36 {
        who(&pool);
    }
    b.delay(500);
    while who(&pool) != "b" {}
    b.delay(0);
    for _ in 0..6 {
        who(&pool);
    }
    assert_eq!(state(&pool, &b), MemberState::Ready);
}

#[test]
fn the_last_usable_member_is_never_ejected() {
    let [a, b, c] = three();
    b.refuse(true);
    c.refuse(true);
    let pool = builder(&[&a, &b, &c])
        .load_balancing(LoadBalancing::RoundRobin)
        .eject_errors(1)
        .build()
        .unwrap();
    for _ in 0..6 {
        assert_eq!(who(&pool), "a");
    }
    a.refuse(true);
    // Idle connections to a still work (how many depends on the dial order
    // above); once they are used up, every dial fails.
    let mut held = Vec::new();
    let failed = (0..12).any(|_| match pool.acquire() {
        Ok(c) => {
            held.push(c);
            false
        }
        Err(_) => true,
    });
    assert!(failed, "a dial to a refusing member succeeded");
    assert_eq!(state(&pool, &a), MemberState::Ready);
}

#[test]
fn a_refused_login_is_not_a_member_fault() {
    let [a, b, _c] = three();
    *a.knobs.deny.lock().unwrap() = Some("invalid credentials".into());
    let pool = builder(&[&a, &b])
        .load_balancing(LoadBalancing::RoundRobin)
        .eject_errors(1)
        .build()
        .unwrap();
    // Checkouts aimed at a fall through to b; a stays in rotation.
    for _ in 0..4 {
        assert_eq!(who(&pool), "b");
    }
    assert_eq!(state(&pool, &a), MemberState::Ready);
    // A capacity refusal is the member being full: that is a fault.
    *a.knobs.deny.lock().unwrap() = Some("too many connections: 500".into());
    for _ in 0..4 {
        assert_eq!(who(&pool), "b");
    }
    assert_eq!(state(&pool, &a), MemberState::Ejected);
}

#[test]
fn dropping_the_pool_stops_its_background_probes() {
    let [a, b, _c] = three();
    b.refuse(true);
    let pool = builder(&[&a, &b])
        .load_balancing(LoadBalancing::RoundRobin)
        .eject_errors(1)
        .eject_backoff(Duration::from_millis(50))
        .eject_backoff_max(Duration::from_millis(50))
        .build()
        .unwrap();
    for _ in 0..4 {
        who(&pool);
    }
    let before = b.refused();
    wait_for("a probe", Duration::from_secs(5), || b.refused() > before);
    drop(pool);
    // A probe already running when the pool went may still land.
    thread::sleep(Duration::from_millis(100));
    let after_drop = b.refused();
    thread::sleep(Duration::from_millis(800));
    assert_eq!(b.refused(), after_drop, "the pool kept probing after it was dropped");
}

// ---- discovery -----------------------------------------------------------------

/// The cluster's (endpoint, state) as every fake member reports it.
type States = Arc<Mutex<Vec<(String, String)>>>;

/// Members a, b, c where c is resyncing; each answers SHOW ENDPOINTS with
/// the shared states, flagging its own row local.
fn discovered() -> ([Member; 3], States) {
    let members = three();
    let states = Arc::new(Mutex::new(vec![
        (members[0].endpoint.clone(), "ready".to_string()),
        (members[1].endpoint.clone(), "ready".to_string()),
        (members[2].endpoint.clone(), "resyncing".to_string()),
    ]));
    for m in &members {
        let (states, me) = (states.clone(), m.endpoint.clone());
        *m.knobs.listing.lock().unwrap() = Some(Box::new(move || {
            states
                .lock()
                .unwrap()
                .iter()
                .map(|(ep, st)| (ep.clone(), st.clone(), *ep == me))
                .collect()
        }));
    }
    (members, states)
}

fn set_state(states: &Mutex<Vec<(String, String)>>, member: &Member, to: Option<&str>) {
    let mut s = states.lock().unwrap();
    match to {
        Some(st) => {
            for (ep, state) in s.iter_mut() {
                if *ep == member.endpoint {
                    *state = st.to_string();
                }
            }
        }
        None => s.retain(|(ep, _)| *ep != member.endpoint),
    }
}

#[test]
fn members_are_discovered_and_resyncing_ones_get_no_connections() {
    let ([a, b, c], states) = discovered();
    let pool = builder(&[&a])
        .load_balancing(LoadBalancing::RoundRobin)
        .discover(true)
        .refresh_interval(Duration::from_millis(200))
        .build()
        .unwrap();
    let served: HashSet<String> = (0..8).map(|_| who(&pool)).collect();
    assert_eq!(served, HashSet::from(["a".to_string(), "b".to_string()]));
    assert_eq!(state(&pool, &c), MemberState::Resyncing);
    assert!(!pool.members().into_iter().find(|m| m.endpoint == b.endpoint).unwrap().seed);
    // c catches up: the next refresh lets it in.
    set_state(&states, &c, Some("ready"));
    wait_for("a refresh", Duration::from_secs(5), || state(&pool, &c) == MemberState::Ready);
    let served: Vec<String> = (0..6).map(|_| who(&pool)).collect();
    assert!(served.iter().any(|s| s == "c"), "{served:?}");
}

#[test]
fn a_seed_given_by_another_name_is_not_counted_twice() {
    let ([a, _b, _c], _states) = discovered();
    let seed = format!("localhost:{}", a.port);
    let pool = Pool::builder(&[seed.as_str()])
        .credentials(USER, PASSWORD)
        .load_balancing(LoadBalancing::RoundRobin)
        .discover(true)
        .build()
        .unwrap();
    who(&pool);
    let members = pool.members();
    assert_eq!(members.len(), 3, "{members:?}");
    let seeds: Vec<_> = members.iter().filter(|m| m.seed).collect();
    assert_eq!(seeds.len(), 1, "{members:?}");
    assert_eq!(seeds[0].endpoint, seed);
    assert_eq!(seeds[0].canonical.as_deref(), Some(a.endpoint.as_str()));
}

#[test]
fn a_member_that_leaves_the_listing_is_dropped() {
    let ([a, b, _c], states) = discovered();
    let pool = builder(&[&a])
        .load_balancing(LoadBalancing::RoundRobin)
        .discover(true)
        .refresh_interval(Duration::from_millis(200))
        .build()
        .unwrap();
    who(&pool);
    assert!(pool.members().iter().any(|m| m.endpoint == b.endpoint));
    set_state(&states, &b, None);
    wait_for("b to be dropped", Duration::from_secs(5), || {
        !pool.members().iter().any(|m| m.endpoint == b.endpoint)
    });
    // The seed leaving the ring is kept, unlisted.
    set_state(&states, &a, None);
    wait_for("a to be unlisted", Duration::from_secs(5), || state(&pool, &a) == MemberState::Unlisted);
}

#[test]
fn an_old_server_turns_discovery_off_and_keeps_the_seeds() {
    let ([a, _b, _c], _states) = discovered();
    a.knobs.old_server.store(true, Ordering::SeqCst);
    let pool = builder(&[&a])
        .load_balancing(LoadBalancing::RoundRobin)
        .discover(true)
        .refresh_interval(Duration::from_millis(50))
        .build()
        .unwrap();
    assert_eq!(distinct((0..4).map(|_| who(&pool))), 1);
    thread::sleep(Duration::from_millis(400));
    assert_eq!(a.asked("SHOW ENDPOINTS"), 1);
    assert_eq!(pool.members().len(), 1);
}

#[test]
fn a_standalone_server_turns_discovery_off() {
    let a = Member::new("a");
    *a.knobs.listing.lock().unwrap() = Some(Box::new(Vec::new));
    let pool = builder(&[&a])
        .load_balancing(LoadBalancing::RoundRobin)
        .discover(true)
        .refresh_interval(Duration::from_millis(50))
        .build()
        .unwrap();
    assert_eq!(distinct((0..4).map(|_| who(&pool))), 1);
    thread::sleep(Duration::from_millis(400));
    assert_eq!(a.asked("SHOW ENDPOINTS"), 1);
    let members = pool.members();
    assert_eq!(members.len(), 1);
    assert_eq!((members[0].state, members[0].seed), (MemberState::Ready, true));
}

// ---- read-your-writes ------------------------------------------------------------

#[test]
fn reads_follow_the_member_that_took_the_write() {
    let [a, b, c] = three();
    let pool = builder(&[&a, &b, &c])
        .load_balancing(LoadBalancing::RoundRobin)
        .read_your_writes(Duration::from_secs(1))
        .build()
        .unwrap();
    let wrote = pool
        .with_affinity("alice", |c| {
            c.execute("INSERT INTO t VALUES (1)")?;
            Ok(c.endpoint().to_string())
        })
        .unwrap();
    let writer = [&a, &b, &c].into_iter().find(|m| m.endpoint == wrote).unwrap().name;
    for _ in 0..6 {
        assert_eq!(who_for(&pool, "alice"), writer);
    }
    // Another key, or no key, still rotates.
    assert_eq!(distinct((0..3).map(|_| who_for(&pool, "bob"))), 3);
    assert_eq!(distinct((0..3).map(|_| who(&pool))), 3);
    thread::sleep(Duration::from_millis(1100));
    assert_eq!(distinct((0..3).map(|_| who_for(&pool, "alice"))), 3);
}

#[test]
fn reads_do_not_set_affinity() {
    let [a, b, c] = three();
    let pool = builder(&[&a, &b, &c])
        .load_balancing(LoadBalancing::RoundRobin)
        .read_your_writes(Duration::from_secs(5))
        .build()
        .unwrap();
    who_for(&pool, "alice");
    assert_eq!(distinct((0..3).map(|_| who_for(&pool, "alice"))), 3);
}
