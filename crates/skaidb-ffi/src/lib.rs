//! `libskaidb` — the C ABI over the reference Rust driver.
//!
//! Every function here is a thin, documented translation of a
//! [`skaidb::Client`] / [`skaidb::Pool`] call: the wire
//! protocol, SCRAM/Kerberos, TLS, failover, prepared statements, pipelining
//! and streaming all live in `skaidb-driver`; this crate owns nothing but
//! the boxing, the string conversions and the error channel. The header
//! (`include/skaidb.h`) is hand-written and is the contract; the C++ RAII
//! wrapper (`include/skaidb.hpp`) sits on top of it with no protocol code
//! of its own, so neither can drift from the driver.
//!
//! Ownership rules (also in the header): every object is created and freed
//! by this library; borrowed pointers handed out from a result, stream or
//! value are valid until that object is freed (a stream's row until the next
//! `skaidb_stream_next`). Parameter values passed in stay the caller's. A
//! client is one connection and must be used from one thread at a time; a
//! pool is thread-safe; an open stream borrows its client exclusively.
//!
//! Errors: fallible calls return a status code and set a THREAD-LOCAL
//! message readable through `skaidb_last_error` until the next call on the
//! same thread — the C idiom that needs no allocation on the error path
//! and no error object to free.
//!
//! This crate is the workspace's second `unsafe_code` exception (its own
//! `[lints.rust]` table allows it): an FFI boundary consists of nothing
//! but raw pointers, and every dereference below is guarded by the
//! null/UTF-8 checks the header promises.

#![allow(clippy::missing_safety_doc)]
#![allow(non_camel_case_types)]

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::ptr;

use skaidb::{Client, DriverError, Pool, Prepared, RowStream, TlsConfig, TlsVerify};
use skaidb_proto::{Consistency, Response};
use skaidb_types::{Decimal, Document, Uuid, Value};

/// Status codes — the header's `skaidb_status_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum skaidb_status {
    SKAIDB_OK = 0,
    SKAIDB_END = 1,
    SKAIDB_ERR_INVALID = 2,
    SKAIDB_ERR_IO = 3,
    SKAIDB_ERR_PROTO = 4,
    SKAIDB_ERR_SERVER = 5,
    SKAIDB_ERR_AUTH = 6,
    SKAIDB_ERR_NO_ENDPOINT = 7,
    SKAIDB_ERR_UNSUPPORTED = 8,
}
use skaidb_status::*;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum skaidb_consistency {
    SKAIDB_ONE = 0,
    SKAIDB_QUORUM = 1,
    SKAIDB_ALL = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum skaidb_tls_verify {
    SKAIDB_TLS_CA_FILE = 0,
    SKAIDB_TLS_SYSTEM = 1,
    SKAIDB_TLS_INSECURE = 2,
}

/// The header's `skaidb_tls_t`.
#[repr(C)]
#[derive(Debug)]
pub struct skaidb_tls {
    pub verify: skaidb_tls_verify,
    pub ca_file: *const c_char,
    pub server_name: *const c_char,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum skaidb_result_kind {
    SKAIDB_RESULT_ROWS = 0,
    SKAIDB_RESULT_MUTATION = 1,
    SKAIDB_RESULT_DDL = 2,
    SKAIDB_RESULT_ERROR = 3,
    SKAIDB_RESULT_SETS = 4,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum skaidb_value_type {
    SKAIDB_NULL = 0,
    SKAIDB_BOOL = 1,
    SKAIDB_INT = 2,
    SKAIDB_FLOAT = 3,
    SKAIDB_DECIMAL = 4,
    SKAIDB_STRING = 5,
    SKAIDB_BYTES = 6,
    SKAIDB_UUID = 7,
    SKAIDB_TIMESTAMP = 8,
    SKAIDB_ARRAY = 9,
    SKAIDB_DOCUMENT = 10,
}

/// Opaque handle: one connection.
#[derive(Debug)]
pub struct skaidb_client(Client);

/// Opaque handle: a prepared statement (bound to the client that made it).
#[derive(Debug)]
pub struct skaidb_prepared(Prepared);

/// Opaque handle: a value. `repr(transparent)` over [`Value`], so a slice of
/// `Value` IS a C array of `skaidb_value_t` — rows are handed out in place.
#[repr(transparent)]
#[derive(Debug)]
pub struct skaidb_value(Value);

/// A result set as the C side reads it: column names as C strings, cells
/// in place.
#[derive(Debug)]
pub struct RowSet {
    columns: Vec<CString>,
    rows: Vec<Vec<Value>>,
}

/// Opaque handle: the outcome of one statement.
#[derive(Debug)]
pub enum skaidb_result {
    Rows(RowSet),
    Mutation(u64),
    Ddl,
    Error(CString),
    Sets(Vec<skaidb_result>),
}

/// Opaque handle: a pipeline's results, one per statement.
#[derive(Debug)]
pub struct skaidb_results(Vec<skaidb_result>);

/// Opaque handle: a streamed result set. Holds the driver stream with its
/// client borrow erased — the header makes the caller promise not to touch
/// the client while the stream is open, which is exactly the borrow the
/// Rust API enforces at compile time.
pub struct skaidb_stream {
    stream: RowStream<'static>,
    columns: Vec<CString>,
    current: Vec<Value>,
    /// `current` as the array of cell pointers `skaidb_stream_next` hands
    /// out (`skaidb_value_t` is opaque to C, so a row is pointers).
    current_ptrs: Vec<*const skaidb_value>,
}

impl std::fmt::Debug for skaidb_stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("skaidb_stream")
            .field("columns", &self.columns)
            .finish_non_exhaustive()
    }
}

/// Opaque handle: a connection pool.
#[derive(Debug)]
pub struct skaidb_pool(Pool);

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_error(msg: impl Into<Vec<u8>>) {
    let c = CString::new(msg)
        .unwrap_or_else(|_| CString::new("error message held a NUL byte").expect("static"));
    LAST_ERROR.with(|e| *e.borrow_mut() = c);
}

fn fail(status: skaidb_status, msg: impl Into<Vec<u8>>) -> skaidb_status {
    set_error(msg);
    status
}

fn fail_driver(e: DriverError) -> skaidb_status {
    let status = match &e {
        DriverError::Io(_) => SKAIDB_ERR_IO,
        DriverError::Proto(_) => SKAIDB_ERR_PROTO,
        DriverError::Server(_) => SKAIDB_ERR_SERVER,
        DriverError::Auth(m) if m.contains("without Kerberos") => SKAIDB_ERR_UNSUPPORTED,
        DriverError::Auth(_) => SKAIDB_ERR_AUTH,
        DriverError::NoEndpoint(_) => SKAIDB_ERR_NO_ENDPOINT,
    };
    fail(status, e.to_string())
}

/// A `const char *` as `&str`, or the INVALID status.
unsafe fn cstr<'a>(p: *const c_char, what: &str) -> Result<&'a str, skaidb_status> {
    if p.is_null() {
        return Err(fail(SKAIDB_ERR_INVALID, format!("{what} is NULL")));
    }
    CStr::from_ptr(p)
        .to_str()
        .map_err(|_| fail(SKAIDB_ERR_INVALID, format!("{what} is not valid UTF-8")))
}

unsafe fn cstr_opt<'a>(p: *const c_char, what: &str) -> Result<Option<&'a str>, skaidb_status> {
    if p.is_null() {
        Ok(None)
    } else {
        cstr(p, what).map(Some)
    }
}

unsafe fn cstr_list(
    items: *const *const c_char,
    n: usize,
    what: &str,
) -> Result<Vec<String>, skaidb_status> {
    if n == 0 {
        return Ok(Vec::new());
    }
    if items.is_null() {
        return Err(fail(SKAIDB_ERR_INVALID, format!("{what} is NULL")));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(cstr(*items.add(i), what)?.to_string());
    }
    Ok(out)
}

unsafe fn tls_config(tls: *const skaidb_tls) -> Result<Option<TlsConfig>, skaidb_status> {
    if tls.is_null() {
        return Ok(None);
    }
    let t = &*tls;
    let server_name = cstr(t.server_name, "tls.server_name")?;
    let verify = match t.verify {
        skaidb_tls_verify::SKAIDB_TLS_CA_FILE => {
            TlsVerify::CaFile(cstr(t.ca_file, "tls.ca_file")?.to_string())
        }
        skaidb_tls_verify::SKAIDB_TLS_SYSTEM => TlsVerify::System,
        skaidb_tls_verify::SKAIDB_TLS_INSECURE => TlsVerify::Insecure,
    };
    TlsConfig::new(verify, server_name)
        .map(Some)
        .map_err(fail_driver)
}

unsafe fn params_slice(
    params: *const *const skaidb_value,
    n: usize,
) -> Result<Vec<Value>, skaidb_status> {
    if n == 0 {
        return Ok(Vec::new());
    }
    if params.is_null() {
        return Err(fail(SKAIDB_ERR_INVALID, "params is NULL"));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let p = *params.add(i);
        if p.is_null() {
            return Err(fail(SKAIDB_ERR_INVALID, format!("params[{i}] is NULL")));
        }
        out.push((*p).0.clone());
    }
    Ok(out)
}

fn consistency_of(c: skaidb_consistency) -> Consistency {
    match c {
        skaidb_consistency::SKAIDB_ONE => Consistency::One,
        skaidb_consistency::SKAIDB_QUORUM => Consistency::Quorum,
        skaidb_consistency::SKAIDB_ALL => Consistency::All,
    }
}

fn c_string_lossy(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|_| CString::new(s.replace('\0', "\u{FFFD}")).expect("no NUL"))
}

fn result_of(resp: Response) -> skaidb_result {
    match resp {
        Response::Rows { columns, rows } => skaidb_result::Rows(RowSet {
            columns: columns.iter().map(|c| c_string_lossy(c)).collect(),
            rows,
        }),
        Response::Mutation { affected } => skaidb_result::Mutation(affected),
        Response::Ddl => skaidb_result::Ddl,
        Response::Error(m) => skaidb_result::Error(c_string_lossy(&m)),
        Response::ResultSets { sets } => skaidb_result::Sets(
            sets.into_iter()
                .map(|(columns, rows)| {
                    skaidb_result::Rows(RowSet {
                        columns: columns.iter().map(|c| c_string_lossy(c)).collect(),
                        rows,
                    })
                })
                .collect(),
        ),
        // Protocol frames the driver consumes itself; never surfaced by
        // `execute`, but the enum is exhaustive.
        other => skaidb_result::Error(c_string_lossy(&format!("unexpected response {other:?}"))),
    }
}

fn dup(s: &str) -> *mut c_char {
    c_string_lossy(s).into_raw()
}

/// Run `f` and box its result into `out`; `out` is left untouched on error.
unsafe fn boxed<T>(
    out: *mut *mut T,
    f: impl FnOnce() -> Result<T, skaidb_status>,
) -> skaidb_status {
    if out.is_null() {
        return fail(SKAIDB_ERR_INVALID, "out is NULL");
    }
    match f() {
        Ok(v) => {
            *out = Box::into_raw(Box::new(v));
            SKAIDB_OK
        }
        Err(s) => s,
    }
}

unsafe fn client_mut<'a>(c: *mut skaidb_client) -> Result<&'a mut Client, skaidb_status> {
    if c.is_null() {
        return Err(fail(SKAIDB_ERR_INVALID, "client is NULL"));
    }
    Ok(&mut (*c).0)
}

// ---- library -------------------------------------------------------------

#[no_mangle]
pub extern "C" fn skaidb_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn skaidb_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

// ---- connecting ----------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn skaidb_connect(
    endpoints: *const *const c_char,
    n_endpoints: usize,
    username: *const c_char,
    password: *const c_char,
    tls: *const skaidb_tls,
    out: *mut *mut skaidb_client,
) -> skaidb_status {
    boxed(out, || {
        let eps = cstr_list(endpoints, n_endpoints, "endpoints")?;
        if eps.is_empty() {
            return Err(fail(SKAIDB_ERR_INVALID, "no endpoints"));
        }
        let user = cstr(username, "username")?;
        let pass = cstr(password, "password")?;
        let tls = tls_config(tls)?;
        Client::connect_many_tls(&eps, user, pass, tls)
            .map(skaidb_client)
            .map_err(fail_driver)
    })
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_connect_anonymous(
    endpoint: *const c_char,
    out: *mut *mut skaidb_client,
) -> skaidb_status {
    boxed(out, || {
        let ep = cstr(endpoint, "endpoint")?;
        Client::connect(ep).map(skaidb_client).map_err(fail_driver)
    })
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_connect_gssapi(
    endpoints: *const *const c_char,
    n_endpoints: usize,
    principal: *const c_char,
    target_spn: *const c_char,
    tls: *const skaidb_tls,
    out: *mut *mut skaidb_client,
) -> skaidb_status {
    boxed(out, || {
        let eps = cstr_list(endpoints, n_endpoints, "endpoints")?;
        if eps.is_empty() {
            return Err(fail(SKAIDB_ERR_INVALID, "no endpoints"));
        }
        let principal = cstr(principal, "principal")?;
        let spn = cstr(target_spn, "target_spn")?;
        let tls = tls_config(tls)?;
        Client::connect_gssapi_tls(&eps, principal, spn, tls)
            .map(skaidb_client)
            .map_err(fail_driver)
    })
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_client_free(client: *mut skaidb_client) {
    if !client.is_null() {
        drop(Box::from_raw(client));
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_client_use_database(
    client: *mut skaidb_client,
    database: *const c_char,
) -> skaidb_status {
    let db = match cstr(database, "database") {
        Ok(d) => d.to_string(),
        Err(s) => return s,
    };
    match client_mut(client) {
        Ok(c) => match c.use_database(&db) {
            Ok(()) => SKAIDB_OK,
            Err(e) => fail_driver(e),
        },
        Err(s) => s,
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_client_set_consistency(
    client: *mut skaidb_client,
    consistency: skaidb_consistency,
) {
    if let Ok(c) = client_mut(client) {
        c.set_consistency(consistency_of(consistency));
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_client_set_scan_budget_rows(
    client: *mut skaidb_client,
    rows: u64,
) -> skaidb_status {
    match client_mut(client) {
        Ok(c) => match c.set_scan_budget_rows(rows) {
            Ok(()) => SKAIDB_OK,
            Err(e) => fail_driver(e),
        },
        Err(s) => s,
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_client_endpoint_dup(client: *const skaidb_client) -> *mut c_char {
    if client.is_null() {
        return ptr::null_mut();
    }
    dup((*client).0.endpoint())
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_client_add_endpoints(
    client: *mut skaidb_client,
    endpoints: *const *const c_char,
    n_endpoints: usize,
) -> skaidb_status {
    let eps = match cstr_list(endpoints, n_endpoints, "endpoints") {
        Ok(e) => e,
        Err(s) => return s,
    };
    match client_mut(client) {
        Ok(c) => {
            c.add_endpoints(&eps);
            SKAIDB_OK
        }
        Err(s) => s,
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_client_reconnect(client: *mut skaidb_client) -> skaidb_status {
    match client_mut(client) {
        Ok(c) => match c.reconnect() {
            Ok(()) => SKAIDB_OK,
            Err(e) => fail_driver(e),
        },
        Err(s) => s,
    }
}

// ---- statements ----------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn skaidb_execute(
    client: *mut skaidb_client,
    sql: *const c_char,
    out: *mut *mut skaidb_result,
) -> skaidb_status {
    boxed(out, || {
        let c = client_mut(client)?;
        let sql = cstr(sql, "sql")?;
        c.execute(sql).map(result_of).map_err(fail_driver)
    })
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_execute_with(
    client: *mut skaidb_client,
    sql: *const c_char,
    consistency: skaidb_consistency,
    out: *mut *mut skaidb_result,
) -> skaidb_status {
    boxed(out, || {
        let c = client_mut(client)?;
        let sql = cstr(sql, "sql")?;
        c.execute_with(sql, consistency_of(consistency))
            .map(result_of)
            .map_err(fail_driver)
    })
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_prepare(
    client: *mut skaidb_client,
    sql: *const c_char,
    out: *mut *mut skaidb_prepared,
) -> skaidb_status {
    boxed(out, || {
        let c = client_mut(client)?;
        let sql = cstr(sql, "sql")?;
        c.prepare(sql).map(skaidb_prepared).map_err(fail_driver)
    })
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_prepared_params(stmt: *const skaidb_prepared) -> usize {
    if stmt.is_null() {
        0
    } else {
        usize::from((*stmt).0.params)
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_prepared_free(stmt: *mut skaidb_prepared) {
    if !stmt.is_null() {
        drop(Box::from_raw(stmt));
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_execute_prepared(
    client: *mut skaidb_client,
    stmt: *mut skaidb_prepared,
    params: *const *const skaidb_value,
    n_params: usize,
    out: *mut *mut skaidb_result,
) -> skaidb_status {
    boxed(out, || {
        let c = client_mut(client)?;
        if stmt.is_null() {
            return Err(fail(SKAIDB_ERR_INVALID, "stmt is NULL"));
        }
        let params = params_slice(params, n_params)?;
        c.execute_prepared(&mut (*stmt).0, &params)
            .map(result_of)
            .map_err(fail_driver)
    })
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_execute_prepared_with(
    client: *mut skaidb_client,
    stmt: *mut skaidb_prepared,
    params: *const *const skaidb_value,
    n_params: usize,
    consistency: skaidb_consistency,
    out: *mut *mut skaidb_result,
) -> skaidb_status {
    boxed(out, || {
        let c = client_mut(client)?;
        if stmt.is_null() {
            return Err(fail(SKAIDB_ERR_INVALID, "stmt is NULL"));
        }
        let params = params_slice(params, n_params)?;
        c.execute_prepared_with(&mut (*stmt).0, &params, consistency_of(consistency))
            .map(result_of)
            .map_err(fail_driver)
    })
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_execute_batch(
    client: *mut skaidb_client,
    stmt: *mut skaidb_prepared,
    rows: *const *const *const skaidb_value,
    n_rows: usize,
    n_params: usize,
    affected: *mut u64,
) -> skaidb_status {
    let c = match client_mut(client) {
        Ok(c) => c,
        Err(s) => return s,
    };
    if stmt.is_null() {
        return fail(SKAIDB_ERR_INVALID, "stmt is NULL");
    }
    if affected.is_null() {
        return fail(SKAIDB_ERR_INVALID, "affected is NULL");
    }
    let mut batch = Vec::with_capacity(n_rows);
    if n_rows > 0 {
        if rows.is_null() {
            return fail(SKAIDB_ERR_INVALID, "rows is NULL");
        }
        for r in 0..n_rows {
            match params_slice(*rows.add(r), n_params) {
                Ok(row) => batch.push(row),
                Err(s) => return s,
            }
        }
    }
    match c.execute_batch(&mut (*stmt).0, batch) {
        Ok(n) => {
            *affected = n;
            SKAIDB_OK
        }
        Err(e) => fail_driver(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_pipeline(
    client: *mut skaidb_client,
    statements: *const *const c_char,
    n_statements: usize,
    out: *mut *mut skaidb_results,
) -> skaidb_status {
    boxed(out, || {
        let c = client_mut(client)?;
        let stmts = cstr_list(statements, n_statements, "statements")?;
        let refs: Vec<&str> = stmts.iter().map(String::as_str).collect();
        c.pipeline(&refs)
            .map(|rs| skaidb_results(rs.into_iter().map(result_of).collect()))
            .map_err(fail_driver)
    })
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_results_len(results: *const skaidb_results) -> usize {
    if results.is_null() {
        0
    } else {
        (*results).0.len()
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_results_get(
    results: *const skaidb_results,
    index: usize,
) -> *const skaidb_result {
    if results.is_null() {
        return ptr::null();
    }
    let results = &*results;
    results
        .0
        .get(index)
        .map_or(ptr::null(), |r| r as *const skaidb_result)
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_results_free(results: *mut skaidb_results) {
    if !results.is_null() {
        drop(Box::from_raw(results));
    }
}

// ---- results -------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn skaidb_result_kind(result: *const skaidb_result) -> skaidb_result_kind {
    if result.is_null() {
        return skaidb_result_kind::SKAIDB_RESULT_ERROR;
    }
    match &*result {
        skaidb_result::Rows(_) => skaidb_result_kind::SKAIDB_RESULT_ROWS,
        skaidb_result::Mutation(_) => skaidb_result_kind::SKAIDB_RESULT_MUTATION,
        skaidb_result::Ddl => skaidb_result_kind::SKAIDB_RESULT_DDL,
        skaidb_result::Error(_) => skaidb_result_kind::SKAIDB_RESULT_ERROR,
        skaidb_result::Sets(_) => skaidb_result_kind::SKAIDB_RESULT_SETS,
    }
}

unsafe fn rowset<'a>(result: *const skaidb_result) -> Option<&'a RowSet> {
    if result.is_null() {
        return None;
    }
    match &*result {
        skaidb_result::Rows(rs) => Some(rs),
        _ => None,
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_result_column_count(result: *const skaidb_result) -> usize {
    rowset(result).map_or(0, |rs| rs.columns.len())
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_result_column_name(
    result: *const skaidb_result,
    column: usize,
) -> *const c_char {
    rowset(result)
        .and_then(|rs| rs.columns.get(column))
        .map_or(ptr::null(), |c| c.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_result_row_count(result: *const skaidb_result) -> usize {
    rowset(result).map_or(0, |rs| rs.rows.len())
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_result_cell(
    result: *const skaidb_result,
    row: usize,
    column: usize,
) -> *const skaidb_value {
    rowset(result)
        .and_then(|rs| rs.rows.get(row))
        .and_then(|r| r.get(column))
        .map_or(ptr::null(), |v| v as *const Value as *const skaidb_value)
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_result_affected(result: *const skaidb_result) -> u64 {
    if result.is_null() {
        return 0;
    }
    match &*result {
        skaidb_result::Mutation(n) => *n,
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_result_error(result: *const skaidb_result) -> *const c_char {
    if result.is_null() {
        return ptr::null();
    }
    match &*result {
        skaidb_result::Error(m) => m.as_ptr(),
        _ => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_result_set_count(result: *const skaidb_result) -> usize {
    if result.is_null() {
        return 0;
    }
    match &*result {
        skaidb_result::Sets(s) => s.len(),
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_result_set(
    result: *const skaidb_result,
    index: usize,
) -> *const skaidb_result {
    if result.is_null() {
        return ptr::null();
    }
    match &*result {
        skaidb_result::Sets(s) => s
            .get(index)
            .map_or(ptr::null(), |r| r as *const skaidb_result),
        _ => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_result_free(result: *mut skaidb_result) {
    if !result.is_null() {
        drop(Box::from_raw(result));
    }
}

// ---- streamed result sets ------------------------------------------------

unsafe fn open_stream(
    client: *mut skaidb_client,
    sql: *const c_char,
    consistency: Option<skaidb_consistency>,
) -> Result<skaidb_stream, skaidb_status> {
    let c = client_mut(client)?;
    let sql = cstr(sql, "sql")?;
    let stream = match consistency {
        Some(cons) => c.query_stream_with(sql, consistency_of(cons)),
        None => c.query_stream(sql),
    }
    .map_err(fail_driver)?;
    // Erase the client borrow: the header's contract (no client use while a
    // stream is open) is the same exclusivity the lifetime enforced.
    let stream: RowStream<'static> =
        std::mem::transmute::<RowStream<'_>, RowStream<'static>>(stream);
    let columns = stream.columns.iter().map(|c| c_string_lossy(c)).collect();
    Ok(skaidb_stream {
        stream,
        columns,
        current: Vec::new(),
        current_ptrs: Vec::new(),
    })
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_query_stream(
    client: *mut skaidb_client,
    sql: *const c_char,
    out: *mut *mut skaidb_stream,
) -> skaidb_status {
    boxed(out, || open_stream(client, sql, None))
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_query_stream_with(
    client: *mut skaidb_client,
    sql: *const c_char,
    consistency: skaidb_consistency,
    out: *mut *mut skaidb_stream,
) -> skaidb_status {
    boxed(out, || open_stream(client, sql, Some(consistency)))
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_stream_column_count(stream: *const skaidb_stream) -> usize {
    if stream.is_null() {
        0
    } else {
        (*stream).columns.len()
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_stream_column_name(
    stream: *const skaidb_stream,
    column: usize,
) -> *const c_char {
    if stream.is_null() {
        return ptr::null();
    }
    let stream = &*stream;
    stream
        .columns
        .get(column)
        .map_or(ptr::null(), |c| c.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_stream_affected(stream: *const skaidb_stream) -> u64 {
    if stream.is_null() {
        0
    } else {
        (*stream).stream.affected
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_stream_next(
    stream: *mut skaidb_stream,
    row: *mut *const *const skaidb_value,
    n_columns: *mut usize,
) -> skaidb_status {
    if stream.is_null() || row.is_null() || n_columns.is_null() {
        return fail(SKAIDB_ERR_INVALID, "stream/row/n_columns is NULL");
    }
    let s = &mut *stream;
    match s.stream.next() {
        Some(Ok(r)) => {
            s.current = r;
            s.current_ptrs = s
                .current
                .iter()
                .map(|v| v as *const Value as *const skaidb_value)
                .collect();
            *row = s.current_ptrs.as_ptr();
            *n_columns = s.current.len();
            SKAIDB_OK
        }
        Some(Err(e)) => fail_driver(e),
        None => {
            *row = ptr::null();
            *n_columns = 0;
            SKAIDB_END
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_stream_free(stream: *mut skaidb_stream) {
    if !stream.is_null() {
        drop(Box::from_raw(stream)); // RowStream's Drop drains the remainder
    }
}

// ---- change streams ------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn skaidb_stream_poll(
    client: *mut skaidb_client,
    stream: *const c_char,
    after: *const c_char,
    limit: usize,
    events: *mut *mut skaidb_result,
    next_cursor: *mut *mut c_char,
) -> skaidb_status {
    if next_cursor.is_null() {
        return fail(SKAIDB_ERR_INVALID, "next_cursor is NULL");
    }
    let mut cursor: Option<String> = None;
    let status = boxed(events, || {
        let c = client_mut(client)?;
        let name = cstr(stream, "stream")?;
        let after = cstr_opt(after, "after")?.unwrap_or("");
        let (rows, next) = c.stream_poll(name, after, limit).map_err(fail_driver)?;
        cursor = Some(next);
        Ok(skaidb_result::Rows(RowSet {
            columns: ["id", "op", "k", "ts", "doc"]
                .iter()
                .map(|c| c_string_lossy(c))
                .collect(),
            rows,
        }))
    });
    if status == SKAIDB_OK {
        *next_cursor = dup(&cursor.unwrap_or_default());
    }
    status
}

// ---- values --------------------------------------------------------------

fn value_box(v: Value) -> *mut skaidb_value {
    Box::into_raw(Box::new(skaidb_value(v)))
}

#[no_mangle]
pub extern "C" fn skaidb_value_null() -> *mut skaidb_value {
    value_box(Value::Null)
}

#[no_mangle]
pub extern "C" fn skaidb_value_bool(v: bool) -> *mut skaidb_value {
    value_box(Value::Bool(v))
}

#[no_mangle]
pub extern "C" fn skaidb_value_int(v: i64) -> *mut skaidb_value {
    value_box(Value::Int(v))
}

#[no_mangle]
pub extern "C" fn skaidb_value_float(v: f64) -> *mut skaidb_value {
    value_box(Value::Float(v))
}

/// "123.45" / "-0.001" / "42" → an exact decimal (mantissa, scale).
fn parse_decimal(text: &str) -> Option<Decimal> {
    let t = text.trim();
    let (neg, digits) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let (int_part, frac_part) = digits.split_once('.').unwrap_or((digits, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return None;
    }
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let mut mantissa: i128 = 0;
    for c in int_part.chars().chain(frac_part.chars()) {
        mantissa = mantissa
            .checked_mul(10)?
            .checked_add(i128::from(c as u8 - b'0'))?;
    }
    if neg {
        mantissa = -mantissa;
    }
    Some(Decimal::new(mantissa, u32::try_from(frac_part.len()).ok()?))
}

fn decimal_text(d: &Decimal) -> String {
    let neg = d.mantissa < 0;
    let digits = d.mantissa.unsigned_abs().to_string();
    let scale = d.scale as usize;
    let body = if scale == 0 {
        digits
    } else if digits.len() > scale {
        format!(
            "{}.{}",
            &digits[..digits.len() - scale],
            &digits[digits.len() - scale..]
        )
    } else {
        format!("0.{}{}", "0".repeat(scale - digits.len()), digits)
    };
    if neg {
        format!("-{body}")
    } else {
        body
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_decimal(text: *const c_char) -> *mut skaidb_value {
    match cstr(text, "decimal") {
        Ok(t) => parse_decimal(t).map_or(ptr::null_mut(), |d| value_box(Value::Decimal(d))),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_string(utf8: *const c_char) -> *mut skaidb_value {
    match cstr(utf8, "string") {
        Ok(s) => value_box(Value::String(s.to_string())),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_string_len(
    utf8: *const c_char,
    len: usize,
) -> *mut skaidb_value {
    if utf8.is_null() {
        return ptr::null_mut();
    }
    let bytes = std::slice::from_raw_parts(utf8 as *const u8, len);
    match std::str::from_utf8(bytes) {
        Ok(s) => value_box(Value::String(s.to_string())),
        Err(_) => {
            set_error("string is not valid UTF-8");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_bytes(data: *const u8, len: usize) -> *mut skaidb_value {
    if data.is_null() && len > 0 {
        return ptr::null_mut();
    }
    let v = if len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(data, len).to_vec()
    };
    value_box(Value::Bytes(v))
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_uuid(bytes: *const u8) -> *mut skaidb_value {
    if bytes.is_null() {
        return ptr::null_mut();
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(std::slice::from_raw_parts(bytes, 16));
    value_box(Value::Uuid(Uuid(b)))
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_uuid_parse(text: *const c_char) -> *mut skaidb_value {
    match cstr(text, "uuid") {
        Ok(t) => match Uuid::parse_str(t) {
            Ok(u) => value_box(Value::Uuid(u)),
            Err(e) => {
                set_error(e.to_string());
                ptr::null_mut()
            }
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn skaidb_value_timestamp(unix_millis: i64) -> *mut skaidb_value {
    value_box(Value::Timestamp(unix_millis))
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_array(
    items: *const *const skaidb_value,
    n: usize,
) -> *mut skaidb_value {
    match params_slice(items, n) {
        Ok(vs) => value_box(Value::Array(vs)),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_document(
    keys: *const *const c_char,
    values: *const *const skaidb_value,
    n: usize,
) -> *mut skaidb_value {
    let ks = match cstr_list(keys, n, "keys") {
        Ok(k) => k,
        Err(_) => return ptr::null_mut(),
    };
    let vs = match params_slice(values, n) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };
    let mut doc = Document::new();
    for (k, v) in ks.into_iter().zip(vs) {
        doc.insert(k, v);
    }
    value_box(Value::Document(doc))
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_from_json(json: *const c_char) -> *mut skaidb_value {
    let text = match cstr(json, "json") {
        Ok(t) => t,
        Err(_) => return ptr::null_mut(),
    };
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(j) => value_box(Value::from_json(j)),
        Err(e) => {
            set_error(e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_clone(v: *const skaidb_value) -> *mut skaidb_value {
    if v.is_null() {
        return ptr::null_mut();
    }
    value_box((*v).0.clone())
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_free(v: *mut skaidb_value) {
    if !v.is_null() {
        drop(Box::from_raw(v));
    }
}

unsafe fn val<'a>(v: *const skaidb_value) -> Option<&'a Value> {
    if v.is_null() {
        None
    } else {
        Some(&(*v).0)
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_type(v: *const skaidb_value) -> skaidb_value_type {
    match val(v) {
        None | Some(Value::Null) => skaidb_value_type::SKAIDB_NULL,
        Some(Value::Bool(_)) => skaidb_value_type::SKAIDB_BOOL,
        Some(Value::Int(_)) => skaidb_value_type::SKAIDB_INT,
        Some(Value::Float(_)) => skaidb_value_type::SKAIDB_FLOAT,
        Some(Value::Decimal(_)) => skaidb_value_type::SKAIDB_DECIMAL,
        Some(Value::String(_)) => skaidb_value_type::SKAIDB_STRING,
        Some(Value::Bytes(_)) => skaidb_value_type::SKAIDB_BYTES,
        Some(Value::Uuid(_)) => skaidb_value_type::SKAIDB_UUID,
        Some(Value::Timestamp(_)) => skaidb_value_type::SKAIDB_TIMESTAMP,
        Some(Value::Array(_)) => skaidb_value_type::SKAIDB_ARRAY,
        Some(Value::Document(_)) => skaidb_value_type::SKAIDB_DOCUMENT,
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_is_null(v: *const skaidb_value) -> bool {
    matches!(val(v), None | Some(Value::Null))
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_get_bool(v: *const skaidb_value) -> bool {
    matches!(val(v), Some(Value::Bool(true)))
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_get_int(v: *const skaidb_value) -> i64 {
    match val(v) {
        Some(Value::Int(n)) | Some(Value::Timestamp(n)) => *n,
        Some(Value::Float(f)) => *f as i64,
        Some(Value::Decimal(d)) => d.to_f64() as i64,
        Some(Value::Bool(b)) => i64::from(*b),
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_get_float(v: *const skaidb_value) -> f64 {
    match val(v) {
        Some(Value::Float(f)) => *f,
        Some(Value::Int(n)) | Some(Value::Timestamp(n)) => *n as f64,
        Some(Value::Decimal(d)) => d.to_f64(),
        _ => 0.0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_get_timestamp(v: *const skaidb_value) -> i64 {
    match val(v) {
        Some(Value::Timestamp(n)) | Some(Value::Int(n)) => *n,
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_get_string(
    v: *const skaidb_value,
    len: *mut usize,
) -> *const c_char {
    match val(v) {
        Some(Value::String(s)) => {
            if !len.is_null() {
                *len = s.len();
            }
            s.as_ptr() as *const c_char
        }
        _ => {
            if !len.is_null() {
                *len = 0;
            }
            ptr::null()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_get_bytes(
    v: *const skaidb_value,
    len: *mut usize,
) -> *const u8 {
    match val(v) {
        Some(Value::Bytes(b)) => {
            if !len.is_null() {
                *len = b.len();
            }
            b.as_ptr()
        }
        _ => {
            if !len.is_null() {
                *len = 0;
            }
            ptr::null()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_get_uuid(v: *const skaidb_value) -> *const u8 {
    match val(v) {
        Some(Value::Uuid(u)) => u.0.as_ptr(),
        _ => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_array_len(v: *const skaidb_value) -> usize {
    match val(v) {
        Some(Value::Array(a)) => a.len(),
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_array_get(
    v: *const skaidb_value,
    index: usize,
) -> *const skaidb_value {
    match val(v) {
        Some(Value::Array(a)) => a
            .get(index)
            .map_or(ptr::null(), |x| x as *const Value as *const skaidb_value),
        _ => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_document_len(v: *const skaidb_value) -> usize {
    match val(v) {
        Some(Value::Document(d)) => d.0.len(),
        _ => 0,
    }
}

thread_local! {
    // Document keys are handed out NUL-terminated; the map stores them
    // without the terminator, so the last requested key is copied here.
    static KEY_SCRATCH: RefCell<CString> = RefCell::new(CString::default());
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_document_key(
    v: *const skaidb_value,
    index: usize,
) -> *const c_char {
    match val(v) {
        Some(Value::Document(d)) => match d.0.keys().nth(index) {
            Some(k) => KEY_SCRATCH.with(|s| {
                *s.borrow_mut() = c_string_lossy(k);
                s.borrow().as_ptr()
            }),
            None => ptr::null(),
        },
        _ => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_document_value(
    v: *const skaidb_value,
    index: usize,
) -> *const skaidb_value {
    match val(v) {
        Some(Value::Document(d)) => {
            d.0.values()
                .nth(index)
                .map_or(ptr::null(), |x| x as *const Value as *const skaidb_value)
        }
        _ => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_document_get(
    v: *const skaidb_value,
    path: *const c_char,
) -> *const skaidb_value {
    let p = match cstr(path, "path") {
        Ok(p) => p,
        Err(_) => return ptr::null(),
    };
    match val(v) {
        Some(Value::Document(d)) => d
            .get_path(p)
            .map_or(ptr::null(), |x| x as *const Value as *const skaidb_value),
        _ => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_to_string_dup(v: *const skaidb_value) -> *mut c_char {
    match val(v) {
        None => ptr::null_mut(),
        Some(Value::String(s)) => dup(s),
        Some(Value::Decimal(d)) => dup(&decimal_text(d)),
        Some(Value::Uuid(u)) => dup(&u.to_string()),
        Some(other) => dup(&other.to_json().to_string()),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_value_to_json_dup(v: *const skaidb_value) -> *mut c_char {
    match val(v) {
        None => ptr::null_mut(),
        Some(x) => dup(&x.to_json().to_string()),
    }
}

// ---- connection pool -----------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn skaidb_pool_new(
    maxsize: usize,
    endpoints: *const *const c_char,
    n_endpoints: usize,
    username: *const c_char,
    password: *const c_char,
    tls: *const skaidb_tls,
    database: *const c_char,
) -> *mut skaidb_pool {
    let build = || -> Result<Pool, skaidb_status> {
        if maxsize == 0 {
            return Err(fail(SKAIDB_ERR_INVALID, "maxsize is 0"));
        }
        let eps = cstr_list(endpoints, n_endpoints, "endpoints")?;
        if eps.is_empty() {
            return Err(fail(SKAIDB_ERR_INVALID, "no endpoints"));
        }
        let user = cstr(username, "username")?.to_string();
        let pass = cstr(password, "password")?.to_string();
        let tls = tls_config(tls)?;
        let db = cstr_opt(database, "database")?.map(str::to_string);
        Ok(Pool::new(maxsize, move || {
            let c = Client::connect_many_tls(&eps, &user, &pass, tls.clone())?;
            match &db {
                Some(d) => c.with_database(d),
                None => Ok(c),
            }
        }))
    };
    match build() {
        Ok(p) => Box::into_raw(Box::new(skaidb_pool(p))),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_pool_acquire(
    pool: *mut skaidb_pool,
    out: *mut *mut skaidb_client,
) -> skaidb_status {
    boxed(out, || {
        if pool.is_null() {
            return Err(fail(SKAIDB_ERR_INVALID, "pool is NULL"));
        }
        (*pool).0.acquire().map(skaidb_client).map_err(fail_driver)
    })
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_pool_release(pool: *mut skaidb_pool, client: *mut skaidb_client) {
    if client.is_null() {
        return;
    }
    let c = Box::from_raw(client);
    if pool.is_null() {
        return; // dropping the client closes the connection
    }
    (*pool).0.release(c.0);
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_pool_idle_len(pool: *const skaidb_pool) -> usize {
    if pool.is_null() {
        0
    } else {
        (*pool).0.idle_len()
    }
}

#[no_mangle]
pub unsafe extern "C" fn skaidb_pool_free(pool: *mut skaidb_pool) {
    if !pool.is_null() {
        let p = Box::from_raw(pool);
        p.0.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimals_round_trip_through_text() {
        for (text, mantissa, scale, back) in [
            ("123.45", 12345, 2, "123.45"),
            ("-0.001", -1, 3, "-0.001"),
            ("42", 42, 0, "42"),
            ("0.5", 5, 1, "0.5"),
            ("+7.10", 710, 2, "7.10"),
        ] {
            let d = parse_decimal(text).unwrap();
            assert_eq!((d.mantissa, d.scale), (mantissa, scale), "{text}");
            assert_eq!(decimal_text(&d), back, "{text}");
        }
        assert!(parse_decimal("abc").is_none());
        assert!(parse_decimal(".").is_none());
        assert!(parse_decimal("1.2.3").is_none());
    }

    #[test]
    fn a_value_slice_is_a_c_array_of_values() {
        // The stream/result cell contract relies on `skaidb_value` being
        // layout-identical to `Value`.
        assert_eq!(
            std::mem::size_of::<skaidb_value>(),
            std::mem::size_of::<Value>()
        );
        assert_eq!(
            std::mem::align_of::<skaidb_value>(),
            std::mem::align_of::<Value>()
        );
    }

    #[test]
    fn errors_are_thread_local_and_readable() {
        let s = fail(SKAIDB_ERR_INVALID, "boom");
        assert_eq!(s, SKAIDB_ERR_INVALID);
        let msg = unsafe { CStr::from_ptr(skaidb_last_error()) }
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(msg, "boom");
        let other = std::thread::spawn(|| {
            unsafe { CStr::from_ptr(skaidb_last_error()) }
                .to_bytes()
                .len()
        })
        .join()
        .unwrap();
        assert_eq!(other, 0, "a fresh thread has no error");
    }

    #[test]
    fn values_construct_and_read_back_through_the_abi() {
        unsafe {
            let s = skaidb_value_string(c"hello".as_ptr());
            let mut len = 0usize;
            let p = skaidb_value_get_string(s, &mut len);
            assert_eq!(std::slice::from_raw_parts(p as *const u8, len), b"hello");
            let items = [
                s as *const skaidb_value,
                skaidb_value_int(7) as *const skaidb_value,
            ];
            let arr = skaidb_value_array(items.as_ptr(), 2);
            assert_eq!(skaidb_value_array_len(arr), 2);
            assert_eq!(skaidb_value_get_int(skaidb_value_array_get(arr, 1)), 7);
            let keys = [c"a".as_ptr(), c"b".as_ptr()];
            let doc = skaidb_value_document(keys.as_ptr(), items.as_ptr(), 2);
            assert_eq!(skaidb_value_document_len(doc), 2);
            let json = skaidb_value_to_json_dup(doc);
            assert_eq!(
                CStr::from_ptr(json).to_str().unwrap(),
                r#"{"a":"hello","b":7}"#
            );
            let parsed = skaidb_value_from_json(json);
            assert_eq!(
                skaidb_value_get_int(skaidb_value_document_get(parsed, c"b".as_ptr())),
                7
            );
            let dec = skaidb_value_decimal(c"12.50".as_ptr());
            assert_eq!(skaidb_value_type(dec), skaidb_value_type::SKAIDB_DECIMAL);
            let dt = skaidb_value_to_string_dup(dec);
            assert_eq!(CStr::from_ptr(dt).to_str().unwrap(), "12.50");
            for p in [json, dt] {
                skaidb_string_free(p);
            }
            for v in [s, items[1] as *mut skaidb_value, arr, doc, parsed, dec] {
                skaidb_value_free(v);
            }
        }
    }
}
