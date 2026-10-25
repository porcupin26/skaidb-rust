/* skaidb C driver — libskaidb
 *
 * A C ABI over the reference Rust driver (crates/skaidb-driver): the same
 * binary protocol, SCRAM-SHA-256 or Kerberos authentication, TLS, nearest-
 * node selection and failover, prepared statements with typed parameters,
 * pipelining, streamed result sets and a connection pool that balances
 * across the cluster's members.
 *
 * Conventions
 *   - Every fallible call returns a skaidb_status_t. On any status other
 *     than SKAIDB_OK / SKAIDB_END, skaidb_last_error() (thread-local) holds
 *     the message until the next call on the same thread.
 *   - Strings are UTF-8, NUL-terminated unless a length is passed/returned.
 *   - Objects are opaque; free each with its own skaidb_*_free(). A pointer
 *     obtained FROM a result/stream/value (column names, cells, string and
 *     byte views) borrows that object and is valid until the object is freed
 *     or (for streams) the next row is fetched. Functions ending in _dup
 *     return malloc'd copies the caller frees with skaidb_string_free().
 *   - A skaidb_client_t is one connection: use it from one thread at a time.
 *     A skaidb_pool_t is thread-safe. A skaidb_stream_t borrows its client
 *     exclusively until skaidb_stream_free() (which drains it) — using the
 *     client while a stream is open is undefined.
 *   - Parameter values passed in (skaidb_value_t) stay owned by the caller.
 */
#ifndef SKAIDB_H
#define SKAIDB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct skaidb_client skaidb_client_t;
typedef struct skaidb_prepared skaidb_prepared_t;
typedef struct skaidb_stream skaidb_stream_t;
typedef struct skaidb_pool skaidb_pool_t;
typedef struct skaidb_value skaidb_value_t;
typedef struct skaidb_result skaidb_result_t;
typedef struct skaidb_results skaidb_results_t;

typedef enum skaidb_status {
    SKAIDB_OK = 0,
    SKAIDB_END = 1,               /* skaidb_stream_next: no more rows */
    SKAIDB_ERR_INVALID = 2,       /* bad argument (NULL, invalid UTF-8, wrong type) */
    SKAIDB_ERR_IO = 3,            /* transport: connect, read, write, TLS handshake */
    SKAIDB_ERR_PROTO = 4,         /* malformed frame from the server */
    SKAIDB_ERR_SERVER = 5,        /* the server rejected the statement */
    SKAIDB_ERR_AUTH = 6,          /* authentication failed */
    SKAIDB_ERR_NO_ENDPOINT = 7,   /* no endpoint connected + authenticated */
    SKAIDB_ERR_UNSUPPORTED = 8    /* not available in this build (e.g. Kerberos) */
} skaidb_status_t;

typedef enum skaidb_consistency {
    SKAIDB_ONE = 0,
    SKAIDB_QUORUM = 1,
    SKAIDB_ALL = 2
} skaidb_consistency_t;

typedef enum skaidb_tls_verify {
    SKAIDB_TLS_CA_FILE = 0,   /* trust certificates chaining to ca_file (the cluster CA) */
    SKAIDB_TLS_SYSTEM = 1,    /* trust the public-CA roots compiled into the driver */
    SKAIDB_TLS_INSECURE = 2   /* encrypt but verify nothing — development only */
} skaidb_tls_verify_t;

typedef struct skaidb_tls {
    skaidb_tls_verify_t verify;
    const char *ca_file;      /* SKAIDB_TLS_CA_FILE only; else NULL */
    const char *server_name;  /* SNI + verification name; "skaidb" for cluster certificates */
} skaidb_tls_t;

typedef enum skaidb_result_kind {
    SKAIDB_RESULT_ROWS = 0,      /* a result set: columns + rows */
    SKAIDB_RESULT_MUTATION = 1,  /* INSERT/UPDATE/DELETE: skaidb_result_affected() */
    SKAIDB_RESULT_DDL = 2,       /* a DDL statement succeeded */
    SKAIDB_RESULT_ERROR = 3,     /* only inside a pipeline: skaidb_result_error() */
    SKAIDB_RESULT_SETS = 4       /* a CALL that EMITted several result sets */
} skaidb_result_kind_t;

typedef enum skaidb_value_type {
    SKAIDB_NULL = 0,
    SKAIDB_BOOL = 1,
    SKAIDB_INT = 2,        /* int64 */
    SKAIDB_FLOAT = 3,      /* float64 */
    SKAIDB_DECIMAL = 4,    /* exact; read as text or double */
    SKAIDB_STRING = 5,
    SKAIDB_BYTES = 6,
    SKAIDB_UUID = 7,       /* 16 raw bytes */
    SKAIDB_TIMESTAMP = 8,  /* milliseconds since the Unix epoch, UTC */
    SKAIDB_ARRAY = 9,
    SKAIDB_DOCUMENT = 10
} skaidb_value_type_t;

/* ---- library ---------------------------------------------------------- */

/* The driver's version, e.g. "0.293.2" (a static string). */
const char *skaidb_version(void);

/* The last error message on this thread (static until the next call). */
const char *skaidb_last_error(void);

/* Free a string returned by a *_dup function. NULL is fine. */
void skaidb_string_free(char *s);

/* ---- connecting ------------------------------------------------------- */

/* SCRAM-SHA-256 across a seed list ("host:port" strings). The driver dials
 * the nearest reachable endpoint and keeps the rest for failover. `tls` may
 * be NULL for plaintext. */
skaidb_status_t skaidb_connect(const char *const *endpoints, size_t n_endpoints,
                               const char *username, const char *password,
                               const skaidb_tls_t *tls, skaidb_client_t **out);

/* Anonymous connection to a server with authentication disabled. */
skaidb_status_t skaidb_connect_anonymous(const char *endpoint, skaidb_client_t **out);

/* Kerberos (SASL GSSAPI) with the ambient ticket cache. Returns
 * SKAIDB_ERR_UNSUPPORTED from a build without the `kerberos` feature. */
skaidb_status_t skaidb_connect_gssapi(const char *const *endpoints, size_t n_endpoints,
                                      const char *principal, const char *target_spn,
                                      const skaidb_tls_t *tls, skaidb_client_t **out);

void skaidb_client_free(skaidb_client_t *client);

/* Bind (or rebind) the session database: USE now and again after every
 * failover. A refusal leaves the previous binding and the connection intact. */
skaidb_status_t skaidb_client_use_database(skaidb_client_t *client, const char *database);

/* Default consistency for later calls (the driver starts at SKAIDB_QUORUM). */
void skaidb_client_set_consistency(skaidb_client_t *client, skaidb_consistency_t consistency);

/* SET SCAN BUDGET ROWS n (0 = server default), replayed after reconnects. */
skaidb_status_t skaidb_client_set_scan_budget_rows(skaidb_client_t *client, uint64_t rows);

/* The endpoint the live connection uses ("host:port"), malloc'd. */
char *skaidb_client_endpoint_dup(const skaidb_client_t *client);

/* Merge more failover targets. */
skaidb_status_t skaidb_client_add_endpoints(skaidb_client_t *client,
                                            const char *const *endpoints, size_t n_endpoints);

/* Drop the live connection and dial another node. */
skaidb_status_t skaidb_client_reconnect(skaidb_client_t *client);

/* ---- statements ------------------------------------------------------- */

/* Any statement — DDL, DML, SELECT, CALL, SHOW. */
skaidb_status_t skaidb_execute(skaidb_client_t *client, const char *sql, skaidb_result_t **out);
skaidb_status_t skaidb_execute_with(skaidb_client_t *client, const char *sql,
                                    skaidb_consistency_t consistency, skaidb_result_t **out);

/* Server-side prepared statement (placeholders are `?`, positional). The
 * handle survives failover: the driver re-prepares transparently. */
skaidb_status_t skaidb_prepare(skaidb_client_t *client, const char *sql, skaidb_prepared_t **out);
size_t skaidb_prepared_params(const skaidb_prepared_t *stmt);
void skaidb_prepared_free(skaidb_prepared_t *stmt);

skaidb_status_t skaidb_execute_prepared(skaidb_client_t *client, skaidb_prepared_t *stmt,
                                        const skaidb_value_t *const *params, size_t n_params,
                                        skaidb_result_t **out);
skaidb_status_t skaidb_execute_prepared_with(skaidb_client_t *client, skaidb_prepared_t *stmt,
                                             const skaidb_value_t *const *params, size_t n_params,
                                             skaidb_consistency_t consistency,
                                             skaidb_result_t **out);

/* One prepared statement, once per row, in a single round trip. `rows` is
 * n_rows arrays of n_params values; the total affected count is returned. */
skaidb_status_t skaidb_execute_batch(skaidb_client_t *client, skaidb_prepared_t *stmt,
                                     const skaidb_value_t *const *const *rows,
                                     size_t n_rows, size_t n_params, uint64_t *affected);

/* Several statements in one round trip, executed serially. Per-statement
 * failures come back INLINE as SKAIDB_RESULT_ERROR results at that index;
 * the call itself fails only on transport/protocol errors. */
skaidb_status_t skaidb_pipeline(skaidb_client_t *client, const char *const *statements,
                                size_t n_statements, skaidb_results_t **out);
size_t skaidb_results_len(const skaidb_results_t *results);
const skaidb_result_t *skaidb_results_get(const skaidb_results_t *results, size_t index);
void skaidb_results_free(skaidb_results_t *results);

/* ---- results ---------------------------------------------------------- */

skaidb_result_kind_t skaidb_result_kind(const skaidb_result_t *result);
size_t skaidb_result_column_count(const skaidb_result_t *result);
const char *skaidb_result_column_name(const skaidb_result_t *result, size_t column);
size_t skaidb_result_row_count(const skaidb_result_t *result);
/* A cell, borrowed from the result. NULL when out of range. */
const skaidb_value_t *skaidb_result_cell(const skaidb_result_t *result, size_t row, size_t column);
uint64_t skaidb_result_affected(const skaidb_result_t *result);
/* SKAIDB_RESULT_ERROR only: the server's message. */
const char *skaidb_result_error(const skaidb_result_t *result);
/* SKAIDB_RESULT_SETS: how many sets, and one set as its own borrowed result
 * (kind SKAIDB_RESULT_ROWS). */
size_t skaidb_result_set_count(const skaidb_result_t *result);
const skaidb_result_t *skaidb_result_set(const skaidb_result_t *result, size_t index);
void skaidb_result_free(skaidb_result_t *result);

/* ---- streamed result sets ---------------------------------------------- */

/* Rows arrive in chunks and at most one chunk is resident — the way to read
 * a result larger than the server's scan budget. Iterate with
 * skaidb_stream_next until it returns SKAIDB_END, then free the stream. */
skaidb_status_t skaidb_query_stream(skaidb_client_t *client, const char *sql, skaidb_stream_t **out);
skaidb_status_t skaidb_query_stream_with(skaidb_client_t *client, const char *sql,
                                         skaidb_consistency_t consistency, skaidb_stream_t **out);
size_t skaidb_stream_column_count(const skaidb_stream_t *stream);
const char *skaidb_stream_column_name(const skaidb_stream_t *stream, size_t column);
/* For a non-row statement: the affected count (the stream is then empty). */
uint64_t skaidb_stream_affected(const skaidb_stream_t *stream);
/* The next row: `*row` becomes an array of n_columns cell pointers, valid
 * until the next call or the free. SKAIDB_END when the stream is finished;
 * an error item ends the stream too. */
skaidb_status_t skaidb_stream_next(skaidb_stream_t *stream, const skaidb_value_t *const **row,
                                   size_t *n_columns);
/* Reads and discards any remaining rows so the connection is reusable. To
 * abandon a huge stream cheaply, free the CLIENT instead. */
void skaidb_stream_free(skaidb_stream_t *stream);

/* ---- change streams (CREATE STREAM) ------------------------------------ */

/* Events after `after` (oldest first; "" to start) as a rows result of
 * (id, op, k, ts, doc) and the cursor to pass next time (malloc'd). */
skaidb_status_t skaidb_stream_poll(skaidb_client_t *client, const char *stream, const char *after,
                                   size_t limit, skaidb_result_t **events, char **next_cursor);

/* ---- values ------------------------------------------------------------ */

skaidb_value_t *skaidb_value_null(void);
skaidb_value_t *skaidb_value_bool(bool v);
skaidb_value_t *skaidb_value_int(int64_t v);
skaidb_value_t *skaidb_value_float(double v);
/* Exact decimal from its text form ("123.45", "-0.001"); NULL on parse failure. */
skaidb_value_t *skaidb_value_decimal(const char *text);
skaidb_value_t *skaidb_value_string(const char *utf8);
skaidb_value_t *skaidb_value_string_len(const char *utf8, size_t len);
skaidb_value_t *skaidb_value_bytes(const uint8_t *data, size_t len);
skaidb_value_t *skaidb_value_uuid(const uint8_t bytes[16]);
/* From "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"; NULL on parse failure. */
skaidb_value_t *skaidb_value_uuid_parse(const char *text);
skaidb_value_t *skaidb_value_timestamp(int64_t unix_millis);
/* Array/document constructors COPY their items; the caller keeps ownership. */
skaidb_value_t *skaidb_value_array(const skaidb_value_t *const *items, size_t n);
skaidb_value_t *skaidb_value_document(const char *const *keys, const skaidb_value_t *const *values, size_t n);
/* Any JSON text → value (objects become documents, arrays arrays, integers
 * ints, other numbers floats); NULL on parse failure. */
skaidb_value_t *skaidb_value_from_json(const char *json);
/* Deep copy. */
skaidb_value_t *skaidb_value_clone(const skaidb_value_t *v);
void skaidb_value_free(skaidb_value_t *v);

skaidb_value_type_t skaidb_value_type(const skaidb_value_t *v);
bool skaidb_value_is_null(const skaidb_value_t *v);
bool skaidb_value_get_bool(const skaidb_value_t *v);
int64_t skaidb_value_get_int(const skaidb_value_t *v);        /* INT and TIMESTAMP; a FLOAT/DECIMAL truncates */
double skaidb_value_get_float(const skaidb_value_t *v);       /* FLOAT, and INT/DECIMAL converted */
int64_t skaidb_value_get_timestamp(const skaidb_value_t *v);
/* Borrowed views (NOT NUL-terminated; use `len`). NULL for other types. */
const char *skaidb_value_get_string(const skaidb_value_t *v, size_t *len);
const uint8_t *skaidb_value_get_bytes(const skaidb_value_t *v, size_t *len);
const uint8_t *skaidb_value_get_uuid(const skaidb_value_t *v);  /* 16 bytes */
size_t skaidb_value_array_len(const skaidb_value_t *v);
const skaidb_value_t *skaidb_value_array_get(const skaidb_value_t *v, size_t index);
size_t skaidb_value_document_len(const skaidb_value_t *v);
/* NUL-terminated; valid until the next skaidb_value_document_key call on
 * this thread. */
const char *skaidb_value_document_key(const skaidb_value_t *v, size_t index);
const skaidb_value_t *skaidb_value_document_value(const skaidb_value_t *v, size_t index);
/* Dotted path lookup ("a.b.c"); NULL when absent. */
const skaidb_value_t *skaidb_value_document_get(const skaidb_value_t *v, const char *path);
/* Malloc'd text forms: strings as-is, decimals/uuids in their canonical
 * text, everything else as JSON. */
char *skaidb_value_to_string_dup(const skaidb_value_t *v);
char *skaidb_value_to_json_dup(const skaidb_value_t *v);

/* ---- connection pool --------------------------------------------------- */

/* Connections are built from these settings on demand; `maxsize` bounds the
 * connections kept IDLE (a burst opens extras and drops the surplus on
 * release). `database` may be NULL. Thread-safe. The most recently released
 * connection is handed out first; for a pool balanced across the members,
 * use skaidb_pool_new_balanced. */
skaidb_pool_t *skaidb_pool_new(size_t maxsize, const char *const *endpoints, size_t n_endpoints,
                               const char *username, const char *password,
                               const skaidb_tls_t *tls, const char *database);
skaidb_status_t skaidb_pool_acquire(skaidb_pool_t *pool, skaidb_client_t **out);
/* A balanced pool drops a connection a transport error broke, or whose
 * member is ejected, not ready or gone, instead of keeping it idle. */
void skaidb_pool_release(skaidb_pool_t *pool, skaidb_client_t *client);
size_t skaidb_pool_idle_len(const skaidb_pool_t *pool);
/* Drops every idle connection and makes acquire fail; stops a balanced
 * pool's background thread; frees the pool. */
void skaidb_pool_free(skaidb_pool_t *pool);

/* -- balancing across members (docs/PROTOCOL.md 6.1,
 *    https://skaidb.org/docs/PROTOCOL.html#61-balancing-a-pool-across-members) */

typedef enum skaidb_load_balancing {
    SKAIDB_LB_RANDOM = 0,        /* any idle connection; a new one dials the usable members in
                                    random order and sticks to the member it reached */
    SKAIDB_LB_ROUND_ROBIN = 1,   /* the next usable member in endpoint order */
    SKAIDB_LB_LEAST_LATENCY = 2  /* of two usable members picked at random, the lower latency
                                    average x (checked-out connections + 1); a member not
                                    measured in the last 2 s scores 0, so it is tried */
} skaidb_load_balancing_t;

typedef enum skaidb_idle_order {
    SKAIDB_IDLE_LIFO = 0,  /* the most recently released idle connection first */
    SKAIDB_IDLE_FIFO = 1   /* the longest idle first: every idle connection keeps being used */
} skaidb_idle_order_t;

/* Options of a balanced pool. Fill with skaidb_pool_options_init (the
 * defaults are in parentheses), then change what you need. */
typedef struct skaidb_pool_options {
    size_t maxsize;                         /* idle connections kept (10; >= 1) */
    skaidb_load_balancing_t load_balancing; /* (SKAIDB_LB_RANDOM) */
    skaidb_idle_order_t idle_order;         /* (SKAIDB_IDLE_LIFO) */
    bool discover;                          /* learn the members from SHOW ENDPOINTS (false):
                                               joiners are added, leavers dropped (a seed is
                                               kept, "unlisted"), resyncing/unreachable members
                                               get no new connections; a standalone or older
                                               server keeps the seeds and stops discovery */
    uint64_t refresh_interval_ms;           /* re-read the members this often (60000; 5000 at
                                               most while one is resyncing/unreachable) */
    uint64_t read_your_writes_ms;           /* after a write, checkouts under the same affinity
                                               key go to the member that took it (0 = off) */
    uint32_t eject_errors;                  /* consecutive transport failures that eject a
                                               member (3; >= 1) */
    double eject_latency_factor;            /* eject a member whose latency average is above
                                               this x the other members' median (3.0; 0 = off) */
    uint64_t eject_latency_floor_ms;        /* ... and more than this above it (50) */
    uint64_t eject_backoff_ms;              /* an ejection lasts this long, doubled per repeat,
                                               then a background probe re-admits (5000) */
    uint64_t eject_backoff_max_ms;          /* the longest ejection (60000) */
} skaidb_pool_options_t;

void skaidb_pool_options_init(skaidb_pool_options_t *options);

/* A pool that knows the endpoints (the seeds) and balances its connections
 * across the members. `tls`, `database` and `options` may be NULL (NULL
 * options = the defaults). Nothing is dialed until the first acquire. An
 * option out of range is SKAIDB_ERR_INVALID. The last usable member is
 * never ejected. */
skaidb_status_t skaidb_pool_new_balanced(const char *const *endpoints, size_t n_endpoints,
                                         const char *username, const char *password,
                                         const skaidb_tls_t *tls, const char *database,
                                         const skaidb_pool_options_t *options,
                                         skaidb_pool_t **out);

/* skaidb_pool_acquire under an affinity key (a user id, a session id) for
 * read_your_writes_ms; NULL = the pool-wide key that skaidb_pool_acquire
 * uses. A pool from skaidb_pool_new ignores the key. Derive the key without
 * querying through the same pool: take the raw id from the session or
 * token — computing it from something that itself reads the database (a
 * framework's "current user" loader) after checking out acquires again from
 * inside the checkout. */
skaidb_status_t skaidb_pool_acquire_affinity(skaidb_pool_t *pool, const char *affinity,
                                             skaidb_client_t **out);

/* One member as a balanced pool sees it. Strings borrow the
 * skaidb_members_t and are valid until skaidb_members_free. */
typedef struct skaidb_member {
    const char *endpoint;   /* what the pool dials */
    const char *canonical;  /* the member's own SHOW ENDPOINTS name; NULL until discovered */
    const char *state;      /* "ready", "ejected", "resyncing", "unreachable" or "unlisted" */
    double latency_ms;      /* round-trip average; negative until measured */
    size_t in_use;          /* connections checked out */
    size_t idle;            /* idle connections */
    bool seed;              /* a configured endpoint (never dropped) */
} skaidb_member_t;

typedef struct skaidb_members skaidb_members_t;

/* A snapshot of the members, in endpoint order (none for a pool from
 * skaidb_pool_new, which knows no members). */
skaidb_status_t skaidb_pool_members(const skaidb_pool_t *pool, skaidb_members_t **out);
size_t skaidb_members_len(const skaidb_members_t *members);
/* NULL when out of range. */
const skaidb_member_t *skaidb_members_get(const skaidb_members_t *members, size_t index);
void skaidb_members_free(skaidb_members_t *members);

#ifdef __cplusplus
}
#endif

#endif /* SKAIDB_H */
