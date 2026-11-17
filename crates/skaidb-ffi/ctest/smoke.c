/* libskaidb C smoke test: connect, DDL, typed parameters through a prepared
 * statement, a batch, a read-back with every value accessor, a pipeline
 * with an inline error, a streamed result (and an abandoned one), the
 * result sets of a streamed CALL, values on their own, the pools (plain
 * and balanced) and the session state they and a reconnect keep. Run by
 * ctest/run.sh. */
#include "skaidb.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr)                                                                           \
    do {                                                                                      \
        skaidb_status_t s__ = (expr);                                                         \
        if (s__ != SKAIDB_OK) {                                                               \
            fprintf(stderr, "%s:%d: %s -> status %d: %s\n", __FILE__, __LINE__, #expr, (int)s__, \
                    skaidb_last_error());                                                     \
            exit(1);                                                                          \
        }                                                                                     \
    } while (0)

#define ASSERT(cond)                                                                    \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            fprintf(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #cond); \
            exit(1);                                                                    \
        }                                                                               \
    } while (0)

/* What a transaction body is told: the client of another writer, how often
 * that writer gets in first, and how many times the body has run. */
struct txn_run {
    skaidb_client_t *other;
    int race_runs;
    int runs;
    int fail;
};

static skaidb_status_t txn_body(skaidb_client_t *c, void *user) {
    struct txn_run *run = user;
    skaidb_result_t *r = NULL;
    run->runs++;
    skaidb_status_t s = skaidb_execute(c, "UPDATE cffi_txn SET n = n + 1 WHERE id = 1", &r);
    if (s != SKAIDB_OK) return s;
    skaidb_result_free(r);
    if (run->runs <= run->race_runs) {
        CHECK(skaidb_execute(run->other, "UPDATE cffi_txn SET n = n + 10 WHERE id = 1", &r));
        skaidb_result_free(r);
    }
    if (run->fail) return skaidb_execute(c, "INSERT INTO cffi_no_such_table (id) VALUES (1)", &r);
    return SKAIDB_OK;
}

static int64_t txn_n(skaidb_client_t *c) {
    skaidb_result_t *r = NULL;
    CHECK(skaidb_execute(c, "SELECT n FROM cffi_txn WHERE id = 1", &r));
    int64_t n = skaidb_value_get_int(skaidb_result_cell(r, 0, 0));
    skaidb_result_free(r);
    return n;
}

static const char *env_or(const char *name, const char *dflt) {
    const char *v = getenv(name);
    return v && *v ? v : dflt;
}

int main(void) {
    const char *endpoint = env_or("SKAIDB_ENDPOINT", "127.0.0.1:7000");
    const char *user = env_or("SKAIDB_USER", "admin");
    const char *password = env_or("SKAIDB_PASSWORD", "");
    printf("libskaidb %s\n", skaidb_version());

    const char *eps[1] = {endpoint};
    skaidb_client_t *c = NULL;
    CHECK(skaidb_connect(eps, 1, user, password, NULL, &c));
    char *at = skaidb_client_endpoint_dup(c);
    ASSERT(at && strlen(at) > 0);
    skaidb_string_free(at);
    skaidb_client_set_consistency(c, SKAIDB_QUORUM);

    skaidb_result_t *r = NULL;
    CHECK(skaidb_execute(c, "DROP TABLE IF EXISTS cffi_smoke", &r));
    skaidb_result_free(r);
    CHECK(skaidb_execute(c, "CREATE TABLE cffi_smoke (PRIMARY KEY (id))", &r));
    ASSERT(skaidb_result_kind(r) == SKAIDB_RESULT_DDL);
    skaidb_result_free(r);

    /* A statement error is a status with a message, not a crash. */
    ASSERT(skaidb_execute(c, "SELEC nonsense", &r) == SKAIDB_ERR_SERVER);
    ASSERT(strlen(skaidb_last_error()) > 0);
    /* A refused USE keeps the connection. */
    ASSERT(skaidb_client_use_database(c, "no_such_db_cffi") == SKAIDB_ERR_SERVER);
    CHECK(skaidb_execute(c, "SELECT count(*) FROM cffi_smoke", &r));
    skaidb_result_free(r);

    /* Typed parameters through a prepared statement. */
    skaidb_prepared_t *ins = NULL;
    CHECK(skaidb_prepare(c,
                         "INSERT INTO cffi_smoke (id, name, score, ok, ts, tags, doc, nothing) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         &ins));
    ASSERT(skaidb_prepared_params(ins) == 8);
    skaidb_value_t *tag_items[2] = {skaidb_value_string("a"), skaidb_value_string("b")};
    const char *keys[2] = {"n", "s"};
    skaidb_value_t *doc_vals[2] = {skaidb_value_int(1), skaidb_value_string("x")};
    skaidb_value_t *p[8] = {
        skaidb_value_int(1),
        skaidb_value_string("one"),
        skaidb_value_float(1.5),
        skaidb_value_bool(true),
        skaidb_value_timestamp(1700000000000LL),
        skaidb_value_array((const skaidb_value_t *const *)tag_items, 2),
        skaidb_value_document(keys, (const skaidb_value_t *const *)doc_vals, 2),
        skaidb_value_null(),
    };
    CHECK(skaidb_execute_prepared(c, ins, (const skaidb_value_t *const *)p, 8, &r));
    ASSERT(skaidb_result_kind(r) == SKAIDB_RESULT_MUTATION);
    ASSERT(skaidb_result_affected(r) == 1);
    skaidb_result_free(r);
    for (int i = 0; i < 8; i++) skaidb_value_free(p[i]);
    for (int i = 0; i < 2; i++) {
        skaidb_value_free(tag_items[i]);
        skaidb_value_free(doc_vals[i]);
    }

    /* Three more rows in one round trip. */
    skaidb_value_t *batch[3][8];
    const skaidb_value_t *const *rows[3];
    const char *names[3] = {"two", "three", "four"};
    for (int i = 0; i < 3; i++) {
        batch[i][0] = skaidb_value_int(i + 2);
        batch[i][1] = skaidb_value_string(names[i]);
        batch[i][2] = skaidb_value_float((double)(i + 2));
        batch[i][3] = skaidb_value_bool(false);
        batch[i][4] = skaidb_value_timestamp(0);
        batch[i][5] = skaidb_value_array(NULL, 0);
        batch[i][6] = skaidb_value_document(NULL, NULL, 0);
        batch[i][7] = skaidb_value_null();
        rows[i] = (const skaidb_value_t *const *)batch[i];
    }
    uint64_t n = 0;
    CHECK(skaidb_execute_batch(c, ins, rows, 3, 8, &n));
    ASSERT(n == 3);
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 8; j++) skaidb_value_free(batch[i][j]);
    /* Released on the server too: a connection holds 256 of them, and a
     * program that prepares as it goes passes far more through. */
    CHECK(skaidb_prepared_close(c, ins));
    for (int i = 0; i < 300; i++) {
        char sql[96];
        snprintf(sql, sizeof sql, "UPDATE cffi_smoke SET score = ? WHERE id = %d", 1000 + i);
        skaidb_prepared_t *st = NULL;
        CHECK(skaidb_prepare(c, sql, &st));
        ASSERT(skaidb_prepared_params(st) == 1);
        CHECK(skaidb_prepared_close(c, st));
    }
    ASSERT(skaidb_prepared_close(c, NULL) == SKAIDB_ERR_INVALID);

    /* Read back with every accessor. */
    CHECK(skaidb_execute(c, "SELECT id, name, score, ok, ts, tags, doc, nothing FROM cffi_smoke ORDER BY id", &r));
    ASSERT(skaidb_result_kind(r) == SKAIDB_RESULT_ROWS);
    ASSERT(skaidb_result_row_count(r) == 4);
    ASSERT(skaidb_result_column_count(r) == 8);
    ASSERT(strcmp(skaidb_result_column_name(r, 1), "name") == 0);
    const skaidb_value_t *v = skaidb_result_cell(r, 0, 0);
    ASSERT(skaidb_value_type(v) == SKAIDB_INT && skaidb_value_get_int(v) == 1);
    size_t len = 0;
    const char *s = skaidb_value_get_string(skaidb_result_cell(r, 0, 1), &len);
    ASSERT(len == 3 && memcmp(s, "one", 3) == 0);
    ASSERT(skaidb_value_get_float(skaidb_result_cell(r, 0, 2)) == 1.5);
    ASSERT(skaidb_value_get_bool(skaidb_result_cell(r, 0, 3)));
    v = skaidb_result_cell(r, 0, 4);
    ASSERT(skaidb_value_type(v) == SKAIDB_TIMESTAMP && skaidb_value_get_timestamp(v) == 1700000000000LL);
    v = skaidb_result_cell(r, 0, 5);
    ASSERT(skaidb_value_type(v) == SKAIDB_ARRAY && skaidb_value_array_len(v) == 2);
    s = skaidb_value_get_string(skaidb_value_array_get(v, 1), &len);
    ASSERT(len == 1 && s[0] == 'b');
    v = skaidb_result_cell(r, 0, 6);
    ASSERT(skaidb_value_type(v) == SKAIDB_DOCUMENT && skaidb_value_document_len(v) == 2);
    ASSERT(skaidb_value_get_int(skaidb_value_document_get(v, "n")) == 1);
    ASSERT(strcmp(skaidb_value_document_key(v, 0), "n") == 0);
    char *js = skaidb_value_to_json_dup(v);
    ASSERT(strcmp(js, "{\"n\":1,\"s\":\"x\"}") == 0);
    skaidb_string_free(js);
    ASSERT(skaidb_value_is_null(skaidb_result_cell(r, 0, 7)));
    ASSERT(skaidb_result_cell(r, 9, 0) == NULL);
    skaidb_result_free(r);

    /* A pipeline: rows, an inline error, rows. */
    const char *stmts[3] = {"SELECT count(*) FROM cffi_smoke", "SELECT * FROM no_such_table_cffi",
                            "SELECT id FROM cffi_smoke WHERE id = 3"};
    skaidb_results_t *rs = NULL;
    CHECK(skaidb_pipeline(c, stmts, 3, &rs));
    ASSERT(skaidb_results_len(rs) == 3);
    ASSERT(skaidb_result_kind(skaidb_results_get(rs, 0)) == SKAIDB_RESULT_ROWS);
    ASSERT(skaidb_value_get_int(skaidb_result_cell(skaidb_results_get(rs, 0), 0, 0)) == 4);
    ASSERT(skaidb_result_kind(skaidb_results_get(rs, 1)) == SKAIDB_RESULT_ERROR);
    ASSERT(skaidb_result_error(skaidb_results_get(rs, 1)) != NULL);
    ASSERT(skaidb_value_get_int(skaidb_result_cell(skaidb_results_get(rs, 2), 0, 0)) == 3);
    skaidb_results_free(rs);

    /* Streaming, then an abandoned stream drained on free. */
    skaidb_stream_t *stm = NULL;
    CHECK(skaidb_query_stream(c, "SELECT id, name FROM cffi_smoke ORDER BY id", &stm));
    ASSERT(skaidb_stream_column_count(stm) == 2);
    ASSERT(strcmp(skaidb_stream_column_name(stm, 0), "id") == 0);
    const skaidb_value_t *const *row = NULL;
    size_t nc = 0;
    int64_t sum = 0;
    size_t seen = 0;
    skaidb_status_t ss;
    while ((ss = skaidb_stream_next(stm, &row, &nc)) == SKAIDB_OK) {
        ASSERT(nc == 2);
        sum += skaidb_value_get_int(row[0]);
        seen++;
    }
    ASSERT(ss == SKAIDB_END && seen == 4 && sum == 10);
    skaidb_stream_free(stm);
    CHECK(skaidb_query_stream(c, "SELECT id FROM cffi_smoke", &stm));
    CHECK(skaidb_stream_next(stm, &row, &nc));
    skaidb_stream_free(stm);
    /* A streamed statement with bound parameters. */
    skaidb_value_t *lo = skaidb_value_int(2);
    const skaidb_value_t *sp[] = {lo};
    CHECK(skaidb_query_stream_params(c, "SELECT id FROM cffi_smoke WHERE id >= ? ORDER BY id", sp, 1,
                                     &stm));
    sum = 0;
    seen = 0;
    while ((ss = skaidb_stream_next(stm, &row, &nc)) == SKAIDB_OK) {
        sum += skaidb_value_get_int(row[0]);
        seen++;
    }
    ASSERT(ss == SKAIDB_END && seen == 3 && sum == 9);
    skaidb_stream_free(stm);
    skaidb_value_free(lo);
    /* A CALL whose body EMITs is answered with every set in one frame, even
     * when streamed: the stream starts on the first set and
     * skaidb_stream_next_set walks the rest. With and without parameters. */
    CHECK(skaidb_execute(c, "DROP PROCEDURE IF EXISTS cffi_report", &r));
    skaidb_result_free(r);
    CHECK(skaidb_execute(c,
                         "CREATE PROCEDURE cffi_report(lo INT) BEGIN "
                         "EMIT SELECT id FROM cffi_smoke WHERE id >= lo ORDER BY id; "
                         "SELECT count(*) AS n FROM cffi_smoke; END",
                         &r));
    skaidb_result_free(r);
    skaidb_value_t *three = skaidb_value_int(3);
    const skaidb_value_t *cp[] = {three};
    for (int bound = 1; bound >= 0; bound--) {
        if (bound)
            CHECK(skaidb_query_stream_params(c, "CALL cffi_report(?)", cp, 1, &stm));
        else
            CHECK(skaidb_query_stream(c, "CALL cffi_report(3)", &stm));
        const char *first_col = skaidb_stream_column_name(stm, 0);
        ASSERT(skaidb_stream_column_count(stm) == 1 && strcmp(first_col, "id") == 0);
        sum = 0;
        seen = 0;
        while ((ss = skaidb_stream_next(stm, &row, &nc)) == SKAIDB_OK) {
            sum += skaidb_value_get_int(row[0]);
            seen++;
        }
        ASSERT(ss == SKAIDB_END && seen == 2 && sum == 7);
        CHECK(skaidb_stream_next_set(stm));
        ASSERT(strcmp(skaidb_stream_column_name(stm, 0), "n") == 0);
        ASSERT(strcmp(first_col, "id") == 0); /* a name handed out lives until the free */
        CHECK(skaidb_stream_next(stm, &row, &nc));
        ASSERT(nc == 1 && skaidb_value_get_int(row[0]) == 4);
        ASSERT(skaidb_stream_next(stm, &row, &nc) == SKAIDB_END);
        ASSERT(skaidb_stream_next_set(stm) == SKAIDB_END);
        skaidb_stream_free(stm);
    }
    skaidb_value_free(three);
    /* A real stream has one set. */
    CHECK(skaidb_query_stream(c, "SELECT id FROM cffi_smoke", &stm));
    while (skaidb_stream_next(stm, &row, &nc) == SKAIDB_OK) {
    }
    ASSERT(skaidb_stream_next_set(stm) == SKAIDB_END);
    skaidb_stream_free(stm);
    CHECK(skaidb_execute(c, "DROP PROCEDURE cffi_report", &r));
    skaidb_result_free(r);
    CHECK(skaidb_execute(c, "SELECT count(*) FROM cffi_smoke", &r));
    ASSERT(skaidb_value_get_int(skaidb_result_cell(r, 0, 0)) == 4);
    skaidb_result_free(r);

    /* Values on their own. */
    skaidb_value_t *d = skaidb_value_decimal("12.50");
    ASSERT(d && skaidb_value_type(d) == SKAIDB_DECIMAL);
    char *t = skaidb_value_to_string_dup(d);
    ASSERT(strcmp(t, "12.50") == 0);
    skaidb_string_free(t);
    skaidb_value_free(d);
    ASSERT(skaidb_value_decimal("abc") == NULL);
    skaidb_value_t *u = skaidb_value_uuid_parse("123e4567-e89b-12d3-a456-426614174000");
    ASSERT(u && skaidb_value_type(u) == SKAIDB_UUID && skaidb_value_get_uuid(u)[0] == 0x12);
    t = skaidb_value_to_string_dup(u);
    ASSERT(strcmp(t, "123e4567-e89b-12d3-a456-426614174000") == 0);
    skaidb_string_free(t);
    skaidb_value_free(u);
    ASSERT(skaidb_value_uuid_parse("nope") == NULL);
    skaidb_value_t *j = skaidb_value_from_json("{\"a\":[1,2,{\"b\":true}],\"c\":\"z\"}");
    ASSERT(j && skaidb_value_type(j) == SKAIDB_DOCUMENT);
    v = skaidb_value_document_get(j, "a");
    ASSERT(v && skaidb_value_array_len(v) == 3);
    ASSERT(skaidb_value_get_bool(skaidb_value_document_get(skaidb_value_array_get(v, 2), "b")));
    skaidb_value_t *jc = skaidb_value_clone(j);
    t = skaidb_value_to_json_dup(jc);
    ASSERT(strcmp(t, "{\"a\":[1,2,{\"b\":true}],\"c\":\"z\"}") == 0);
    skaidb_string_free(t);
    skaidb_value_free(jc);
    skaidb_value_free(j);
    ASSERT(skaidb_value_from_json("{nope") == NULL);
    const uint8_t raw[3] = {1, 2, 3};
    skaidb_value_t *b = skaidb_value_bytes(raw, 3);
    const uint8_t *bp = skaidb_value_get_bytes(b, &len);
    ASSERT(len == 3 && bp[2] == 3);
    skaidb_value_free(b);

    /* The pool. */
    skaidb_pool_t *pool = skaidb_pool_new(2, eps, 1, user, password, NULL, NULL);
    ASSERT(pool != NULL);
    skaidb_client_t *pc = NULL;
    CHECK(skaidb_pool_acquire(pool, &pc));
    CHECK(skaidb_execute(pc, "SELECT count(*) FROM cffi_smoke", &r));
    ASSERT(skaidb_value_get_int(skaidb_result_cell(r, 0, 0)) == 4);
    skaidb_result_free(r);
    skaidb_pool_release(pool, pc);
    ASSERT(skaidb_pool_idle_len(pool) == 1);
    skaidb_members_t *none = NULL;
    CHECK(skaidb_pool_members(pool, &none));
    ASSERT(skaidb_members_len(none) == 0); /* a plain pool knows no members */
    skaidb_members_free(none);
    skaidb_pool_free(pool);

    /* Session state. A SET sent as a statement is the session's: the
     * connection that replaces this one is given it back. */
    CHECK(skaidb_execute(c, "SET SCAN BUDGET ROWS 1", &r));
    skaidb_result_free(r);
    ASSERT(skaidb_execute(c, "SELECT id FROM cffi_smoke WHERE score >= 0", &r) == SKAIDB_ERR_SERVER);
    ASSERT(strstr(skaidb_last_error(), "scan budget") != NULL);
    CHECK(skaidb_client_reconnect(c));
    ASSERT(skaidb_execute(c, "SELECT id FROM cffi_smoke WHERE score >= 0", &r) == SKAIDB_ERR_SERVER);
    ASSERT(strstr(skaidb_last_error(), "scan budget") != NULL);
    /* The method and the statement are one setting: cleared by either. */
    CHECK(skaidb_client_set_scan_budget_rows(c, 0));
    CHECK(skaidb_client_reconnect(c));
    CHECK(skaidb_execute(c, "SELECT count(*) FROM cffi_smoke", &r));
    ASSERT(skaidb_value_get_int(skaidb_result_cell(r, 0, 0)) == 4);
    skaidb_result_free(r);

    /* A pool hands every borrower its own session state: one borrower's
     * scan budget and open transaction are not the next one's. */
    pool = skaidb_pool_new(1, eps, 1, user, password, NULL, NULL);
    ASSERT(pool != NULL);
    CHECK(skaidb_pool_acquire(pool, &pc));
    CHECK(skaidb_execute(pc, "SET SCAN BUDGET ROWS 1", &r));
    skaidb_result_free(r);
    CHECK(skaidb_execute(pc, "BEGIN", &r));
    skaidb_result_free(r);
    CHECK(skaidb_execute(pc, "INSERT INTO cffi_smoke (id) VALUES (99)", &r));
    skaidb_result_free(r);
    skaidb_pool_release(pool, pc);
    ASSERT(skaidb_pool_idle_len(pool) == 1); /* put back, not closed */
    CHECK(skaidb_pool_acquire(pool, &pc));
    CHECK(skaidb_execute(pc, "SELECT count(*) FROM cffi_smoke", &r));
    ASSERT(skaidb_value_get_int(skaidb_result_cell(r, 0, 0)) == 4); /* rolled back */
    skaidb_result_free(r);
    /* A consistency override is cleared, or (a server before 0.349) the
     * connection closed: either way the next borrower has none. */
    CHECK(skaidb_execute(pc, "SET CONSISTENCY ALL", &r));
    skaidb_result_free(r);
    skaidb_pool_release(pool, pc);
    CHECK(skaidb_pool_acquire(pool, &pc));
    CHECK(skaidb_execute(pc, "SELECT count(*) FROM cffi_smoke", &r));
    skaidb_result_free(r);
    skaidb_pool_release(pool, pc);
    skaidb_pool_free(pool);

    /* A transaction by hand, with no connection lost, is as it was. */
    CHECK(skaidb_execute(c, "BEGIN", &r));
    skaidb_result_free(r);
    CHECK(skaidb_execute(c, "INSERT INTO cffi_smoke (id) VALUES (98)", &r));
    skaidb_result_free(r);
    ASSERT(skaidb_client_reconnect(c) == SKAIDB_ERR_IO); /* refused while it is open */
    CHECK(skaidb_execute(c, "ROLLBACK", &r));
    skaidb_result_free(r);
    CHECK(skaidb_client_reconnect(c));
    CHECK(skaidb_execute(c, "SELECT count(*) FROM cffi_smoke", &r));
    ASSERT(skaidb_value_get_int(skaidb_result_cell(r, 0, 0)) == 4);
    skaidb_result_free(r);

    /* The balanced pool, against one standalone server: SHOW ENDPOINTS
     * answers no rows there, so discovery keeps the seed and stops. */
    skaidb_pool_options_t opts;
    skaidb_pool_options_init(&opts);
    ASSERT(opts.maxsize == 10 && opts.eject_errors == 3 && opts.load_balancing == SKAIDB_LB_RANDOM);
    ASSERT(opts.idle_order == SKAIDB_IDLE_LIFO && opts.refresh_interval_ms == 60000 && !opts.discover);
    ASSERT(opts.read_your_writes_ms == 0 && opts.eject_latency_factor == 3.0 && opts.eject_latency_floor_ms == 50);
    ASSERT(opts.eject_backoff_ms == 5000 && opts.eject_backoff_max_ms == 60000);
    opts.maxsize = 2;
    opts.load_balancing = SKAIDB_LB_ROUND_ROBIN;
    opts.idle_order = SKAIDB_IDLE_FIFO;
    opts.discover = true;
    opts.read_your_writes_ms = 2000;
    skaidb_pool_t *bpool = NULL;
    CHECK(skaidb_pool_new_balanced(eps, 1, user, password, NULL, NULL, &opts, &bpool));
    CHECK(skaidb_pool_acquire_affinity(bpool, "alice", &pc));
    CHECK(skaidb_execute(pc, "UPDATE cffi_smoke SET name = 'four' WHERE id = 4", &r));
    skaidb_result_free(r);
    skaidb_members_t *ms = NULL;
    CHECK(skaidb_pool_members(bpool, &ms));
    ASSERT(skaidb_members_len(ms) == 1);
    const skaidb_member_t *m = skaidb_members_get(ms, 0);
    ASSERT(m && strcmp(m->endpoint, endpoint) == 0 && m->seed && m->canonical == NULL);
    ASSERT(strcmp(m->state, "ready") == 0 && m->in_use == 1 && m->idle == 0);
    ASSERT(m->latency_ms < 0); /* one round trip: measured from its third */
    ASSERT(skaidb_members_get(ms, 1) == NULL);
    skaidb_members_free(ms);
    skaidb_pool_release(bpool, pc);
    CHECK(skaidb_pool_acquire_affinity(bpool, "alice", &pc)); /* the writer's member: the seed */
    CHECK(skaidb_execute(pc, "SELECT count(*) FROM cffi_smoke", &r));
    ASSERT(skaidb_value_get_int(skaidb_result_cell(r, 0, 0)) == 4);
    skaidb_result_free(r);
    CHECK(skaidb_execute(pc, "SELECT count(*) FROM cffi_smoke", &r));
    skaidb_result_free(r);
    skaidb_pool_release(bpool, pc);
    CHECK(skaidb_pool_acquire(bpool, &pc));
    skaidb_pool_release(bpool, pc);
    CHECK(skaidb_pool_members(bpool, &ms));
    m = skaidb_members_get(ms, 0);
    ASSERT(skaidb_members_len(ms) == 1 && m->in_use == 0 && m->idle == 1 && m->latency_ms >= 0);
    skaidb_members_free(ms);
    ASSERT(skaidb_pool_idle_len(bpool) == 1);
    skaidb_pool_free(bpool);
    /* Options out of range are refused. */
    opts.load_balancing = (skaidb_load_balancing_t)7;
    ASSERT(skaidb_pool_new_balanced(eps, 1, user, password, NULL, NULL, &opts, &bpool) == SKAIDB_ERR_INVALID);
    skaidb_pool_options_init(&opts);
    opts.maxsize = 0;
    ASSERT(skaidb_pool_new_balanced(eps, 1, user, password, NULL, NULL, &opts, &bpool) == SKAIDB_ERR_INVALID);

    /* Transactions: the helper commits, runs again on a conflict, gives the
     * conflict back after its attempts, and rolls back a body that failed. */
    skaidb_client_t *other = NULL;
    CHECK(skaidb_connect(eps, 1, user, password, NULL, &other));
    CHECK(skaidb_execute(c, "DROP TABLE IF EXISTS cffi_txn", &r));
    skaidb_result_free(r);
    CHECK(skaidb_execute(c, "CREATE TABLE cffi_txn (PRIMARY KEY (id))", &r));
    skaidb_result_free(r);
    CHECK(skaidb_execute(c, "INSERT INTO cffi_txn (id, n) VALUES (1, 0)", &r));
    skaidb_result_free(r);
    struct txn_run run = {other, 0, 0, 0};
    CHECK(skaidb_transaction(c, NULL, 3, txn_body, &run));
    ASSERT(run.runs == 1 && txn_n(c) == 1);
    ASSERT(!skaidb_last_error_is_transaction_conflict());
    run = (struct txn_run){other, 2, 0, 0}; /* the other writer wins twice */
    CHECK(skaidb_transaction(c, "BEGIN", 3, txn_body, &run));
    ASSERT(run.runs == 3 && txn_n(c) == 22);
    run = (struct txn_run){other, 9, 0, 0}; /* ... and every time */
    ASSERT(skaidb_transaction(c, NULL, 2, txn_body, &run) == SKAIDB_ERR_SERVER);
    ASSERT(skaidb_last_error_is_transaction_conflict());
    ASSERT(strstr(skaidb_last_error(), "transaction conflict:") != NULL);
    ASSERT(run.runs == 2 && txn_n(c) == 42);
    run = (struct txn_run){other, 0, 0, 1}; /* the body fails: rolled back, its error kept */
    ASSERT(skaidb_transaction(c, NULL, 3, txn_body, &run) == SKAIDB_ERR_SERVER);
    ASSERT(strstr(skaidb_last_error(), "cffi_no_such_table") != NULL);
    ASSERT(!skaidb_last_error_is_transaction_conflict());
    ASSERT(run.runs == 1 && txn_n(c) == 42);
    /* Nothing is left open: a ROLLBACK now has nothing to discard and
     * succeeds, a COMMIT has nothing to apply and does not. */
    CHECK(skaidb_execute(c, "ROLLBACK", &r));
    skaidb_result_free(r);
    ASSERT(skaidb_execute(c, "COMMIT", &r) == SKAIDB_ERR_SERVER);
    /* A refused opening statement: the body does not run. */
    run = (struct txn_run){other, 0, 0, 0};
    ASSERT(skaidb_transaction(c, "BEGIN ATOMIC PARTITION (tenant = 't1')", 3, txn_body, &run) == SKAIDB_ERR_SERVER);
    ASSERT(run.runs == 0);
    ASSERT(skaidb_transaction(c, NULL, 3, NULL, NULL) == SKAIDB_ERR_INVALID);
    CHECK(skaidb_execute(c, "DROP TABLE cffi_txn", &r));
    skaidb_result_free(r);
    skaidb_client_free(other);

    CHECK(skaidb_execute(c, "DROP TABLE cffi_smoke", &r));
    skaidb_result_free(r);
    skaidb_client_free(c);
    puts("C smoke: OK");
    return 0;
}
