/* libskaidb C smoke test: connect, DDL, typed parameters through a prepared
 * statement, a batch, a read-back with every value accessor, a pipeline
 * with an inline error, a streamed result (and an abandoned one), values
 * on their own, and the pool. Run by ctest/run.sh. */
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
    skaidb_prepared_free(ins);

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
    skaidb_pool_free(pool);

    CHECK(skaidb_execute(c, "DROP TABLE cffi_smoke", &r));
    skaidb_result_free(r);
    skaidb_client_free(c);
    puts("C smoke: OK");
    return 0;
}
