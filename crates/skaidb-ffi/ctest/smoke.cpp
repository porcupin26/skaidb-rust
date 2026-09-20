// libskaidb C++ smoke test: the RAII layer over the same ground the C test
// covers — connect, DDL, prepared statements with typed parameters, a
// batch, range-for over results and streams, a pipeline with an inline
// error, values, and the pool. Run by ctest/run.sh.
#include "skaidb.hpp"

#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#define ASSERT(cond)                                                                       \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            std::cerr << __FILE__ << ':' << __LINE__ << ": assertion failed: " #cond "\n"; \
            std::exit(1);                                                                  \
        }                                                                                  \
    } while (0)

static std::string env_or(const char *name, const char *dflt) {
    const char *v = std::getenv(name);
    return v && *v ? v : dflt;
}

int main() {
    const std::string endpoint = env_or("SKAIDB_ENDPOINT", "127.0.0.1:7000");
    const std::string user = env_or("SKAIDB_USER", "admin");
    const std::string password = env_or("SKAIDB_PASSWORD", "");

    auto c = skaidb::Client::connect(endpoint, user, password);
    ASSERT(!c.endpoint().empty());
    c.set_consistency(skaidb::Consistency::Quorum);
    c.execute("DROP TABLE IF EXISTS cppffi_smoke");
    ASSERT(c.execute("CREATE TABLE cppffi_smoke (PRIMARY KEY (id))").kind() == skaidb::Kind::Ddl);

    // Errors are exceptions carrying the status.
    try {
        c.execute("SELEC nonsense");
        ASSERT(false);
    } catch (const skaidb::Error &e) {
        ASSERT(e.status() == SKAIDB_ERR_SERVER);
        ASSERT(std::string(e.what()).size() > 0);
    }
    try {
        c.use_database("no_such_db_cppffi");
        ASSERT(false);
    } catch (const skaidb::Error &) {
    }
    ASSERT(c.execute("SELECT count(*) FROM cppffi_smoke")[0][0].as_int() == 0);

    // Prepared statement with typed parameters, then a batch.
    auto ins = c.prepare("INSERT INTO cppffi_smoke (id, name, score, ok, ts, tags, doc) VALUES (?, ?, ?, ?, ?, ?, ?)");
    ASSERT(ins.params() == 7);
    auto r = c.execute(ins, {1, "one", 1.5, true, skaidb::Value::timestamp(1700000000000LL),
                             skaidb::Value::array({"a", "b"}), skaidb::Value::document({{"n", 1}, {"s", "x"}})});
    ASSERT(r.kind() == skaidb::Kind::Mutation && r.affected() == 1);
    std::vector<std::vector<skaidb::Value>> rows;
    for (int i = 2; i <= 4; ++i)
        rows.push_back({i, "n" + std::to_string(i), i * 1.0, false, skaidb::Value::timestamp(0),
                        skaidb::Value::array({}), skaidb::Value::document({})});
    ASSERT(c.execute_batch(ins, rows) == 3);

    // Read back: range-for, indexing, accessors.
    auto sel = c.execute("SELECT id, name, score, ok, ts, tags, doc FROM cppffi_smoke ORDER BY id");
    ASSERT(sel.kind() == skaidb::Kind::Rows && sel.row_count() == 4 && sel.column_name(1) == "name");
    ASSERT(sel.columns().size() == 7);
    std::int64_t sum = 0;
    for (skaidb::Row row : sel) sum += row[0].as_int();
    ASSERT(sum == 10);
    ASSERT(sel[0][1].as_string() == "one");
    ASSERT(sel[0][2].as_float() == 1.5);
    ASSERT(sel[0][3].as_bool());
    ASSERT(sel[0][4].type() == skaidb::Type::Timestamp && sel[0][4].as_timestamp() == 1700000000000LL);
    ASSERT(sel[0][5].type() == skaidb::Type::Array && sel[0][5].size() == 2 && sel[0][5][1].as_string() == "b");
    ASSERT(sel[0][6].get("n").as_int() == 1 && sel[0][6].key(1) == "s");
    ASSERT(sel[0][6].json() == "{\"n\":1,\"s\":\"x\"}");
    ASSERT(!sel[0][9] && sel[0][9].is_null());
    skaidb::Value copy = skaidb::Value::copy(sel[0][6]);
    ASSERT(copy.get("s").as_string() == "x");
    try {
        sel[0].at(9);
        ASSERT(false);
    } catch (const std::out_of_range &) {
    }

    // Pipeline: an inline error does not throw.
    auto rs = c.pipeline({"SELECT count(*) FROM cppffi_smoke", "SELECT * FROM no_such_table_cppffi",
                          "SELECT id FROM cppffi_smoke WHERE id = 3"});
    ASSERT(rs.size() == 3);
    ASSERT(rs[0][0][0].as_int() == 4);
    ASSERT(rs[1].is_error() && !rs[1].error().empty());
    ASSERT(rs[2][0][0].as_int() == 3);
    std::size_t errors = 0;
    for (skaidb::ResultView v : rs) errors += v.is_error() ? 1 : 0;
    ASSERT(errors == 1);

    // Streams: range-for, and an abandoned stream drained on destruction.
    sum = 0;
    std::size_t seen = 0;
    for (const skaidb::Row &row : c.query_stream("SELECT id FROM cppffi_smoke ORDER BY id")) {
        sum += row[0].as_int();
        ++seen;
    }
    ASSERT(seen == 4 && sum == 10);
    {
        auto st = c.query_stream("SELECT id, name FROM cppffi_smoke");
        ASSERT(st.column_count() == 2 && st.columns()[1] == "name");
        auto first = st.next();
        ASSERT(first && first->size() == 2);
    }
    ASSERT(c.execute("SELECT count(*) FROM cppffi_smoke")[0][0].as_int() == 4);

    // Values.
    ASSERT(skaidb::Value::decimal("12.50").str() == "12.50");
    ASSERT(skaidb::Value::uuid("123e4567-e89b-12d3-a456-426614174000").str() ==
           "123e4567-e89b-12d3-a456-426614174000");
    try {
        skaidb::Value::uuid("nope");
        ASSERT(false);
    } catch (const skaidb::Error &) {
    }
    auto j = skaidb::Value::from_json("{\"a\":[1,2,{\"b\":true}]}");
    ASSERT(j.get("a")[2].get("b").as_bool());
    skaidb::Value moved = std::move(j);
    ASSERT(moved.get("a").size() == 3 && !j);
    std::vector<std::uint8_t> raw{1, 2, 3};
    ASSERT(skaidb::Value::bytes(raw).as_bytes() == raw);
    ASSERT(skaidb::Value(nullptr).is_null() && skaidb::Value().is_null());
    ASSERT(skaidb::Value(std::string_view("sv")).as_string_view() == "sv");

    // The pool.
    skaidb::Pool pool(2, {endpoint}, user, password);
    {
        auto lease = pool.acquire();
        ASSERT(lease->execute("SELECT count(*) FROM cppffi_smoke")[0][0].as_int() == 4);
    }
    ASSERT(pool.idle_len() == 1);
    ASSERT(pool.with([](skaidb::Client &cl) {
        return cl.execute("SELECT count(*) FROM cppffi_smoke")[0][0].as_int();
    }) == 4);

    c.execute("DROP TABLE cppffi_smoke");
    std::cout << "C++ smoke: OK (libskaidb " << skaidb::version() << ")\n";
    return 0;
}
