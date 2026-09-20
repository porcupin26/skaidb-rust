/* skaidb C++ driver — a header-only C++17 RAII layer over libskaidb
 * (skaidb.h). Nothing here speaks the protocol: every call is one C call,
 * every object owns exactly one C handle and frees it in its destructor,
 * and every failure is a thrown skaidb::Error carrying the C status and
 * the thread-local message.
 *
 *   auto c = skaidb::Client::connect("db.example:7000", "app", "secret");
 *   c.use_database("shop");
 *   auto ins = c.prepare("INSERT INTO orders (id, total) VALUES (?, ?)");
 *   c.execute(ins, {42, 12.5});
 *   for (skaidb::Row row : c.execute("SELECT id, total FROM orders ORDER BY id"))
 *       std::cout << row[0].as_int() << ' ' << row[1].as_float() << '\n';
 *   for (const skaidb::Row &row : c.query_stream("SELECT * FROM big_table"))
 *       ...;                                   // one chunk resident at a time
 *
 * Views (ValueView, Row, ResultView) borrow from an owner (Value, Result,
 * Results, Stream) and are valid as long as it is; a stream's Row only
 * until the next row. A Client is one connection: use it from one thread
 * at a time. A Pool is thread-safe.
 */
#ifndef SKAIDB_HPP
#define SKAIDB_HPP

#include "skaidb.h"

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace skaidb {

/* A failed call: the C status plus skaidb_last_error() at the time. */
class Error : public std::runtime_error {
public:
    Error(skaidb_status_t status, const std::string &message)
        : std::runtime_error(message), status_(status) {}
    skaidb_status_t status() const noexcept { return status_; }

private:
    skaidb_status_t status_;
};

enum class Consistency : int { One = SKAIDB_ONE, Quorum = SKAIDB_QUORUM, All = SKAIDB_ALL };

enum class Type : int {
    Null = SKAIDB_NULL,
    Bool = SKAIDB_BOOL,
    Int = SKAIDB_INT,
    Float = SKAIDB_FLOAT,
    Decimal = SKAIDB_DECIMAL,
    String = SKAIDB_STRING,
    Bytes = SKAIDB_BYTES,
    Uuid = SKAIDB_UUID,
    Timestamp = SKAIDB_TIMESTAMP,
    Array = SKAIDB_ARRAY,
    Document = SKAIDB_DOCUMENT,
};

enum class Kind : int {
    Rows = SKAIDB_RESULT_ROWS,
    Mutation = SKAIDB_RESULT_MUTATION,
    Ddl = SKAIDB_RESULT_DDL,
    Error = SKAIDB_RESULT_ERROR,
    Sets = SKAIDB_RESULT_SETS,
};

/* TLS settings for connect(): how to verify the server certificate and the
 * name it must carry (skaidb clusters sign one DNS name, "skaidb" by
 * default, which is not the address dialled). */
struct Tls {
    enum class Verify : int {
        CaFile = SKAIDB_TLS_CA_FILE,
        System = SKAIDB_TLS_SYSTEM,
        Insecure = SKAIDB_TLS_INSECURE,
    };
    Verify verify = Verify::System;
    std::string ca_file;
    std::string server_name = "skaidb";

    static Tls ca(std::string path, std::string name = "skaidb") {
        Tls t;
        t.verify = Verify::CaFile;
        t.ca_file = std::move(path);
        t.server_name = std::move(name);
        return t;
    }
    static Tls system(std::string name = "skaidb") {
        Tls t;
        t.server_name = std::move(name);
        return t;
    }
    static Tls insecure(std::string name = "skaidb") {
        Tls t;
        t.verify = Verify::Insecure;
        t.server_name = std::move(name);
        return t;
    }
};

namespace detail {

inline std::string last_error() {
    const char *m = skaidb_last_error();
    return m ? std::string(m) : std::string();
}

inline void check(skaidb_status_t s) {
    if (s != SKAIDB_OK) throw Error(s, last_error());
}

template <class T>
T *checked(T *p) {
    if (!p) throw Error(SKAIDB_ERR_INVALID, last_error());
    return p;
}

/* A malloc'd C string into a std::string, freeing it. */
inline std::string take(char *s) {
    if (!s) return std::string();
    std::string out(s);
    skaidb_string_free(s);
    return out;
}

inline std::vector<const char *> c_strings(const std::vector<std::string> &v) {
    std::vector<const char *> out;
    out.reserve(v.size());
    for (const auto &s : v) out.push_back(s.c_str());
    return out;
}

struct TlsRaw {
    skaidb_tls_t raw{};
    const skaidb_tls_t *ptr = nullptr;
    explicit TlsRaw(const std::optional<Tls> &t) {
        if (t) {
            raw.verify = static_cast<skaidb_tls_verify_t>(t->verify);
            raw.ca_file = t->ca_file.empty() ? nullptr : t->ca_file.c_str();
            raw.server_name = t->server_name.c_str();
            ptr = &raw;
        }
    }
};

struct ClientDeleter {
    void operator()(skaidb_client_t *p) const noexcept { skaidb_client_free(p); }
};
struct PreparedDeleter {
    void operator()(skaidb_prepared_t *p) const noexcept { skaidb_prepared_free(p); }
};
struct ResultDeleter {
    void operator()(skaidb_result_t *p) const noexcept { skaidb_result_free(p); }
};
struct ResultsDeleter {
    void operator()(skaidb_results_t *p) const noexcept { skaidb_results_free(p); }
};
struct StreamDeleter {
    void operator()(skaidb_stream_t *p) const noexcept { skaidb_stream_free(p); }
};
struct PoolDeleter {
    void operator()(skaidb_pool_t *p) const noexcept { skaidb_pool_free(p); }
};

}  // namespace detail

/* A borrowed value: a result cell, a stream cell, an array item, a document
 * field. Accessors on the wrong type return the zero value (0, "", empty);
 * check type() when it matters. */
class ValueView {
public:
    ValueView() = default;
    explicit ValueView(const skaidb_value_t *v) noexcept : v_(v) {}

    const skaidb_value_t *raw() const noexcept { return v_; }
    explicit operator bool() const noexcept { return v_ != nullptr; }

    Type type() const noexcept { return static_cast<Type>(skaidb_value_type(v_)); }
    bool is_null() const noexcept { return skaidb_value_is_null(v_); }
    bool as_bool() const noexcept { return skaidb_value_get_bool(v_); }
    std::int64_t as_int() const noexcept { return skaidb_value_get_int(v_); }
    double as_float() const noexcept { return skaidb_value_get_float(v_); }
    std::int64_t as_timestamp() const noexcept { return skaidb_value_get_timestamp(v_); }
    std::string_view as_string_view() const noexcept {
        std::size_t n = 0;
        const char *p = skaidb_value_get_string(v_, &n);
        return p ? std::string_view(p, n) : std::string_view();
    }
    std::string as_string() const { return std::string(as_string_view()); }
    std::vector<std::uint8_t> as_bytes() const {
        std::size_t n = 0;
        const std::uint8_t *p = skaidb_value_get_bytes(v_, &n);
        return p ? std::vector<std::uint8_t>(p, p + n) : std::vector<std::uint8_t>();
    }
    /* 16 bytes, or nullptr for a non-UUID. */
    const std::uint8_t *uuid_bytes() const noexcept { return skaidb_value_get_uuid(v_); }

    /* Arrays and documents. */
    std::size_t size() const noexcept {
        return type() == Type::Document ? skaidb_value_document_len(v_) : skaidb_value_array_len(v_);
    }
    ValueView operator[](std::size_t i) const noexcept {
        return ValueView(type() == Type::Document ? skaidb_value_document_value(v_, i)
                                                  : skaidb_value_array_get(v_, i));
    }
    std::string key(std::size_t i) const {
        const char *k = skaidb_value_document_key(v_, i);
        return k ? std::string(k) : std::string();
    }
    /* Dotted path lookup ("a.b.c"); a null view when absent. */
    ValueView get(const char *path) const noexcept { return ValueView(skaidb_value_document_get(v_, path)); }
    ValueView get(const std::string &path) const noexcept { return get(path.c_str()); }

    /* Text forms: strings as-is, decimals/uuids canonical, the rest JSON. */
    std::string str() const { return detail::take(skaidb_value_to_string_dup(v_)); }
    std::string json() const { return detail::take(skaidb_value_to_json_dup(v_)); }

protected:
    const skaidb_value_t *v_ = nullptr;
};

/* An owned value — a parameter you build. Implicit from the common C++
 * types; the named constructors cover the rest. */
class Value : public ValueView {
public:
    Value() : Value(skaidb_value_null()) {}
    Value(std::nullptr_t) : Value() {}
    Value(bool b) : Value(skaidb_value_bool(b)) {}
    Value(int v) : Value(skaidb_value_int(v)) {}
    Value(long v) : Value(skaidb_value_int(static_cast<std::int64_t>(v))) {}
    Value(long long v) : Value(skaidb_value_int(static_cast<std::int64_t>(v))) {}
    Value(unsigned v) : Value(skaidb_value_int(static_cast<std::int64_t>(v))) {}
    Value(unsigned long v) : Value(skaidb_value_int(static_cast<std::int64_t>(v))) {}
    Value(unsigned long long v) : Value(skaidb_value_int(static_cast<std::int64_t>(v))) {}
    Value(double v) : Value(skaidb_value_float(v)) {}
    Value(const char *s) : Value(skaidb_value_string(s)) {}
    Value(std::string_view s) : Value(skaidb_value_string_len(s.data(), s.size())) {}
    Value(const std::string &s) : Value(skaidb_value_string_len(s.data(), s.size())) {}

    static Value null() { return Value(); }
    /* Exact decimal from its text ("12.50"). */
    static Value decimal(const std::string &text) { return Value(skaidb_value_decimal(text.c_str())); }
    static Value bytes(const std::uint8_t *data, std::size_t len) { return Value(skaidb_value_bytes(data, len)); }
    static Value bytes(const std::vector<std::uint8_t> &b) { return bytes(b.data(), b.size()); }
    static Value uuid(const std::uint8_t (&bytes)[16]) { return Value(skaidb_value_uuid(bytes)); }
    static Value uuid(const std::string &text) { return Value(skaidb_value_uuid_parse(text.c_str())); }
    static Value timestamp(std::int64_t unix_millis) { return Value(skaidb_value_timestamp(unix_millis)); }
    static Value array(const std::vector<Value> &items) {
        std::vector<const skaidb_value_t *> ptrs;
        ptrs.reserve(items.size());
        for (const auto &v : items) ptrs.push_back(v.raw());
        return Value(skaidb_value_array(ptrs.data(), ptrs.size()));
    }
    static Value document(const std::vector<std::pair<std::string, Value>> &fields) {
        std::vector<const char *> keys;
        std::vector<const skaidb_value_t *> vals;
        keys.reserve(fields.size());
        vals.reserve(fields.size());
        for (const auto &kv : fields) {
            keys.push_back(kv.first.c_str());
            vals.push_back(kv.second.raw());
        }
        return Value(skaidb_value_document(keys.data(), vals.data(), keys.size()));
    }
    static Value from_json(const std::string &json) { return Value(skaidb_value_from_json(json.c_str())); }
    /* A deep copy of a borrowed view. */
    static Value copy(ValueView v) { return Value(skaidb_value_clone(v.raw())); }

    Value(const Value &o) : Value(skaidb_value_clone(o.v_)) {}
    Value &operator=(const Value &o) {
        if (this != &o) {
            Value tmp(o);
            swap(tmp);
        }
        return *this;
    }
    Value(Value &&o) noexcept : ValueView(o.v_), owned_(o.owned_) {
        o.v_ = nullptr;
        o.owned_ = nullptr;
    }
    Value &operator=(Value &&o) noexcept {
        if (this != &o) {
            reset();
            v_ = o.v_;
            owned_ = o.owned_;
            o.v_ = nullptr;
            o.owned_ = nullptr;
        }
        return *this;
    }
    ~Value() { reset(); }
    void swap(Value &o) noexcept {
        std::swap(v_, o.v_);
        std::swap(owned_, o.owned_);
    }

private:
    explicit Value(skaidb_value_t *owned) : ValueView(detail::checked(owned)), owned_(owned) {}
    void reset() noexcept {
        skaidb_value_free(owned_);
        owned_ = nullptr;
        v_ = nullptr;
    }
    skaidb_value_t *owned_ = nullptr;
};

/* One row of a result or a stream: n cells by index. */
class Row {
public:
    Row() = default;
    std::size_t size() const noexcept { return n_; }
    ValueView operator[](std::size_t i) const noexcept {
        if (i >= n_) return ValueView();
        return ValueView(cells_ ? cells_[i] : skaidb_result_cell(result_, index_, i));
    }
    ValueView at(std::size_t i) const {
        if (i >= n_) throw std::out_of_range("skaidb::Row: column index out of range");
        return (*this)[i];
    }
    /* The row's index within its result (0 for a stream row). */
    std::size_t index() const noexcept { return index_; }

private:
    friend class ResultView;
    friend class Stream;
    Row(const skaidb_result_t *r, std::size_t index, std::size_t n) : result_(r), index_(index), n_(n) {}
    Row(const skaidb_value_t *const *cells, std::size_t n) : cells_(cells), n_(n) {}
    const skaidb_result_t *result_ = nullptr;
    std::size_t index_ = 0;
    const skaidb_value_t *const *cells_ = nullptr;
    std::size_t n_ = 0;
};

/* A borrowed result: a pipeline entry or a member of a multi-set result. */
class ResultView {
public:
    ResultView() = default;
    explicit ResultView(const skaidb_result_t *r) noexcept : r_(r) {}

    const skaidb_result_t *raw() const noexcept { return r_; }
    explicit operator bool() const noexcept { return r_ != nullptr; }

    Kind kind() const noexcept { return static_cast<Kind>(skaidb_result_kind(r_)); }
    bool is_error() const noexcept { return kind() == Kind::Error; }
    std::string error() const {
        const char *e = skaidb_result_error(r_);
        return e ? std::string(e) : std::string();
    }
    /* Turn an inline (pipeline) error into an exception. */
    void throw_if_error() const {
        if (is_error()) throw Error(SKAIDB_ERR_SERVER, error());
    }

    std::size_t column_count() const noexcept { return skaidb_result_column_count(r_); }
    std::string column_name(std::size_t i) const {
        const char *c = skaidb_result_column_name(r_, i);
        return c ? std::string(c) : std::string();
    }
    std::vector<std::string> columns() const {
        std::vector<std::string> out;
        for (std::size_t i = 0, n = column_count(); i < n; ++i) out.push_back(column_name(i));
        return out;
    }
    std::size_t row_count() const noexcept { return skaidb_result_row_count(r_); }
    std::size_t size() const noexcept { return row_count(); }
    bool empty() const noexcept { return row_count() == 0; }
    Row row(std::size_t i) const noexcept { return Row(r_, i, column_count()); }
    Row operator[](std::size_t i) const noexcept { return row(i); }
    ValueView cell(std::size_t row, std::size_t column) const noexcept {
        return ValueView(skaidb_result_cell(r_, row, column));
    }
    std::uint64_t affected() const noexcept { return skaidb_result_affected(r_); }
    std::size_t set_count() const noexcept { return skaidb_result_set_count(r_); }
    ResultView set(std::size_t i) const noexcept { return ResultView(skaidb_result_set(r_, i)); }

    class iterator {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = Row;
        using difference_type = std::ptrdiff_t;
        using pointer = const Row *;
        using reference = Row;
        iterator() = default;
        iterator(const skaidb_result_t *r, std::size_t i) : r_(r), i_(i) {}
        Row operator*() const { return ResultView(r_).row(i_); }
        iterator &operator++() {
            ++i_;
            return *this;
        }
        iterator operator++(int) {
            iterator t = *this;
            ++i_;
            return t;
        }
        bool operator==(const iterator &o) const noexcept { return r_ == o.r_ && i_ == o.i_; }
        bool operator!=(const iterator &o) const noexcept { return !(*this == o); }

    private:
        const skaidb_result_t *r_ = nullptr;
        std::size_t i_ = 0;
    };
    iterator begin() const noexcept { return iterator(r_, 0); }
    iterator end() const noexcept { return iterator(r_, row_count()); }

protected:
    const skaidb_result_t *r_ = nullptr;
};

/* The owned outcome of one statement. */
class Result : public ResultView {
public:
    explicit Result(skaidb_result_t *r) : ResultView(r), owned_(r) {}
    Result(Result &&o) noexcept : ResultView(o.r_), owned_(std::move(o.owned_)) { o.r_ = nullptr; }
    Result &operator=(Result &&o) noexcept {
        if (this != &o) {
            owned_ = std::move(o.owned_);
            r_ = o.r_;
            o.r_ = nullptr;
        }
        return *this;
    }
    Result(const Result &) = delete;
    Result &operator=(const Result &) = delete;

private:
    std::unique_ptr<skaidb_result_t, detail::ResultDeleter> owned_;
};

/* A pipeline's results, one per statement, in order. */
class Results {
public:
    explicit Results(skaidb_results_t *r) : p_(r) {}
    std::size_t size() const noexcept { return skaidb_results_len(p_.get()); }
    ResultView operator[](std::size_t i) const noexcept { return ResultView(skaidb_results_get(p_.get(), i)); }
    ResultView at(std::size_t i) const {
        if (i >= size()) throw std::out_of_range("skaidb::Results: index out of range");
        return (*this)[i];
    }

    class iterator {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = ResultView;
        using difference_type = std::ptrdiff_t;
        using pointer = const ResultView *;
        using reference = ResultView;
        iterator() = default;
        iterator(const skaidb_results_t *r, std::size_t i) : r_(r), i_(i) {}
        ResultView operator*() const { return ResultView(skaidb_results_get(r_, i_)); }
        iterator &operator++() {
            ++i_;
            return *this;
        }
        iterator operator++(int) {
            iterator t = *this;
            ++i_;
            return t;
        }
        bool operator==(const iterator &o) const noexcept { return r_ == o.r_ && i_ == o.i_; }
        bool operator!=(const iterator &o) const noexcept { return !(*this == o); }

    private:
        const skaidb_results_t *r_ = nullptr;
        std::size_t i_ = 0;
    };
    iterator begin() const noexcept { return iterator(p_.get(), 0); }
    iterator end() const noexcept { return iterator(p_.get(), size()); }

private:
    std::unique_ptr<skaidb_results_t, detail::ResultsDeleter> p_;
};

/* A prepared statement, bound to the client that made it. */
class Prepared {
public:
    explicit Prepared(skaidb_prepared_t *p) : p_(p) {}
    std::size_t params() const noexcept { return skaidb_prepared_params(p_.get()); }
    skaidb_prepared_t *raw() const noexcept { return p_.get(); }

private:
    std::unique_ptr<skaidb_prepared_t, detail::PreparedDeleter> p_;
};

/* A streamed result set: rows arrive in chunks, one chunk resident. The
 * client is borrowed exclusively until the Stream is destroyed (which
 * drains it). */
class Stream {
public:
    explicit Stream(skaidb_stream_t *s) : p_(s) {}
    std::size_t column_count() const noexcept { return skaidb_stream_column_count(p_.get()); }
    std::string column_name(std::size_t i) const {
        const char *c = skaidb_stream_column_name(p_.get(), i);
        return c ? std::string(c) : std::string();
    }
    std::vector<std::string> columns() const {
        std::vector<std::string> out;
        for (std::size_t i = 0, n = column_count(); i < n; ++i) out.push_back(column_name(i));
        return out;
    }
    std::uint64_t affected() const noexcept { return skaidb_stream_affected(p_.get()); }
    /* The next row, or nullopt at the end; valid until the next call. */
    std::optional<Row> next() {
        const skaidb_value_t *const *cells = nullptr;
        std::size_t n = 0;
        skaidb_status_t s = skaidb_stream_next(p_.get(), &cells, &n);
        if (s == SKAIDB_END) return std::nullopt;
        detail::check(s);
        return Row(cells, n);
    }
    skaidb_stream_t *raw() const noexcept { return p_.get(); }

    class iterator {
    public:
        using iterator_category = std::input_iterator_tag;
        using value_type = Row;
        using difference_type = std::ptrdiff_t;
        using pointer = const Row *;
        using reference = const Row &;
        iterator() = default;
        explicit iterator(Stream *s) : s_(s) { advance(); }
        const Row &operator*() const { return *row_; }
        const Row *operator->() const { return &*row_; }
        iterator &operator++() {
            advance();
            return *this;
        }
        void operator++(int) { advance(); }
        bool operator==(const iterator &o) const noexcept { return s_ == o.s_; }
        bool operator!=(const iterator &o) const noexcept { return s_ != o.s_; }

    private:
        void advance() {
            row_ = s_->next();
            if (!row_) s_ = nullptr;
        }
        Stream *s_ = nullptr;
        std::optional<Row> row_;
    };
    iterator begin() { return iterator(this); }
    iterator end() noexcept { return iterator(); }

private:
    std::unique_ptr<skaidb_stream_t, detail::StreamDeleter> p_;
};

/* One connection. */
class Client {
public:
    Client() = default;

    /* SCRAM-SHA-256 across a seed list; the nearest reachable endpoint is
     * dialled and the rest kept for failover. */
    static Client connect(const std::vector<std::string> &endpoints, const std::string &username,
                          const std::string &password, const std::optional<Tls> &tls = std::nullopt) {
        auto eps = detail::c_strings(endpoints);
        detail::TlsRaw t(tls);
        skaidb_client_t *c = nullptr;
        detail::check(skaidb_connect(eps.data(), eps.size(), username.c_str(), password.c_str(), t.ptr, &c));
        return Client(c);
    }
    static Client connect(const std::string &endpoint, const std::string &username, const std::string &password,
                          const std::optional<Tls> &tls = std::nullopt) {
        return connect(std::vector<std::string>{endpoint}, username, password, tls);
    }
    /* A server with authentication disabled. */
    static Client connect_anonymous(const std::string &endpoint) {
        skaidb_client_t *c = nullptr;
        detail::check(skaidb_connect_anonymous(endpoint.c_str(), &c));
        return Client(c);
    }
    /* Kerberos with the ambient ticket cache (needs a `kerberos` build). */
    static Client connect_gssapi(const std::vector<std::string> &endpoints, const std::string &principal,
                                 const std::string &target_spn, const std::optional<Tls> &tls = std::nullopt) {
        auto eps = detail::c_strings(endpoints);
        detail::TlsRaw t(tls);
        skaidb_client_t *c = nullptr;
        detail::check(
            skaidb_connect_gssapi(eps.data(), eps.size(), principal.c_str(), target_spn.c_str(), t.ptr, &c));
        return Client(c);
    }
    /* Take ownership of a raw handle (C interop). */
    static Client adopt(skaidb_client_t *raw) { return Client(raw); }

    Client(Client &&) noexcept = default;
    Client &operator=(Client &&) noexcept = default;
    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;

    skaidb_client_t *raw() const noexcept { return p_.get(); }
    /* Give up ownership of the raw handle. */
    skaidb_client_t *release() noexcept { return p_.release(); }
    explicit operator bool() const noexcept { return static_cast<bool>(p_); }

    void use_database(const std::string &database) {
        detail::check(skaidb_client_use_database(p_.get(), database.c_str()));
    }
    void set_consistency(Consistency c) noexcept {
        skaidb_client_set_consistency(p_.get(), static_cast<skaidb_consistency_t>(c));
    }
    void set_scan_budget_rows(std::uint64_t rows) { detail::check(skaidb_client_set_scan_budget_rows(p_.get(), rows)); }
    std::string endpoint() const { return detail::take(skaidb_client_endpoint_dup(p_.get())); }
    void add_endpoints(const std::vector<std::string> &endpoints) {
        auto eps = detail::c_strings(endpoints);
        detail::check(skaidb_client_add_endpoints(p_.get(), eps.data(), eps.size()));
    }
    void reconnect() { detail::check(skaidb_client_reconnect(p_.get())); }

    /* Any statement — DDL, DML, SELECT, CALL, SHOW. */
    Result execute(const std::string &sql) {
        skaidb_result_t *r = nullptr;
        detail::check(skaidb_execute(p_.get(), sql.c_str(), &r));
        return Result(r);
    }
    Result execute(const std::string &sql, Consistency c) {
        skaidb_result_t *r = nullptr;
        detail::check(skaidb_execute_with(p_.get(), sql.c_str(), static_cast<skaidb_consistency_t>(c), &r));
        return Result(r);
    }
    Prepared prepare(const std::string &sql) {
        skaidb_prepared_t *p = nullptr;
        detail::check(skaidb_prepare(p_.get(), sql.c_str(), &p));
        return Prepared(p);
    }
    Result execute(Prepared &stmt, const std::vector<Value> &params) {
        auto ps = param_ptrs(params);
        skaidb_result_t *r = nullptr;
        detail::check(skaidb_execute_prepared(p_.get(), stmt.raw(), ps.data(), ps.size(), &r));
        return Result(r);
    }
    Result execute(Prepared &stmt, const std::vector<Value> &params, Consistency c) {
        auto ps = param_ptrs(params);
        skaidb_result_t *r = nullptr;
        detail::check(skaidb_execute_prepared_with(p_.get(), stmt.raw(), ps.data(), ps.size(),
                                                   static_cast<skaidb_consistency_t>(c), &r));
        return Result(r);
    }
    /* One prepared statement once per row, one round trip; the total
     * affected count. Every row must have the same number of values. */
    std::uint64_t execute_batch(Prepared &stmt, const std::vector<std::vector<Value>> &rows) {
        if (rows.empty()) return 0;
        const std::size_t n_params = rows.front().size();
        std::vector<std::vector<const skaidb_value_t *>> cells;
        cells.reserve(rows.size());
        for (const auto &row : rows) {
            if (row.size() != n_params)
                throw Error(SKAIDB_ERR_INVALID, "skaidb::Client::execute_batch: rows differ in length");
            cells.push_back(param_ptrs(row));
        }
        std::vector<const skaidb_value_t *const *> ptrs;
        ptrs.reserve(cells.size());
        for (const auto &c : cells) ptrs.push_back(c.data());
        std::uint64_t affected = 0;
        detail::check(skaidb_execute_batch(p_.get(), stmt.raw(), ptrs.data(), ptrs.size(), n_params, &affected));
        return affected;
    }
    /* Several statements in one round trip; per-statement failures come
     * back inline (ResultView::is_error). */
    Results pipeline(const std::vector<std::string> &statements) {
        auto ss = detail::c_strings(statements);
        skaidb_results_t *r = nullptr;
        detail::check(skaidb_pipeline(p_.get(), ss.data(), ss.size(), &r));
        return Results(r);
    }
    /* Streamed rows — the way to read a result larger than the scan budget. */
    Stream query_stream(const std::string &sql) {
        skaidb_stream_t *s = nullptr;
        detail::check(skaidb_query_stream(p_.get(), sql.c_str(), &s));
        return Stream(s);
    }
    Stream query_stream(const std::string &sql, Consistency c) {
        skaidb_stream_t *s = nullptr;
        detail::check(skaidb_query_stream_with(p_.get(), sql.c_str(), static_cast<skaidb_consistency_t>(c), &s));
        return Stream(s);
    }
    /* Change-stream events after `after` ("" to start) and the next cursor. */
    struct Events {
        Result events;
        std::string next_cursor;
    };
    Events stream_poll(const std::string &stream, const std::string &after, std::size_t limit) {
        skaidb_result_t *r = nullptr;
        char *cursor = nullptr;
        detail::check(skaidb_stream_poll(p_.get(), stream.c_str(), after.c_str(), limit, &r, &cursor));
        return Events{Result(r), detail::take(cursor)};
    }

private:
    explicit Client(skaidb_client_t *c) : p_(c) {}
    static std::vector<const skaidb_value_t *> param_ptrs(const std::vector<Value> &params) {
        std::vector<const skaidb_value_t *> ps;
        ps.reserve(params.size());
        for (const auto &v : params) ps.push_back(v.raw());
        return ps;
    }
    std::unique_ptr<skaidb_client_t, detail::ClientDeleter> p_;
};

/* A thread-safe pool of connections with the same settings; `maxsize` is
 * how many idle connections it keeps. */
class Pool {
public:
    Pool(std::size_t maxsize, const std::vector<std::string> &endpoints, const std::string &username,
         const std::string &password, const std::optional<Tls> &tls = std::nullopt,
         const std::optional<std::string> &database = std::nullopt) {
        auto eps = detail::c_strings(endpoints);
        detail::TlsRaw t(tls);
        p_.reset(detail::checked(skaidb_pool_new(maxsize, eps.data(), eps.size(), username.c_str(),
                                                 password.c_str(), t.ptr, database ? database->c_str() : nullptr)));
    }

    /* A connection on loan: returned to the pool when the Lease dies. */
    class Lease {
    public:
        Lease(Lease &&o) noexcept : pool_(o.pool_), client_(std::move(o.client_)) { o.pool_ = nullptr; }
        Lease &operator=(Lease &&o) noexcept {
            if (this != &o) {
                release();
                pool_ = o.pool_;
                client_ = std::move(o.client_);
                o.pool_ = nullptr;
            }
            return *this;
        }
        Lease(const Lease &) = delete;
        Lease &operator=(const Lease &) = delete;
        ~Lease() { release(); }

        Client &client() noexcept { return client_; }
        Client &operator*() noexcept { return client_; }
        Client *operator->() noexcept { return &client_; }
        /* Return the connection now. */
        void release() noexcept {
            if (pool_ && client_.raw()) skaidb_pool_release(pool_, client_.release());
            pool_ = nullptr;
        }

    private:
        friend class Pool;
        Lease(skaidb_pool_t *pool, skaidb_client_t *c) : pool_(pool), client_(Client::adopt(c)) {}
        skaidb_pool_t *pool_ = nullptr;
        Client client_;
    };

    Lease acquire() {
        skaidb_client_t *c = nullptr;
        detail::check(skaidb_pool_acquire(p_.get(), &c));
        return Lease(p_.get(), c);
    }
    /* Run `f(Client&)` on a pooled connection and return its result. */
    template <class F>
    auto with(F &&f) -> decltype(f(std::declval<Client &>())) {
        Lease lease = acquire();
        return f(lease.client());
    }
    std::size_t idle_len() const noexcept { return skaidb_pool_idle_len(p_.get()); }

private:
    std::unique_ptr<skaidb_pool_t, detail::PoolDeleter> p_;
};

inline const char *version() noexcept { return skaidb_version(); }

}  // namespace skaidb

#endif /* SKAIDB_HPP */
