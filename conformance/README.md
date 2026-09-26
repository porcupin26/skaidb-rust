# skaidb wire-protocol conformance vectors

`vectors.json` is the one conformance suite every official skaidb driver
runs in its own CI. It is generated from the server's reference encoders
(`cargo run -p skaidb-conformance -- --write` in the monorepo), so a driver
is checked against the server's own bytes, never against its own encoder.
It is published at <https://skaidb.org/conformance/vectors.json>; each
driver repository vendors a copy under `conformance/vectors.json` and its CI
fails when that copy differs from the published one.

The spec it tests is [PROTOCOL.md](https://skaidb.org/docs/PROTOCOL.html).

## What a driver's harness does

A harness is a test in the driver's own language with three parts.

### 1. Pure vectors

- **`values`**: each entry has `name`, `value` (tagged JSON, below) and
  `encoded` (hex of the §4 encoding). The harness decodes `encoded` with the
  driver's decoder and compares the result to `value`, and, where the
  driver can encode that value as a parameter, encodes `value` and compares
  the bytes to `encoded`.
- **`scram`**: each entry gives `username`, `password`, `salt`,
  `iterations`, `client_nonce`, `server_nonce` and the expected
  `auth_message`, `salted_password`, `client_proof` and `server_signature`
  (hex). The harness computes each with the driver's own SCRAM code.

### 2. A scripted fake server

The harness starts a TCP listener and connects the driver to it with
`auth.username` / `auth.password`. For every connection the fake server:

1. Reads `AuthStart` (tag 10). It answers `AuthChallenge` (tag 11) with
   `auth.challenge.salt`, `auth.challenge.iterations`, and a server nonce
   equal to the client's nonce followed by
   `auth.challenge.server_nonce_suffix`.
2. Reads `AuthFinish` (tag 12) and verifies the client proof with
   HMAC-SHA-256 / PBKDF2 over the auth message (§2.1), computed
   independently of the driver's code.
3. Answers `AuthOutcome` (tag 13) according to the outcome under test (see
   below). For the `ok` outcome it sends the correct server signature.

Then it serves requests. `OP_CLOSE` (4) and `OP_HELLO` (8) may arrive at any
point: answer them with `ignorable_requests.ddl_payload` and do not count
them. Every other request must equal the next `exchanges[i].request` of the
case being run, byte for byte; the fake server then sends every payload in
`exchanges[i].responses`, each as its own frame (§1, big-endian length).

### 3. Cases

Each entry of `cases` has a `call`, one or more `exchanges`, and an
`expect`. The harness makes the call through the driver's PUBLIC API:

| `call.method`      | The driver API to use                                                     |
|--------------------|---------------------------------------------------------------------------|
| `query`            | run `call.sql` at `call.consistency` (one / quorum / all)                  |
| `query_stream`     | the streaming query API (`OP_QUERY_STREAM`), iterating every row           |
| `execute_prepared` | prepare `call.sql`, execute it with `call.params` (tagged JSON values)     |
| `execute_batch`    | prepare `call.sql`, run the batch API (`OP_EXECUTE_BATCH`) with `call.rows` |
| `sequence`         | run each of `call.calls` in order on the same connection                  |

and compares what the driver returns to `expect`:

| `expect` key      | Meaning                                                                           |
|-------------------|-----------------------------------------------------------------------------------|
| `rows`            | `{columns, rows}` — column names and cell values (tagged JSON)                     |
| `affected`        | the affected-row count, as a decimal string                                        |
| `ddl`             | the statement succeeded without rows or a count                                    |
| `error`           | the driver raised / returned its query error, whose message CONTAINS this text      |
| `result_sets`     | every result set in order (drivers that expose only the last compare that one)    |
| `rows_then_error` | a stream yielded `rows` and then raised `error`                                    |
| `sequence`        | one of the above per call of a `sequence`                                          |

A harness may skip a case whose `call.method` the driver has no API for,
but it must say so in its output, and the driver's README must list what
it skips.

### Auth outcomes

`auth.outcomes` lists handshakes a driver must get right, each run on a
fresh connection before any case: `ok` (correct server signature: connect
succeeds), `bad_server_signature` (the fake server sends 32 bytes that do
not verify: the connect must FAIL — mutual authentication), and `denied`
(the fake server sends the outcome in `payload`: the connect fails with
`reason` in the error).

## Tagged JSON values

| Type      | Form                                                            |
|-----------|-----------------------------------------------------------------|
| Null      | `{"null": true}`                                                |
| Bool      | `{"bool": true}`                                                |
| Int       | `{"int": "-9223372036854775808"}` (decimal string, i64)         |
| Float     | `{"float": 1.5, "float_bits": "3ff8000000000000"}` (compare the bits) |
| Decimal   | `{"decimal": {"mantissa": "12345", "scale": 2}}` (value = mantissa / 10^scale) |
| String    | `{"string": "…"}`                                               |
| Bytes     | `{"bytes": "00017f80ff"}` (hex)                                 |
| Uuid      | `{"uuid": "123e4567-e89b-12d3-a456-426614174000"}`              |
| Timestamp | `{"timestamp_ms": "1700000000123"}` (Unix milliseconds)         |
| Array     | `{"array": [ … ]}`                                              |
| Document  | `{"document": [{"key": "a", "value": { … }}, …]}` (wire order)  |

A driver maps its native values onto these forms. When a language has no
faithful native form (a Decimal surfaced as a string, a Uuid as text), the
harness converts the tagged value to the driver's documented form and
compares that.

## Versioning

`format_version` changes only when the document's shape changes (a new
section, a new `call.method` or `expect` key). New cases and values do not
change it; a harness must ignore sections it does not know.
