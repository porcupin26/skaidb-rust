//! The shared wire-protocol conformance suite (`conformance/vectors.json`,
//! contract in `conformance/README.md`), run against this driver through
//! its public API and a scripted fake server that sends the REFERENCE bytes
//! from the vectors — never bytes this driver encoded itself.

use std::net::TcpListener;
use std::thread;

use serde_json::{json, Value as J};
use skaidb::{Client, Consistency, DriverError, Response, Value};
use skaidb_proto::{
    read_frame, write_frame, AuthChallenge, AuthFinish, AuthOutcome, AuthStart,
};
use skaidb_types::{Decimal, Document, Uuid};

fn vectors() -> J {
    let here = env!("CARGO_MANIFEST_DIR");
    // In the monorepo the vectors sit at the workspace root; the generated
    // mirror vendors them at its own root.
    for rel in ["../../conformance/vectors.json", "conformance/vectors.json"] {
        if let Ok(text) = std::fs::read_to_string(format!("{here}/{rel}")) {
            return serde_json::from_str(&text).expect("vectors.json parses");
        }
    }
    panic!("conformance/vectors.json not found");
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A driver value in the vectors' tagged JSON form.
fn tagged(v: &Value) -> J {
    match v {
        Value::Null => json!({"null": true}),
        Value::Bool(b) => json!({"bool": b}),
        Value::Int(i) => json!({"int": i.to_string()}),
        Value::Float(f) => json!({"float": f, "float_bits": format!("{:016x}", f.to_bits())}),
        Value::Decimal(d) => json!({"decimal": {"mantissa": d.mantissa.to_string(), "scale": d.scale}}),
        Value::String(s) => json!({"string": s}),
        Value::Bytes(b) => json!({"bytes": hex(b)}),
        Value::Uuid(u) => {
            let h = hex(&u.0);
            json!({"uuid": format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])})
        }
        Value::Timestamp(ms) => json!({"timestamp_ms": ms.to_string()}),
        Value::Array(items) => json!({"array": items.iter().map(tagged).collect::<Vec<_>>()}),
        Value::Document(d) => json!({"document": d.0.iter()
            .map(|(k, v)| json!({"key": k, "value": tagged(v)})).collect::<Vec<_>>()}),
    }
}

/// A tagged JSON value as a driver value (for parameters).
fn native(t: &J) -> Value {
    let o = t.as_object().expect("tagged value is an object");
    let (k, v) = o
        .iter()
        .find(|(k, _)| k.as_str() != "float")
        .or_else(|| o.iter().next())
        .unwrap();
    match k.as_str() {
        "null" => Value::Null,
        "bool" => Value::Bool(v.as_bool().unwrap()),
        "int" => Value::Int(v.as_str().unwrap().parse().unwrap()),
        "float_bits" | "float" => Value::Float(f64::from_bits(
            u64::from_str_radix(o["float_bits"].as_str().unwrap(), 16).unwrap(),
        )),
        "decimal" => Value::Decimal(Decimal::new(
            v["mantissa"].as_str().unwrap().parse().unwrap(),
            v["scale"].as_u64().unwrap() as u32,
        )),
        "string" => Value::String(v.as_str().unwrap().into()),
        "bytes" => Value::Bytes(unhex(v.as_str().unwrap())),
        "uuid" => {
            let b = unhex(&v.as_str().unwrap().replace('-', ""));
            Value::Uuid(Uuid(b.try_into().unwrap()))
        }
        "timestamp_ms" => Value::Timestamp(v.as_str().unwrap().parse().unwrap()),
        "array" => Value::Array(v.as_array().unwrap().iter().map(native).collect()),
        "document" => {
            let mut d = Document::new();
            for e in v.as_array().unwrap() {
                d.insert(e["key"].as_str().unwrap(), native(&e["value"]));
            }
            Value::Document(d)
        }
        other => panic!("unknown tagged value {other}"),
    }
}

fn rows_json(columns: &[String], rows: &[Vec<Value>]) -> J {
    json!({"columns": columns, "rows": rows.iter()
        .map(|r| r.iter().map(tagged).collect::<Vec<_>>()).collect::<Vec<_>>()})
}

#[derive(Clone, Copy, PartialEq)]
enum Outcome {
    Ok,
    BadSignature,
    Denied,
}

/// One scripted connection: the handshake per `outcome`, then the
/// exchanges. Returns any mismatch it saw (the driver side cannot).
fn fake_server(v: &J, outcome: Outcome, exchanges: Vec<(Vec<u8>, Vec<Vec<u8>>)>) -> (String, thread::JoinHandle<Result<(), String>>) {
    use skaidb_auth::scram::{client_proof_salted, salted_password, server_signature_salted};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let auth = v["auth"].clone();
    let ddl = unhex(v["ignorable_requests"]["ddl_payload"].as_str().unwrap());
    let denied = v["auth"]["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["name"] == "denied")
        .map(|o| unhex(o["payload"].as_str().unwrap()))
        .unwrap();
    let h = thread::spawn(move || -> Result<(), String> {
        let (mut s, _) = listener.accept().map_err(|e| e.to_string())?;
        let start = AuthStart::decode(&read_frame(&mut s).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let salt = unhex(auth["challenge"]["salt"].as_str().unwrap());
        let iterations = auth["challenge"]["iterations"].as_u64().unwrap() as u32;
        let server_nonce = format!(
            "{}{}",
            start.client_nonce,
            auth["challenge"]["server_nonce_suffix"].as_str().unwrap()
        );
        write_frame(
            &mut s,
            &AuthChallenge {
                salt: salt.clone(),
                iterations,
                server_nonce: server_nonce.clone(),
            }
            .encode(),
        )
        .map_err(|e| e.to_string())?;
        let finish = AuthFinish::decode(&read_frame(&mut s).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let am = skaidb_proto::auth_message(&start.username, &start.client_nonce, &server_nonce, &salt, iterations);
        let salted = salted_password(auth["password"].as_str().unwrap(), &salt, iterations);
        if finish.client_proof != client_proof_salted(&salted, &am) {
            return Err("client proof did not verify".into());
        }
        let reply = match outcome {
            Outcome::Ok => AuthOutcome::Ok { server_signature: server_signature_salted(&salted, &am) }.encode(),
            Outcome::BadSignature => AuthOutcome::Ok { server_signature: [0xAA; 32] }.encode(),
            Outcome::Denied => denied,
        };
        write_frame(&mut s, &reply).map_err(|e| e.to_string())?;
        if outcome != Outcome::Ok {
            return Ok(());
        }
        let mut pending = exchanges.into_iter();
        loop {
            let Ok(req) = read_frame(&mut s) else {
                // The driver closed the connection.
                return match pending.next() {
                    None => Ok(()),
                    Some((want, _)) => Err(format!("never received request {}", hex(&want))),
                };
            };
            if matches!(req.first(), Some(4) | Some(8)) {
                write_frame(&mut s, &ddl).map_err(|e| e.to_string())?;
                continue;
            }
            let Some((want, responses)) = pending.next() else {
                return Err(format!("unexpected extra request {}", hex(&req)));
            };
            if req != want {
                return Err(format!("request mismatch:\n  got  {}\n  want {}", hex(&req), hex(&want)));
            }
            for r in responses {
                write_frame(&mut s, &r).map_err(|e| e.to_string())?;
            }
        }
    });
    (addr, h)
}

fn consistency(name: &str) -> Consistency {
    match name {
        "one" => Consistency::One,
        "all" => Consistency::All,
        _ => Consistency::Quorum,
    }
}

fn outcome_json(r: Result<Response, DriverError>) -> J {
    match r {
        Ok(Response::Rows { columns, rows }) => json!({"rows": rows_json(&columns, &rows)}),
        Ok(Response::Mutation { affected }) => json!({"affected": affected.to_string()}),
        Ok(Response::Ddl) => json!({"ddl": true}),
        Ok(Response::ResultSets { sets }) => json!({"result_sets": sets.iter()
            .map(|(c, r)| rows_json(c, r)).collect::<Vec<_>>()}),
        Ok(other) => json!({"unexpected": format!("{other:?}")}),
        Err(DriverError::Server(msg)) => json!({"error": msg}),
        Err(e) => json!({"driver_error": e.to_string()}),
    }
}

fn run_call(client: &mut Client, call: &J) -> J {
    let sql = call["sql"].as_str().unwrap_or_default();
    match call["method"].as_str().unwrap() {
        "query" => outcome_json(client.execute_with(sql, consistency(call["consistency"].as_str().unwrap()))),
        "query_stream" => {
            let params: Vec<Value> = call["params"]
                .as_array()
                .map(|a| a.iter().map(native).collect())
                .unwrap_or_default();
            let mut stream = match client.query_stream_params(sql, &params) {
                Ok(s) => s,
                Err(e) => return outcome_json(Err(e)),
            };
            if stream.columns.is_empty() {
                return json!({"affected": stream.affected.to_string()});
            }
            // Every set: a streamed CALL that EMITs walks them in order.
            let mut sets = Vec::new();
            loop {
                let columns = stream.columns.clone();
                let mut rows = Vec::new();
                for row in stream.by_ref() {
                    match row {
                        Ok(r) => rows.push(r),
                        Err(DriverError::Server(msg)) => {
                            return json!({"rows_then_error": {"rows": rows_json(&columns, &rows), "error": msg}})
                        }
                        Err(e) => return json!({"driver_error": e.to_string()}),
                    }
                }
                sets.push(rows_json(&columns, &rows));
                if !stream.next_result_set() {
                    break;
                }
            }
            match sets.len() {
                1 => json!({"rows": sets.pop()}),
                _ => json!({"result_sets": sets}),
            }
        }
        "execute_prepared" => {
            let mut stmt = client.prepare(sql).expect("prepare");
            let params: Vec<Value> = call["params"].as_array().unwrap().iter().map(native).collect();
            outcome_json(client.execute_prepared_with(&mut stmt, &params, consistency(call["consistency"].as_str().unwrap())))
        }
        "execute_batch" => {
            let mut stmt = client.prepare(sql).expect("prepare");
            let rows: Vec<Vec<Value>> = call["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_array().unwrap().iter().map(native).collect())
                .collect();
            match client.execute_batch(&mut stmt, rows) {
                Ok(n) => json!({"affected": n.to_string()}),
                Err(e) => outcome_json(Err(e)),
            }
        }
        "sequence" => json!({"sequence": call["calls"].as_array().unwrap().iter()
            .map(|c| run_call(client, c)).collect::<Vec<_>>()}),
        other => panic!("unknown call.method {other}"),
    }
}

/// `expect` matches when every key agrees, `error` by containment.
fn matches(expect: &J, got: &J) -> bool {
    match (expect, got) {
        (J::Object(e), J::Object(g)) if e.contains_key("error") && g.contains_key("error") => {
            g["error"].as_str().unwrap_or("").contains(e["error"].as_str().unwrap_or("\u{0}"))
        }
        (J::Object(e), J::Object(g)) if e.contains_key("sequence") => {
            let (es, gs) = (e["sequence"].as_array().unwrap(), g["sequence"].as_array());
            gs.is_some_and(|gs| es.len() == gs.len() && es.iter().zip(gs).all(|(a, b)| matches(a, b)))
        }
        (J::Object(e), J::Object(g)) if e.contains_key("rows_then_error") => {
            let (ei, gi) = (&e["rows_then_error"], &g["rows_then_error"]);
            ei["rows"] == gi["rows"] && gi["error"].as_str().unwrap_or("").contains(ei["error"].as_str().unwrap())
        }
        _ => expect == got,
    }
}

#[test]
fn values_decode_to_their_vectors() {
    let v = vectors();
    for entry in v["values"].as_array().unwrap() {
        let bytes = unhex(entry["encoded"].as_str().unwrap());
        let decoded = Value::decode(&bytes).unwrap_or_else(|e| panic!("{}: {e}", entry["name"]));
        assert_eq!(tagged(&decoded), entry["value"], "decode {}", entry["name"]);
        assert_eq!(hex(&native(&entry["value"]).encode()), entry["encoded"], "encode {}", entry["name"]);
    }
}

#[test]
fn scram_computations_match() {
    use skaidb_auth::scram::{client_proof_salted, salted_password, server_signature_salted};
    let v = vectors();
    for s in v["scram"].as_array().unwrap() {
        let salt = unhex(s["salt"].as_str().unwrap());
        let it = s["iterations"].as_u64().unwrap() as u32;
        let am = skaidb_proto::auth_message(
            s["username"].as_str().unwrap(),
            s["client_nonce"].as_str().unwrap(),
            s["server_nonce"].as_str().unwrap(),
            &salt,
            it,
        );
        assert_eq!(hex(&am), s["auth_message"]);
        let salted = salted_password(s["password"].as_str().unwrap(), &salt, it);
        assert_eq!(hex(&salted), s["salted_password"]);
        assert_eq!(hex(&client_proof_salted(&salted, &am)), s["client_proof"]);
        assert_eq!(hex(&server_signature_salted(&salted, &am)), s["server_signature"]);
    }
}

#[test]
fn auth_outcomes() {
    let v = vectors();
    let user = v["auth"]["username"].as_str().unwrap().to_string();
    let pass = v["auth"]["password"].as_str().unwrap().to_string();
    for (outcome, name) in [(Outcome::Ok, "ok"), (Outcome::BadSignature, "bad_server_signature"), (Outcome::Denied, "denied")] {
        let (addr, h) = fake_server(&v, outcome, vec![]);
        let r = Client::connect_with(addr.as_str(), &user, &pass);
        match (outcome, r) {
            (Outcome::Ok, r) => assert!(r.is_ok(), "{name}: {:?}", r.err()),
            (Outcome::BadSignature, r) => {
                assert!(r.is_err(), "{name}: a signature that does not verify must fail the connect")
            }
            (Outcome::Denied, r) => {
                let e = r.expect_err("denied connect fails").to_string();
                assert!(e.contains("invalid credentials"), "{name}: {e}");
            }
        }
        h.join().unwrap().unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn cases() {
    let v = vectors();
    let user = v["auth"]["username"].as_str().unwrap().to_string();
    let pass = v["auth"]["password"].as_str().unwrap().to_string();
    let mut failures = Vec::new();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let exchanges: Vec<(Vec<u8>, Vec<Vec<u8>>)> = case["exchanges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    unhex(e["request"].as_str().unwrap()),
                    e["responses"].as_array().unwrap().iter().map(|r| unhex(r.as_str().unwrap())).collect(),
                )
            })
            .collect();
        let (addr, h) = fake_server(&v, Outcome::Ok, exchanges);
        let got = {
            let mut client = Client::connect_with(addr.as_str(), &user, &pass).expect("connect");
            run_call(&mut client, &case["call"])
        };
        if let Err(e) = h.join().unwrap() {
            failures.push(format!("{name}: server saw: {e}"));
        }
        if !matches(&case["expect"], &got) {
            failures.push(format!("{name}:\n  expected {}\n  got      {}", case["expect"], got));
        }
    }
    assert!(failures.is_empty(), "{} case(s) failed:\n{}", failures.len(), failures.join("\n"));
}

// ---- beyond the vectors: a streamed CALL whose body EMITs (PROTOCOL.md §3.2)

/// `u32` little-endian, as every length and count on the wire.
fn le32(n: usize) -> Vec<u8> {
    (n as u32).to_le_bytes().to_vec()
}

/// A length-prefixed UTF-8 string.
fn wire_text(s: &str) -> Vec<u8> {
    [le32(s.len()), s.as_bytes().to_vec()].concat()
}

/// A Rows body of one TEXT column: the column block, then the rows, each
/// cell a length-prefixed String value (tag 5). Built from the spec, not
/// with the driver's encoder.
fn one_column_rows(column: &str, cells: &[&str]) -> Vec<u8> {
    let mut b = [le32(1), wire_text(column), le32(cells.len())].concat();
    for c in cells {
        let value = [vec![5u8], wire_text(c)].concat();
        b.extend([le32(1), le32(value.len()), value].concat());
    }
    b
}

/// The server answers a CALL whose body EMITs with ONE ResultSets frame, to
/// a stream request too: the stream starts on the first set,
/// `next_result_set` walks the rest, and nothing is left on the socket.
#[test]
fn a_streamed_call_returns_its_result_sets() {
    let v = vectors();
    let user = v["auth"]["username"].as_str().unwrap().to_string();
    let pass = v["auth"]["password"].as_str().unwrap().to_string();
    // [a: x, y] then [b: z].
    let sets = [
        vec![8u8],
        le32(2),
        one_column_rows("a", &["x", "y"]),
        one_column_rows("b", &["z"]),
    ]
    .concat();
    let quorum = 1u8;
    let bound = "CALL report(?)";
    let five = [vec![2u8], 5i64.to_le_bytes().to_vec()].concat(); // Int 5
    let with_params = [
        vec![9u8, quorum],
        wire_text(bound),
        1u16.to_le_bytes().to_vec(),
        le32(five.len()),
        five,
    ]
    .concat();
    let plain = [vec![5u8, quorum], wire_text("CALL report()")].concat();
    let query = [vec![1u8, quorum], wire_text("SELECT 1")].concat();
    let one = [
        vec![0u8],
        le32(1),
        wire_text("x"),
        le32(1),
        le32(1),
        le32(9),
        vec![2u8],
        1i64.to_le_bytes().to_vec(),
    ]
    .concat();
    let (addr, h) = fake_server(
        &v,
        Outcome::Ok,
        vec![
            (with_params, vec![sets.clone()]),
            (plain, vec![sets]),
            (query, vec![one]),
        ],
    );
    {
        let mut client = Client::connect_with(addr.as_str(), &user, &pass).expect("connect");
        for (sql, params) in [(bound, vec![Value::Int(5)]), ("CALL report()", vec![])] {
            let mut stream = client.query_stream_params(sql, &params).expect(sql);
            let mut walked = Vec::new();
            loop {
                let mut set = format!("{}:", stream.columns.join(","));
                for row in stream.by_ref() {
                    match row.expect("row").as_slice() {
                        [Value::String(s)] => set.push_str(s),
                        other => panic!("{sql}: unexpected row {other:?}"),
                    }
                }
                walked.push(set);
                if !stream.next_result_set() {
                    break;
                }
            }
            assert_eq!(walked.join("|"), "a:xy|b:z", "{sql}");
            assert!(!stream.next_result_set());
        }
        // The same socket answers the next statement: nothing was left on it.
        match client.execute("SELECT 1").expect("the next statement") {
            Response::Rows { rows, .. } => assert_eq!(rows, vec![vec![Value::Int(1)]]),
            other => panic!("unexpected {other:?}"),
        }
    }
    h.join()
        .unwrap()
        .unwrap_or_else(|e| panic!("server saw: {e}"));
}
