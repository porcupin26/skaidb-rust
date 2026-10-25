//! Mixed-workload probe over the binary protocol: point readers alone and
//! beside single-row writers and range aggregates, each class for a fixed
//! time, reporting ops/s and latency percentiles per class — the shape in
//! which point reads collapsed beside range aggregates under the single
//! engine lock (perf round 2: 17k/s alone → 700/s combined).
//!
//! Usage: mixed_probe <addr[,addr…]> <user> <pass> <secs> <readers> <writers> <aggs> [rows]
//! The table `mix` (`id`, `v`, `k`, `n`) is created and loaded with `rows`
//! rows (default 200,000) when it does not hold them yet.
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use skaidb::Client;
use skaidb::Response;

fn connect(addrs: &[String], user: &str, pass: &str, i: usize) -> Client {
    let addr = &addrs[i % addrs.len()];
    if pass == "-" {
        // An anonymous cluster (authentication disabled).
        Client::connect(addr).expect("connect")
    } else {
        Client::connect_with(addr, user, pass).expect("connect")
    }
}

fn ok(c: &mut Client, sql: &str) -> bool {
    matches!(c.execute(sql), Ok(r) if !matches!(r, Response::Error(_)))
}

fn pct(v: &[f64], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)]
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 8 {
        eprintln!("usage: mixed_probe <addrs> <user> <pass> <secs> <readers> <writers> <aggs> [rows]");
        std::process::exit(2);
    }
    let addrs: Vec<String> = a[1].split(',').map(|s| s.trim().to_string()).collect();
    let (user, pass) = (a[2].clone(), a[3].clone());
    let secs: u64 = a[4].parse().unwrap();
    let counts: Vec<usize> = a[5..8].iter().map(|s| s.parse().unwrap()).collect();
    let rows: usize = a.get(8).map_or(200_000, |s| s.parse().unwrap());
    {
        let mut c = connect(&addrs, &user, &pass, 0);
        assert!(ok(&mut c, "CREATE TABLE IF NOT EXISTS mix (PRIMARY KEY (id))"));
        let _ = c.execute("CREATE INDEX IF NOT EXISTS mix_k ON mix (k)");
        let loaded = matches!(
            c.execute(&format!("SELECT id FROM mix WHERE id = {}", rows - 1)),
            Ok(Response::Rows { rows: r, .. }) if !r.is_empty()
        );
        if !loaded {
            let payload = "w".repeat(200);
            let mut id = 0;
            while id < rows {
                let end = (id + 500).min(rows);
                let vals: Vec<String> = (id..end).map(|i| format!("({i}, '{payload}', {}, {})", i % 1000, i as f64 / 7.0)).collect();
                assert!(ok(&mut c, &format!("INSERT INTO mix (id, v, k, n) VALUES {}", vals.join(","))), "load");
                id = end;
            }
            std::thread::sleep(Duration::from_secs(5));
            eprintln!("loaded {rows} rows");
        }
    }
    let classes = ["read", "write", "agg"];
    let total: usize = counts.iter().sum();
    let barrier = Arc::new(Barrier::new(total + 1));
    let addrs = Arc::new(addrs);
    let mut handles = Vec::new();
    let mut idx = 0usize;
    for (ci, &n) in counts.iter().enumerate() {
        for _ in 0..n {
            let (addrs, user, pass, barrier) = (Arc::clone(&addrs), user.clone(), pass.clone(), Arc::clone(&barrier));
            let seed = idx as u64;
            idx += 1;
            handles.push(std::thread::spawn(move || {
                let mut c = connect(&addrs, &user, &pass, seed as usize);
                barrier.wait();
                let stop = Instant::now() + Duration::from_secs(secs);
                let (mut lat, mut errs, mut rng) = (Vec::new(), 0usize, seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407));
                while Instant::now() < stop {
                    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                    let k = (rng % rows as u64) as usize;
                    let sql = match ci {
                        0 => format!("SELECT v FROM mix WHERE id = {k}"),
                        1 => format!("INSERT INTO mix (id, v, k, n) VALUES ({k}, '{}', {}, {})", "w".repeat(200), k % 1000, k as f64 / 11.0),
                        _ => format!("SELECT count(*), sum(n), avg(n) FROM mix WHERE id >= {k} AND id < {}", k + 20_000),
                    };
                    let t = Instant::now();
                    if ok(&mut c, &sql) {
                        lat.push(t.elapsed().as_secs_f64() * 1000.0);
                    } else {
                        errs += 1;
                    }
                }
                (ci, lat, errs)
            }));
        }
    }
    barrier.wait();
    let mut per: Vec<(Vec<f64>, usize)> = vec![(Vec::new(), 0); 3];
    for h in handles {
        let (ci, lat, errs) = h.join().unwrap();
        per[ci].0.extend(lat);
        per[ci].1 += errs;
    }
    let mut out = format!("readers={} writers={} aggs={} secs={secs}", counts[0], counts[1], counts[2]);
    for (ci, (lat, errs)) in per.iter_mut().enumerate() {
        if lat.is_empty() && *errs == 0 {
            continue;
        }
        lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
        out.push_str(&format!(
            " | {}: {:.0}/s p50 {:.2} ms p99 {:.2} ms err {}",
            classes[ci],
            lat.len() as f64 / secs as f64,
            pct(lat, 0.5),
            pct(lat, 0.99),
            errs
        ));
    }
    println!("{out}");
}
