//! Process-wide server (operational) log.
//!
//! Distinct from the per-query *audit* log: this carries startup, membership,
//! anti-entropy and bind/listen events — the things an operator greps for when
//! a node misbehaves. It lives in this leaf crate so both the server and the
//! cluster background threads can reach it without a dependency cycle.
//!
//! The destination is set once at startup with [`init_server_log`] from
//! `observability.log_file`: a path makes `skaidb.log` the catch-all server log;
//! an empty path keeps lines on stderr (journald under systemd). Writing before
//! init, or with no path configured, falls back to stderr.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

/// Where operational lines go: stderr (the default) or an append-mode file.
enum Sink {
    Stderr,
    File(Mutex<std::fs::File>),
}

static SERVER_LOG: OnceLock<Sink> = OnceLock::new();

/// Point the server log at `path` (empty = stderr). Idempotent: only the first
/// call wins, so it should run once early in startup, before workers spawn. A
/// path that can't be opened logs the reason once and stays on stderr.
pub fn init_server_log(path: &str) {
    let sink = if path.is_empty() {
        Sink::Stderr
    } else {
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(f) => Sink::File(Mutex::new(f)),
            Err(e) => {
                eprintln!("skaidb: cannot open log file {path}: {e}; logging to stderr instead");
                Sink::Stderr
            }
        }
    };
    let _ = SERVER_LOG.set(sink);
}

/// Current wall time as an ISO-8601 UTC string with millisecond precision
/// (`2026-07-20T18:42:13.123Z`) — every server/audit log line's prefix, and
/// the `ts` field of JSON-format audit lines.
pub fn log_timestamp() -> String {
    let mut out = String::with_capacity(24);
    log_timestamp_into(&mut out);
    out
}

/// [`log_timestamp`] appended to `out` — the per-statement audit line
/// builds itself into one buffer, and a `format!` with six padded fields was
/// a third of that line's cost (callgrind, 2026-09-02). Digits are pushed
/// by hand for the same reason.
pub fn log_timestamp_into(out: &mut String) {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    // Civil-from-days (Howard Hinnant's algorithm) — same math as the SQL
    // timestamp formatter, kept dependency-free in this leaf crate.
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let (secs, ms_part) = (rem / 1000, rem % 1000);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    push_padded(out, y, 4);
    out.push('-');
    push_padded(out, m, 2);
    out.push('-');
    push_padded(out, d, 2);
    out.push('T');
    push_padded(out, hh, 2);
    out.push(':');
    push_padded(out, mm, 2);
    out.push(':');
    push_padded(out, ss, 2);
    out.push('.');
    push_padded(out, ms_part, 3);
    out.push('Z');
}

/// `n` zero-padded to `width` digits (`{n:0width$}`) without the formatter.
/// Values wider than `width` print in full, as the formatter would.
fn push_padded(out: &mut String, n: i64, width: usize) {
    // The timestamp's seven fields are all non-negative and fit their width
    // (a year is four digits until 10000): pure fixed-width digit pushes.
    if n >= 0 && (1..=4).contains(&width) && (n as u64) < [1, 10, 100, 1_000, 10_000][width] {
        let mut div = [1u64, 10, 100, 1_000][width - 1];
        let v = n as u64;
        while div > 0 {
            out.push((b'0' + ((v / div) % 10) as u8) as char);
            div /= 10;
        }
        return;
    }
    if n < 0 {
        out.push('-');
    }
    let mut buf = [b'0'; 20];
    let mut i = buf.len();
    let mut v = n.unsigned_abs();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let start = i.min(buf.len() - width);
    out.push_str(std::str::from_utf8(&buf[start..]).expect("ASCII digits"));
}

/// `n` appended as decimal digits (`{n}`) without the formatter — for the
/// hot log lines that carry a couple of counters each.
pub fn push_u64(out: &mut String, n: u64) {
    let mut buf = [b'0'; 20];
    let mut i = buf.len();
    let mut v = n;
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.push_str(std::str::from_utf8(&buf[i..]).expect("ASCII digits"));
}

/// Write one operational line to the configured server log, or stderr if the
/// log is unset/uninitialized. Every line carries a [`log_timestamp`] prefix.
/// Best-effort: a write error is dropped rather than
/// taking down the server. Prefer the [`slog!`] macro at call sites.
pub fn server_log(msg: &str) {
    let ts = log_timestamp();
    match SERVER_LOG.get() {
        Some(Sink::File(f)) => {
            // One write_all of the whole line (incl. newline) so concurrent
            // append writers don't interleave a partial line.
            let line = format!("{ts} {msg}\n");
            let mut guard = f.lock().unwrap_or_else(|e| e.into_inner());
            let _ = guard.write_all(line.as_bytes());
        }
        _ => eprintln!("{ts} {msg}"),
    }
}

/// Format and emit one server-log line, like `println!` but to the server log.
#[macro_export]
macro_rules! slog {
    ($($arg:tt)*) => { $crate::server_log(&format!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    #[test]
    fn log_timestamp_shape() {
        let ts = super::log_timestamp();
        // 2026-07-20T18:42:13.123Z — fixed width, UTC, millisecond precision.
        assert_eq!(ts.len(), 24, "{ts}");
        assert!(ts.ends_with('Z') && ts.as_bytes()[10] == b'T', "{ts}");
        assert!(ts.starts_with("20"), "{ts}");
    }

    /// The hand-rolled digit pushes must print exactly what the formatter
    /// printed: zero padding, widths, and the plain counter form.
    #[test]
    fn padded_and_plain_digits_match_the_formatter() {
        for (n, w) in [
            (0, 2),
            (7, 2),
            (12, 2),
            (999, 3),
            (5, 3),
            (2026, 4),
            (12345, 4),
            (100, 2),
            (0, 1),
            (123_456, 5),
        ] {
            let mut out = String::new();
            super::push_padded(&mut out, n, w);
            assert_eq!(out, format!("{n:0w$}"), "n={n} w={w}");
        }
        for n in [0u64, 9, 10, 250, u64::MAX] {
            let mut out = String::new();
            super::push_u64(&mut out, n);
            assert_eq!(out, n.to_string());
        }
        let mut out = String::from("x ");
        super::log_timestamp_into(&mut out);
        assert_eq!(out.len(), 2 + 24, "{out}");
    }
}
