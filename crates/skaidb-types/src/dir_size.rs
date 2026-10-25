//! A directory's on-disk size, kept off every lock.
//!
//! `stats()` on a time-series store or a full-text index used to walk its
//! directory — one `stat` per file — inside the caller's locks. A cold walk
//! of a store with ~135k block files sat in disk waits for a minute while
//! holding the engine read lock, and every query, write and peer request on
//! the member queued behind it (2026-09-30, caught by the engine-lock
//! watchdog). [`DirSize`] answers from a cached value instead and refreshes
//! it on a background thread that holds no lock, at most once per
//! [`DirSize::REFRESH`] and never twice at a time.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct Shared {
    dir: PathBuf,
    bytes: AtomicU64,
    /// Wall-clock ms of the last completed walk; 0 = never.
    refreshed_ms: AtomicU64,
    refreshing: AtomicBool,
}

/// Cached recursive size of one directory (see the module docs).
#[derive(Debug, Clone)]
pub struct DirSize(Arc<Shared>);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Total size of the files under `dir`, recursively; unreadable entries
/// count as zero.
pub fn walk(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        total += if meta.is_dir() {
            walk(&entry.path())
        } else {
            meta.len()
        };
    }
    total
}

impl DirSize {
    /// How old the cached size may get before a read starts a refresh.
    pub const REFRESH: Duration = Duration::from_secs(300);

    /// Track `dir`, starting the first walk in the background.
    pub fn new(dir: impl Into<PathBuf>) -> DirSize {
        let size = DirSize(Arc::new(Shared {
            dir: dir.into(),
            bytes: AtomicU64::new(0),
            refreshed_ms: AtomicU64::new(0),
            refreshing: AtomicBool::new(false),
        }));
        size.refresh_in_background();
        size
    }

    /// The cached size in bytes (0 until the first walk completes). Never
    /// touches the filesystem; starts a background refresh when the value
    /// is older than [`DirSize::REFRESH`].
    pub fn get(&self) -> u64 {
        let at = self.0.refreshed_ms.load(Ordering::Relaxed);
        if now_ms().saturating_sub(at) >= Self::REFRESH.as_millis() as u64 {
            self.refresh_in_background();
        }
        self.0.bytes.load(Ordering::Relaxed)
    }

    /// Walk now, on the calling thread, and return the fresh size. For
    /// callers that hold no lock (and tests).
    pub fn refresh_now(&self) -> u64 {
        let bytes = walk(&self.0.dir);
        self.0.bytes.store(bytes, Ordering::Relaxed);
        self.0
            .refreshed_ms
            .store(now_ms().max(1), Ordering::Relaxed);
        bytes
    }

    /// Whether a background walk is running right now.
    pub fn refreshing(&self) -> bool {
        self.0.refreshing.load(Ordering::Acquire)
    }

    fn refresh_in_background(&self) {
        if self.0.refreshing.swap(true, Ordering::AcqRel) {
            return; // a walk is already running
        }
        let me = self.clone();
        let spawned = std::thread::Builder::new()
            .name("dir-size".into())
            .spawn(move || {
                me.refresh_now();
                me.0.refreshing.store(false, Ordering::Release);
            });
        if spawned.is_err() {
            self.0.refreshing.store(false, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("skaidb-dirsize-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("sub")).unwrap();
        d
    }

    #[test]
    fn walks_in_the_background_and_reads_without_touching_the_disk() {
        let d = tmp("bg");
        std::fs::write(d.join("a"), vec![0u8; 1000]).unwrap();
        std::fs::write(d.join("sub").join("b"), vec![0u8; 500]).unwrap();
        let size = DirSize::new(&d);
        let deadline = Instant::now() + Duration::from_secs(5);
        while size.get() != 1500 {
            assert!(Instant::now() < deadline, "background walk never landed");
            std::thread::sleep(Duration::from_millis(5));
        }
        // A new file is not seen until the next refresh: reads are cached.
        std::fs::write(d.join("c"), vec![0u8; 100]).unwrap();
        assert_eq!(size.get(), 1500, "a read inside the window does not walk");
        assert_eq!(size.refresh_now(), 1600);
        assert_eq!(size.get(), 1600);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_missing_directory_is_zero() {
        let size = DirSize::new("/nonexistent/skaidb-dirsize");
        assert_eq!(size.refresh_now(), 0);
    }
}
