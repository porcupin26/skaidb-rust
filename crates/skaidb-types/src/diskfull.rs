//! The one place every storage-layer I/O error passes through on its way
//! to becoming a typed error — so a real `ENOSPC` can be counted and
//! reported to whoever guards the disk, without the storage crates
//! knowing that a guard exists.
//!
//! The disk guard samples free space on a timer. A volume can go from
//! "comfortably above the watermark" to "full" inside one interval (a
//! compaction output is written in one go, and an unrelated process can
//! take the space too), and then the first thing to notice is a write
//! failing with `No space left on device` — after which the node kept
//! answering `/ready` 200 and `iwm.state` 0 until the next sample. The
//! hook closes that gap: the error itself trips the guard.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

static ENOSPC_TOTAL: AtomicU64 = AtomicU64::new(0);
static HOOK: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// Whether `e` is the filesystem refusing for lack of space.
pub fn is_enospc(e: &io::Error) -> bool {
    // `StorageFull` covers ENOSPC on Unix and ERROR_DISK_FULL on Windows;
    // the raw check catches an ENOSPC that arrived wrapped in a custom
    // error (some std paths do that) and so lost its kind.
    e.kind() == io::ErrorKind::StorageFull || e.raw_os_error() == Some(28)
}

/// Record an I/O error at the moment it becomes a storage error. Cheap
/// for every non-ENOSPC error (one kind compare); an ENOSPC bumps the
/// counter and runs the installed hook, if any.
pub fn note_io_error(e: &io::Error) {
    if is_enospc(e) {
        ENOSPC_TOTAL.fetch_add(1, Ordering::Relaxed);
        if let Some(h) = HOOK.get() {
            h();
        }
    }
}

/// Install the process-wide ENOSPC hook. First installer wins; later calls
/// are ignored (tests that share a process must not depend on replacing
/// it). The hook runs on the thread that hit the error, possibly under a
/// storage engine lock — it must be non-blocking and must not touch storage.
pub fn install_enospc_hook(f: impl Fn() + Send + Sync + 'static) {
    let _ = HOOK.set(Box::new(f));
}

/// Number of I/O errors that were ENOSPC since process start.
pub fn enospc_total() -> u64 {
    ENOSPC_TOTAL.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_enospc_by_kind_and_by_raw_errno() {
        assert!(is_enospc(&io::Error::from_raw_os_error(28)));
        assert!(is_enospc(&io::Error::new(io::ErrorKind::StorageFull, "full")));
        assert!(!is_enospc(&io::Error::from_raw_os_error(13)));
        assert!(!is_enospc(&io::Error::other("nope")));
    }

    #[test]
    fn counts_only_enospc() {
        let before = enospc_total();
        note_io_error(&io::Error::from_raw_os_error(13));
        assert_eq!(enospc_total(), before);
        note_io_error(&io::Error::from_raw_os_error(28));
        assert_eq!(enospc_total(), before + 1);
    }
}
