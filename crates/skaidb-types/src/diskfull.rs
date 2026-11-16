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

//!
//! The same funnel notices a **storage fault**: a write refused because the
//! filesystem went read-only (`EROFS` — ext4 remounts itself read-only on
//! an I/O error) or failed outright (`EIO`). Every write then fails, yet the
//! process kept serving `/metrics` and answering `/ready` 200: a BI witness
//! ran a day and a half on a read-only volume looking healthy (2026-11-09).
//! A fault LATCHES here; the server's readiness probe then tests the data
//! directory with a real write and stays not-ready until one succeeds
//! (`storage_fault_latched`, `clear_storage_fault`).

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

static ENOSPC_TOTAL: AtomicU64 = AtomicU64::new(0);
static HOOK: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();
static FAULT_TOTAL: AtomicU64 = AtomicU64::new(0);
static FAULT_LATCHED: AtomicBool = AtomicBool::new(false);
static LAST_FAULT: Mutex<String> = Mutex::new(String::new());

/// Whether `e` says the storage cannot be written at all: the filesystem is
/// read-only (`EROFS`, os error 30) or the device failed the I/O (`EIO`, 5).
/// Unlike a full disk these do not pass when space is freed.
pub fn is_storage_fault(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ReadOnlyFilesystem || matches!(e.raw_os_error(), Some(30) | Some(5))
}

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
    } else if is_storage_fault(e) {
        FAULT_TOTAL.fetch_add(1, Ordering::Relaxed);
        if !FAULT_LATCHED.swap(true, Ordering::Relaxed) {
            crate::slog!(
                "skaidb: ERROR storage fault: an I/O operation on the data failed with \"{e}\" \
                 — the node reports not ready until a write to its data directory succeeds again"
            );
        }
        let mut last = LAST_FAULT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *last = e.to_string();
    }
}

/// Number of I/O errors that were storage faults ([`is_storage_fault`])
/// since process start.
pub fn storage_faults_total() -> u64 {
    FAULT_TOTAL.load(Ordering::Relaxed)
}

/// Whether a storage fault was seen and no write has proven the storage
/// writable since (the readiness probe's [`clear_storage_fault`]); with the
/// last fault's message.
pub fn storage_fault_latched() -> Option<String> {
    FAULT_LATCHED
        .load(Ordering::Relaxed)
        .then(|| LAST_FAULT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone())
}

/// A write to the data directory succeeded: the storage is writable again.
pub fn clear_storage_fault() {
    if FAULT_LATCHED.swap(false, Ordering::Relaxed) {
        crate::slog!("skaidb: storage fault cleared: a write to the data directory succeeded");
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
    fn a_read_only_or_failed_write_latches_a_storage_fault() {
        assert!(is_storage_fault(&io::Error::from_raw_os_error(30)));
        assert!(is_storage_fault(&io::Error::from_raw_os_error(5)));
        assert!(!is_storage_fault(&io::Error::from_raw_os_error(28)));
        assert!(!is_storage_fault(&io::Error::from_raw_os_error(2)));
        let before = storage_faults_total();
        note_io_error(&io::Error::from_raw_os_error(30));
        assert_eq!(storage_faults_total(), before + 1);
        assert!(storage_fault_latched().is_some_and(|m| m.contains("Read-only")));
        clear_storage_fault();
        assert!(storage_fault_latched().is_none());
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
