//! Exclusive lock on the application's data directory (`<dir>/engine.lock`).
//!
//! Prevents running two [`Engine`](crate) instances concurrently on the same SQLite store
//! (e.g., Tauri UI + Android WorkManager headless worker). Combines an in-process registry
//! (required on Unix where `flock` is per process/inode edge cases on same fd or within the same
//! process via separate handles) with an OS advisory/mandatory file lock (`File::try_lock`).

use std::collections::HashMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const LOCK_FILE: &str = "engine.lock";

/// Identity of the current `data_dir` lock holder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockOwner {
    pub pid: u32,
    pub mode: String,
    pub started_at: i64,
}

impl LockOwner {
    fn current(mode: &str) -> Self {
        LockOwner {
            pid: std::process::id(),
            mode: mode.to_string(),
            started_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        }
    }
}

/// Exclusive lock guard for a `data_dir`. Released on drop.
#[derive(Debug)]
pub struct DataDirLock {
    path: PathBuf,
    file: Option<File>,
}

fn in_process() -> &'static Mutex<HashMap<PathBuf, LockOwner>> {
    static IN_PROCESS: OnceLock<Mutex<HashMap<PathBuf, LockOwner>>> = OnceLock::new();
    IN_PROCESS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn canonical_dir(dir: &Path) -> PathBuf {
    std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
}

fn read_owner_file(path: &Path) -> Option<LockOwner> {
    let raw = std::fs::read(path).ok()?;
    serde_json::from_slice(&raw).ok()
}

impl DataDirLock {
    /// Tries to acquire an exclusive lock on `<dir>/engine.lock` with holder tag `mode`.
    /// Returns `Err(Some(owner))` when another live owner holds the lock.
    pub fn try_acquire(dir: &Path, mode: &str) -> Result<Self, Option<LockOwner>> {
        if std::fs::create_dir_all(dir).is_err() {
            return Err(None);
        }
        let canon = canonical_dir(dir);
        let lock_path = canon.join(LOCK_FILE);

        {
            let map = in_process().lock().unwrap_or_else(|p| p.into_inner());
            if let Some(owner) = map.get(&canon) {
                return Err(Some(owner.clone()));
            }
        }

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| None)?;

        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) | Err(TryLockError::Error(_)) => {
                return Err(read_owner_file(&lock_path));
            }
        }

        let owner = LockOwner::current(mode);
        if let Ok(bytes) = serde_json::to_vec(&owner) {
            let _ = file.set_len(0);
            let _ = file.seek(SeekFrom::Start(0));
            let _ = file.write_all(&bytes);
            let _ = file.flush();
        }

        let mut map = in_process().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = map.get(&canon) {
            drop(file);
            return Err(Some(existing.clone()));
        }
        map.insert(canon.clone(), owner);
        Ok(DataDirLock {
            path: canon,
            file: Some(file),
        })
    }

    /// Waits up to `timeout` to acquire the lock before failing with the current owner info.
    pub fn acquire_wait(
        dir: &Path,
        mode: &str,
        timeout: Duration,
    ) -> Result<Self, Option<LockOwner>> {
        let deadline = Instant::now() + timeout;
        loop {
            match Self::try_acquire(dir, mode) {
                Ok(guard) => return Ok(guard),
                Err(owner) => {
                    if Instant::now() >= deadline {
                        return Err(owner);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }

    /// Canonicalized directory path protected by this lock.
    pub fn dir(&self) -> &Path {
        &self.path
    }
}

impl Drop for DataDirLock {
    fn drop(&mut self) {
        // Release the OS file handle first so subsequent `try_acquire` sees it unlocked immediately.
        drop(self.file.take());
        let mut map = in_process().lock().unwrap_or_else(|p| p.into_inner());
        map.remove(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_lock_exclusive_and_releases_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let guard = DataDirLock::try_acquire(tmp.path(), "headless").expect("first acquire");
        assert!(tmp.path().join(LOCK_FILE).exists());

        let err = DataDirLock::try_acquire(tmp.path(), "ui").unwrap_err();
        let owner = err.expect("owner info present");
        assert_eq!(owner.mode, "headless");
        assert_eq!(owner.pid, std::process::id());

        drop(guard);
        let guard2 = DataDirLock::try_acquire(tmp.path(), "ui").expect("re-acquire after drop");
        assert_eq!(guard2.dir(), canonical_dir(tmp.path()));
    }
}
