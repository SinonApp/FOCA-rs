//! Random tokens without external crates (`RandomState` keys are unique per process, plus a
//! counter).

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn state() -> &'static RandomState {
    static S: OnceLock<RandomState> = OnceLock::new();
    S.get_or_init(RandomState::new)
}

/// Returns a random `u64`.
pub fn next_u64() -> u64 {
    let mut h = state().build_hasher();
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    h.write_u64(nanos);
    h.finish()
}

/// Returns a random number in `0..n` (`n > 0`).
pub fn below(n: u64) -> u64 {
    if n == 0 {
        0
    } else {
        next_u64() % n
    }
}

/// Returns a random `[a-z0-9]` token of length `len` (for calibration paths and hosts).
pub fn token(len: usize) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = String::with_capacity(len);
    let mut x = next_u64();
    for i in 0..len {
        if i % 10 == 9 {
            x = next_u64();
        }
        s.push(A[(x % A.len() as u64) as usize] as char);
        x /= A.len() as u64;
    }
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn tokens_differ() {
        let a = super::token(16);
        let b = super::token(16);
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
        assert!(super::below(5) < 5);
    }
}
