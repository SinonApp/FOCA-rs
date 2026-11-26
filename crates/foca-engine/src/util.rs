//! Small helpers: command arguments, masks, hashes, time.

use std::sync::Arc;

use foca_core::Clock;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset};

use crate::CmdError;

/// Clock with a local offset, so `iso()` in the store and the analysis yields local time without an offset.
pub struct LocalClock {
    pub inner: Arc<dyn Clock>,
    pub off: UtcOffset,
}

impl Clock for LocalClock {
    fn now(&self) -> OffsetDateTime {
        self.inner.now().to_offset(self.off)
    }
}

pub fn iso(t: OffsetDateTime) -> String {
    foca_store::iso(t)
}

pub fn arg_str<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k).and_then(Value::as_str)
}

pub fn req_str<'a>(a: &'a Value, k: &str) -> Result<&'a str, CmdError> {
    arg_str(a, k).ok_or_else(|| CmdError::new("bad_args", format!("нет аргумента {k}")))
}

pub fn arg_u64(a: &Value, k: &str) -> Option<u64> {
    match a.get(k)? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

pub fn arg_ids(a: &Value, k: &str) -> Vec<u64> {
    match a.get(k) {
        Some(Value::Array(v)) => v
            .iter()
            .filter_map(|x| {
                x.as_u64()
                    .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
            })
            .collect(),
        Some(Value::Number(n)) => n.as_u64().into_iter().collect(),
        Some(Value::String(s)) => s.parse().ok().into_iter().collect(),
        _ => vec![],
    }
}

/// Masks a secret as the demo backend does: `abc••••••••yz` for strings longer than 10, otherwise `••••••••`.
pub fn mask(v: &str) -> String {
    let c: Vec<char> = v.chars().collect();
    if c.len() > 10 {
        format!(
            "{}••••••••{}",
            c[..3].iter().collect::<String>(),
            c[c.len() - 2..].iter().collect::<String>()
        )
    } else {
        "••••••••".into()
    }
}

/// FNV-1a 32 (same as the demo backend's `hash()`), used for out-of-scope candidate ids.
pub fn fnv(s: &str) -> u32 {
    let mut h: u32 = 2166136261;
    for c in s.encode_utf16() {
        h = (h ^ c as u32).wrapping_mul(16777619);
    }
    h
}

pub fn base36(mut n: u64) -> String {
    if n == 0 {
        return "0".into();
    }
    let d = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    while n > 0 {
        out.push(d[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Sha256::new();
    ipad.update(k.map(|x| x ^ 0x36));
    ipad.update(msg);
    let inner = ipad.finalize();
    let mut opad = Sha256::new();
    opad.update(k.map(|x| x ^ 0x5c));
    opad.update(inner);
    opad.finalize().into()
}

/// PBKDF2-HMAC-SHA256, single block (32 bytes).
pub fn pbkdf2_sha256(pass: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    let mut s = salt.to_vec();
    s.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha256(pass, &s);
    let mut out = u;
    for _ in 1..iters {
        u = hmac_sha256(pass, &u);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

/// Generates a 16-byte salt from `RandomState` system randomness, the time and an address.
pub fn random_salt() -> [u8; 16] {
    use std::hash::{BuildHasher, Hasher};
    let mut buf = Vec::new();
    for i in 0..4u64 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(i);
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        h.write_usize(&buf as *const _ as usize);
        buf.extend_from_slice(&h.finish().to_le_bytes());
    }
    let d = sha256(&buf);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// Constant-time comparison (no early exit).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Runs a parser with panic catching; a panic becomes an `Err` describing a parse error.
pub(crate) fn catch_panic<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(p) => {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            Err(format!("ошибка разбора (panic): {msg}"))
        }
    }
}

pub(crate) fn is_private_or_metadata_host(host: &str) -> bool {
    let h = host
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    if h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h == "internal"
        || h.ends_with(".internal")
        || h == "metadata.google.internal"
    {
        return true;
    }
    let Ok(ip) = h.parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                let o = v4.octets();
                return v4.is_unspecified()
                    || v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_multicast()
                    || (o[0] == 100 && (64..=127).contains(&o[1]));
            }
            let seg0 = v6.segments()[0];
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (seg0 & 0xfe00) == 0xfc00
                || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_matches(|c| c == '[' || c == ']');
    h.eq_ignore_ascii_case("localhost")
        || h.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub(crate) fn size_label(n: usize) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1} МБ", n as f64 / 1024.0 / 1024.0).replace('.', ",")
    } else {
        format!("{} КБ", n.div_ceil(1024).max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_vector() {
        // RFC 7914 §11: PBKDF2-HMAC-SHA256("passwd", "salt", 1)
        let d = pbkdf2_sha256(b"passwd", b"salt", 1);
        assert_eq!(
            hex(&d),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    #[test]
    fn masks_and_hash() {
        assert_eq!(mask("Kont0so#2024!"), "Kon••••••••4!");
        assert_eq!(mask("short"), "••••••••");
        assert_eq!(base36(35), "z");
        assert_eq!(fnv(""), 2166136261);
    }
}
