//! Dependency-free hashes: MurmurHash3 x86_32, MD5 (RFC 1321), MIME base64 (like Python's
//! `base64.encodebytes`), sha256 (via the `sha2` crate) and Shannon entropy.

use sha2::{Digest, Sha256};

/// MurmurHash3 x86_32 (Austin Appleby, public domain). The result is a signed i32, matching
/// Python's `mmh3.hash` and Shodan's `http.favicon.hash`.
pub fn murmur3_32(data: &[u8], seed: u32) -> i32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    let mut h = seed;
    let (blocks, tail) = data.as_chunks::<4>();
    for c in blocks {
        let mut k = u32::from_le_bytes(*c);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    let mut k: u32 = 0;
    for (i, b) in tail.iter().enumerate() {
        k |= u32::from(*b) << (8 * i);
    }
    if !tail.is_empty() {
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h as i32
}

/// Encodes base64 with MIME rules: a `\n` every 76 characters plus a trailing `\n` (empty
/// input gives an empty string), exactly like Python's `base64.encodebytes`.
pub fn base64_mime(data: &[u8]) -> String {
    let flat = foca_core::b64::encode(data);
    let mut out = String::with_capacity(flat.len() + flat.len() / 76 + 1);
    for chunk in flat.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out
}

/// sha256 → hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Returns the MD5 digest as hex (RFC 1321; for identification only, not for security).
pub fn md5_hex(data: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32)
        .collect();
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_le_bytes());
    for block in msg.as_chunks::<64>().0 {
        let m: Vec<u32> = block
            .as_chunks::<4>()
            .0
            .iter()
            .map(|w| u32::from_le_bytes(*w))
            .collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = Vec::with_capacity(16);
    for v in [a0, b0, c0, d0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    hex(&out)
}

/// Returns the Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let n = s.chars().count() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur_vectors_match_python_mmh3() {
        // Expected values come from `python3 -c "import mmh3; print(mmh3.hash(b'...'))"` (mmh3 5.x).
        assert_eq!(murmur3_32(b"", 0), 0);
        assert_eq!(murmur3_32(b"hello", 0), 613153351);
        assert_eq!(
            murmur3_32(b"The quick brown fox jumps over the lazy dog", 0),
            776992547
        );
        let d: Vec<u8> = (0..=255u8).cycle().take(768).collect();
        assert_eq!(murmur3_32(base64_mime(&d).as_bytes(), 0), 1836528006);
    }

    #[test]
    fn mime_base64_wraps_at_76() {
        let d: Vec<u8> = (0..60u8).collect();
        assert_eq!(
            base64_mime(&d),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4\nOTo7\n"
        );
        assert_eq!(base64_mime(b""), "");
    }

    #[test]
    fn md5_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        let d: Vec<u8> = (0..=255u8).cycle().take(768).collect();
        assert_eq!(md5_hex(&d), "e6899eaaf06fd702f3ed3f988eb19362");
    }

    #[test]
    fn entropy() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!(shannon_entropy("aB3xK9qZ") > 2.9);
    }
}
