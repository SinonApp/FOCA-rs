//! Magic numbers of the stream and archive formats, shared by detection and the parsers.

pub(crate) const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
pub(crate) const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";

pub(crate) const GZIP_MAGIC: [u8; 3] = [0x1F, 0x8B, 0x08];
pub(crate) const XZ_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];

pub(crate) fn is_bzip2(b: &[u8]) -> bool {
    b.len() >= 10
        && b.starts_with(b"BZh")
        && (b'1'..=b'9').contains(&b[3])
        && (b[4..10] == [0x31, 0x41, 0x59, 0x26, 0x53, 0x59]
            || b[4..10] == [0x17, 0x72, 0x45, 0x38, 0x50, 0x90])
}

/// Returns `true` for a block whose header checksum is valid (any tar dialect).
pub(crate) fn is_tar(b: &[u8]) -> bool {
    let Some(h) = b.get(..512) else { return false };
    if h.iter().all(|&c| c == 0) {
        return false;
    }
    let Some(sum) = octal(&h[148..156]) else {
        return false;
    };
    let calc: u64 = h
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(c)
            }
        })
        .sum();
    sum == calc
}

pub(crate) fn octal(f: &[u8]) -> Option<u64> {
    // base-256 for large values (GNU)
    if f.first().is_some_and(|c| c & 0x80 != 0) {
        let mut v: u64 = u64::from(f[0] & 0x7F);
        for &c in &f[1..] {
            v = v.checked_mul(256)?.checked_add(u64::from(c))?;
        }
        return Some(v);
    }
    let s: String = f
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as char)
        .collect();
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, 8).ok()
}
