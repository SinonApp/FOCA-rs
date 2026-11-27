//! Shared helpers: text decoding, dates and bounds-checked integer reads.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Decodes bytes as text: UTF-8/UTF-16 BOM, a UTF-16 heuristic without BOM, otherwise lossy UTF-8.
pub fn decode_text(b: &[u8]) -> String {
    if let Some(rest) = b.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    if let Some(rest) = b.strip_prefix(&[0xFF, 0xFE]) {
        return utf16le(rest);
    }
    if let Some(rest) = b.strip_prefix(&[0xFE, 0xFF]) {
        return utf16be(rest);
    }
    // UTF-16LE without BOM: many zero bytes at odd positions
    if b.len() >= 8 {
        let n = b.len().min(512) / 2;
        let zeros_odd = (0..n).filter(|i| b[i * 2 + 1] == 0).count();
        let zeros_even = (0..n).filter(|i| b[i * 2] == 0).count();
        if zeros_odd * 10 > n * 8 && zeros_even * 10 < n {
            return utf16le(b);
        }
    }
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => {
            // not UTF-8, so probably cp1252 or cp1251; choose by the share of Cyrillic letters
            let hi = b.iter().filter(|&&c| c >= 0xC0).count();
            if hi * 4 > b.len().max(1) {
                decode_codepage(b, 1251)
            } else {
                String::from_utf8_lossy(b).into_owned()
            }
        }
    }
}

pub fn utf16le(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn utf16be(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Decodes UTF-16LE up to the first NUL.
pub fn utf16le_z(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

const CP1252_80: [u16; 32] = [
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039,
    0x0152, 0x008D, 0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
];

const CP1251_80: [u16; 64] = [
    0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021, 0x20AC, 0x2030, 0x0409, 0x2039,
    0x040A, 0x040C, 0x040B, 0x040F, 0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0xFFFD, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F, 0x00A0, 0x040E, 0x045E, 0x0408,
    0x00A4, 0x0490, 0x00A6, 0x00A7, 0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407,
    0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7, 0x0451, 0x2116, 0x0454, 0x00BB,
    0x0458, 0x0405, 0x0455, 0x0457,
];

/// Decodes a single-byte Windows code page (1251 and 1252; others as Latin-1), as well as
/// 65001 (UTF-8) and 1200 (UTF-16LE).
pub fn decode_codepage(b: &[u8], cp: u16) -> String {
    match cp {
        65001 => String::from_utf8_lossy(b).into_owned(),
        1200 => utf16le(b),
        1201 => utf16be(b),
        1251 => b
            .iter()
            .map(|&c| match c {
                0..=0x7F => c as char,
                0x80..=0xBF => char::from_u32(u32::from(CP1251_80[usize::from(c - 0x80)]))
                    .unwrap_or('\u{FFFD}'),
                _ => char::from_u32(0x0410 + u32::from(c - 0xC0)).unwrap_or('\u{FFFD}'),
            })
            .collect(),
        _ => match codepage_encoding(cp) {
            Some(enc) => enc.decode_without_bom_handling(b).0.into_owned(),
            None => decode_cp1252(b),
        },
    }
}

/// Encoding of a Windows code page number other than 1251/1252/UTF (Shift-JIS, GBK, Big5,
/// EUC-KR, the other cp125x, KOI8, DOS 866 and Mac Roman). `None` falls back to cp1252.
pub fn codepage_encoding(cp: u16) -> Option<&'static encoding_rs::Encoding> {
    use encoding_rs as e;
    Some(match cp {
        932 => e::SHIFT_JIS,
        936 | 54936 => e::GBK,
        949 | 51949 => e::EUC_KR,
        950 => e::BIG5,
        866 => e::IBM866,
        874 => e::WINDOWS_874,
        1250 => e::WINDOWS_1250,
        1253 => e::WINDOWS_1253,
        1254 => e::WINDOWS_1254,
        1255 => e::WINDOWS_1255,
        1256 => e::WINDOWS_1256,
        1257 => e::WINDOWS_1257,
        1258 => e::WINDOWS_1258,
        10000 => e::MACINTOSH,
        10007 => e::X_MAC_CYRILLIC,
        20866 => e::KOI8_R,
        21866 => e::KOI8_U,
        20932 | 51932 => e::EUC_JP,
        28592 => e::ISO_8859_2,
        28595 => e::ISO_8859_5,
        28597 => e::ISO_8859_7,
        50220..=50222 => e::ISO_2022_JP,
        _ => return None,
    })
}

fn decode_cp1252(b: &[u8]) -> String {
    b.iter()
        .map(|&c| match c {
            0x80..=0x9F => {
                char::from_u32(u32::from(CP1252_80[usize::from(c - 0x80)])).unwrap_or('\u{FFFD}')
            }
            _ => c as char,
        })
        .collect()
}

/// Cleans a metadata string: removes NUL and control characters and trims whitespace. Returns `None` if empty.
pub fn clean_str(s: &str) -> Option<String> {
    let t: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    let t = t.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// Truncates a string to `max` characters.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

pub fn rd_u16le(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

pub fn rd_u32le(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

pub fn rd_u64le(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

pub fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Converts a Windows FILETIME (100 ns ticks since 1601-01-01) to ISO 8601 UTC.
pub fn filetime_to_iso(ft: u64) -> Option<String> {
    if ft == 0 {
        return None;
    }
    let secs = (ft / 10_000_000) as i64 - 11_644_473_600;
    // sanity bounds: 1980..2100
    if !(315_532_800..=4_102_444_800).contains(&secs) {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// Converts Unix seconds to RFC 3339 within sane bounds (1980..2100).
pub fn unix_to_iso(secs: i64) -> Option<String> {
    if !(315_532_800..=4_102_444_800).contains(&secs) {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// Reads a big-endian u32.
pub fn rd_u32be(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn digits(s: &str, from: usize, n: usize) -> Option<u32> {
    let part = s.get(from..from + n)?;
    if part.bytes().all(|b| b.is_ascii_digit()) {
        part.parse().ok()
    } else {
        None
    }
}

/// Normalizes a document date to ISO 8601.
///
/// Understands ISO/W3CDTF (kept as is), PDF `D:YYYYMMDDHHmmSS+HH'mm'` and EXIF
/// `YYYY:MM:DD HH:MM:SS`. Unrecognized input is returned as is (truncated).
pub fn normalize_date(raw: &str) -> Option<String> {
    let s = raw.trim().trim_matches('\0');
    if s.is_empty() {
        return None;
    }
    // EXIF
    let b = s.as_bytes();
    if b.len() >= 19 && b[4] == b':' && b[7] == b':' && b[10] == b' ' {
        if let (Some(y), Some(mo), Some(d)) = (digits(s, 0, 4), digits(s, 5, 2), digits(s, 8, 2)) {
            if y == 0 {
                return None;
            }
            return Some(format!(
                "{y:04}-{mo:02}-{d:02}T{}",
                s.get(11..19).unwrap_or("00:00:00")
            ));
        }
    }
    // PDF
    let p = s.strip_prefix("D:").unwrap_or(s);
    let pb = p.as_bytes();
    if p.len() >= 4
        && p.len() <= 30
        && pb.iter().take(4).all(u8::is_ascii_digit)
        && pb.get(4).is_none_or(u8::is_ascii_digit)
    {
        if let Some(y) = digits(p, 0, 4) {
            let mo = digits(p, 4, 2).unwrap_or(1);
            let d = digits(p, 6, 2).unwrap_or(1);
            let h = digits(p, 8, 2).unwrap_or(0);
            let mi = digits(p, 10, 2).unwrap_or(0);
            let se = digits(p, 12, 2).unwrap_or(0);
            let mut out = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{se:02}");
            let rest_start = p
                .char_indices()
                .take_while(|(_, c)| c.is_ascii_digit())
                .count();
            let rest = p.get(rest_start..).unwrap_or("");
            if rest.starts_with('Z') {
                out.push('Z');
            } else if let Some(sign) = rest.chars().next().filter(|c| *c == '+' || *c == '-') {
                let tz: String = rest[1..].chars().filter(|c| c.is_ascii_digit()).collect();
                let th = tz.get(0..2).unwrap_or("00");
                let tm = tz.get(2..4).unwrap_or("00");
                out.push_str(&format!("{sign}{th}:{tm}"));
            }
            if (1..=12).contains(&mo) && (1..=31).contains(&d) && h < 24 && mi < 60 && se < 61 {
                return Some(out);
            }
        }
    }
    Some(truncate(s, 64))
}

/// Converts an ISO 8601 duration (`PT1H2M3S`, `P1DT2H`) to seconds.
pub fn parse_iso_duration(s: &str) -> Option<u64> {
    let s = s.trim().strip_prefix('P')?;
    let mut total: f64 = 0.0;
    let mut num = String::new();
    let mut in_time = false;
    for c in s.chars() {
        match c {
            'T' => in_time = true,
            '0'..='9' | '.' | ',' => num.push(if c == ',' { '.' } else { c }),
            _ => {
                let v: f64 = num.parse().ok()?;
                num.clear();
                total += v * match (c, in_time) {
                    ('Y', false) => 365.0 * 86400.0,
                    ('M', false) => 30.0 * 86400.0,
                    ('W', false) => 7.0 * 86400.0,
                    ('D', false) => 86400.0,
                    ('H', true) => 3600.0,
                    ('M', true) => 60.0,
                    ('S', true) => 1.0,
                    _ => return None,
                };
            }
        }
    }
    if total.is_finite() && total >= 0.0 {
        Some(total as u64)
    } else {
        None
    }
}

/// Simple deterministic PRNG (xorshift64*) for property tests.
#[cfg(test)]
pub struct Rng(pub u64);

#[cfg(test)]
impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Returns the largest index `<= i` that lies on a char boundary (like `str::floor_char_boundary`),
/// for safely slicing a string at a byte limit.
pub fn floor_char_boundary(s: &str, i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    let mut i = i;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(
            normalize_date("D:20240314184200+02'00'").as_deref(),
            Some("2024-03-14T18:42:00+02:00")
        );
        assert_eq!(
            normalize_date("D:2024").as_deref(),
            Some("2024-01-01T00:00:00")
        );
        assert_eq!(
            normalize_date("D:20240314184200Z").as_deref(),
            Some("2024-03-14T18:42:00Z")
        );
        assert_eq!(
            normalize_date("D:20050718143045-04'00'").as_deref(),
            Some("2005-07-18T14:30:45-04:00")
        );
        assert_eq!(
            normalize_date("2024:08:02 11:05:33").as_deref(),
            Some("2024-08-02T11:05:33")
        );
        assert_eq!(
            normalize_date("2024-03-14T18:42:00Z").as_deref(),
            Some("2024-03-14T18:42:00Z")
        );
        assert_eq!(normalize_date("0000:00:00 00:00:00"), None);
        assert_eq!(normalize_date(""), None);
        assert_eq!(
            filetime_to_iso(133_550_000_000_000_000).as_deref(),
            Some("2024-03-15T18:13:20Z")
        );
        assert_eq!(parse_iso_duration("PT1H2M3S"), Some(3723));
        assert_eq!(parse_iso_duration("P1DT1S"), Some(86401));
        assert_eq!(parse_iso_duration("garbage"), None);
    }

    #[test]
    fn codepages() {
        assert_eq!(
            decode_codepage(&[0xCF, 0xF0, 0xE8, 0xE2, 0xB3, 0xF2], 1251),
            "Привіт"
        );
        assert_eq!(decode_codepage(&[0x80, 0xE9], 1252), "€é");
        assert_eq!(decode_text(&[0xFF, 0xFE, b'h', 0, b'i', 0]), "hi");
        assert_eq!(decode_text(b"h\0i\0 \0x\0"), "hi x");
    }
}
