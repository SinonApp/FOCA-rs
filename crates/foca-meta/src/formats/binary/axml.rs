//! Minimal Android binary XML (AXML) reader: string pool, resource map and start-element
//! chunks only. Attribute names that aapt stripped are recovered from the resource map ids of
//! the few attributes we need.

use crate::util::{rd_u16le, rd_u32le};

pub(crate) struct AxmlElement {
    pub name: String,
    pub attrs: Vec<(String, String)>,
}

const MAX_STRINGS: usize = 20_000;
const MAX_ELEMENTS: usize = 5_000;

/// Parses the elements of an AXML document; `None` if the header is not AXML.
pub(crate) fn parse(b: &[u8]) -> Option<Vec<AxmlElement>> {
    if rd_u16le(b, 0)? != 0x0003 {
        return None;
    }
    let total = (rd_u32le(b, 4)? as usize).min(b.len());
    let mut strings: Vec<String> = Vec::new();
    let mut res_ids: Vec<u32> = Vec::new();
    let mut out = Vec::new();
    let mut at = rd_u16le(b, 2)? as usize;
    let mut chunks = 0;
    while at + 8 <= total && chunks < 100_000 {
        chunks += 1;
        let ty = rd_u16le(b, at)?;
        let size = rd_u32le(b, at + 4)? as usize;
        if size < 8 {
            break;
        }
        let chunk = b.get(at..at.checked_add(size)?.min(total))?;
        match ty {
            0x0001 => strings = string_pool(chunk),
            0x0180 => {
                res_ids = chunk[8..]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .take(MAX_STRINGS)
                    .map(|c| u32::from_le_bytes(*c))
                    .collect();
            }
            0x0102 if out.len() < MAX_ELEMENTS => {
                if let Some(e) = start_element(chunk, &strings, &res_ids) {
                    out.push(e);
                }
            }
            _ => {}
        }
        at += size;
    }
    Some(out)
}

fn string_pool(c: &[u8]) -> Vec<String> {
    let count = rd_u32le(c, 8).unwrap_or(0) as usize;
    let utf8 = rd_u32le(c, 16).unwrap_or(0) & 0x100 != 0;
    let start = rd_u32le(c, 20).unwrap_or(0) as usize;
    let hsize = rd_u16le(c, 2).unwrap_or(28) as usize;
    let mut out = Vec::new();
    for i in 0..count.min(MAX_STRINGS) {
        let Some(off) = rd_u32le(c, hsize + i * 4) else {
            break;
        };
        let p = start.saturating_add(off as usize);
        out.push(if utf8 { utf8_at(c, p) } else { utf16_at(c, p) }.unwrap_or_default());
    }
    out
}

fn utf8_at(c: &[u8], mut p: usize) -> Option<String> {
    // character count then byte count, each 1 or 2 bytes
    let skip = |p: &mut usize| -> Option<usize> {
        let a = *c.get(*p)? as usize;
        *p += 1;
        if a & 0x80 != 0 {
            let b2 = *c.get(*p)? as usize;
            *p += 1;
            Some(((a & 0x7F) << 8) | b2)
        } else {
            Some(a)
        }
    };
    skip(&mut p)?;
    let n = skip(&mut p)?.min(4096);
    Some(String::from_utf8_lossy(c.get(p..p + n)?).into_owned())
}

fn utf16_at(c: &[u8], p: usize) -> Option<String> {
    let mut n = rd_u16le(c, p)? as usize;
    let mut s = p + 2;
    if n & 0x8000 != 0 {
        n = ((n & 0x7FFF) << 16) | rd_u16le(c, p + 2)? as usize;
        s += 2;
    }
    let n = n.min(4096);
    Some(crate::util::utf16le(c.get(s..s + n * 2)?))
}

fn attr_name_by_id(id: u32) -> Option<&'static str> {
    Some(match id {
        0x0101_0003 => "name",
        0x0101_021b => "versionCode",
        0x0101_021c => "versionName",
        0x0101_020c => "minSdkVersion",
        0x0101_0270 => "targetSdkVersion",
        0x0101_0572 => "compileSdkVersion",
        _ => return None,
    })
}

fn start_element(c: &[u8], strings: &[String], res_ids: &[u32]) -> Option<AxmlElement> {
    let s = |i: u32| strings.get(i as usize).cloned().unwrap_or_default();
    let name = s(rd_u32le(c, 20)?);
    let attr_start = rd_u16le(c, 24)? as usize;
    let attr_size = (rd_u16le(c, 26)? as usize).max(20);
    let attr_count = (rd_u16le(c, 28)? as usize).min(256);
    let mut attrs = Vec::new();
    for i in 0..attr_count {
        let a = 16 + attr_start + i * attr_size;
        let Some(name_idx) = rd_u32le(c, a + 4) else {
            break;
        };
        let raw = rd_u32le(c, a + 8).unwrap_or(u32::MAX);
        let dtype = *c.get(a + 15).unwrap_or(&0);
        let data = rd_u32le(c, a + 16).unwrap_or(0);
        let mut key = s(name_idx);
        if key.is_empty() {
            if let Some(n) = res_ids
                .get(name_idx as usize)
                .and_then(|&id| attr_name_by_id(id))
            {
                key = n.to_string();
            }
        }
        let value = if raw != u32::MAX {
            s(raw)
        } else {
            match dtype {
                0x03 => s(data),
                0x10 => (data as i32).to_string(),
                0x11 => format!("0x{data:x}"),
                0x12 => (data != 0).to_string(),
                0x01 => format!("@0x{data:08x}"),
                _ => continue,
            }
        };
        attrs.push((key, value));
    }
    Some(AxmlElement { name, attrs })
}
