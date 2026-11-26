//! Safe `.DS_Store` parsing (Finder, "Bud1" format): file names only.
//!
//! Implemented from the public format description (Mark Mentovai, "DS_Store File Format");
//! Alastair Houghton's `ds_store` module (MIT) served only as a reference for the fixtures.
//! Every read is bounds-checked, with limits on input size, node count, tree depth and name
//! count, plus cycle detection. Corrupted input never panics.

use std::collections::{BTreeSet, HashSet};

/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DsStoreError {
    #[error("слишком большой файл .DS_Store ({0} байт)")]
    TooLarge(usize),
    #[error("не .DS_Store (нет сигнатуры Bud1)")]
    BadMagic,
    #[error("повреждённый .DS_Store: {0}")]
    Corrupt(&'static str),
}

/// Parse limits.
#[derive(Debug, Clone, Copy)]
pub struct DsLimits {
    pub max_input: usize,
    pub max_names: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
}

impl Default for DsLimits {
    fn default() -> Self {
        DsLimits {
            max_input: 4 * 1024 * 1024,
            max_names: 5000,
            max_nodes: 4096,
            max_depth: 16,
        }
    }
}

/// Result: unique names (without `.` and `..`) and whether the limit truncated them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DsStoreNames {
    pub names: Vec<String>,
    pub truncated: bool,
}

/// Returns `true` if the data starts with the `.DS_Store` signature.
pub fn looks_like_ds_store(b: &[u8]) -> bool {
    b.len() >= 8 && b[..4] == [0, 0, 0, 1] && &b[4..8] == b"Bud1"
}

struct Rd<'a> {
    b: &'a [u8],
}

impl<'a> Rd<'a> {
    fn u32(&self, at: usize) -> Result<u32, DsStoreError> {
        let s = self
            .b
            .get(at..at.checked_add(4).ok_or(DsStoreError::Corrupt("смещение"))?)
            .ok_or(DsStoreError::Corrupt("выход за границы"))?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn bytes(&self, at: usize, n: usize) -> Result<&'a [u8], DsStoreError> {
        self.b
            .get(at..at.checked_add(n).ok_or(DsStoreError::Corrupt("смещение"))?)
            .ok_or(DsStoreError::Corrupt("выход за границы"))
    }
}

/// Parses a `.DS_Store` and returns the file names.
///
/// # Errors
///
/// Returns a [`DsStoreError`] if the data is not a `.DS_Store`, is corrupted or exceeds the
/// limits.
pub fn parse_ds_store(data: &[u8], lim: DsLimits) -> Result<DsStoreNames, DsStoreError> {
    if data.len() > lim.max_input {
        return Err(DsStoreError::TooLarge(data.len()));
    }
    if !looks_like_ds_store(data) {
        return Err(DsStoreError::BadMagic);
    }
    let r = Rd { b: data };
    // Offsets in the file are relative to position 4.
    let root_off = r.u32(8)? as usize;
    let root_size = r.u32(12)? as usize;
    if r.u32(16)? as usize != root_off {
        return Err(DsStoreError::Corrupt("заголовок"));
    }
    let root_start = 4usize
        .checked_add(root_off)
        .ok_or(DsStoreError::Corrupt("заголовок"))?;
    let root = r.bytes(root_start, root_size)?;
    let rr = Rd { b: root };
    let count = rr.u32(0)? as usize;
    if count > 1 << 20 {
        return Err(DsStoreError::Corrupt("число блоков"));
    }
    let mut addrs = Vec::with_capacity(count.min(4096));
    for i in 0..count {
        let off = i
            .checked_mul(4)
            .and_then(|x| 8usize.checked_add(x))
            .ok_or(DsStoreError::Corrupt("число блоков"))?;
        addrs.push(rr.u32(off)?);
    }
    // The address table is padded to a multiple of 256.
    let padded = count.div_ceil(256).saturating_mul(256);
    let mut p = padded
        .checked_mul(4)
        .and_then(|x| 8usize.checked_add(x))
        .ok_or(DsStoreError::Corrupt("оглавление"))?;
    let toc_count = rr.u32(p)? as usize;
    p = p
        .checked_add(4)
        .ok_or(DsStoreError::Corrupt("оглавление"))?;
    if toc_count > 1024 {
        return Err(DsStoreError::Corrupt("оглавление"));
    }
    let mut dsdb = None;
    for _ in 0..toc_count {
        let n = *rr
            .bytes(p, 1)?
            .first()
            .ok_or(DsStoreError::Corrupt("оглавление"))? as usize;
        let name = rr.bytes(p + 1, n)?;
        let val = rr.u32(p + 1 + n)?;
        p += 1 + n + 4;
        if name == b"DSDB" {
            dsdb = Some(val as usize);
        }
    }
    let dsdb = dsdb.ok_or(DsStoreError::Corrupt("нет DSDB"))?;
    let block = |id: usize| -> Result<&[u8], DsStoreError> {
        let a = *addrs.get(id).ok_or(DsStoreError::Corrupt("номер блока"))?;
        let off = (a & !0x1f) as usize;
        let shift = a & 0x1f;
        if shift > 24 {
            return Err(DsStoreError::Corrupt("размер блока"));
        }
        let size = 1usize << shift;
        r.bytes(4 + off, size)
    };
    let master = Rd { b: block(dsdb)? };
    let root_node = master.u32(0)? as usize;
    let levels = master.u32(4)? as usize;
    if levels > lim.max_depth {
        return Err(DsStoreError::Corrupt("глубина дерева"));
    }
    let mut names = BTreeSet::new();
    let mut truncated = false;
    let mut visited = HashSet::new();
    // Iterative traversal: (node, depth).
    let mut stack = vec![(root_node, 0usize)];
    while let Some((id, depth)) = stack.pop() {
        if depth > lim.max_depth {
            return Err(DsStoreError::Corrupt("глубина дерева"));
        }
        if !visited.insert(id) {
            return Err(DsStoreError::Corrupt("цикл в дереве"));
        }
        if visited.len() > lim.max_nodes {
            truncated = true;
            break;
        }
        let nb = block(id)?;
        let n = Rd { b: nb };
        let right = n.u32(0)? as usize;
        let cnt = n.u32(4)? as usize;
        if cnt > nb.len() / 12 + 1 {
            return Err(DsStoreError::Corrupt("число записей"));
        }
        let mut q = 8;
        for _ in 0..cnt {
            if right != 0 {
                let child = n.u32(q)? as usize;
                q += 4;
                stack.push((child, depth + 1));
            }
            let (name, next) = read_record(&n, q)?;
            q = next;
            if names.len() >= lim.max_names {
                truncated = true;
            } else if name != "." && name != ".." && !name.is_empty() {
                names.insert(name);
            }
        }
        if right != 0 {
            stack.push((right, depth + 1));
        }
    }
    Ok(DsStoreNames {
        names: names.into_iter().collect(),
        truncated,
    })
}

fn read_utf16(r: &Rd<'_>, at: usize, units: usize) -> Result<String, DsStoreError> {
    if units > 4096 {
        return Err(DsStoreError::Corrupt("длина имени"));
    }
    let b = r.bytes(at, units * 2)?;
    let u: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect();
    Ok(String::from_utf16_lossy(&u))
}

/// Reads a record: name (UTF-16BE), structure code, type, data. Returns the name and the
/// offset of the next record.
fn read_record(r: &Rd<'_>, at: usize) -> Result<(String, usize), DsStoreError> {
    let units = r.u32(at)? as usize;
    let name = read_utf16(r, at + 4, units)?;
    let mut p = at + 4 + units * 2 + 4;
    let ty = r.bytes(p, 4)?;
    p += 4;
    let skip = match ty {
        b"long" | b"shor" | b"type" => 4,
        b"bool" => 1,
        b"comp" | b"dutc" => 8,
        b"blob" => 4 + r.u32(p)? as usize,
        b"ustr" => 4 + 2 * (r.u32(p)? as usize),
        _ => return Err(DsStoreError::Corrupt("неизвестный тип записи")),
    };
    r.bytes(p, skip)?;
    Ok((name, p + skip))
}

/// Returns `true` if a .DS_Store name is usable as a candidate path (no obfuscation, no
/// directory escape).
pub fn safe_candidate(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && !name.chars().any(|c| c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage_without_panic() {
        assert_eq!(
            parse_ds_store(b"hello", DsLimits::default()),
            Err(DsStoreError::BadMagic)
        );
        let mut b = vec![0, 0, 0, 1];
        b.extend_from_slice(b"Bud1");
        b.extend_from_slice(&[0xff; 24]);
        assert!(parse_ds_store(&b, DsLimits::default()).is_err());
        // Every possible truncation of a short header.
        for n in 0..b.len() {
            let _ = parse_ds_store(&b[..n], DsLimits::default());
        }
    }

    #[test]
    fn too_large_rejected() {
        let lim = DsLimits {
            max_input: 16,
            ..Default::default()
        };
        assert_eq!(
            parse_ds_store(&[0u8; 17], lim),
            Err(DsStoreError::TooLarge(17))
        );
    }

    #[test]
    fn candidate_names() {
        assert!(safe_candidate("report.pdf"));
        assert!(!safe_candidate("../etc"));
        assert!(!safe_candidate("a/b"));
        assert!(!safe_candidate("."));
    }
}
