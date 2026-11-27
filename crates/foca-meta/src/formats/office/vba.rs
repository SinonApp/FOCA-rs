//! VBA projects (MS-OVBA): module names and source text decompressed from the module streams,
//! scanned for URLs, paths, hosts, e-mail addresses and credentials. The full source is never
//! stored: only the extracted items and the lines that carry them (for secret scanning).

use std::io::{Cursor, Read, Seek};

use foca_core::Metadata;

use crate::util::{rd_u16le, rd_u32le, truncate};

const MAX_OUT: usize = 1 << 20;
const MAX_MODULES: usize = 200;
const MAX_LINES: usize = 500;

/// MS-OVBA 2.4.1 decompression of a CompressedContainer, bounded by [`MAX_OUT`].
pub(crate) fn decompress(b: &[u8]) -> Option<Vec<u8>> {
    if b.first() != Some(&1) {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut i = 1;
    while i + 2 <= b.len() && out.len() < MAX_OUT {
        let h = rd_u16le(b, i)?;
        let size = (h & 0x0FFF) as usize + 3;
        let compressed = h & 0x8000 != 0;
        let end = (i + size).min(b.len());
        i += 2;
        let chunk_start = out.len();
        if !compressed {
            out.extend_from_slice(b.get(i..(i + 4096).min(end))?);
            i = end;
            continue;
        }
        while i < end && out.len() < MAX_OUT {
            let flags = b[i];
            i += 1;
            for bit in 0..8 {
                if i >= end {
                    break;
                }
                if flags & (1 << bit) == 0 {
                    out.push(b[i]);
                    i += 1;
                } else {
                    let token = rd_u16le(b, i)?;
                    i += 2;
                    let diff = out.len() - chunk_start;
                    let bits = (usize::BITS - diff.saturating_sub(1).leading_zeros()).max(4);
                    let len_mask = 0xFFFFu16 >> bits;
                    let len = (token & len_mask) as usize + 3;
                    let off = ((token & !len_mask) >> (16 - bits)) as usize + 1;
                    if off > diff {
                        return Some(out);
                    }
                    for _ in 0..len {
                        let c = out[out.len() - off];
                        out.push(c);
                    }
                }
            }
        }
        i = end;
    }
    Some(out)
}

/// `(stream name, text offset)` of every module from the decompressed `dir` stream.
fn modules(dir: &[u8]) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut name: Option<String> = None;
    while i + 6 <= dir.len() && out.len() < MAX_MODULES {
        let id = rd_u16le(dir, i).unwrap_or(0);
        let size = rd_u32le(dir, i + 2).unwrap_or(0) as usize;
        // PROJECTVERSION declares 4 but carries 6 bytes
        let size = if id == 0x0009 { 6 } else { size };
        let data = dir.get(i + 6..(i + 6).saturating_add(size)).unwrap_or(&[]);
        match id {
            0x001A => name = Some(String::from_utf8_lossy(data).into_owned()),
            0x0031 => {
                if let (Some(n), Some(off)) = (name.take(), rd_u32le(data, 0)) {
                    out.push((n, off));
                }
            }
            _ => {}
        }
        i = i + 6 + size;
    }
    out
}

/// Reads every VBA project found in an OLE file (`vbaProject.bin`, `.doc`, `.xls`) and adds the
/// extracted items to `meta`. Returns the interesting source lines.
pub(crate) fn scan_ole(bytes: &[u8], meta: &mut Metadata) -> Vec<String> {
    crate::guard("vba", || {
        let Ok(mut cf) = cfb::CompoundFile::open(Cursor::new(bytes)) else {
            return Ok(Vec::new());
        };
        let dirs: Vec<String> = cf
            .walk()
            .filter(|e| e.is_stream() && e.name().eq_ignore_ascii_case("dir"))
            .map(|e| e.path().to_string_lossy().replace('\\', "/"))
            .filter(|p| p.to_ascii_lowercase().ends_with("/vba/dir"))
            .take(4)
            .collect();
        let mut lines = Vec::new();
        for d in dirs {
            let parent = d[..d.len() - 3].to_string();
            let Some(dir) = read(&mut cf, &d).and_then(|r| decompress(&r)) else {
                continue;
            };
            for (stream, off) in modules(&dir) {
                let Some(raw) = read(&mut cf, &format!("{parent}{stream}")) else {
                    continue;
                };
                let Some(src) = raw.get(off as usize..).and_then(decompress) else {
                    continue;
                };
                let text = crate::util::decode_text(&src);
                scan_source(meta, &stream, &text, &mut lines);
            }
        }
        Ok(lines)
    })
    .unwrap_or_default()
}

fn read<F: Read + Seek>(cf: &mut cfb::CompoundFile<F>, path: &str) -> Option<Vec<u8>> {
    let mut s = cf.open_stream(path).ok()?;
    let mut v = Vec::new();
    s.by_ref().take(8 << 20).read_to_end(&mut v).ok()?;
    Some(v)
}

const CRED_WORDS: &[&str] = &[
    "password",
    "pwd=",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "connectionstring",
    "provider=",
    "data source",
    "user id",
    "uid=",
];

/// Adds URLs, paths, e-mails and hosts from one module; keeps the lines that hold them.
fn scan_source(meta: &mut Metadata, module: &str, text: &str, lines: &mut Vec<String>) {
    let source = format!("vba:{}", truncate(module, 64));
    let mut urls = 0;
    for line in text.lines().take(100_000) {
        let l = line.trim();
        // comments and string-free lines are skipped quickly
        if l.is_empty() || l.starts_with('\'') && !l.contains("://") && !l.contains('\\') {
            continue;
        }
        let mut keep = false;
        for p in crate::paths::find_paths(l) {
            if crate::paths::add_path(meta, &p, &source) {
                keep = true;
            }
        }
        for e in crate::paths::find_emails(l) {
            Metadata::add_unique(&mut meta.emails, &e);
            keep = true;
        }
        for u in urls_in(l) {
            if urls < 100 {
                urls += 1;
                Metadata::add_unique(&mut meta.links, &u);
            }
            keep = true;
        }
        let lower = l.to_ascii_lowercase();
        if CRED_WORDS.iter().any(|w| lower.contains(w)) {
            keep = true;
        }
        if keep && lines.len() < MAX_LINES {
            lines.push(truncate(l, 512));
        }
    }
}

fn urls_in(l: &str) -> Vec<String> {
    let mut out = Vec::new();
    for scheme in ["https://", "http://", "ftp://", "ldap://", "file://"] {
        let mut from = 0;
        while let Some(i) = l[from..].find(scheme) {
            let s = from + i;
            let end = l[s..]
                .find(|c: char| c == '"' || c.is_whitespace() || c == '\'' || c == ')')
                .map_or(l.len(), |e| s + e);
            out.push(truncate(&l[s..end], 512));
            from = end.max(s + 1);
            if out.len() > 20 {
                return out;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compresses with literal-only chunks (valid MS-OVBA, no copy tokens).
    pub(crate) fn literal_container(data: &[u8]) -> Vec<u8> {
        let mut out = vec![1u8];
        for chunk in data.chunks(4096) {
            let mut body = Vec::new();
            for group in chunk.chunks(8) {
                body.push(0);
                body.extend_from_slice(group);
            }
            let h = 0x8000u16 | 0x3000 | ((body.len() + 2 - 3) as u16 & 0x0FFF);
            out.extend(h.to_le_bytes());
            out.extend(body);
        }
        out
    }

    #[test]
    fn decompress_spec_example() {
        // MS-OVBA 3.2.3: "#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
        let c: [u8; 59] = [
            0x01, 0x2F, 0xB0, 0x00, 0x23, 0x61, 0x61, 0x61, 0x62, 0x63, 0x64, 0x65, 0x82, 0x66,
            0x00, 0x70, 0x61, 0x67, 0x68, 0x69, 0x6A, 0x01, 0x38, 0x08, 0x61, 0x6B, 0x6C, 0x00,
            0x30, 0x6D, 0x6E, 0x6F, 0x70, 0x06, 0x71, 0x02, 0x70, 0x04, 0x10, 0x72, 0x73, 0x74,
            0x75, 0x76, 0x10, 0x77, 0x78, 0x79, 0x7A, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];
        let d = decompress(&c).unwrap();
        assert!(
            String::from_utf8_lossy(&d)
                .starts_with("#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"),
            "{:?}",
            String::from_utf8_lossy(&d)
        );
        let lit = literal_container(b"Attribute VB_Name = \"Module1\"");
        assert_eq!(
            decompress(&lit).unwrap(),
            b"Attribute VB_Name = \"Module1\""
        );
    }

    #[test]
    fn source_items() {
        let mut m = Metadata::default();
        let mut lines = Vec::new();
        scan_source(
            &mut m,
            "Module1",
            "Sub Upload()\n  Const URL = \"https://intranet.corp.example/upload\"\n  Open \"\\\\fs01\\share\\out.csv\" For Output As #1\n  cn.Open \"Provider=SQLOLEDB;Data Source=sql01;User ID=sa;Password=x\"\n  x = 1\nEnd Sub",
            &mut lines,
        );
        assert!(m
            .links
            .iter()
            .any(|l| l == "https://intranet.corp.example/upload"));
        assert!(m.paths.iter().any(|p| p.source == "vba:Module1"));
        assert_eq!(lines.len(), 3);
    }
}
