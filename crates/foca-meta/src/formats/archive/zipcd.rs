//! Raw ZIP central directory walker: the fields the `zip` crate does not expose (host OS of
//! "version made by", per-entry comments, Unix uid/gid and NTFS time extra fields).

use foca_core::Metadata;

use crate::util::{clean_str, filetime_to_iso, rd_u16le, rd_u32le, rd_u64le, truncate};

pub(crate) struct CdEntry {
    pub name: String,
    /// High byte of "version made by" (0 = MS-DOS/FAT, 3 = Unix, 10 = NTFS, 19 = macOS).
    pub host: u8,
    pub comment: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// NTFS modification time (FILETIME) from extra field 0x000a.
    pub ntfs_mtime: Option<u64>,
    /// Unix modification time from extra field 0x5455 (extended timestamp).
    pub unix_mtime: Option<u32>,
}

/// Locates the end-of-central-directory record and walks up to `max` entries.
pub(crate) fn entries(b: &[u8], max: usize) -> Vec<CdEntry> {
    let mut out = Vec::new();
    let tail = b.len().saturating_sub(65_557);
    let Some(eocd) = (tail..b.len().saturating_sub(21))
        .rev()
        .find(|&i| b.get(i..i + 4) == Some(b"PK\x05\x06"))
    else {
        return out;
    };
    let count = rd_u16le(b, eocd + 10).unwrap_or(0) as usize;
    let mut at = rd_u32le(b, eocd + 16).unwrap_or(0) as usize;
    for _ in 0..count.min(max) {
        if b.get(at..at + 4) != Some(b"PK\x01\x02") {
            break;
        }
        let (Some(made), Some(nlen), Some(xlen), Some(clen)) = (
            rd_u16le(b, at + 4),
            rd_u16le(b, at + 28),
            rd_u16le(b, at + 30),
            rd_u16le(b, at + 32),
        ) else {
            break;
        };
        let (nlen, xlen, clen) = (nlen as usize, xlen as usize, clen as usize);
        let name_at = at + 46;
        let Some(name) = b.get(name_at..name_at + nlen) else {
            break;
        };
        let extra = b.get(name_at + nlen..name_at + nlen + xlen).unwrap_or(&[]);
        let comment = b
            .get(name_at + nlen + xlen..name_at + nlen + xlen + clen)
            .unwrap_or(&[]);
        let mut e = CdEntry {
            name: String::from_utf8_lossy(name).into_owned(),
            host: (made >> 8) as u8,
            comment: crate::util::decode_text(comment),
            uid: None,
            gid: None,
            ntfs_mtime: None,
            unix_mtime: None,
        };
        parse_extra(extra, &mut e);
        out.push(e);
        at = name_at + nlen + xlen + clen;
    }
    out
}

fn parse_extra(x: &[u8], e: &mut CdEntry) {
    let mut i = 0;
    let mut n = 0;
    while i + 4 <= x.len() && n < 32 {
        n += 1;
        let id = rd_u16le(x, i).unwrap_or(0);
        let len = rd_u16le(x, i + 2).unwrap_or(0) as usize;
        let Some(d) = x.get(i + 4..i + 4 + len) else {
            break;
        };
        match id {
            // Info-ZIP Unix (new): version, uid size, uid, gid size, gid
            0x7875 if d.len() >= 3 => {
                let us = d[1] as usize;
                let uid = read_var(d.get(2..2 + us));
                let gs_at = 2 + us;
                let gs = d.get(gs_at).copied().unwrap_or(0) as usize;
                let gid = read_var(d.get(gs_at + 1..gs_at + 1 + gs));
                e.uid = uid;
                e.gid = gid;
            }
            // Info-ZIP Unix (old): atime, mtime, uid, gid
            0x5855 if d.len() >= 12 => {
                e.uid = rd_u16le(d, 8).map(u32::from);
                e.gid = rd_u16le(d, 10).map(u32::from);
            }
            0x5455 if d.len() >= 5 && d[0] & 1 != 0 => {
                e.unix_mtime = rd_u32le(d, 1);
            }
            // NTFS: reserved u32, then tag 1 size 24: mtime, atime, ctime
            0x000a if d.len() >= 32 && rd_u16le(d, 4) == Some(1) => {
                e.ntfs_mtime = rd_u64le(d, 8);
            }
            _ => {}
        }
        i += 4 + len;
    }
}

fn read_var(b: Option<&[u8]>) -> Option<u32> {
    let b = b?;
    match b.len() {
        1 => Some(u32::from(b[0])),
        2 => rd_u16le(b, 0).map(u32::from),
        4 => rd_u32le(b, 0),
        8 => rd_u64le(b, 0).and_then(|v| u32::try_from(v).ok()),
        _ => None,
    }
}

/// Name of a ZIP "version made by" host system.
pub(crate) fn host_name(h: u8) -> &'static str {
    match h {
        0 => "MS-DOS/Windows (FAT)",
        3 => "Unix",
        7 => "Macintosh",
        10 => "Windows NTFS",
        11 => "MVS",
        14 => "VFAT",
        19 => "macOS",
        _ => "other",
    }
}

/// Adds the central directory details to archive metadata: host systems, entry comments,
/// Unix owner ids and the newest NTFS/Unix modification time.
pub(crate) fn apply(meta: &mut Metadata, b: &[u8], max: usize) {
    let list = entries(b, max);
    let mut hosts: Vec<&'static str> = Vec::new();
    let mut uids: Vec<u32> = Vec::new();
    let mut gids: Vec<u32> = Vec::new();
    let mut newest: Option<String> = None;
    let mut comments = 0;
    for e in &list {
        let h = host_name(e.host);
        if !hosts.contains(&h) {
            hosts.push(h);
        }
        if let Some(u) = e.uid.filter(|u| !uids.contains(u)) {
            if uids.len() < 16 {
                uids.push(u);
            }
        }
        if let Some(g) = e.gid.filter(|g| !gids.contains(g)) {
            if gids.len() < 16 {
                gids.push(g);
            }
        }
        let t = e.ntfs_mtime.and_then(filetime_to_iso).or_else(|| {
            e.unix_mtime
                .and_then(|t| crate::util::unix_to_iso(i64::from(t)))
        });
        if let Some(t) = t {
            if newest.as_ref().is_none_or(|n| &t > n) {
                newest = Some(t);
            }
        }
        if let Some(c) = clean_str(&e.comment) {
            if comments < 50 {
                comments += 1;
                meta.fields.insert(
                    format!("zip:comment:{}", truncate(&e.name, 128)),
                    truncate(&c, 512),
                );
            }
        }
    }
    if !hosts.is_empty() {
        meta.fields.insert("zip:host_os".into(), hosts.join(", "));
        if hosts.len() == 1 && meta.os.is_none() && hosts[0] != "other" {
            meta.os = Some(hosts[0].to_string());
        }
    }
    let join = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
    if !uids.is_empty() {
        meta.fields.insert("zip:uid".into(), join(&uids));
    }
    if !gids.is_empty() {
        meta.fields.insert("zip:gid".into(), join(&gids));
    }
    if let Some(t) = newest {
        meta.fields.insert("zip:newest_mtime".into(), t);
    }
}
