//! TAR archives (v7, ustar, GNU, PAX): member names, owner user/group names and ids,
//! modification times, and recursive parsing of members (they are stored, not compressed).

use foca_core::{Attachment, DocFormat, Metadata, PersonRole};

use crate::formats::archive::zipfile::is_unsafe_name;
use crate::util::{clean_str, truncate, unix_to_iso};
use crate::{Ctx, MetaError, MAX_CHILDREN};

const MAX_LISTED: usize = 1000;

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

fn octal(f: &[u8]) -> Option<u64> {
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

fn cstr(f: &[u8]) -> String {
    let end = f.iter().position(|&c| c == 0).unwrap_or(f.len());
    String::from_utf8_lossy(&f[..end]).into_owned()
}

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    crate::guard("tar", || extract_inner(b, ctx))
}

fn extract_inner(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    if !is_tar(b) {
        return Err(MetaError::malformed("tar", "неверная контрольная сумма"));
    }
    let mut meta = Metadata::new(DocFormat::Tar);
    let mut at = 0usize;
    let mut files = 0u64;
    let mut times: Vec<String> = Vec::new();
    let mut users: Vec<String> = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut ids: Vec<String> = Vec::new();
    let mut long_name: Option<String> = None;
    let mut pax_path: Option<String> = None;
    let mut unsafe_names = 0;
    let mut n = 0usize;
    while at + 512 <= b.len() {
        n += 1;
        if n > ctx.max_entries() {
            meta.warnings.push("TAR: слишком много записей".into());
            break;
        }
        let h = &b[at..at + 512];
        if h.iter().all(|&c| c == 0) || !is_tar(h) {
            break;
        }
        let size = octal(&h[124..136]).unwrap_or(0);
        let ty = h[156];
        let data_at = at + 512;
        let data_end = data_at.saturating_add(size as usize).min(b.len());
        let data = &b[data_at..data_end];
        let next = data_at.saturating_add((size as usize).div_ceil(512) * 512);
        match ty {
            b'L' => {
                long_name = Some(cstr(&data[..data.len().min(4096)]));
                at = next;
                continue;
            }
            b'x' | b'g' => {
                pax_path = pax(&mut meta, &data[..data.len().min(64 * 1024)]).or(pax_path);
                at = next;
                continue;
            }
            _ => {}
        }
        let ustar = &h[257..262] == b"ustar";
        let mut name = cstr(&h[0..100]);
        if ustar {
            let prefix = cstr(&h[345..500]);
            if !prefix.is_empty() && h[263] == b'0' {
                name = format!("{prefix}/{name}");
            }
        }
        if let Some(l) = long_name.take() {
            name = l;
        }
        if let Some(p) = pax_path.take() {
            name = p;
        }
        if let Some(t) = octal(&h[136..148]).and_then(|t| unix_to_iso(t as i64)) {
            times.push(t);
        }
        if ustar {
            let u = cstr(&h[265..297]);
            let g = cstr(&h[297..329]);
            if let Some(u) = clean_str(&u) {
                if !users.contains(&u) && users.len() < 32 {
                    users.push(u);
                }
            }
            if let Some(g) = clean_str(&g) {
                if !groups.contains(&g) && groups.len() < 32 {
                    groups.push(g);
                }
            }
        }
        let id = format!(
            "{}:{}",
            octal(&h[108..116]).unwrap_or(0),
            octal(&h[116..124]).unwrap_or(0)
        );
        if !ids.contains(&id) && ids.len() < 32 {
            ids.push(id);
        }
        if is_unsafe_name(&name) {
            unsafe_names += 1;
        }
        let is_file = matches!(ty, b'0' | 0 | b'7');
        if is_file {
            files += 1;
            if meta.attachments.len() < MAX_LISTED {
                meta.attachments.push(Attachment {
                    name: truncate(&name, 512),
                    size: Some(size),
                    mime: None,
                });
            }
            for root in ["home/", "Users/", "root/"] {
                if name.starts_with(root) {
                    crate::paths::add_path(&mut meta, &format!("/{name}"), "tar:name");
                }
            }
            if name.starts_with('/') {
                crate::paths::add_path(&mut meta, &name, "tar:name");
            }
            if ctx.can_descend()
                && meta.embedded.len() < MAX_CHILDREN
                && !data.is_empty()
                && data.len() as u64 == size
            {
                let short = name.rsplit('/').next().unwrap_or(&name).to_string();
                ctx.attach_child(&mut meta, data, &short, &name)?;
            }
        }
        if next <= at {
            break;
        }
        at = next;
    }
    for u in &users {
        meta.add_person(u, PersonRole::Account, "tar:uname");
    }
    if !users.is_empty() {
        meta.fields.insert("tar:uname".into(), users.join(", "));
    }
    if !groups.is_empty() {
        meta.fields.insert("tar:gname".into(), groups.join(", "));
    }
    if !ids.is_empty() {
        meta.fields.insert("tar:uid_gid".into(), ids.join(", "));
    }
    if unsafe_names > 0 {
        meta.stats
            .insert("archive_unsafe_names".into(), unsafe_names);
        meta.warnings.push(format!(
            "TAR: {unsafe_names} entries with path traversal names"
        ));
    }
    meta.stats.insert("files".into(), files);
    times.sort();
    meta.created = times.first().cloned();
    meta.modified = times.last().cloned();
    Ok(meta)
}

/// PAX extended header records `"<len> key=value\n"`; returns `path` if present.
fn pax(meta: &mut Metadata, d: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(d);
    let mut path = None;
    for rec in text.split('\n').take(256) {
        let Some((_, kv)) = rec.split_once(' ') else {
            continue;
        };
        let Some((k, v)) = kv.split_once('=') else {
            continue;
        };
        match k {
            "path" => path = clean_str(v).map(|p| truncate(&p, 1024)),
            "uname" => meta.add_person(v, PersonRole::Account, "tar:pax.uname"),
            "SCHILY.fflags" | "LIBARCHIVE.creationtime" | "comment" => {
                if let Some(v) = clean_str(v) {
                    meta.fields.insert(format!("tar:{k}"), truncate(&v, 256));
                }
            }
            _ => {}
        }
    }
    path
}
