//! RAR archives, v4 and v5: member names, host OS, modification times and the archive comment
//! flag, read from block headers without decompressing anything. Encrypted headers stop the walk.

use foca_core::{Attachment, DocFormat, Metadata};

use crate::formats::archive::zipfile::is_unsafe_name;
use crate::formats::magic::{RAR4, RAR5};
use crate::util::{rd_u16le, rd_u32le, truncate, unix_to_iso};
use crate::{Ctx, MetaError};

const MAX_LISTED: usize = 1000;

#[derive(Default)]
struct Acc {
    files: u64,
    hosts: Vec<&'static str>,
    times: Vec<String>,
    unsafe_names: u64,
}

impl Acc {
    fn add(
        &mut self,
        meta: &mut Metadata,
        name: &str,
        size: u64,
        host: &'static str,
        t: Option<String>,
    ) {
        self.files += 1;
        if !self.hosts.contains(&host) {
            self.hosts.push(host);
        }
        if let Some(t) = t {
            self.times.push(t);
        }
        if is_unsafe_name(name) {
            self.unsafe_names += 1;
        }
        if meta.attachments.len() < MAX_LISTED {
            meta.attachments.push(Attachment {
                name: truncate(name, 512),
                size: Some(size),
                mime: None,
            });
        }
    }
}

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    crate::guard("rar", || {
        let mut meta = Metadata::new(DocFormat::Rar);
        let mut acc = Acc::default();
        if b.starts_with(RAR5) {
            meta.fields.insert("rar:version".into(), "5".into());
            v5(&mut meta, &mut acc, b, ctx.max_entries());
        } else if b.starts_with(RAR4) {
            meta.fields.insert("rar:version".into(), "4".into());
            v4(&mut meta, &mut acc, b, ctx.max_entries());
        } else {
            return Err(MetaError::malformed("rar", "нет сигнатуры RAR"));
        }
        Metadata::add_unique(&mut meta.software, "WinRAR");
        meta.stats.insert("files".into(), acc.files);
        if !acc.hosts.is_empty() {
            meta.fields
                .insert("rar:host_os".into(), acc.hosts.join(", "));
            if acc.hosts.len() == 1 {
                meta.os = Some(acc.hosts[0].to_string());
            }
        }
        if acc.unsafe_names > 0 {
            meta.stats
                .insert("archive_unsafe_names".into(), acc.unsafe_names);
        }
        acc.times.sort();
        meta.created = acc.times.first().cloned();
        meta.modified = acc.times.last().cloned();
        Ok(meta)
    })
}

fn host4(h: u8) -> &'static str {
    match h {
        0 => "MS-DOS",
        1 => "OS/2",
        2 => "Windows",
        3 => "Unix",
        4 => "macOS",
        5 => "BeOS",
        _ => "other",
    }
}

fn dos_time(t: u32) -> Option<String> {
    let (d, tm) = ((t >> 16) as u16, t as u16);
    let y = 1980 + u32::from(d >> 9);
    let mo = (d >> 5) & 0xF;
    let day = d & 0x1F;
    if !(1..=12).contains(&mo) || day == 0 {
        return None;
    }
    Some(format!(
        "{y:04}-{mo:02}-{day:02}T{:02}:{:02}:{:02}",
        tm >> 11,
        (tm >> 5) & 0x3F,
        (tm & 0x1F) * 2
    ))
}

fn v4(meta: &mut Metadata, acc: &mut Acc, b: &[u8], max: usize) {
    let mut at = RAR4.len();
    for _ in 0..max {
        let (Some(ty), Some(flags), Some(hsize)) = (
            b.get(at + 2).copied(),
            rd_u16le(b, at + 3),
            rd_u16le(b, at + 5),
        ) else {
            break;
        };
        let hsize = hsize as usize;
        if hsize < 7 {
            break;
        }
        let add = if flags & 0x8000 != 0 {
            rd_u32le(b, at + 7).unwrap_or(0) as usize
        } else {
            0
        };
        match ty {
            0x73 => {
                if flags & 0x0080 != 0 {
                    meta.encrypted = true;
                    meta.warnings.push("RAR: заголовки зашифрованы".into());
                    return;
                }
                if flags & 0x0002 != 0 {
                    meta.fields.insert("rar:comment".into(), "yes".into());
                }
                if flags & 0x0100 != 0 {
                    meta.fields.insert("rar:locked".into(), "yes".into());
                }
            }
            0x74 => {
                let unp = rd_u32le(b, at + 11).unwrap_or(0);
                let host = b.get(at + 15).copied().unwrap_or(255);
                let ftime = rd_u32le(b, at + 20).unwrap_or(0);
                let nsize = rd_u16le(b, at + 26).unwrap_or(0) as usize;
                let name_at = at + 32 + if flags & 0x100 != 0 { 8 } else { 0 };
                if let Some(raw) = b.get(name_at..name_at + nsize.min(hsize)) {
                    // Unicode names: ASCII part, NUL, compressed UTF-16 (ASCII part is enough)
                    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
                    let name = String::from_utf8_lossy(&raw[..end]).replace('\\', "/");
                    if flags & 0x04 != 0 {
                        meta.encrypted = true;
                    }
                    acc.add(meta, &name, u64::from(unp), host4(host), dos_time(ftime));
                }
            }
            0x7B => break,
            _ => {}
        }
        let next = at.saturating_add(hsize).saturating_add(add);
        if next <= at {
            break;
        }
        at = next;
    }
}

/// RAR5 variable-length integer: 7 bits per byte, high bit = continue.
fn vint(b: &[u8], at: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    for i in 0..10 {
        let c = *b.get(*at)?;
        *at += 1;
        v |= u64::from(c & 0x7F) << (7 * i);
        if c & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fn v5(meta: &mut Metadata, acc: &mut Acc, b: &[u8], max: usize) {
    let mut at = RAR5.len();
    for _ in 0..max {
        let start = at;
        let mut p = at + 4;
        let Some(hsize) = vint(b, &mut p) else { break };
        let body_start = p;
        let Some(hend) = body_start.checked_add(hsize as usize) else {
            break;
        };
        if hsize == 0 || hend > b.len() {
            break;
        }
        let (Some(ty), Some(hflags)) = (vint(b, &mut p), vint(b, &mut p)) else {
            break;
        };
        if hflags & 1 != 0 && vint(b, &mut p).is_none() {
            break;
        }
        let data = if hflags & 2 != 0 {
            vint(b, &mut p).unwrap_or(0)
        } else {
            0
        };
        match ty {
            4 => {
                meta.encrypted = true;
                meta.warnings.push("RAR: заголовки зашифрованы".into());
                return;
            }
            2 => file5(meta, acc, &b[..hend], p),
            5 => break,
            _ => {}
        }
        let Some(next) = hend.checked_add(data as usize) else {
            break;
        };
        if next <= start {
            break;
        }
        at = next;
    }
}

fn file5(meta: &mut Metadata, acc: &mut Acc, b: &[u8], mut p: usize) {
    let Some(fflags) = vint(b, &mut p) else {
        return;
    };
    let unp = vint(b, &mut p).unwrap_or(0);
    let _attr = vint(b, &mut p);
    let mut t = None;
    if fflags & 2 != 0 {
        t = rd_u32le(b, p).and_then(|x| unix_to_iso(i64::from(x)));
        p += 4;
    }
    if fflags & 4 != 0 {
        p += 4;
    }
    let _comp = vint(b, &mut p);
    let host = match vint(b, &mut p) {
        Some(0) => "Windows",
        Some(1) => "Unix",
        _ => "other",
    };
    let nlen = vint(b, &mut p).unwrap_or(0) as usize;
    let Some(raw) = b.get(p..p.saturating_add(nlen.min(4096))) else {
        return;
    };
    let name = String::from_utf8_lossy(raw).into_owned();
    if fflags & 1 == 0 {
        acc.add(meta, &name, unp, host, t);
    }
}
