//! Windows shell links (MS-SHLLINK): target timestamps and size, LinkInfo (local or UNC path,
//! drive type, volume serial number and label), StringData (description, relative path,
//! working directory, arguments, icon), TrackerDataBlock (NetBIOS machine name and the MAC
//! address from a version 1 object GUID) and environment-variable blocks.
//!
//! Every offset is bounds-checked; malformed sub-structures are skipped with a warning.

use foca_core::{DocFormat, Metadata};

use crate::util::{
    clean_str, decode_text, filetime_to_iso, rd_u16le, rd_u32le, rd_u64le, truncate, utf16le_z,
};
use crate::{Ctx, MetaError};

/// Shell link header CLSID `00021401-0000-0000-C000-000000000046` preceded by the header size.
pub(crate) const MAGIC: [u8; 20] = [
    0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x46,
];

const HAS_ID_LIST: u32 = 0x1;
const HAS_LINK_INFO: u32 = 0x2;
const HAS_NAME: u32 = 0x4;
const HAS_RELATIVE_PATH: u32 = 0x8;
const HAS_WORKING_DIR: u32 = 0x10;
const HAS_ARGUMENTS: u32 = 0x20;
const HAS_ICON_LOCATION: u32 = 0x40;
const IS_UNICODE: u32 = 0x80;

const MAX_STRING_FIELD: usize = 4096;
const MAX_EXTRA_BLOCKS: usize = 64;

/// 100 ns ticks between the UUID epoch (1582-10-15) and the FILETIME epoch (1601-01-01).
const UUID_TO_FILETIME: u64 = 5_748_192_000_000_000;

fn drive_type(t: u32) -> &'static str {
    match t {
        1 => "no_root_dir",
        2 => "removable",
        3 => "fixed",
        4 => "remote",
        5 => "cdrom",
        6 => "ramdisk",
        _ => "unknown",
    }
}

/// Reads a NUL-terminated ANSI string at `off` (bounded by `end`).
fn ansi_z(b: &[u8], off: usize, end: usize) -> Option<String> {
    let s = b.get(off..end.min(b.len()))?;
    let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    clean_str(&decode_text(s.get(..n.min(MAX_STRING_FIELD))?))
}

/// Reads a NUL-terminated UTF-16LE string at `off` (bounded by `end`).
fn unicode_z(b: &[u8], off: usize, end: usize) -> Option<String> {
    let s = b.get(off..end.min(b.len()))?;
    let s = s.get(..s.len().min(MAX_STRING_FIELD * 2))?;
    clean_str(&utf16le_z(s))
}

fn put(meta: &mut Metadata, key: &str, v: Option<String>) {
    if let Some(v) = v {
        meta.fields.insert(format!("lnk:{key}"), truncate(&v, 1024));
    }
}

/// Formats a GUID stored in the Microsoft mixed-endian layout.
fn guid(g: &[u8]) -> Option<String> {
    let d1 = rd_u32le(g, 0)?;
    let d2 = rd_u16le(g, 4)?;
    let d3 = rd_u16le(g, 6)?;
    let r = g.get(8..16)?;
    Some(format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]
    ))
}

/// For a version 1 (time-based) GUID returns the node (MAC address) and the generation time.
fn guid_v1(g: &[u8]) -> Option<(String, Option<String>)> {
    let time_low = u64::from(rd_u32le(g, 0)?);
    let time_mid = u64::from(rd_u16le(g, 4)?);
    let time_hi = rd_u16le(g, 6)?;
    if time_hi >> 12 != 1 {
        return None;
    }
    let node = g.get(10..16)?;
    if node.iter().all(|&x| x == 0) {
        return None;
    }
    let mac = node
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let ts = (u64::from(time_hi & 0x0FFF) << 48) | (time_mid << 32) | time_low;
    let when = ts.checked_sub(UUID_TO_FILETIME).and_then(filetime_to_iso);
    Some((mac, when))
}

fn link_info(meta: &mut Metadata, b: &[u8], base: usize) -> Option<usize> {
    let size = rd_u32le(b, base)? as usize;
    let end = base.checked_add(size)?;
    let li = b.get(base..end)?;
    let header = rd_u32le(li, 4)? as usize;
    let flags = rd_u32le(li, 8)?;
    let vol_off = rd_u32le(li, 12)? as usize;
    let local_off = rd_u32le(li, 16)? as usize;
    let net_off = rd_u32le(li, 20)? as usize;
    let suffix_off = rd_u32le(li, 24)? as usize;
    let (local_u, suffix_u) = if header >= 0x24 {
        (
            rd_u32le(li, 28).map(|v| v as usize),
            rd_u32le(li, 32).map(|v| v as usize),
        )
    } else {
        (None, None)
    };
    let n = li.len();
    if flags & 1 != 0 {
        // VolumeID
        if let Some(vsize) = rd_u32le(li, vol_off).map(|v| v as usize) {
            let vend = vol_off.saturating_add(vsize).min(n);
            if let (Some(dt), Some(serial)) = (
                rd_u32le(li, vol_off.saturating_add(4)),
                rd_u32le(li, vol_off.saturating_add(8)),
            ) {
                meta.fields
                    .insert("lnk:drive_type".into(), drive_type(dt).into());
                meta.fields.insert(
                    "lnk:volume_serial".into(),
                    format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF),
                );
            }
            if let Some(lo) = rd_u32le(li, vol_off.saturating_add(12)).map(|v| v as usize) {
                let label = if lo == 0x14 {
                    rd_u32le(li, vol_off.saturating_add(16))
                        .and_then(|u| unicode_z(li, vol_off.saturating_add(u as usize), vend))
                } else {
                    ansi_z(li, vol_off.saturating_add(lo), vend)
                };
                put(meta, "volume_label", label);
            }
        }
        let local = local_u
            .filter(|&o| o != 0)
            .and_then(|o| unicode_z(li, o, n))
            .or_else(|| ansi_z(li, local_off, n));
        put(meta, "local_base_path", local);
    }
    let suffix = suffix_u
        .filter(|&o| o != 0)
        .and_then(|o| unicode_z(li, o, n))
        .or_else(|| ansi_z(li, suffix_off, n));
    if flags & 2 != 0 {
        // CommonNetworkRelativeLink
        let csize = rd_u32le(li, net_off).map(|v| v as usize).unwrap_or(0);
        let cend = net_off.saturating_add(csize).min(n);
        let cflags = rd_u32le(li, net_off.saturating_add(4)).unwrap_or(0);
        let name_off = rd_u32le(li, net_off.saturating_add(8)).unwrap_or(0) as usize;
        let dev_off = rd_u32le(li, net_off.saturating_add(12)).unwrap_or(0) as usize;
        let (name, dev) = if name_off > 0x14 {
            let nu = rd_u32le(li, net_off.saturating_add(20)).unwrap_or(0) as usize;
            let du = rd_u32le(li, net_off.saturating_add(24)).unwrap_or(0) as usize;
            (
                unicode_z(li, net_off.saturating_add(nu), cend),
                (cflags & 1 != 0)
                    .then(|| unicode_z(li, net_off.saturating_add(du), cend))
                    .flatten(),
            )
        } else {
            (
                ansi_z(li, net_off.saturating_add(name_off), cend),
                (cflags & 1 != 0)
                    .then(|| ansi_z(li, net_off.saturating_add(dev_off), cend))
                    .flatten(),
            )
        };
        if let Some(name) = name {
            let full = match &suffix {
                Some(s) if !name.ends_with('\\') => format!("{name}\\{s}"),
                Some(s) => format!("{name}{s}"),
                None => name.clone(),
            };
            put(meta, "network_share", Some(name));
            put(meta, "network_path", Some(full));
        }
        put(meta, "device_name", dev);
    } else if let Some(s) = suffix {
        put(meta, "path_suffix", Some(s));
    }
    Some(end)
}

fn string_data(meta: &mut Metadata, b: &[u8], mut off: usize, flags: u32) -> usize {
    let unicode = flags & IS_UNICODE != 0;
    let items = [
        (HAS_NAME, "description"),
        (HAS_RELATIVE_PATH, "relative_path"),
        (HAS_WORKING_DIR, "working_dir"),
        (HAS_ARGUMENTS, "arguments"),
        (HAS_ICON_LOCATION, "icon_location"),
    ];
    for (flag, key) in items {
        if flags & flag == 0 {
            continue;
        }
        let Some(count) = rd_u16le(b, off) else {
            meta.warnings
                .push(format!("LNK: StringData {key} truncated"));
            return b.len();
        };
        let bytes = usize::from(count) * if unicode { 2 } else { 1 };
        let start = off + 2;
        let Some(s) = b.get(start..start + bytes) else {
            meta.warnings
                .push(format!("LNK: StringData {key} truncated"));
            return b.len();
        };
        let v = if unicode {
            clean_str(&crate::util::utf16le(s))
        } else {
            clean_str(&decode_text(s))
        };
        if key == "description" && meta.description.is_none() {
            meta.description = v.clone();
        }
        put(meta, key, v);
        off = start + bytes;
    }
    off
}

fn extra_data(meta: &mut Metadata, b: &[u8], mut off: usize) {
    for _ in 0..MAX_EXTRA_BLOCKS {
        let Some(size) = rd_u32le(b, off).map(|v| v as usize) else {
            return;
        };
        if size < 8 {
            return; // terminal block
        }
        let Some(blk) = off.checked_add(size).and_then(|end| b.get(off..end)) else {
            meta.warnings.push("LNK: ExtraData block truncated".into());
            return;
        };
        let sig = rd_u32le(blk, 4).unwrap_or(0);
        match sig {
            // TrackerDataBlock
            0xA000_0003 if blk.len() >= 0x60 => {
                if let Some(machine) = ansi_z(blk, 16, 32) {
                    meta.add_server(&machine, "lnk:machine_id");
                    put(meta, "machine_id", Some(machine));
                }
                put(meta, "droid_volume_id", blk.get(32..48).and_then(guid));
                put(meta, "droid_file_id", blk.get(48..64).and_then(guid));
                put(meta, "birth_droid_file_id", blk.get(80..96).and_then(guid));
                for (range, key) in [(48..64, "mac"), (80..96, "birth_mac")] {
                    if let Some((mac, when)) = blk.get(range).and_then(guid_v1) {
                        if key == "mac" || meta.fields.get("lnk:mac") != Some(&mac) {
                            put(meta, key, Some(mac));
                        }
                        if key == "mac" {
                            put(meta, "droid_time", when);
                        }
                    }
                }
            }
            // EnvironmentVariableDataBlock, DarwinDataBlock, IconEnvironmentDataBlock
            0xA000_0001 | 0xA000_0006 | 0xA000_0007 if blk.len() >= 788 => {
                let key = match sig {
                    0xA000_0001 => "env_target",
                    0xA000_0006 => "darwin_id",
                    _ => "icon_env_target",
                };
                let v = unicode_z(blk, 268, 788).or_else(|| ansi_z(blk, 8, 268));
                put(meta, key, v);
            }
            // KnownFolderDataBlock
            0xA000_000B if blk.len() >= 28 => {
                put(meta, "known_folder_id", blk.get(8..24).and_then(guid));
            }
            _ => {}
        }
        off += size;
    }
}

pub fn extract(b: &[u8], _ctx: &Ctx) -> Result<Metadata, MetaError> {
    if !b.starts_with(&MAGIC) || b.len() < 0x4C {
        return Err(MetaError::malformed("lnk", "bad header"));
    }
    let mut meta = Metadata::new(DocFormat::Lnk);
    let flags = rd_u32le(b, 0x14).unwrap_or(0);
    let attrs = rd_u32le(b, 0x18).unwrap_or(0);
    meta.created = rd_u64le(b, 0x1C).and_then(filetime_to_iso);
    let access = rd_u64le(b, 0x24).and_then(filetime_to_iso);
    put(&mut meta, "access_time", access);
    meta.modified = rd_u64le(b, 0x2C).and_then(filetime_to_iso);
    if let Some(sz) = rd_u32le(b, 0x34) {
        meta.fields.insert("lnk:target_size".into(), sz.to_string());
    }
    meta.fields
        .insert("lnk:file_attributes".into(), format!("0x{attrs:08x}"));
    let mut off = 0x4C;
    if flags & HAS_ID_LIST != 0 {
        let Some(n) = rd_u16le(b, off) else {
            meta.warnings.push("LNK: IDList truncated".into());
            return Ok(meta);
        };
        off += 2 + usize::from(n);
    }
    if flags & HAS_LINK_INFO != 0 {
        match link_info(&mut meta, b, off) {
            Some(end) => off = end,
            None => {
                meta.warnings.push("LNK: LinkInfo malformed".into());
                // skip by the declared size if it is sane
                match rd_u32le(b, off).map(|v| v as usize) {
                    Some(s) if s >= 4 && off.checked_add(s).is_some_and(|e| e <= b.len()) => {
                        off += s
                    }
                    _ => return Ok(meta),
                }
            }
        }
    }
    let off = string_data(&mut meta, b, off, flags);
    extra_data(&mut meta, b, off);
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_v1_extracts_mac_and_time() {
        // {e2e0a1a4-1d3a-11ef-a1b2-0a0027000001}: version 1, node 0a:00:27:00:00:01
        let g = [
            0xA4, 0xA1, 0xE0, 0xE2, 0x3A, 0x1D, 0xEF, 0x11, 0xA1, 0xB2, 0x0A, 0x00, 0x27, 0x00,
            0x00, 0x01,
        ];
        let (mac, when) = guid_v1(&g).unwrap();
        assert_eq!(mac, "0a:00:27:00:00:01");
        assert!(when.unwrap().starts_with("2024-"));
        assert_eq!(guid(&g).unwrap(), "e2e0a1a4-1d3a-11ef-a1b2-0a0027000001");
        let mut v4 = g;
        v4[7] = 0x41;
        assert!(guid_v1(&v4).is_none());
    }
}
