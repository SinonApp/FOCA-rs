//! Windows PE executables and libraries (exe, dll, sys, scr).
//!
//! Reads the COFF header (machine, build timestamp), the `VS_VERSIONINFO` resource (company,
//! product, versions, original file name, copyright), the CodeView debug record (PDB path and
//! GUID: the path often holds the developer's user name and project folders), the Authenticode
//! certificate table (signer subject and issuer, no validation) and the .NET runtime version.
//! Every offset is bounds-checked; resource walking is limited in depth and entry count.

use foca_core::{DocFormat, Metadata, PersonRole, SignatureKind};

use crate::formats::signature;
use crate::util::{clean_str, rd_u16le, rd_u32le, truncate, utf16le};
use crate::{Ctx, MetaError};

/// Returns `true` for a DOS header that points at a `PE\0\0` signature.
pub(crate) fn is_pe(b: &[u8]) -> bool {
    pe_offset(b).is_some()
}

fn pe_offset(b: &[u8]) -> Option<usize> {
    if !b.starts_with(b"MZ") {
        return None;
    }
    let off = rd_u32le(b, 0x3C)? as usize;
    (off >= 0x40 && b.get(off..off + 4)? == b"PE\0\0").then_some(off)
}

struct Section {
    va: u32,
    vsize: u32,
    raw: u32,
    raw_size: u32,
}

struct Pe<'a> {
    b: &'a [u8],
    sections: Vec<Section>,
}

impl<'a> Pe<'a> {
    /// Converts an RVA to a file offset through the section table.
    fn off(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            let size = s.vsize.max(s.raw_size);
            if rva >= s.va && rva < s.va.checked_add(size)? {
                let o = (rva - s.va).checked_add(s.raw)? as usize;
                return (o < self.b.len()).then_some(o);
            }
        }
        // headers-only images map RVA == offset
        let o = rva as usize;
        (self.sections.is_empty() && o < self.b.len()).then_some(o)
    }

    fn slice(&self, rva: u32, len: u32) -> Option<&'a [u8]> {
        let o = self.off(rva)?;
        let end = o.checked_add(len as usize)?.min(self.b.len());
        self.b.get(o..end)
    }
}

const MAX_RES_ENTRIES: usize = 256;

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    crate::guard("pe", || extract_inner(b, ctx))
}

fn extract_inner(b: &[u8], _ctx: &Ctx) -> Result<Metadata, MetaError> {
    let pe_off = pe_offset(b).ok_or_else(|| MetaError::malformed("pe", "нет заголовка PE"))?;
    let mut meta = Metadata::new(DocFormat::Exe);
    let coff = pe_off + 4;
    let machine = rd_u16le(b, coff).ok_or_else(|| MetaError::malformed("pe", "COFF"))?;
    let nsect = rd_u16le(b, coff + 2).unwrap_or(0).min(96) as usize;
    let ts = rd_u32le(b, coff + 4).unwrap_or(0);
    let opt_size = rd_u16le(b, coff + 16).unwrap_or(0) as usize;
    let chars = rd_u16le(b, coff + 18).unwrap_or(0);
    meta.fields
        .insert("pe:machine".into(), machine_name(machine).into());
    if chars & 0x2000 != 0 {
        meta.fields.insert("pe:type".into(), "dll".into());
    }
    if ts != 0 {
        // Reproducible builds store a hash here; only a plausible date is a build time.
        if (631_152_000..=2_208_988_800).contains(&ts) {
            if let Some(d) = crate::util::unix_to_iso(i64::from(ts)) {
                meta.fields.insert("pe:timestamp".into(), d.clone());
                meta.created = Some(d);
            }
        } else {
            meta.fields
                .insert("pe:timestamp_raw".into(), format!("{ts:08x}"));
        }
    }
    let opt = coff + 20;
    let magic = rd_u16le(b, opt).unwrap_or(0);
    let (dir_at, count_at) = match magic {
        0x10b => (opt + 96, opt + 92),
        0x20b => (opt + 112, opt + 108),
        _ => {
            meta.warnings
                .push("PE: неизвестный опциональный заголовок".into());
            return Ok(meta);
        }
    };
    if let Some(sub) = rd_u16le(b, opt + 68) {
        let s = match sub {
            1 => "native",
            2 => "windows-gui",
            3 => "windows-console",
            9 => "windows-ce",
            10..=13 => "efi",
            _ => "",
        };
        if !s.is_empty() {
            meta.fields.insert("pe:subsystem".into(), s.into());
        }
    }
    if let (Some(maj), Some(min)) = (rd_u16le(b, opt + 40), rd_u16le(b, opt + 42)) {
        meta.fields
            .insert("pe:os_version".into(), format!("{maj}.{min}"));
    }
    if let (Some(maj), Some(min)) = (b.get(opt + 2), b.get(opt + 3)) {
        meta.fields
            .insert("pe:linker".into(), format!("{maj}.{min}"));
    }
    let ndirs = rd_u32le(b, count_at).unwrap_or(0).min(16) as usize;
    let dir = |i: usize| -> (u32, u32) {
        if i >= ndirs {
            return (0, 0);
        }
        (
            rd_u32le(b, dir_at + i * 8).unwrap_or(0),
            rd_u32le(b, dir_at + i * 8 + 4).unwrap_or(0),
        )
    };
    let sect_at = opt + opt_size;
    let mut sections = Vec::new();
    for i in 0..nsect {
        let s = sect_at + i * 40;
        let (Some(vsize), Some(va), Some(raw_size), Some(raw)) = (
            rd_u32le(b, s + 8),
            rd_u32le(b, s + 12),
            rd_u32le(b, s + 16),
            rd_u32le(b, s + 20),
        ) else {
            break;
        };
        sections.push(Section {
            va,
            vsize,
            raw,
            raw_size,
        });
    }
    let pe = Pe { b, sections };

    let (res_rva, _) = dir(2);
    if res_rva != 0 {
        if let Some(vi) = find_version_resource(&pe, res_rva) {
            version_info(&mut meta, vi);
        }
    }
    let (dbg_rva, dbg_size) = dir(6);
    if dbg_rva != 0 {
        debug_dir(&mut meta, &pe, dbg_rva, dbg_size);
    }
    let (cert_off, cert_size) = dir(4);
    if cert_off != 0 && cert_size >= 8 {
        authenticode(&mut meta, b, cert_off as usize, cert_size as usize);
    }
    let (clr_rva, _) = dir(14);
    if clr_rva != 0 {
        dotnet(&mut meta, &pe, clr_rva);
    }
    Ok(meta)
}

fn machine_name(m: u16) -> &'static str {
    match m {
        0x14c => "x86",
        0x8664 => "x64",
        0x1c0 | 0x1c4 => "arm",
        0xaa64 => "arm64",
        0x200 => "ia64",
        0 => "any",
        _ => "other",
    }
}

/// Walks the resource tree `type 16 (RT_VERSION) -> first name -> first language`.
fn find_version_resource<'a>(pe: &Pe<'a>, res_rva: u32) -> Option<&'a [u8]> {
    let root = pe.off(res_rva)?;
    let b = pe.b;
    let entries = |dir: usize| -> Vec<(u32, u32)> {
        let named = rd_u16le(b, dir + 12).unwrap_or(0) as usize;
        let ids = rd_u16le(b, dir + 14).unwrap_or(0) as usize;
        (0..(named + ids).min(MAX_RES_ENTRIES))
            .map_while(|i| {
                let e = dir + 16 + i * 8;
                Some((rd_u32le(b, e)?, rd_u32le(b, e + 4)?))
            })
            .collect()
    };
    let sub = |off: u32| -> Option<usize> {
        if off & 0x8000_0000 == 0 {
            return None;
        }
        let o = root.checked_add((off & 0x7FFF_FFFF) as usize)?;
        (o + 16 <= b.len()).then_some(o)
    };
    let (_, t) = entries(root).into_iter().find(|(id, _)| *id == 16)?;
    let names = sub(t)?;
    let (_, n) = *entries(names).first()?;
    let langs = sub(n)?;
    let (_, leaf) = *entries(langs).first()?;
    if leaf & 0x8000_0000 != 0 {
        return None;
    }
    let data = root.checked_add(leaf as usize)?;
    let rva = rd_u32le(b, data)?;
    let size = rd_u32le(b, data + 4)?.min(64 * 1024);
    pe.slice(rva, size)
}

/// One `VS_VERSIONINFO`-style block: key, value bytes and the child area.
struct Block<'a> {
    key: String,
    value: &'a [u8],
    value_is_text: bool,
    children: &'a [u8],
    len: usize,
}

fn align4(x: usize) -> usize {
    (x + 3) & !3
}

fn block(b: &[u8]) -> Option<Block<'_>> {
    let len = (rd_u16le(b, 0)? as usize).min(b.len());
    if len < 6 {
        return None;
    }
    let vlen = rd_u16le(b, 2)? as usize;
    let ty = rd_u16le(b, 4)?;
    let mut i = 6;
    let mut key = Vec::new();
    while i + 1 < len {
        let c = u16::from_le_bytes([b[i], b[i + 1]]);
        i += 2;
        if c == 0 {
            break;
        }
        key.push(c);
        if key.len() > 64 {
            return None;
        }
    }
    let key = String::from_utf16_lossy(&key);
    let vstart = align4(i).min(len);
    // String values count UTF-16 units, binary values count bytes.
    let vbytes = if ty == 1 { vlen * 2 } else { vlen };
    let vend = (vstart + vbytes).min(len);
    let children = &b[align4(vend).min(len)..len];
    Some(Block {
        key,
        value: &b[vstart..vend],
        value_is_text: ty == 1,
        children,
        len,
    })
}

fn blocks(mut b: &[u8]) -> Vec<Block<'_>> {
    let mut out = Vec::new();
    while out.len() < 128 {
        let Some(bl) = block(b) else { break };
        let next = align4(bl.len);
        out.push(bl);
        if next >= b.len() {
            break;
        }
        b = &b[next..];
    }
    out
}

fn version_info(meta: &mut Metadata, vi: &[u8]) {
    let Some(root) = block(vi) else { return };
    if root.key != "VS_VERSION_INFO" {
        return;
    }
    // VS_FIXEDFILEINFO: signature 0xFEEF04BD, file version at 8..16
    if rd_u32le(root.value, 0) == Some(0xFEEF_04BD) {
        let v = |o| rd_u32le(root.value, o).unwrap_or(0);
        let (ms, ls) = (v(8), v(12));
        if ms != 0 || ls != 0 {
            meta.fields.insert(
                "pe:FileVersionNumber".into(),
                format!("{}.{}.{}.{}", ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF),
            );
        }
    }
    for sfi in blocks(root.children) {
        if sfi.key != "StringFileInfo" {
            continue;
        }
        for table in blocks(sfi.children).into_iter().take(4) {
            for s in blocks(table.children) {
                if !s.value_is_text {
                    continue;
                }
                let Some(v) = clean_str(&utf16le(s.value)) else {
                    continue;
                };
                let v = truncate(&v, 512);
                let key = truncate(&s.key, 64);
                apply_version_string(meta, &key, &v);
                meta.fields.insert(format!("pe:{key}"), v);
            }
        }
    }
}

fn apply_version_string(meta: &mut Metadata, key: &str, v: &str) {
    match key {
        "CompanyName" => {
            meta.company.get_or_insert_with(|| v.to_string());
        }
        "ProductName" => {
            meta.title.get_or_insert_with(|| v.to_string());
        }
        "FileDescription" => {
            meta.description.get_or_insert_with(|| v.to_string());
        }
        "LegalCopyright" => {
            meta.custom.insert("copyright".into(), v.to_string());
        }
        _ => {}
    }
}

/// Reads the CodeView record (`RSDS` PDB 7.0 or `NB10` PDB 2.0) from the debug directory.
fn debug_dir(meta: &mut Metadata, pe: &Pe, rva: u32, size: u32) {
    let Some(dir) = pe.slice(rva, size.min(28 * 32)) else {
        return;
    };
    for e in dir.as_chunks::<28>().0 {
        let ty = rd_u32le(e, 12).unwrap_or(0);
        if ty != 2 {
            continue;
        }
        let len = rd_u32le(e, 16).unwrap_or(0).min(4096) as usize;
        let ptr = rd_u32le(e, 24).unwrap_or(0) as usize;
        let Some(cv) = pe.b.get(ptr..ptr.saturating_add(len).min(pe.b.len())) else {
            continue;
        };
        let (path, guid) = if cv.starts_with(b"RSDS") && cv.len() > 24 {
            (&cv[24..], Some(guid_str(&cv[4..20])))
        } else if cv.starts_with(b"NB10") && cv.len() > 16 {
            (&cv[16..], None)
        } else {
            continue;
        };
        let end = path.iter().position(|&c| c == 0).unwrap_or(path.len());
        let Some(p) = clean_str(&String::from_utf8_lossy(&path[..end])) else {
            continue;
        };
        let p = truncate(&p, 1024);
        if let Some(g) = guid {
            meta.fields.insert("pe:pdb_guid".into(), g);
        }
        crate::paths::add_path(meta, &p, "pe:pdb");
        if let Some(folder) = build_folder(&p) {
            meta.fields.insert("pe:build_folder".into(), folder);
        }
        meta.fields.insert("pe:pdb".into(), p);
        break;
    }
}

/// The project folder of a PDB path: everything before `\obj\`, `\bin\`, `\Release\`,
/// `\Debug\`, `\x64\` or `\out\`, else the parent directory.
pub(crate) fn build_folder(p: &str) -> Option<String> {
    let norm = p.replace('/', "\\");
    let lower = norm.to_ascii_lowercase();
    let cut = [
        "\\obj\\",
        "\\bin\\",
        "\\release\\",
        "\\debug\\",
        "\\x64\\",
        "\\x86\\",
        "\\out\\",
        "\\build\\",
        "\\target\\",
    ]
    .iter()
    .filter_map(|m| lower.find(m))
    .min()
    .or_else(|| norm.rfind('\\'))?;
    (cut > 2).then(|| norm[..cut].to_string())
}

fn guid_str(g: &[u8]) -> String {
    let d1 = rd_u32le(g, 0).unwrap_or(0);
    let d2 = rd_u16le(g, 4).unwrap_or(0);
    let d3 = rd_u16le(g, 6).unwrap_or(0);
    let rest: String = g[8..].iter().map(|x| format!("{x:02X}")).collect();
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{}-{}",
        &rest[..4.min(rest.len())],
        rest.get(4..).unwrap_or("")
    )
}

/// `WIN_CERTIFICATE` entries in the certificate table (a file offset, not an RVA).
fn authenticode(meta: &mut Metadata, b: &[u8], off: usize, size: usize) {
    let end = off.saturating_add(size).min(b.len());
    let mut at = off;
    let mut n = 0;
    while at + 8 <= end && n < 4 {
        let len = rd_u32le(b, at).unwrap_or(0) as usize;
        let ty = rd_u16le(b, at + 6).unwrap_or(0);
        if len < 8 {
            break;
        }
        let blob = &b[at + 8..(at + len).min(end)];
        if ty == 2 {
            if let Some(cms) = signature::find_cms(blob) {
                meta.signatures.push(signature::from_cms(
                    SignatureKind::Authenticode,
                    "pe:certificate_table",
                    &cms,
                ));
            }
        }
        n += 1;
        at = at.saturating_add(align8(len));
    }
    let signers: Vec<_> = meta
        .signatures
        .iter()
        .filter_map(|s| s.signer.clone())
        .collect();
    for c in signers {
        if let Some(o) = c.organization.as_deref() {
            meta.fields
                .entry("pe:signer_org".into())
                .or_insert_with(|| o.to_string());
        }
        if let Some(cn) = c.common_name.as_deref() {
            meta.fields
                .entry("pe:signer".into())
                .or_insert_with(|| cn.to_string());
            // An individual developer certificate names a person, a company one does not.
            if c.organization.is_none() || c.organization.as_deref() == Some(cn) {
                meta.add_person(cn, PersonRole::Other, "pe:signer");
            }
        }
        if !c.serial.is_empty() {
            meta.fields
                .entry("pe:signer_serial".into())
                .or_insert(c.serial.clone());
        }
        if let Some(i) = c.issuer_cn.as_deref() {
            meta.fields
                .entry("pe:signer_issuer".into())
                .or_insert_with(|| i.to_string());
        }
    }
}

fn align8(x: usize) -> usize {
    (x + 7) & !7
}

/// .NET: the CLR header points at the metadata root (`BSJB`) holding the runtime version.
fn dotnet(meta: &mut Metadata, pe: &Pe, clr_rva: u32) {
    let Some(clr) = pe.slice(clr_rva, 72) else {
        return;
    };
    let (Some(md_rva), Some(md_size)) = (rd_u32le(clr, 8), rd_u32le(clr, 12)) else {
        return;
    };
    let Some(md) = pe.slice(md_rva, md_size.min(4096)) else {
        return;
    };
    if rd_u32le(md, 0) != Some(0x424A_5342) {
        return;
    }
    let vlen = rd_u32le(md, 12).unwrap_or(0).min(255) as usize;
    if let Some(v) = md.get(16..16 + vlen) {
        let end = v.iter().position(|&c| c == 0).unwrap_or(v.len());
        if let Some(s) = clean_str(&String::from_utf8_lossy(&v[..end])) {
            meta.fields.insert("pe:dotnet_runtime".into(), s);
        }
    }
    meta.fields.insert("pe:dotnet".into(), "yes".into());
}

/// Software, application and people derived after all fields are read.
pub(crate) fn finish(meta: &mut Metadata) {
    let product = meta.fields.get("pe:ProductName").cloned();
    let version = meta
        .fields
        .get("pe:ProductVersion")
        .or_else(|| meta.fields.get("pe:FileVersion"))
        .cloned();
    if let Some(p) = product {
        let sw = match version {
            Some(v) => format!("{p} {v}"),
            None => p,
        };
        Metadata::add_unique(&mut meta.software, &sw);
        meta.application.get_or_insert(sw);
    }
    if let Some(l) = meta.fields.get("pe:linker").cloned() {
        Metadata::add_unique(&mut meta.software, &format!("Microsoft Linker {l}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_folder_cuts_output_dirs() {
        assert_eq!(
            build_folder(r"C:\Users\dev\source\repos\Billing\obj\Release\Billing.pdb").as_deref(),
            Some(r"C:\Users\dev\source\repos\Billing")
        );
        assert_eq!(build_folder(r"D:\a\b.pdb").as_deref(), Some(r"D:\a"));
        assert_eq!(build_folder("x.pdb"), None);
    }
}
