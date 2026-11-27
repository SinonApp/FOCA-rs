//! Extra image metadata: generative AI markers (PNG generator parameters, XMP digital source
//! type, C2PA/JUMBF manifests), ICC profile description and device, and camera maker notes
//! (Canon, Nikon, Fujifilm, Apple) with internal serial numbers, owner and firmware.

use std::io::Read;

use foca_core::{AiGenerated, Camera, Metadata, PersonRole};

use crate::util::{clean_str, rd_u16le, rd_u32be, rd_u32le, truncate};
use crate::{Ctx, MetaError};

const MAX_PROMPT: usize = 2000;

/// PNG text keys written by image generators.
pub(crate) fn is_generator_key(key: &str) -> bool {
    matches!(
        key,
        "parameters"
            | "prompt"
            | "workflow"
            | "Dream"
            | "sd-metadata"
            | "invokeai_metadata"
            | "generation_data"
            | "Comment"
    )
}

/// Reads one PNG text chunk of a generator; returns `true` when it was generator data (and must
/// not be stored as a plain field).
pub(crate) fn png_generator(meta: &mut Metadata, key: &str, text: &str) -> bool {
    let t = text.trim();
    let ai = |generator: &str, model: Option<String>, prompt: Option<String>| AiGenerated {
        generator: Some(generator.to_string()),
        model: model.map(|m| truncate(&m, 256)),
        prompt: prompt.map(|p| truncate(&p, MAX_PROMPT)),
        source: format!("png:{key}"),
    };
    let found = match key {
        "parameters" if t.contains("Steps:") || t.contains("Negative prompt:") => {
            let prompt = t
                .split("\nNegative prompt:")
                .next()
                .and_then(|p| p.split("\nSteps:").next())
                .map(str::to_string);
            let model = kv_after(t, "Model: ");
            let generator = if t.contains("Version: f") || t.contains("Forge") {
                "Stable Diffusion WebUI Forge"
            } else {
                "Stable Diffusion WebUI"
            };
            Some(ai(generator, model, prompt))
        }
        "prompt" | "workflow"
            if t.starts_with('{') && (t.contains("class_type") || t.contains("\"nodes\"")) =>
        {
            let model = json_after(t, "\"ckpt_name\"").or_else(|| json_after(t, "\"unet_name\""));
            let prompt = json_after(t, "\"text\"");
            Some(ai("ComfyUI", model, prompt))
        }
        "Dream" | "sd-metadata" | "invokeai_metadata" => {
            let model =
                json_after(t, "\"model_name\"").or_else(|| json_after(t, "\"model_weights\""));
            let prompt =
                json_after(t, "\"positive_prompt\"").or_else(|| json_after(t, "\"prompt\""));
            Some(ai("InvokeAI", model, prompt))
        }
        "generation_data" => Some(ai(
            "Generative tool",
            json_after(t, "\"model\""),
            json_after(t, "\"prompt\""),
        )),
        "Comment"
            if t.starts_with('{') && (t.contains("\"n_samples\"") || t.contains("\"uc\"")) =>
        {
            Some(ai("NovelAI", None, json_after(t, "\"prompt\"")))
        }
        _ => None,
    };
    let Some(a) = found else { return false };
    merge_ai(meta, a);
    true
}

/// Keeps the first marker, filling gaps from later ones.
pub(crate) fn merge_ai(meta: &mut Metadata, a: AiGenerated) {
    match meta.ai_generated.as_mut() {
        None => meta.ai_generated = Some(a),
        Some(cur) => {
            if cur.generator.is_none() {
                cur.generator = a.generator;
            }
            if cur.model.is_none() {
                cur.model = a.model;
            }
            if cur.prompt.is_none() {
                cur.prompt = a.prompt;
            }
        }
    }
    if let Some(g) = meta.ai_generated.as_ref().and_then(|x| x.generator.clone()) {
        Metadata::add_unique(&mut meta.software, &g);
    }
}

/// `Model: name,` in A1111 parameters.
fn kv_after(t: &str, key: &str) -> Option<String> {
    let i = t.find(key)? + key.len();
    let v = t[i..].split([',', '\n']).next()?.trim();
    clean_str(v)
}

/// The first JSON string value after `"key"` (a cheap scan; the JSON may be nested or huge).
fn json_after(t: &str, key: &str) -> Option<String> {
    let i = t.find(key)? + key.len();
    let rest = t[i..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut esc = false;
    for c in rest.chars() {
        if esc {
            out.push(match c {
                'n' => '\n',
                't' => '\t',
                c => c,
            });
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == '"' {
            break;
        } else {
            out.push(c);
        }
        if out.len() > MAX_PROMPT {
            break;
        }
    }
    clean_str(&out)
}

/// XMP `DigitalSourceType` (IPTC) or a generator name in the creator tool.
pub(crate) fn xmp_ai(meta: &mut Metadata) {
    let dst = meta
        .xmp
        .iter()
        .find(|(k, _)| k.ends_with("DigitalSourceType"))
        .map(|(_, v)| v.clone());
    if let Some(v) = dst {
        if v.contains("trainedAlgorithmicMedia") {
            let tool = meta.xmp.get("xmp:CreatorTool").cloned();
            merge_ai(
                meta,
                AiGenerated {
                    generator: tool,
                    source: "xmp:DigitalSourceType".into(),
                    ..Default::default()
                },
            );
        }
    }
    let tool = meta
        .xmp
        .get("xmp:CreatorTool")
        .or(meta.application.as_ref())
        .cloned()
        .unwrap_or_default();
    let lower = tool.to_ascii_lowercase();
    for g in [
        "dall-e",
        "dall·e",
        "midjourney",
        "stable diffusion",
        "adobe firefly",
        "imagen",
        "gpt-4o",
        "ideogram",
    ] {
        if lower.contains(g) {
            merge_ai(
                meta,
                AiGenerated {
                    generator: Some(truncate(&tool, 256)),
                    source: "creator tool".into(),
                    ..Default::default()
                },
            );
            break;
        }
    }
}

/// C2PA manifest store in JUMBF (JPEG APP11, PNG `caBX`): presence, claim generator and the
/// synthetic media marker.
pub(crate) fn c2pa(meta: &mut Metadata, jumbf: &[u8]) {
    if crate::util::find(jumbf, b"c2pa", 0).is_none() {
        return;
    }
    meta.fields.insert("c2pa:manifest".into(), "present".into());
    let gen = cbor_text_after(jumbf, b"claim_generator");
    if let Some(g) = &gen {
        meta.fields
            .insert("c2pa:claim_generator".into(), truncate(g, 256));
        Metadata::add_unique(&mut meta.software, &truncate(g, 256));
    }
    if crate::util::find(jumbf, b"trainedAlgorithmicMedia", 0).is_some() {
        merge_ai(
            meta,
            AiGenerated {
                generator: gen,
                source: "c2pa".into(),
                ..Default::default()
            },
        );
    }
}

/// A CBOR text string right after a CBOR text key.
fn cbor_text_after(b: &[u8], key: &[u8]) -> Option<String> {
    let at = crate::util::find(b, key, 0)? + key.len();
    let h = *b.get(at)?;
    let (len, start) = match h {
        0x60..=0x77 => ((h - 0x60) as usize, at + 1),
        0x78 => (*b.get(at + 1)? as usize, at + 2),
        0x79 => (
            u16::from_be_bytes([*b.get(at + 1)?, *b.get(at + 2)?]) as usize,
            at + 3,
        ),
        _ => return None,
    };
    let s = b.get(start..start + len.min(1024))?;
    clean_str(&String::from_utf8_lossy(s))
}

/// ICC profile: description, device manufacturer/model, creator.
pub(crate) fn icc(meta: &mut Metadata, p: &[u8]) {
    if p.len() < 132 || p.get(36..40) != Some(b"acsp") {
        return;
    }
    let sig = |o: usize| {
        p.get(o..o + 4)
            .filter(|s| s.iter().all(|c| c.is_ascii_graphic() || *c == b' '))
            .and_then(|s| clean_str(&String::from_utf8_lossy(s)))
    };
    for (o, k) in [
        (4, "cmm"),
        (48, "device_manufacturer"),
        (52, "device_model"),
        (80, "creator"),
    ] {
        if let Some(v) = sig(o) {
            meta.fields.insert(format!("icc:{k}"), v);
        }
    }
    let n = rd_u32be(p, 128).unwrap_or(0).min(100) as usize;
    for i in 0..n {
        let e = 132 + i * 12;
        let (Some(tag), Some(off), Some(len)) =
            (p.get(e..e + 4), rd_u32be(p, e + 4), rd_u32be(p, e + 8))
        else {
            break;
        };
        let key = match tag {
            b"desc" => "description",
            b"dmdd" => "device_model_desc",
            b"dmnd" => "device_manufacturer_desc",
            b"cprt" => "copyright",
            _ => continue,
        };
        let Some(d) = p.get(off as usize..(off as usize).saturating_add(len as usize).min(p.len()))
        else {
            continue;
        };
        if let Some(v) = icc_text(d) {
            meta.fields.insert(format!("icc:{key}"), truncate(&v, 256));
        }
    }
}

fn icc_text(d: &[u8]) -> Option<String> {
    match d.get(0..4)? {
        b"desc" => {
            let n = rd_u32be(d, 8)? as usize;
            let s = d.get(12..12 + n.min(512))?;
            clean_str(&String::from_utf8_lossy(s).replace('\0', ""))
        }
        b"text" => clean_str(&String::from_utf8_lossy(d.get(8..)?).replace('\0', "")),
        b"mluc" => {
            let len = rd_u32be(d, 20)? as usize;
            let off = rd_u32be(d, 24)? as usize;
            let s = d.get(off..off + len.min(1024))?;
            let u: Vec<u16> = s
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect();
            clean_str(&String::from_utf16_lossy(&u))
        }
        _ => None,
    }
}

/// Inflates a PNG `iCCP` chunk (name, method, zlib data) under the budget.
pub(crate) fn png_iccp(meta: &mut Metadata, data: &[u8], ctx: &Ctx) -> Result<(), MetaError> {
    let z = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    let Some(payload) = data.get(z + 2..) else {
        return Ok(());
    };
    let cap = ctx.remaining().min(4 << 20);
    let mut out = Vec::new();
    let _ = flate2::read::ZlibDecoder::new(payload)
        .take(cap)
        .read_to_end(&mut out);
    ctx.spend(out.len() as u64)?;
    icc(meta, &out);
    Ok(())
}

// ------------------------------------------------------------------ maker notes

struct Ifd<'a> {
    /// Buffer that offsets are relative to.
    base: &'a [u8],
    le: bool,
}

impl Ifd<'_> {
    fn u16(&self, o: usize) -> Option<u16> {
        if self.le {
            rd_u16le(self.base, o)
        } else {
            self.base
                .get(o..o + 2)
                .map(|s| u16::from_be_bytes([s[0], s[1]]))
        }
    }

    fn u32(&self, o: usize) -> Option<u32> {
        if self.le {
            rd_u32le(self.base, o)
        } else {
            rd_u32be(self.base, o)
        }
    }

    /// Entries `(tag, type, count, value bytes)` of the IFD at `at`.
    fn entries(&self, at: usize) -> Vec<(u16, u16, u32, &[u8])> {
        let mut out = Vec::new();
        let n = self.u16(at).unwrap_or(0).min(512) as usize;
        for i in 0..n {
            let e = at + 2 + i * 12;
            let (Some(tag), Some(ty), Some(count)) =
                (self.u16(e), self.u16(e + 2), self.u32(e + 4))
            else {
                break;
            };
            let unit = match ty {
                1 | 2 | 6 | 7 => 1,
                3 | 8 => 2,
                4 | 9 | 11 => 4,
                5 | 10 | 12 => 8,
                _ => continue,
            };
            let size = (count as usize).saturating_mul(unit);
            if size > 64 * 1024 {
                continue;
            }
            let val = if size <= 4 {
                self.base.get(e + 8..e + 8 + size)
            } else {
                self.u32(e + 8)
                    .and_then(|o| self.base.get(o as usize..(o as usize).saturating_add(size)))
            };
            if let Some(v) = val {
                out.push((tag, ty, count, v));
            }
        }
        out
    }

    fn num(&self, ty: u16, v: &[u8]) -> Option<u64> {
        match ty {
            3 => self.u16_of(v).map(u64::from),
            4 => self.u32_of(v).map(u64::from),
            _ => None,
        }
    }

    fn u16_of(&self, v: &[u8]) -> Option<u16> {
        let b: [u8; 2] = v.get(..2)?.try_into().ok()?;
        Some(if self.le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }

    fn u32_of(&self, v: &[u8]) -> Option<u32> {
        let b: [u8; 4] = v.get(..4)?.try_into().ok()?;
        Some(if self.le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }
}

fn ascii(v: &[u8]) -> Option<String> {
    let end = v.iter().position(|&c| c == 0).unwrap_or(v.len());
    clean_str(&String::from_utf8_lossy(&v[..end]))
}

/// Parses the maker note of `make`. `tiff` is the whole EXIF TIFF block, `off` the offset of
/// the maker note inside it.
pub(crate) fn maker_note(meta: &mut Metadata, make: &str, tiff: &[u8], off: usize, le: bool) {
    let Some(mn) = tiff.get(off..) else { return };
    let make = make.to_ascii_lowercase();
    let mut found: Vec<(&'static str, String)> = Vec::new();
    if make.starts_with("canon") {
        let ifd = Ifd { base: tiff, le };
        for (tag, ty, _, v) in ifd.entries(off) {
            match tag {
                0x0006 => push(&mut found, "ImageType", ascii(v)),
                0x0007 => push(&mut found, "FirmwareVersion", ascii(v)),
                0x0009 => push(&mut found, "OwnerName", ascii(v)),
                0x000C => push(
                    &mut found,
                    "SerialNumber",
                    ifd.num(ty, v).map(|n| n.to_string()),
                ),
                0x0096 => push(&mut found, "InternalSerialNumber", ascii(v)),
                0x0095 => push(&mut found, "LensModel", ascii(v)),
                _ => {}
            }
        }
    } else if make.starts_with("nikon") && mn.starts_with(b"Nikon\0") {
        // own TIFF header after the 10-byte prefix; offsets relative to it
        let Some(t) = mn.get(10..) else { return };
        let le = t.starts_with(b"II");
        let ifd = Ifd { base: t, le };
        let first = ifd.u32(4).unwrap_or(8) as usize;
        for (tag, ty, _, v) in ifd.entries(first) {
            match tag {
                0x001D => push(&mut found, "SerialNumber", ascii(v)),
                0x00A7 => push(
                    &mut found,
                    "ShutterCount",
                    ifd.num(ty, v).map(|n| n.to_string()),
                ),
                _ => {}
            }
        }
    } else if make.starts_with("fujifilm") && mn.starts_with(b"FUJIFILM") {
        let ifd = Ifd { base: mn, le: true };
        let first = rd_u32le(mn, 8).unwrap_or(12) as usize;
        for (tag, _, _, v) in ifd.entries(first) {
            if tag == 0x0010 {
                push(&mut found, "InternalSerialNumber", ascii(v));
            }
        }
    } else if make.starts_with("apple") && mn.starts_with(b"Apple iOS\0") {
        let ifd = Ifd {
            base: mn,
            le: false,
        };
        for (tag, _, _, v) in ifd.entries(14) {
            if tag == 0x000B {
                // burst/run identifier, stable per capture session
                push(&mut found, "RunTimeId", ascii(v));
            }
            if tag == 0x0011 {
                push(&mut found, "ContentIdentifier", ascii(v));
            }
        }
    }
    for (k, v) in found {
        let v = truncate(&v, 128);
        let cam = meta.camera.get_or_insert_with(Camera::default);
        match k {
            "SerialNumber" | "InternalSerialNumber" if cam.serial.is_none() => {
                cam.serial = Some(v.clone())
            }
            "OwnerName" => {
                cam.owner.get_or_insert(v.clone());
            }
            "LensModel" => {
                cam.lens.get_or_insert(v.clone());
            }
            _ => {}
        }
        if k == "OwnerName" {
            meta.add_person(&v, PersonRole::Owner, "makernote:OwnerName");
        }
        if k == "FirmwareVersion" {
            Metadata::add_unique(&mut meta.software, &v);
        }
        meta.fields.insert(format!("makernote:{k}"), v);
    }
}

fn push(v: &mut Vec<(&'static str, String)>, k: &'static str, s: Option<String>) {
    if let Some(s) = s {
        v.push((k, s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a1111_and_comfy() {
        let mut m = Metadata::default();
        assert!(png_generator(
            &mut m,
            "parameters",
            "a lighthouse at dusk\nNegative prompt: blurry\nSteps: 20, Sampler: Euler a, Model: dreamshaper_8, Model hash: abc",
        ));
        let a = m.ai_generated.clone().unwrap();
        assert_eq!(a.generator.as_deref(), Some("Stable Diffusion WebUI"));
        assert_eq!(a.model.as_deref(), Some("dreamshaper_8"));
        assert_eq!(a.prompt.as_deref(), Some("a lighthouse at dusk"));
        let mut m = Metadata::default();
        assert!(png_generator(
            &mut m,
            "prompt",
            r#"{"4":{"class_type":"CheckpointLoaderSimple","inputs":{"ckpt_name":"sd_xl_base_1.0.safetensors"}},"6":{"class_type":"CLIPTextEncode","inputs":{"text":"an office"}}}"#,
        ));
        assert_eq!(
            m.ai_generated.unwrap().model.as_deref(),
            Some("sd_xl_base_1.0.safetensors")
        );
        assert!(!png_generator(
            &mut Metadata::default(),
            "Comment",
            "just a note"
        ));
    }

    #[test]
    fn c2pa_claim_generator() {
        let mut j = b"....jumb....c2pa....".to_vec();
        j.extend(b"\x6Fclaim_generator\x6CExampleCam/1");
        j.extend(b"...http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia");
        let mut m = Metadata::default();
        c2pa(&mut m, &j);
        assert_eq!(m.fields["c2pa:claim_generator"], "ExampleCam/1");
        assert_eq!(m.ai_generated.unwrap().source, "c2pa");
    }
}
