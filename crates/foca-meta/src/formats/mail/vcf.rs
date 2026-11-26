//! vCard (`.vcf`, versions 2.1-4.0): names, e-mails, phone numbers, organizations, titles,
//! addresses, URLs, notes, birthdays, GEO, producer and revision, and embedded photos parsed
//! recursively (their EXIF may carry GPS and camera data).

use foca_core::{DocFormat, Gps, Metadata, PersonRole};

use crate::formats::mail::ics::{ical_date, parse_lines, Line};
use crate::util::{clean_str, truncate};
use crate::{Ctx, MetaError};

/// Maximum number of cards whose details are stored in `fields`.
const MAX_CARD_FIELDS: usize = 100;

fn geo(v: &str) -> Option<Gps> {
    let v = v.trim().trim_start_matches("geo:");
    let v = v.split(';').take(2).collect::<Vec<_>>().join(",");
    let mut it = v.split(',');
    let lat: f64 = it.next()?.trim().parse().ok()?;
    let lon: f64 = it.next()?.trim().parse().ok()?;
    ((-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) && (lat, lon) != (0.0, 0.0))
        .then_some(Gps {
            lat,
            lon,
            alt: None,
        })
}

fn append(meta: &mut Metadata, key: String, v: &str) {
    let v = truncate(v, 512);
    meta.fields
        .entry(key)
        .and_modify(|e| {
            if e.len() < 2048 && !e.split("; ").any(|x| x == v) {
                e.push_str("; ");
                e.push_str(&v);
            }
        })
        .or_insert(v);
}

fn structured(v: &str) -> String {
    v.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut meta = Metadata::new(DocFormat::Vcf);
    let lines = parse_lines(b);
    let mut cards = 0usize;
    let mut in_card = false;
    let mut revs: Vec<String> = Vec::new();
    let mut name_n: Option<String> = None;
    let mut has_fn = false;
    for l in &lines {
        let v = l.text();
        match l.name.as_str() {
            "BEGIN" if l.value.trim().eq_ignore_ascii_case("VCARD") => {
                cards += 1;
                if cards > ctx.max_entries() {
                    return Err(MetaError::TooManyEntries("vCard: too many cards".into()));
                }
                in_card = true;
                name_n = None;
                has_fn = false;
                continue;
            }
            "END" if l.value.trim().eq_ignore_ascii_case("VCARD") => {
                if !has_fn {
                    if let Some(n) = name_n.take() {
                        meta.add_person(&n, PersonRole::Other, "vcf:n");
                    }
                }
                in_card = false;
                continue;
            }
            _ => {}
        }
        if !in_card {
            continue;
        }
        let store = cards <= MAX_CARD_FIELDS;
        let key = |k: &str| format!("vcf:{cards:02}.{k}");
        match l.name.as_str() {
            "FN" => {
                if let Some(n) = clean_str(&v) {
                    has_fn = true;
                    meta.add_person(&truncate(&n, 256), PersonRole::Other, "vcf:fn");
                    if store {
                        meta.fields.insert(key("fn"), truncate(&n, 256));
                    }
                }
            }
            "N" => {
                // family;given;additional;prefix;suffix
                let p: Vec<&str> = v.split(';').map(str::trim).collect();
                let given = [p.get(3), p.get(1), p.get(2), p.first(), p.get(4)]
                    .into_iter()
                    .flatten()
                    .filter(|s| !s.is_empty())
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" ");
                name_n = clean_str(&given);
            }
            "EMAIL" => {
                let e = v.trim().trim_start_matches("mailto:");
                if e.contains('@') {
                    Metadata::add_unique(&mut meta.emails, e);
                }
            }
            "TEL" if store => append(&mut meta, key("tel"), v.trim().trim_start_matches("tel:")),
            "ORG" => {
                let o = structured(&v);
                if let Some(o) = clean_str(&o) {
                    meta.company.get_or_insert(truncate(&o, 256));
                    if store {
                        append(&mut meta, key("org"), &o);
                    }
                }
            }
            "TITLE" | "ROLE" | "NOTE" | "BDAY" | "ANNIVERSARY" | "UID" | "NICKNAME" | "IMPP"
            | "X-SOCIALPROFILE" | "X-SKYPE" | "X-TELEGRAM"
                if store =>
            {
                let k = l.name.to_ascii_lowercase();
                append(&mut meta, key(&k), &v);
            }
            "ADR" if store => {
                let a = structured(&v);
                if !a.is_empty() {
                    append(&mut meta, key("adr"), &a);
                }
                if let Some(g) = l.param("GEO").and_then(geo) {
                    meta.gps.get_or_insert(g);
                }
            }
            "URL" => {
                let u = v.trim();
                if u.starts_with("http") {
                    Metadata::add_unique(&mut meta.links, &truncate(u, 2048));
                }
            }
            "GEO" => {
                if let Some(g) = geo(&v) {
                    meta.gps.get_or_insert(g);
                }
            }
            "PRODID" => {
                if let Some(p) = clean_str(&v) {
                    meta.application.get_or_insert(truncate(&p, 256));
                    Metadata::add_unique(&mut meta.software, &truncate(&p, 256));
                }
            }
            "REV" => {
                if let Some(d) = ical_date(&v) {
                    revs.push(d);
                }
            }
            "PHOTO" | "LOGO" => photo(&mut meta, ctx, l, cards)?,
            _ => {}
        }
    }
    if cards == 0 {
        return Err(MetaError::malformed("vcf", "no VCARD"));
    }
    revs.sort();
    meta.modified = revs.last().cloned();
    meta.stats.insert("cards".into(), cards as u64);
    Ok(meta)
}

fn photo(meta: &mut Metadata, ctx: &Ctx, l: &Line, card: usize) -> Result<(), MetaError> {
    let data = match l.binary() {
        Some(d) => d,
        None => {
            let v = l.value.trim();
            // vCard 4.0 data URI
            match v
                .strip_prefix("data:")
                .and_then(|r| r.split_once(";base64,"))
            {
                Some((_, b64)) => crate::formats::mail::eml::base64_decode(b64.as_bytes()),
                None => {
                    if v.starts_with("http") {
                        Metadata::add_unique(&mut meta.links, &truncate(v, 2048));
                    }
                    return Ok(());
                }
            }
        }
    };
    if data.is_empty() {
        return Ok(());
    }
    ctx.spend(data.len() as u64)?;
    let ext = l
        .param("TYPE")
        .map(|t| t.split(',').next().unwrap_or("").to_ascii_lowercase())
        .filter(|t| !t.is_empty() && t.len() <= 5 && t.bytes().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| "bin".into());
    let name = format!("card-{card:02}-{}.{ext}", l.name.to_ascii_lowercase());
    meta.attachments.push(foca_core::Attachment {
        name: name.clone(),
        size: Some(data.len() as u64),
        mime: l
            .param("TYPE")
            .map(|t| format!("image/{}", t.to_ascii_lowercase())),
    });
    ctx.attach_child(meta, &data, &name, &name)
}
