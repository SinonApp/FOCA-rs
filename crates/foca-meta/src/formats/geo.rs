//! Geodata: KML, KMZ (zipped KML) and GPX. Coordinates become [`GeoPoint`]s with their source
//! (capped), plus document name, author, creating tool and times.

use foca_core::{DocFormat, GeoPoint, Metadata, PersonRole};

use crate::util::{clean_str, truncate};
use crate::xml::Element;
use crate::zipx::SafeZip;
use crate::{Ctx, MetaError};

const MAX_POINTS: usize = 500;

/// A ZIP with a `.kml` at the root is KMZ.
pub(crate) fn is_kmz(names: &[String]) -> bool {
    names
        .iter()
        .any(|n| !n.contains('/') && n.to_ascii_lowercase().ends_with(".kml"))
}

pub fn extract_kmz(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut z = SafeZip::open(b, ctx.max_entries())?;
    let name = z
        .names()
        .iter()
        .find(|n| n.eq_ignore_ascii_case("doc.kml"))
        .or_else(|| z.names().iter().find(|n| is_kmz(std::slice::from_ref(n))))
        .cloned()
        .ok_or_else(|| MetaError::malformed("kmz", "нет KML"))?;
    let kml = z
        .read(&name, ctx)?
        .ok_or_else(|| MetaError::malformed("kmz", "KML не читается"))?;
    let mut meta = extract_kml(&kml, ctx)?;
    meta.format = DocFormat::Kmz;
    Ok(meta)
}

struct Acc {
    total: u64,
}

impl Acc {
    fn push(&mut self, meta: &mut Metadata, p: GeoPoint) {
        if !(-90.0..=90.0).contains(&p.lat) || !(-180.0..=180.0).contains(&p.lon) {
            return;
        }
        self.total += 1;
        if meta.geo_points.len() < MAX_POINTS {
            meta.geo_points.push(p);
        }
    }
}

pub fn extract_kml(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let root = crate::xml::parse_bytes(b, ctx.max_xml_depth(), ctx.max_xml_nodes())?;
    let mut meta = Metadata::new(DocFormat::Kml);
    let mut acc = Acc { total: 0 };
    if let Some(doc) = root.child("Document").or(Some(&root)) {
        if let Some(n) = doc.child("name").and_then(Element::text_opt) {
            meta.title = Some(truncate(&n, 512));
        }
        if let Some(d) = doc.child("description").and_then(Element::text_opt) {
            meta.description = Some(truncate(&d, 2048));
        }
    }
    for a in root.descendants("author") {
        if let Some(n) = a.child("name").and_then(Element::text_opt) {
            meta.add_person(&n, PersonRole::Author, "kml:atom:author");
            meta.author.get_or_insert(truncate(&n, 256));
        }
        if let Some(e) = a.child("email").and_then(Element::text_opt) {
            Metadata::add_unique(&mut meta.emails, &e);
        }
    }
    for pm in root.descendants("Placemark") {
        let name = pm
            .child("name")
            .and_then(Element::text_opt)
            .map(|n| truncate(&n, 256));
        let when = pm.descendants("when").first().and_then(|w| w.text_opt());
        for c in pm.descendants("coordinates") {
            for tuple in c.text().split_whitespace().take(MAX_POINTS * 4) {
                let mut it = tuple.split(',').map(|x| x.trim().parse::<f64>());
                if let (Some(Ok(lon)), Some(Ok(lat))) = (it.next(), it.next()) {
                    let alt = it.next().and_then(Result::ok);
                    acc.push(
                        &mut meta,
                        GeoPoint {
                            lat,
                            lon,
                            alt,
                            time: when.clone(),
                            name: name.clone(),
                            source: "kml:coordinates".into(),
                        },
                    );
                }
            }
        }
        for c in pm.descendants("coord") {
            let t = c.text();
            let mut it = t.split_whitespace().map(str::parse::<f64>);
            if let (Some(Ok(lon)), Some(Ok(lat))) = (it.next(), it.next()) {
                acc.push(
                    &mut meta,
                    GeoPoint {
                        lat,
                        lon,
                        alt: it.next().and_then(Result::ok),
                        time: None,
                        name: name.clone(),
                        source: "kml:gx:coord".into(),
                    },
                );
            }
        }
    }
    let mut times: Vec<String> = root
        .descendants("when")
        .into_iter()
        .chain(root.descendants("begin"))
        .filter_map(|w| w.text_opt())
        .take(10_000)
        .collect();
    times.sort();
    meta.created = times.first().cloned();
    meta.modified = times.last().cloned();
    meta.stats.insert("geo_points".into(), acc.total);
    Ok(meta)
}

pub fn extract_gpx(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let root = crate::xml::parse_bytes(b, ctx.max_xml_depth(), ctx.max_xml_nodes())?;
    let mut meta = Metadata::new(DocFormat::Gpx);
    if let Some(c) = root.attr("creator").and_then(clean_str) {
        Metadata::add_unique(&mut meta.software, &c);
        meta.application = Some(truncate(&c, 256));
    }
    if let Some(v) = root.attr("version") {
        meta.fields.insert("gpx:version".into(), truncate(v, 16));
    }
    if let Some(md) = root.child("metadata") {
        if let Some(n) = md.child("name").and_then(Element::text_opt) {
            meta.title = Some(truncate(&n, 512));
        }
        if let Some(d) = md.child("desc").and_then(Element::text_opt) {
            meta.description = Some(truncate(&d, 2048));
        }
        if let Some(t) = md.child("time").and_then(Element::text_opt) {
            meta.created = Some(truncate(&t, 64));
        }
        if let Some(k) = md.child("keywords").and_then(Element::text_opt) {
            meta.keywords = Some(truncate(&k, 512));
        }
        if let Some(a) = md.child("author") {
            if let Some(n) = a.child("name").and_then(Element::text_opt) {
                meta.add_person(&n, PersonRole::Author, "gpx:author");
                meta.author = Some(truncate(&n, 256));
            }
            if let Some(e) = a.child("email") {
                if let (Some(id), Some(dom)) = (e.attr("id"), e.attr("domain")) {
                    Metadata::add_unique(&mut meta.emails, &format!("{id}@{dom}"));
                }
            }
        }
    }
    let mut acc = Acc { total: 0 };
    let mut times: Vec<String> = Vec::new();
    for el in root.walk() {
        let src = match el.local() {
            "wpt" => "gpx:wpt",
            "trkpt" => "gpx:trkpt",
            "rtept" => "gpx:rtept",
            _ => continue,
        };
        let (Some(lat), Some(lon)) = (
            el.attr("lat").and_then(|v| v.trim().parse::<f64>().ok()),
            el.attr("lon").and_then(|v| v.trim().parse::<f64>().ok()),
        ) else {
            continue;
        };
        let time = el.child("time").and_then(Element::text_opt);
        if let Some(t) = &time {
            if times.len() < 100_000 {
                times.push(t.clone());
            }
        }
        acc.push(
            &mut meta,
            GeoPoint {
                lat,
                lon,
                alt: el
                    .child("ele")
                    .and_then(|e| e.text().trim().parse::<f64>().ok()),
                time,
                name: el
                    .child("name")
                    .and_then(Element::text_opt)
                    .map(|n| truncate(&n, 256)),
                source: src.into(),
            },
        );
    }
    times.sort();
    if meta.created.is_none() {
        meta.created = times.first().cloned();
    }
    meta.modified = times.last().cloned();
    meta.stats.insert("geo_points".into(), acc.total);
    Ok(meta)
}
