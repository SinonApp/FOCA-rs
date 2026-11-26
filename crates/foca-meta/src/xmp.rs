//! XMP (RDF/XML) flattened into `prefix:name` to value pairs and mapped onto [`Metadata`] fields.
//!
//! `xmpMM:History` and the `xmpMM` identifiers are also collected in structured form. To keep
//! the `parse` → `apply` contract used by every format parser, the structured records travel
//! inside the flat map under reserved keys starting with [`RESERVED`]; `apply` turns them into
//! [`Metadata::xmp_history`]/[`Metadata::xmp_ids`] and never copies them into `meta.xmp`.

use std::collections::BTreeMap;

use foca_core::{Metadata, PersonRole, XmpEvent, XmpIds};

use crate::util::normalize_date;
use crate::xml::{self, Element};
use crate::Ctx;

fn add(map: &mut BTreeMap<String, String>, k: &str, v: &str) {
    let v = v.trim();
    if v.is_empty() {
        return;
    }
    let v = crate::util::truncate(v, 2048);
    match map.get_mut(k) {
        Some(prev) => {
            if !prev.split("; ").any(|x| x == v) && prev.len() < 8192 {
                prev.push_str("; ");
                prev.push_str(&v);
            }
        }
        None => {
            map.insert(k.to_string(), v);
        }
    }
}

fn is_rdf_container(e: &Element) -> bool {
    matches!(e.name.as_str(), "rdf:Seq" | "rdf:Bag" | "rdf:Alt")
}

fn walk_prop(map: &mut BTreeMap<String, String>, key: &str, e: &Element, depth: usize) {
    if depth > 16 {
        return;
    }
    if let Some(r) = e.attr("rdf:resource") {
        add(map, key, r);
    }
    // property attributes on li or struct elements (stEvt:softwareAgent="...")
    for (ak, av) in &e.attrs {
        if !ak.starts_with("xmlns") && !ak.starts_with("rdf:") && !ak.starts_with("xml:") {
            add(map, &format!("{key}/{ak}"), av);
        }
    }
    let kids: Vec<&Element> = e.elements().collect();
    if kids.is_empty() {
        add(map, key, &e.text());
        return;
    }
    for k in kids {
        if is_rdf_container(k) {
            for li in k.elements() {
                walk_prop(map, key, li, depth + 1);
            }
        } else if k.name == "rdf:Description" {
            walk_desc(map, Some(key), k, depth + 1);
        } else {
            walk_prop(map, &format!("{key}/{}", k.name), k, depth + 1);
        }
    }
}

fn walk_desc(map: &mut BTreeMap<String, String>, prefix: Option<&str>, d: &Element, depth: usize) {
    let key = |n: &str| match prefix {
        Some(p) => format!("{p}/{n}"),
        None => n.to_string(),
    };
    for (ak, av) in &d.attrs {
        if !ak.starts_with("xmlns")
            && !ak.starts_with("rdf:")
            && !ak.starts_with("xml:")
            && ak != "about"
        {
            add(map, &key(ak), av);
        }
    }
    for p in d.elements() {
        walk_prop(map, &key(&p.name), p, depth + 1);
    }
}

/// Prefix of reserved map keys that carry structured history and identifiers.
pub(crate) const RESERVED: char = '\u{1}';
/// Maximum number of history events kept per packet.
const MAX_EVENTS: usize = 500;

/// Collects `(local name, value)` property pairs of a struct-valued RDF node: attributes,
/// simple child elements and a nested `rdf:Description`.
fn struct_props(e: &Element, out: &mut Vec<(String, String)>, depth: usize) {
    if depth > 4 {
        return;
    }
    for (k, v) in &e.attrs {
        if !k.starts_with("xmlns") && !k.starts_with("rdf:") && !k.starts_with("xml:") {
            out.push((xml::local(k).to_string(), v.clone()));
        }
    }
    for c in e.elements() {
        if c.name == "rdf:Description" {
            struct_props(c, out, depth + 1);
        } else if is_rdf_container(c) {
            // multi-valued property (rare): join the items
            let vals: Vec<String> = c.elements().filter_map(Element::text_opt).collect();
            if !vals.is_empty() {
                out.push((c.local().to_string(), vals.join("; ")));
            }
        } else if let Some(v) = c.text_opt() {
            out.push((c.local().to_string(), v));
        }
    }
}

fn prop<'a>(props: &'a [(String, String)], name: &str) -> Option<&'a str> {
    props
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Writes the structured `xmpMM` records under reserved keys.
fn collect_structured(root: &Element, map: &mut BTreeMap<String, String>) {
    let mut idx = map
        .keys()
        .filter(|k| k.starts_with(RESERVED) && k.contains("h/"))
        .count();
    for e in root.walk() {
        let is_mm = e.name.ends_with("MM:History") || e.name == "History";
        if is_mm {
            let items: Vec<&Element> = match e.elements().find(|c| is_rdf_container(c)) {
                Some(seq) => seq.elements().collect(),
                None => Vec::new(),
            };
            for li in items {
                if idx >= MAX_EVENTS {
                    break;
                }
                let mut props = Vec::new();
                struct_props(li, &mut props, 0);
                if props.is_empty() {
                    continue;
                }
                for (k, v) in props {
                    let v = crate::util::truncate(v.trim(), 1024);
                    if !v.is_empty() {
                        map.insert(format!("{RESERVED}h/{idx:05}/{k}"), v);
                    }
                }
                idx += 1;
            }
            continue;
        }
        if e.name.ends_with("MM:DerivedFrom") {
            let mut props = Vec::new();
            struct_props(e, &mut props, 0);
            for (k, key) in [
                ("documentID", "derived_doc"),
                ("instanceID", "derived_inst"),
            ] {
                if let Some(v) = prop(&props, k) {
                    map.entry(format!("{RESERVED}id/{key}"))
                        .or_insert_with(|| crate::util::truncate(v.trim(), 512));
                }
            }
        }
    }
}

/// Builds the structured history and identifiers from the reserved keys.
fn structured(map: &BTreeMap<String, String>) -> (Vec<XmpEvent>, XmpIds) {
    let mut events: Vec<XmpEvent> = Vec::new();
    let mut cur: Option<(String, XmpEvent)> = None;
    for (k, v) in map.range(format!("{RESERVED}h/")..) {
        let Some(rest) = k.strip_prefix(&format!("{RESERVED}h/")) else {
            break;
        };
        let Some((n, field)) = rest.split_once('/') else {
            continue;
        };
        if cur.as_ref().is_none_or(|(id, _)| id != n) {
            if let Some((_, ev)) = cur.take() {
                events.push(ev);
            }
            cur = Some((n.to_string(), XmpEvent::default()));
        }
        let Some((_, ev)) = cur.as_mut() else {
            continue;
        };
        let v = Some(v.clone());
        match field {
            "action" => ev.action = v,
            "when" => ev.when = v.as_deref().and_then(normalize_date).or(v),
            "softwareAgent" => ev.software_agent = v,
            "instanceID" => ev.instance_id = v,
            "changed" => ev.changed = v,
            "parameters" => ev.parameters = v,
            _ => {}
        }
    }
    if let Some((_, ev)) = cur {
        events.push(ev);
    }
    events.retain(|e| *e != XmpEvent::default());
    let pick = |keys: &[&str]| first(map, keys);
    let ids = XmpIds {
        document_id: pick(&["xmpMM:DocumentID", "xapMM:DocumentID"]),
        instance_id: pick(&["xmpMM:InstanceID", "xapMM:InstanceID"]),
        original_document_id: pick(&["xmpMM:OriginalDocumentID", "xapMM:OriginalDocumentID"]),
        derived_from_document_id: map.get(&format!("{RESERVED}id/derived_doc")).cloned(),
        derived_from_instance_id: map.get(&format!("{RESERVED}id/derived_inst")).cloned(),
    };
    (events, ids)
}

/// Parses an XMP packet from bytes. Errors yield an empty map.
pub fn parse(bytes: &[u8], ctx: &Ctx) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let Ok(root) = xml::parse_bytes(bytes, ctx.max_xml_depth(), ctx.max_xml_nodes()) else {
        return map;
    };
    parse_element(&root, &mut map);
    map
}

/// Collects XMP from an already parsed element (for example `<metadata>` in SVG).
pub fn parse_element(root: &Element, map: &mut BTreeMap<String, String>) {
    for d in root.walk() {
        if d.name == "rdf:Description" || (d.local() == "Work" && d.name.starts_with("cc:")) {
            walk_desc(map, None, d, 0);
        }
    }
    collect_structured(root, map);
}

fn first(map: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| map.get(*k))
        .map(|v| v.split("; ").next().unwrap_or(v).to_string())
}

/// Maps XMP onto metadata: fills empty fields and adds people and software.
pub fn apply(meta: &mut Metadata, map: &BTreeMap<String, String>, source: &str) {
    let set = |slot: &mut Option<String>, v: Option<String>| {
        if slot.is_none() {
            *slot = v;
        }
    };
    set(&mut meta.title, first(map, &["dc:title"]));
    set(&mut meta.description, first(map, &["dc:description"]));
    set(
        &mut meta.keywords,
        map.get("pdf:Keywords")
            .or_else(|| map.get("dc:subject"))
            .cloned(),
    );
    set(
        &mut meta.author,
        first(
            map,
            &[
                "dc:creator",
                "cc:Work/dc:creator/cc:Agent/dc:title",
                "dc:creator/cc:Agent/dc:title",
            ],
        ),
    );
    set(
        &mut meta.application,
        first(map, &["xmp:CreatorTool", "xap:CreatorTool"]),
    );
    set(&mut meta.producer, first(map, &["pdf:Producer"]));
    set(
        &mut meta.created,
        first(
            map,
            &[
                "xmp:CreateDate",
                "xap:CreateDate",
                "photoshop:DateCreated",
                "exif:DateTimeOriginal",
            ],
        )
        .and_then(|d| normalize_date(&d)),
    );
    set(
        &mut meta.modified,
        first(map, &["xmp:ModifyDate", "xap:ModifyDate"]).and_then(|d| normalize_date(&d)),
    );
    for k in ["dc:creator", "dc:creator/cc:Agent/dc:title"] {
        if let Some(v) = map.get(k) {
            for name in v.split("; ") {
                meta.add_person(name, PersonRole::Creator, &format!("{source}:{k}"));
            }
        }
    }
    if let Some(v) = map.get("xmp:CreatorTool") {
        Metadata::add_unique(&mut meta.software, v);
    }
    if let Some(v) = map.get("pdf:Producer") {
        Metadata::add_unique(&mut meta.software, v);
    }
    for (k, v) in map {
        if k.ends_with("softwareAgent") && !k.starts_with(RESERVED) {
            for s in v.split("; ") {
                Metadata::add_unique(&mut meta.software, s);
            }
        }
    }
    for (k, v) in map {
        if !k.starts_with(RESERVED) {
            meta.xmp.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    let (events, ids) = structured(map);
    if meta.xmp_history.is_empty() {
        meta.xmp_history = events;
    }
    if meta.xmp_ids.is_none() && !ids.is_empty() {
        meta.xmp_ids = Some(ids);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_default(x: &[u8]) -> BTreeMap<String, String> {
        let limits = crate::Limits::default();
        let budget = std::cell::Cell::new(limits.max_unzipped_total);
        parse(x, &Ctx::standalone(&limits, &budget))
    }

    #[test]
    fn flatten() {
        let x = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreatorTool="Word">
<dc:creator><rdf:Seq><rdf:li>Ann</rdf:li><rdf:li>Bob</rdf:li></rdf:Seq></dc:creator>
<dc:title><rdf:Alt><rdf:li xml:lang="x-default">T</rdf:li></rdf:Alt></dc:title>
<xmpMM:History xmlns:xmpMM="m" xmlns:stEvt="e"><rdf:Seq><rdf:li stEvt:action="saved" stEvt:softwareAgent="Adobe Photoshop CC 2019"/></rdf:Seq></xmpMM:History>
</rdf:Description></rdf:RDF></x:xmpmeta>"#;
        let m = parse_default(x);
        assert_eq!(m.get("dc:creator").map(String::as_str), Some("Ann; Bob"));
        assert_eq!(m.get("dc:title").map(String::as_str), Some("T"));
        assert_eq!(m.get("xmp:CreatorTool").map(String::as_str), Some("Word"));
        assert_eq!(
            m.get("xmpMM:History/stEvt:softwareAgent")
                .map(String::as_str),
            Some("Adobe Photoshop CC 2019")
        );
        let mut meta = Metadata::default();
        apply(&mut meta, &m, "xmp");
        assert_eq!(meta.author.as_deref(), Some("Ann"));
        assert_eq!(meta.people.len(), 2);
        assert!(meta
            .software
            .contains(&"Adobe Photoshop CC 2019".to_string()));
        assert_eq!(meta.xmp_history.len(), 1);
        assert!(meta.xmp.keys().all(|k| !k.starts_with(RESERVED)));
    }

    #[test]
    fn structured_history() {
        let x = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#" xmlns:stRef="http://ns.adobe.com/xap/1.0/sType/ResourceRef#"
  xmpMM:DocumentID="xmp.did:AAA" xmpMM:InstanceID="xmp.iid:BBB" xmpMM:OriginalDocumentID="xmp.did:OOO">
<xmpMM:DerivedFrom rdf:parseType="Resource"><stRef:instanceID>xmp.iid:P1</stRef:instanceID><stRef:documentID>xmp.did:P0</stRef:documentID></xmpMM:DerivedFrom>
<xmpMM:History><rdf:Seq>
 <rdf:li rdf:parseType="Resource"><stEvt:action>created</stEvt:action><stEvt:instanceID>xmp.iid:1</stEvt:instanceID><stEvt:when>2024-03-01T10:00:00+02:00</stEvt:when><stEvt:softwareAgent>Adobe Photoshop 25.0 (Windows)</stEvt:softwareAgent></rdf:li>
 <rdf:li stEvt:action="converted" stEvt:parameters="from image/png to image/jpeg"/>
 <rdf:li><rdf:Description stEvt:action="saved" stEvt:changed="/" stEvt:when="2024-03-02T11:00:00Z" stEvt:softwareAgent="Adobe Photoshop 25.1 (Macintosh)"/></rdf:li>
</rdf:Seq></xmpMM:History>
</rdf:Description></rdf:RDF></x:xmpmeta>"#;
        let m = parse_default(x);
        // old flat keys are kept
        assert!(m.contains_key("xmpMM:History/stEvt:action"));
        assert_eq!(
            m.get("xmpMM:DocumentID").map(String::as_str),
            Some("xmp.did:AAA")
        );
        let mut meta = Metadata::default();
        apply(&mut meta, &m, "xmp");
        let h = &meta.xmp_history;
        assert_eq!(h.len(), 3, "{h:?}");
        assert_eq!(h[0].action.as_deref(), Some("created"));
        assert_eq!(h[0].instance_id.as_deref(), Some("xmp.iid:1"));
        assert_eq!(
            h[0].software_agent.as_deref(),
            Some("Adobe Photoshop 25.0 (Windows)")
        );
        assert!(h[0].when.is_some());
        assert_eq!(
            h[1].parameters.as_deref(),
            Some("from image/png to image/jpeg")
        );
        assert_eq!(h[2].changed.as_deref(), Some("/"));
        let ids = meta.xmp_ids.unwrap();
        assert_eq!(ids.document_id.as_deref(), Some("xmp.did:AAA"));
        assert_eq!(ids.instance_id.as_deref(), Some("xmp.iid:BBB"));
        assert_eq!(ids.original_document_id.as_deref(), Some("xmp.did:OOO"));
        assert_eq!(ids.derived_from_document_id.as_deref(), Some("xmp.did:P0"));
        assert_eq!(ids.derived_from_instance_id.as_deref(), Some("xmp.iid:P1"));
        assert!(meta.software.iter().any(|s| s.contains("25.1")));
    }
}
