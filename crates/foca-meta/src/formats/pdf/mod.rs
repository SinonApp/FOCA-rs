//! PDF parsing with a lightweight in-house parser (no lopdf).
//!
//! Uses a recovery-style approach: objects are found by scanning the whole file for `N G obj`
//! (robust against broken xref tables), and every version of an object is kept by position,
//! which exposes older revisions of the Info dictionary. Object streams (ObjStm), xref streams
//! and bounded FlateDecode are supported. References are resolved with a depth limit and
//! cycle protection.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;

use foca_core::{
    Attachment, BadRedaction, CommentRef, DocFormat, Embedded, Metadata, OldVersion, PdfRevision,
    PersonRole, SignatureKind,
};

use crate::util::{find, normalize_date, truncate};
use crate::{formats::signature, xmp, Ctx, MetaError};

mod redaction;
pub(crate) mod syntax;

use redaction::{ExtraBox, Fill, PageScan};
use syntax::{content_str, dget, dname, is_delim, is_ws, pdf_str, Dict, Lex, Obj};

pub(crate) struct IObj {
    pub(crate) num: u32,
    pub(crate) pos: usize,
    pub(crate) obj: Obj,
}

pub(crate) struct Pdf<'a> {
    pub(crate) b: &'a [u8],
    /// Every object version found in the file.
    objs: Vec<IObj>,
    /// The latest version of each object: index into `objs`.
    latest: HashMap<u32, usize>,
    /// Every version of each object: indices into `objs`, sorted by position.
    versions: HashMap<u32, Vec<usize>>,
    /// Trailer dictionaries with their positions, oldest first.
    trailers: Vec<(usize, Dict)>,
}

fn inflate(data: &[u8], cap: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut z = flate2::read::ZlibDecoder::new(data).take(cap.saturating_add(1));
    if z.read_to_end(&mut out).is_err() && out.is_empty() {
        let mut d = flate2::read::DeflateDecoder::new(data).take(cap.saturating_add(1));
        let _ = d.read_to_end(&mut out);
    }
    out
}

impl<'a> Pdf<'a> {
    pub(crate) fn parse(b: &'a [u8], ctx: &Ctx) -> Result<Pdf<'a>, MetaError> {
        let max_objs = ctx.max_entries().saturating_mul(10);
        let max_depth = ctx.max_xml_depth().min(128);
        // 1. find "N G obj" positions
        let mut offsets: Vec<(u32, usize)> = Vec::new(); // object number, position after "obj"
        let mut i = 0;
        while let Some(at) = find(b, b"obj", i) {
            i = at + 3;
            if b.get(at + 3).is_some_and(|&c| !(is_ws(c) || is_delim(c))) {
                continue;
            }
            // walk backwards: ws gen ws num
            let mut j = at;
            let skip_ws_back = |j: &mut usize| {
                while *j > 0 && is_ws(b[*j - 1]) {
                    *j -= 1;
                }
            };
            skip_ws_back(&mut j);
            let ge = j;
            while j > 0 && b[j - 1].is_ascii_digit() {
                j -= 1;
            }
            if j == ge || ge - j > 5 {
                continue;
            }
            let gs = j;
            skip_ws_back(&mut j);
            if j == gs {
                continue;
            }
            let ne = j;
            while j > 0 && b[j - 1].is_ascii_digit() {
                j -= 1;
            }
            if j == ne || ne - j > 10 || (j > 0 && !(is_ws(b[j - 1]) || is_delim(b[j - 1]))) {
                continue;
            }
            let Some(num) = std::str::from_utf8(&b[j..ne])
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            offsets.push((num, at + 3));
            if offsets.len() > max_objs {
                return Err(MetaError::TooManyEntries(format!(
                    "PDF: больше {max_objs} объектов"
                )));
            }
        }
        let mut last_off: HashMap<u32, usize> = HashMap::new();
        for (n, p) in &offsets {
            last_off.insert(*n, *p);
        }
        let mut pdf = Pdf {
            b,
            objs: Vec::with_capacity(offsets.len()),
            latest: HashMap::new(),
            versions: HashMap::new(),
            trailers: Vec::new(),
        };
        // 2. parse objects
        for (num, p) in &offsets {
            let mut lx = Lex::new(b, *p, max_depth);
            let Some(mut obj) = lx.parse(0) else { continue };
            if let Obj::Dict(d) = &obj {
                if let Some(s) = lx.stream_data_start() {
                    let len = match dget(d, "Length") {
                        Some(Obj::Num(n)) => Some(*n as usize),
                        Some(Obj::Ref(rn, _)) => last_off
                            .get(rn)
                            .and_then(|&rp| Lex::new(b, rp, 4).parse(0))
                            .and_then(|o| o.num())
                            .map(|n| n as usize),
                        _ => None,
                    };
                    let end = match len {
                        Some(l)
                            if s.checked_add(l).is_some_and(|e| e <= b.len()) && {
                                let e = s + l;
                                let tail = &b[e..b.len().min(e + 32)];
                                find(tail, b"endstream", 0).is_some()
                            } =>
                        {
                            s + l
                        }
                        _ => {
                            let e = find(b, b"endstream", s).unwrap_or(b.len());
                            let mut e2 = e;
                            if e2 > s && b[e2 - 1] == b'\n' {
                                e2 -= 1;
                            }
                            if e2 > s && b[e2 - 1] == b'\r' {
                                e2 -= 1;
                            }
                            e2
                        }
                    };
                    obj = Obj::Stream(d.clone(), s, end.max(s));
                }
            }
            pdf.objs.push(IObj {
                num: *num,
                pos: *p,
                obj,
            });
        }
        // 3. object streams
        let mut extra = Vec::new();
        for o in &pdf.objs {
            if let Obj::Stream(d, s, e) = &o.obj {
                if dname(d, "Type") != Some("ObjStm") {
                    continue;
                }
                let Some(data) = pdf.decode(d, *s, *e, ctx)? else {
                    continue;
                };
                let n = dget(d, "N").and_then(Obj::num).unwrap_or(0.0) as usize;
                let first = dget(d, "First").and_then(Obj::num).unwrap_or(0.0) as usize;
                let mut lx = Lex::new(&data, 0, 4);
                let mut pairs = Vec::new();
                for _ in 0..n.min(100_000) {
                    match (lx.parse(0), lx.parse(0)) {
                        (Some(Obj::Num(a)), Some(Obj::Num(b2))) => {
                            pairs.push((a as u32, b2 as usize))
                        }
                        _ => break,
                    }
                }
                for (onum, off) in pairs {
                    let Some(start) = first.checked_add(off) else {
                        continue;
                    };
                    if start >= data.len() {
                        continue;
                    }
                    if let Some(obj) = Lex::new(&data, start, max_depth).parse(0) {
                        extra.push(IObj {
                            num: onum,
                            pos: o.pos,
                            obj,
                        });
                    }
                    if pdf.objs.len() + extra.len() > max_objs {
                        return Err(MetaError::TooManyEntries(format!(
                            "PDF: больше {max_objs} объектов"
                        )));
                    }
                }
            }
        }
        pdf.objs.extend(extra);
        for (idx, o) in pdf.objs.iter().enumerate() {
            pdf.versions.entry(o.num).or_default().push(idx);
            match pdf.latest.get(&o.num) {
                Some(&prev) if pdf.objs[prev].pos > o.pos => {}
                _ => {
                    pdf.latest.insert(o.num, idx);
                }
            }
        }
        // 4. trailers and xref streams
        let mut i = 0;
        while let Some(at) = find(b, b"trailer", i) {
            i = at + 7;
            let mut lx = Lex::new(b, at + 7, max_depth);
            if let Some(Obj::Dict(d)) = lx.parse(0) {
                pdf.trailers.push((at, d));
            }
        }
        for o in &pdf.objs {
            if let Obj::Stream(d, _, _) = &o.obj {
                if dname(d, "Type") == Some("XRef") {
                    pdf.trailers.push((o.pos, d.clone()));
                }
            }
        }
        pdf.trailers.sort_by_key(|t| t.0);
        for v in pdf.versions.values_mut() {
            let objs = &pdf.objs;
            v.sort_by_key(|&i| objs.get(i).map_or(0, |o| o.pos));
        }
        Ok(pdf)
    }

    /// Decodes a stream (FlateDecode or unfiltered), charging the budget.
    pub(crate) fn decode(
        &self,
        d: &Dict,
        s: usize,
        e: usize,
        ctx: &Ctx,
    ) -> Result<Option<Vec<u8>>, MetaError> {
        let raw = match self.b.get(s..e) {
            Some(r) => r,
            None => return Ok(None),
        };
        let filters: Vec<String> = match dget(d, "Filter") {
            Some(Obj::Name(n)) => vec![n.clone()],
            Some(Obj::Arr(a)) => a
                .iter()
                .filter_map(|x| {
                    if let Obj::Name(n) = x {
                        Some(n.clone())
                    } else {
                        None
                    }
                })
                .collect(),
            _ => vec![],
        };
        let mut data = raw.to_vec();
        let mut decoded_stream = false;
        for f in filters {
            match f.as_str() {
                "FlateDecode" | "Fl" => {
                    let cap = ctx.remaining();
                    let out = inflate(&data, cap);
                    if out.len() as u64 > cap {
                        let _ = ctx.spend(cap);
                        return Err(MetaError::ZipBomb(
                            "PDF: поток распаковывается больше бюджета".into(),
                        ));
                    }
                    ctx.spend(out.len() as u64)?;
                    decoded_stream = true;
                    data = out;
                }
                _ => return Ok(None),
            }
        }
        if !decoded_stream {
            ctx.spend(data.len() as u64)?;
        }
        Ok(Some(data))
    }

    /// The latest version of each object, in the order they were found.
    pub(crate) fn latest_objects(&self) -> impl Iterator<Item = &IObj> {
        let mut idx: Vec<usize> = self.latest.values().copied().collect();
        idx.sort_unstable();
        idx.into_iter().filter_map(|i| self.objs.get(i))
    }

    /// Visits every dictionary (nested ones included) of every object version in file order,
    /// together with the number of the object that holds it.
    pub(crate) fn for_each_dict<'b>(&'b self, f: &mut dyn FnMut(u32, &'b Dict)) {
        for o in &self.objs {
            visit_dicts(&o.obj, 0, &mut |d| f(o.num, d));
        }
    }

    /// The newest catalog dictionary written before position `before`.
    pub(crate) fn catalog_before(&self, before: usize) -> Option<&Dict> {
        self.objs
            .iter()
            .filter(|o| o.pos < before)
            .filter(|o| {
                o.obj
                    .dict()
                    .is_some_and(|d| dname(d, "Type") == Some("Catalog"))
            })
            .max_by_key(|o| o.pos)
            .and_then(|o| o.obj.dict())
    }

    /// Number of object versions written in `start..end`.
    pub(crate) fn count_objects_in(&self, start: usize, end: usize) -> usize {
        self.objs
            .iter()
            .filter(|o| o.pos >= start && o.pos < end)
            .count()
    }

    /// The `/Info` entry of the last trailer in `start..end` that has one, resolved as of `end`.
    pub(crate) fn info_in(&self, start: usize, end: usize) -> Option<&Obj> {
        self.trailers
            .iter()
            .filter(|(p, _)| *p >= start && *p < end)
            .filter_map(|(_, t)| dget(t, "Info"))
            .next_back()
            .map(|i| self.resolve_at(i, end))
    }

    /// The Info dictionary of every trailer as it stood at that trailer, oldest first.
    pub(crate) fn trailer_infos(&self) -> Vec<&Dict> {
        let mut out = Vec::new();
        for (pos, t) in &self.trailers {
            if let Some(Obj::Ref(n, _)) = dget(t, "Info") {
                if let Some(Obj::Dict(d)) = self.get_before(*n, *pos).map(|o| self.resolve(o)) {
                    out.push(d);
                }
            } else if let Some(Obj::Dict(d)) = dget(t, "Info") {
                out.push(d);
            }
        }
        out
    }

    /// The last plain (non-stream) dictionary in the file that matches `pred`.
    pub(crate) fn last_dict(&self, pred: impl Fn(&Dict) -> bool) -> Option<&Dict> {
        self.objs.iter().rev().find_map(|o| match &o.obj {
            Obj::Dict(d) if pred(d) => Some(d),
            _ => None,
        })
    }

    /// XMP metadata streams (dictionary and data range) of every object version, except the
    /// latest version of object `skip`.
    pub(crate) fn xmp_streams_except(
        &self,
        skip: Option<u32>,
    ) -> impl Iterator<Item = (&Dict, usize, usize)> {
        let skip_idx = skip.and_then(|n| self.latest.get(&n).copied());
        self.objs
            .iter()
            .enumerate()
            .filter_map(move |(idx, o)| match &o.obj {
                Obj::Stream(d, s, e)
                    if dname(d, "Subtype") == Some("XML")
                        && dname(d, "Type") == Some("Metadata")
                        && Some(idx) != skip_idx =>
                {
                    Some((d, *s, *e))
                }
                _ => None,
            })
    }

    /// Returns `true` if any trailer declares encryption.
    pub(crate) fn is_encrypted(&self) -> bool {
        self.trailers
            .iter()
            .any(|(_, d)| dget(d, "Encrypt").is_some())
    }

    /// Returns `true` for a linearized file (its first-page hint dictionary leads the file).
    pub(crate) fn is_linearized(&self) -> bool {
        self.objs.iter().take(3).any(|o| {
            o.obj
                .dict()
                .is_some_and(|d| dget(d, "Linearized").is_some())
        })
    }

    /// The document catalog: the newest trailer `/Root` that points to a catalog, otherwise the
    /// last catalog dictionary in the file.
    pub(crate) fn root(&self) -> Option<u32> {
        let is_catalog = |n: u32| {
            self.get(n)
                .and_then(Obj::dict)
                .is_some_and(|d| dname(d, "Type") == Some("Catalog") || dget(d, "Pages").is_some())
        };
        for (_, t) in self.trailers.iter().rev() {
            if let Some(Obj::Ref(n, _)) = dget(t, "Root") {
                if is_catalog(*n) {
                    return Some(*n);
                }
            }
        }
        self.objs
            .iter()
            .filter(|o| {
                o.obj
                    .dict()
                    .is_some_and(|d| dname(d, "Type") == Some("Catalog"))
            })
            .max_by_key(|o| o.pos)
            .map(|o| o.num)
    }

    pub(crate) fn get(&self, num: u32) -> Option<&Obj> {
        self.latest
            .get(&num)
            .and_then(|&i| self.objs.get(i))
            .map(|o| &o.obj)
    }

    /// Returns the version of an object that was current before position `before`.
    fn get_before(&self, num: u32, before: usize) -> Option<&Obj> {
        self.objs
            .iter()
            .filter(|o| o.num == num && o.pos < before)
            .max_by_key(|o| o.pos)
            .map(|o| &o.obj)
            .or_else(|| self.get(num))
    }

    /// Resolves a reference; reference chains are followed with a depth limit and cycle protection.
    pub(crate) fn resolve<'b>(&'b self, o: &'b Obj) -> &'b Obj {
        let mut cur = o;
        let mut seen = HashSet::new();
        while let Obj::Ref(n, _) = cur {
            if !seen.insert(*n) || seen.len() > 32 {
                return &Obj::Null;
            }
            match self.get(*n) {
                Some(x) => cur = x,
                None => return &Obj::Null,
            }
        }
        cur
    }

    /// Returns the version of object `num` written before position `before` (no fallback).
    fn get_at(&self, num: u32, before: usize) -> Option<&Obj> {
        if before == usize::MAX {
            return self.get(num);
        }
        let v = self.versions.get(&num)?;
        let objs = &self.objs;
        let n = v.partition_point(|&i| objs.get(i).is_some_and(|o| o.pos < before));
        v.get(n.checked_sub(1)?)
            .and_then(|&i| objs.get(i))
            .map(|o| &o.obj)
    }

    /// Resolves a reference as of position `before`.
    fn resolve_at<'b>(&'b self, o: &'b Obj, before: usize) -> &'b Obj {
        let mut cur = o;
        let mut seen = HashSet::new();
        while let Obj::Ref(n, _) = cur {
            if !seen.insert(*n) || seen.len() > 32 {
                return &Obj::Null;
            }
            match self.get_at(*n, before) {
                Some(x) => cur = x,
                None => return &Obj::Null,
            }
        }
        cur
    }

    /// Returns raw JPEG/JPEG 2000 bytes of an image stream (undoing a leading FlateDecode),
    /// with the file extension. The budget is charged.
    fn image_bytes(
        &self,
        d: &Dict,
        s: usize,
        e: usize,
        ctx: &Ctx,
    ) -> Result<Option<(Vec<u8>, &'static str)>, MetaError> {
        let filters: Vec<&str> = match dget(d, "Filter") {
            Some(Obj::Name(n)) => vec![n.as_str()],
            Some(Obj::Arr(a)) => a
                .iter()
                .filter_map(|x| match x {
                    Obj::Name(n) => Some(n.as_str()),
                    _ => None,
                })
                .collect(),
            _ => return Ok(None),
        };
        let ext = match filters.last() {
            Some(&("DCTDecode" | "DCT")) => "jpg",
            Some(&"JPXDecode") => "jp2",
            _ => return Ok(None),
        };
        let Some(raw) = self.b.get(s..e) else {
            return Ok(None);
        };
        let mut data = raw.to_vec();
        for f in &filters[..filters.len() - 1] {
            match *f {
                "FlateDecode" | "Fl" => {
                    let cap = ctx.remaining();
                    let out = inflate(&data, cap);
                    if out.len() as u64 > cap {
                        return Err(MetaError::ZipBomb(
                            "PDF: поток распаковывается больше бюджета".into(),
                        ));
                    }
                    data = out;
                }
                _ => return Ok(None),
            }
        }
        ctx.spend(data.len() as u64)?;
        Ok(Some((data, ext)))
    }
}

/// A page with inherited attributes, as of some revision.
struct PageNode<'b> {
    dict: &'b Dict,
    res: Option<&'b Dict>,
    media: Option<[f64; 4]>,
}

const MAX_PAGES: usize = 2000;

fn rect_of(o: &Obj) -> Option<[f64; 4]> {
    let Obj::Arr(a) = o else { return None };
    let v: Vec<f64> = a.iter().filter_map(Obj::num).collect();
    if v.len() != 4 || v.iter().any(|x| !x.is_finite()) {
        return None;
    }
    Some([
        v[0].min(v[2]),
        v[1].min(v[3]),
        v[0].max(v[2]),
        v[1].max(v[3]),
    ])
}

/// Page tree walk frame: node, inherited resources, inherited MediaBox, depth.
type PageFrame<'b> = (&'b Obj, Option<&'b Dict>, Option<[f64; 4]>, usize);

/// Walks the page tree from the catalog as of position `before`.
fn pages_at<'b>(pdf: &'b Pdf, before: usize) -> Vec<PageNode<'b>> {
    let mut out = Vec::new();
    // the latest catalog written before `before`
    let catalog = pdf.catalog_before(before);
    let Some(root) = catalog.and_then(|c| dget(c, "Pages")) else {
        return out;
    };
    let mut seen = HashSet::new();
    let mut stack: Vec<PageFrame> = vec![(root, None, None, 0)];
    while let Some((node, res, media, depth)) = stack.pop() {
        if depth > 64 || out.len() >= MAX_PAGES {
            break;
        }
        if let Obj::Ref(n, _) = node {
            if !seen.insert(*n) {
                continue;
            }
        }
        let Some(d) = pdf.resolve_at(node, before).dict() else {
            continue;
        };
        let res = dget(d, "Resources")
            .map(|r| pdf.resolve_at(r, before))
            .and_then(Obj::dict)
            .or(res);
        let media = dget(d, "MediaBox")
            .map(|r| pdf.resolve_at(r, before))
            .and_then(rect_of)
            .or(media);
        match dget(d, "Kids").map(|k| pdf.resolve_at(k, before)) {
            Some(Obj::Arr(kids)) if dname(d, "Type") != Some("Page") => {
                for k in kids.iter().rev().take(100_000) {
                    stack.push((k, res, media, depth + 1));
                }
            }
            _ => out.push(PageNode {
                dict: d,
                res,
                media,
            }),
        }
    }
    out
}

/// Decoded content streams, cached by object identity across revisions.
type StreamCache = HashMap<usize, std::rc::Rc<Vec<u8>>>;

fn page_content(
    pdf: &Pdf,
    p: &PageNode,
    before: usize,
    ctx: &Ctx,
    cache: &mut StreamCache,
) -> Result<Vec<u8>, MetaError> {
    let mut refs: Vec<&Obj> = Vec::new();
    match dget(p.dict, "Contents").map(|c| pdf.resolve_at(c, before)) {
        Some(Obj::Arr(a)) => refs.extend(a.iter().take(1000)),
        Some(o @ Obj::Stream(..)) => refs.push(o),
        _ => {}
    }
    let mut data = Vec::new();
    let mut seen = HashSet::new();
    for r in refs {
        let o = pdf.resolve_at(r, before);
        let Obj::Stream(d, s, e) = o else { continue };
        let key = o as *const Obj as usize;
        if !seen.insert(key) {
            continue;
        }
        let part = match cache.get(&key) {
            Some(c) => c.clone(),
            None => {
                let c = std::rc::Rc::new(pdf.decode(d, *s, *e, ctx)?.unwrap_or_default());
                cache.insert(key, c.clone());
                c
            }
        };
        let next = data.len().saturating_add(part.len()).saturating_add(1);
        if next as u64 > ctx.max_unzipped_total() {
            return Err(MetaError::ZipBomb(
                "PDF: содержимое страниц превышает бюджет распаковки".into(),
            ));
        }
        data.extend_from_slice(&part);
        data.push(b'\n');
    }
    Ok(data)
}

fn page_images(pdf: &Pdf, p: &PageNode, before: usize) -> HashSet<String> {
    let mut names = HashSet::new();
    let Some(xo) = p
        .res
        .and_then(|r| dget(r, "XObject"))
        .map(|x| pdf.resolve_at(x, before))
        .and_then(Obj::dict)
    else {
        return names;
    };
    for (k, v) in xo.iter().take(10_000) {
        if let Some(d) = pdf.resolve_at(v, before).dict() {
            if dname(d, "Subtype") == Some("Image") {
                names.insert(k.clone());
            }
        }
    }
    names
}

/// Unapplied `/Redact` annotations and opaque `/Square` annotations on a page.
fn page_annot_boxes(pdf: &Pdf, p: &PageNode, before: usize) -> Vec<ExtraBox> {
    let mut out = Vec::new();
    let Some(Obj::Arr(annots)) = dget(p.dict, "Annots").map(|a| pdf.resolve_at(a, before)) else {
        return out;
    };
    for a in annots.iter().take(5000) {
        let Some(d) = pdf.resolve_at(a, before).dict() else {
            continue;
        };
        let sub = dname(d, "Subtype");
        if !matches!(sub, Some("Redact" | "Square")) {
            continue;
        }
        let Some(rect) = dget(d, "Rect").and_then(|r| rect_of(pdf.resolve_at(r, before))) else {
            continue;
        };
        let fill = match dget(d, "IC").map(|c| pdf.resolve_at(c, before)) {
            Some(Obj::Arr(c)) => {
                let v: Vec<f64> = c.iter().filter_map(Obj::num).collect();
                Fill::from_components(&v)
            }
            _ if sub == Some("Redact") => Fill::Black,
            _ => Fill::Other,
        };
        if fill != Fill::Other || sub == Some("Redact") {
            let fill = if fill == Fill::Other {
                Fill::Black
            } else {
                fill
            };
            out.push(ExtraBox { rect, fill });
        }
    }
    out
}

/// Interprets every page as of position `before`.
fn scan_pages(
    pdf: &Pdf,
    before: usize,
    ctx: &Ctx,
    cache: &mut StreamCache,
    with_annots: bool,
) -> Result<Vec<PageScan>, MetaError> {
    let mut out = Vec::new();
    for p in pages_at(pdf, before) {
        let data = page_content(pdf, &p, before, ctx, cache)?;
        let images = page_images(pdf, &p, before);
        let extra = if with_annots {
            page_annot_boxes(pdf, &p, before)
        } else {
            Vec::new()
        };
        out.push(redaction::scan_page(&data, &images, p.media, &extra));
    }
    Ok(out)
}

/// Positions just after each `%%EOF`.
fn eof_ends(b: &[u8]) -> Vec<usize> {
    let mut v = Vec::new();
    let mut i = 0;
    while let Some(at) = find(b, b"%%EOF", i) {
        i = at + 5;
        v.push(i);
        if v.len() > 10_000 {
            break;
        }
    }
    v
}

fn text_lines(pages: &[PageScan]) -> Vec<String> {
    let mut v = Vec::new();
    for p in pages {
        for l in p.text.lines() {
            let l = l.split_whitespace().collect::<Vec<_>>().join(" ");
            if l.chars().any(char::is_alphanumeric) {
                v.push(l);
            }
        }
    }
    v
}

/// Lines of `a` missing from `b`, deduplicated and truncated.
fn missing(a: &[String], b: &[String]) -> Vec<String> {
    let set: HashSet<&String> = b.iter().collect();
    let mut seen = HashSet::new();
    a.iter()
        .filter(|l| !set.contains(l) && seen.insert(*l))
        .take(50)
        .map(|l| truncate(l, 200))
        .collect()
}

const MAX_TEXT_REVISIONS: usize = 30;

/// Incremental revisions: per-revision Info and a line diff of the page text.
fn revisions(
    pdf: &Pdf,
    b: &[u8],
    linearized: bool,
    ctx: &Ctx,
    cache: &mut StreamCache,
    meta: &mut Metadata,
) -> Result<(), MetaError> {
    let mut ends = eof_ends(b);
    if linearized && ends.len() > 1 {
        ends.remove(0);
    }
    if ends.len() < 2 || ends.len() > 200 {
        return Ok(());
    }
    let pages = pages_at(pdf, usize::MAX).len().max(1);
    let with_text = ends.len() <= MAX_TEXT_REVISIONS && pages * ends.len() <= 5000;
    let mut prev_text: Option<Vec<String>> = None;
    let mut start = 0usize;
    for (i, &end) in ends.iter().enumerate() {
        let mut rev = PdfRevision {
            revision: (i + 1) as u32,
            end_offset: end as u64,
            objects: pdf.count_objects_in(start, end) as u32,
            ..PdfRevision::default()
        };
        let info = pdf.info_in(start, end);
        if let Some(Obj::Dict(d)) = info {
            if !meta.encrypted {
                let m = info_map(pdf, d);
                rev.author = m.get("Author").cloned();
                rev.creator = m.get("Creator").cloned();
                rev.producer = m.get("Producer").cloned();
                rev.modified = m.get("ModDate").and_then(|d| normalize_date(d));
            }
        }
        if with_text && !meta.encrypted {
            let lines = text_lines(&scan_pages(pdf, end, ctx, cache, false)?);
            if let Some(prev) = &prev_text {
                rev.removed_text = missing(prev, &lines);
                rev.added_text = missing(&lines, prev);
            }
            prev_text = Some(lines);
        }
        meta.pdf_revisions.push(rev);
        start = end;
    }
    Ok(())
}

/// Image XObjects: JPEG/JPEG 2000 bytes are parsed recursively (EXIF, GPS, XMP).
fn images(pdf: &Pdf, ctx: &Ctx, meta: &mut Metadata) -> Result<(), MetaError> {
    if !ctx.can_descend() {
        return Ok(());
    }
    let mut n = 0usize;
    for o in pdf.latest_objects() {
        let Obj::Stream(d, s, e) = &o.obj else {
            continue;
        };
        if dname(d, "Subtype") != Some("Image") {
            continue;
        }
        n += 1;
        if n > 500 || meta.embedded.len() >= 200 {
            break;
        }
        let Some((data, ext)) = pdf.image_bytes(d, *s, *e, ctx)? else {
            continue;
        };
        let name = format!("image-{}.{ext}", o.num);
        match ctx.extract_child(&data, &name) {
            Some(Ok(m)) => {
                let interesting = m.gps.is_some()
                    || m.camera.is_some()
                    || m.thumbnail.is_some()
                    || !m.xmp.is_empty()
                    || !m.people.is_empty()
                    || !m.software.is_empty()
                    || m.created.is_some()
                    || m.description.is_some();
                if interesting {
                    meta.embedded.push(Embedded {
                        name: format!("pdf:obj {} ({name})", o.num),
                        metadata: Box::new(m),
                    });
                }
            }
            Some(Err(e @ MetaError::ZipBomb(_))) => return Err(e),
            Some(Err(_)) | None => {}
        }
    }
    Ok(())
}

fn str_field(pdf: &Pdf, d: &Dict, k: &str) -> Option<String> {
    match dget(d, k).map(|v| pdf.resolve(v)) {
        Some(Obj::Str(s)) => crate::util::clean_str(&pdf_str(s)).map(|s| truncate(&s, 512)),
        Some(Obj::Name(n)) => Some(n.clone()),
        _ => None,
    }
}

/// Signature dictionaries (`/ByteRange` + `/Contents`): signer, TSA and coverage.
fn signatures(pdf: &Pdf, b: &[u8], meta: &mut Metadata) {
    let mut found: Vec<(u32, &Dict)> = Vec::new();
    pdf.for_each_dict(&mut |num, d| {
        if dget(d, "ByteRange").is_some() && dget(d, "Contents").is_some() && found.len() < 64 {
            found.push((num, d));
        }
    });
    let len = b.len() as u64;
    let mut seen: HashSet<Vec<u64>> = HashSet::new();
    for (num, d) in found {
        let br: Vec<u64> = match dget(d, "ByteRange").map(|r| pdf.resolve(r)) {
            Some(Obj::Arr(a)) => a
                .iter()
                .filter_map(|x| pdf.resolve(x).num())
                .filter(|n| n.is_finite() && *n >= 0.0 && *n < 1e15)
                .map(|n| n as u64)
                .collect(),
            _ => continue,
        };
        if br.len() != 4 || !seen.insert(br.clone()) {
            continue;
        }
        let Some(Obj::Str(contents)) = dget(d, "Contents").map(|c| pdf.resolve(c)) else {
            continue;
        };
        let sub_filter = dname(d, "SubFilter").map(str::to_string);
        let source = format!("pdf:obj {num}");
        let mut sig = if sub_filter.as_deref() == Some("ETSI.RFC3161") {
            let mut s = signature::from_cms(SignatureKind::Pdf, &source, &Default::default());
            s.timestamp = signature::parse_timestamp_token(contents);
            s
        } else {
            match signature::parse_cms(contents) {
                Some(cms) => {
                    let mut s = signature::from_cms(SignatureKind::Pdf, &source, &cms);
                    let (a, l1, c, l2) = (br[0], br[1], br[2], br[3]);
                    let part = |off: u64, n: u64| {
                        let s = usize::try_from(off).ok()?;
                        let e = s.checked_add(usize::try_from(n).ok()?)?;
                        b.get(s..e)
                    };
                    if let (Some(p1), Some(p2)) = (part(a, l1), part(c, l2)) {
                        s.digest_valid = cms.digest_matches(&[p1, p2]);
                    }
                    s
                }
                None => {
                    meta.warnings
                        .push(format!("{source}: подпись CMS не разобрана"));
                    signature::from_cms(SignatureKind::Pdf, &source, &Default::default())
                }
            }
        };
        let covered_end = br[2].saturating_add(br[3]);
        if covered_end <= len {
            let after = len - covered_end;
            sig.bytes_after = Some(after);
            let tail = b.get(covered_end as usize..).unwrap_or_default();
            sig.modified_after_signing = tail.iter().any(|c| !is_ws(*c));
        }
        sig.sub_filter = sub_filter;
        sig.name = str_field(pdf, d, "Name");
        sig.reason = str_field(pdf, d, "Reason");
        sig.location = str_field(pdf, d, "Location");
        sig.contact = str_field(pdf, d, "ContactInfo");
        if sig.signing_time.is_none() {
            sig.signing_time = str_field(pdf, d, "M").and_then(|m| normalize_date(&m));
        }
        sig.byte_range = br;
        meta.signatures.push(sig);
    }
    signature::apply_signers(meta, "signature:pdf");
}

/// Bad redactions and the scan-without-text flag from the current page content.
fn page_forensics(
    pdf: &Pdf,
    ctx: &Ctx,
    cache: &mut StreamCache,
    meta: &mut Metadata,
) -> Result<(), MetaError> {
    let pages = scan_pages(pdf, usize::MAX, ctx, cache, true)?;
    for (i, p) in pages.iter().enumerate() {
        for h in &p.hits {
            if meta.bad_redactions.len() >= 200 {
                break;
            }
            meta.bad_redactions.push(BadRedaction {
                page: (i + 1) as u32,
                text: h.text.clone(),
                fill: h.fill.name().to_string(),
                rect: h.rect.map(|v| v as f32),
            });
        }
    }
    let chars: usize = pages
        .iter()
        .map(|p| p.visible_chars + p.invisible_chars)
        .sum();
    meta.scan_without_text =
        !pages.is_empty() && pages.iter().all(|p| p.images > 0) && chars < 16 * pages.len().min(4);
    Ok(())
}

fn info_map(pdf: &Pdf, d: &Dict) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for (k, v) in d {
        let v = pdf.resolve(v);
        let s = match v {
            Obj::Str(b) => pdf_str(b),
            Obj::Name(n) => n.clone(),
            Obj::Num(n) => n.to_string(),
            Obj::Bool(b) => b.to_string(),
            _ => continue,
        };
        if let Some(s) = crate::util::clean_str(&s) {
            m.insert(k.clone(), truncate(&s, 2048));
        }
    }
    m
}

/// Visits every dictionary inside an object, up to a depth limit.
fn visit_dicts<'b>(o: &'b Obj, depth: usize, f: &mut dyn FnMut(&'b Dict)) {
    if depth > 64 {
        return;
    }
    match o {
        Obj::Dict(d) | Obj::Stream(d, _, _) => {
            f(d);
            for (_, v) in d {
                visit_dicts(v, depth + 1, f);
            }
        }
        Obj::Arr(a) => {
            for v in a {
                visit_dicts(v, depth + 1, f);
            }
        }
        _ => {}
    }
}

pub(crate) fn count_eof(b: &[u8]) -> u32 {
    let mut n = 0;
    let mut i = 0;
    while let Some(at) = find(b, b"%%EOF", i) {
        n += 1;
        i = at + 5;
    }
    n
}

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut meta = Metadata::new(DocFormat::Pdf);
    let head = &b[..b.len().min(1024)];
    if let Some(p) = find(head, b"%PDF-", 0) {
        let v: String = head[p + 5..]
            .iter()
            .take(4)
            .take_while(|c| c.is_ascii_digit() || **c == b'.')
            .map(|&c| c as char)
            .collect();
        if !v.is_empty() {
            meta.fields.insert("pdf:version".into(), v);
        }
    }
    let pdf = Pdf::parse(b, ctx)?;

    // incremental updates
    let eofs = count_eof(b);
    let linearized = pdf.is_linearized();
    let mut upd = eofs.saturating_sub(1);
    if linearized && upd > 0 {
        upd -= 1;
    }
    meta.incremental_updates = Some(upd);

    meta.encrypted = pdf.is_encrypted();

    // Info per revision
    let mut versions: Vec<BTreeMap<String, String>> = Vec::new();
    if !meta.encrypted {
        for d in pdf.trailer_infos() {
            let m = info_map(&pdf, d);
            if !m.is_empty() && versions.last() != Some(&m) {
                versions.push(m);
            }
        }
        if versions.is_empty() {
            // no trailer (broken file): look for a dictionary that resembles Info
            let cand = pdf.last_dict(|d| {
                dget(d, "Type").is_none()
                    && (dget(d, "Producer").is_some()
                        || dget(d, "Creator").is_some()
                        || dget(d, "Author").is_some())
            });
            if let Some(d) = cand {
                versions.push(info_map(&pdf, d));
            }
        }
    } else {
        meta.warnings
            .push("PDF зашифрован: строки Info не читаются".into());
    }
    if let Some(last) = versions.last().cloned() {
        for (k, v) in &last {
            match k.as_str() {
                "Title" => meta.title = Some(v.clone()),
                "Author" => {
                    meta.add_person(v, PersonRole::Author, "pdf:Info:Author");
                    meta.author = Some(v.clone());
                }
                "Subject" => meta.subject = Some(v.clone()),
                "Keywords" => meta.keywords = Some(v.clone()),
                "Creator" => {
                    Metadata::add_unique(&mut meta.software, v);
                    meta.application = Some(v.clone());
                }
                "Producer" => {
                    Metadata::add_unique(&mut meta.software, v);
                    meta.producer = Some(v.clone());
                }
                "CreationDate" => meta.created = normalize_date(v),
                "ModDate" => meta.modified = normalize_date(v),
                "Trapped" => {
                    meta.fields.insert("pdf:Trapped".into(), v.clone());
                }
                _ => {
                    meta.custom.insert(k.clone(), v.clone());
                }
            }
        }
    }
    let n = versions.len();
    for (i, v) in versions.iter().enumerate().take(n.saturating_sub(1)) {
        if let Some(a) = v.get("Author") {
            meta.add_person(a, PersonRole::Author, &format!("pdf:Info:rev{}", i + 1));
        }
        for k in ["Creator", "Producer"] {
            if let Some(s) = v.get(k) {
                Metadata::add_unique(&mut meta.software, s);
            }
        }
        meta.old_versions.push(OldVersion {
            revision: (i + 1) as u32,
            fields: v.clone(),
        });
    }

    // catalog: XMP, AcroForm, pages
    let catalog = pdf.catalog_before(usize::MAX);
    let mut primary_xmp: Option<u32> = None;
    if let Some(c) = catalog {
        if let Some(Obj::Ref(n, _)) = dget(c, "Metadata") {
            primary_xmp = Some(*n);
        }
        if dget(c, "AcroForm").is_some() {
            meta.fields.insert("pdf:acroform".into(), "true".into());
        }
        if let Some(Obj::Dict(pages)) = dget(c, "Pages").map(|p| pdf.resolve(p)) {
            if let Some(cnt) = dget(pages, "Count").and_then(Obj::num) {
                if (0.0..1e9).contains(&cnt) {
                    meta.stats.insert("pages".into(), cnt as u64);
                }
            }
        }
    }
    if !meta.encrypted || primary_xmp.is_some() {
        if let Some(n) = primary_xmp {
            if let Some(Obj::Stream(d, s, e)) = pdf.get(n) {
                if let Some(data) = pdf.decode(d, *s, *e, ctx)? {
                    let map = xmp::parse(&data, ctx);
                    xmp::apply(&mut meta, &map, "xmp");
                }
            }
        }
    }
    // other XMP packets (images, older revisions): software only
    for (d, s, e) in pdf.xmp_streams_except(primary_xmp) {
        if let Some(data) = pdf.decode(d, s, e, ctx)? {
            let map = xmp::parse(&data, ctx);
            for (k, v) in &map {
                if k.ends_with("CreatorTool") || k.ends_with("softwareAgent") || k == "pdf:Producer"
                {
                    for s in v.split("; ") {
                        Metadata::add_unique(&mut meta.software, s);
                    }
                }
            }
        }
    }

    // JavaScript, embedded files, annotations
    let mut files: Vec<(String, Option<Obj>)> = Vec::new();
    let mut found_js = false;
    pdf.for_each_dict(&mut |_, d| {
        if dget(d, "JS").is_some()
            || dname(d, "S") == Some("JavaScript")
            || dget(d, "JavaScript").is_some()
        {
            found_js = true;
        }
        if dname(d, "Type") == Some("Filespec") || dget(d, "EF").is_some() {
            let name = dget(d, "UF")
                .or_else(|| dget(d, "F"))
                .map(|n| pdf.resolve(n))
                .and_then(|n| match n {
                    Obj::Str(s) => Some(pdf_str(s)),
                    _ => None,
                });
            let ef = dget(d, "EF")
                .map(|e| pdf.resolve(e))
                .and_then(|e| e.dict())
                .and_then(|e| dget(e, "F").or_else(|| dget(e, "UF")))
                .cloned();
            if let Some(n) = name {
                if dget(d, "EF").is_some() && !files.iter().any(|(x, _)| *x == n) {
                    files.push((n, ef));
                }
            }
        }
        if dname(d, "Type") == Some("Annot")
            || matches!(
                dname(d, "Subtype"),
                Some("Text" | "FreeText" | "Highlight" | "Underline" | "StrikeOut" | "Squiggly")
            )
        {
            if let (Some(Obj::Str(t)), sub) =
                (dget(d, "T").map(|t| pdf.resolve(t)), dname(d, "Subtype"))
            {
                if matches!(
                    sub,
                    Some(
                        "Text"
                            | "FreeText"
                            | "Highlight"
                            | "Underline"
                            | "StrikeOut"
                            | "Squiggly"
                            | "Popup"
                    )
                ) {
                    let author = crate::util::clean_str(&pdf_str(t));
                    let text = match dget(d, "Contents").map(|c| pdf.resolve(c)) {
                        Some(Obj::Str(c)) => pdf_str(c),
                        _ => String::new(),
                    };
                    let date = match dget(d, "M")
                        .or_else(|| dget(d, "CreationDate"))
                        .map(|c| pdf.resolve(c))
                    {
                        Some(Obj::Str(c)) => normalize_date(&pdf_str(c)),
                        _ => None,
                    };
                    if author.is_some() || !text.is_empty() {
                        let c = CommentRef {
                            author,
                            initials: None,
                            date,
                            text: truncate(text.trim(), 2048),
                            source: "pdf:annot".into(),
                        };
                        if !meta.comments.contains(&c) && meta.comments.len() < 2000 {
                            if let Some(a) = &c.author {
                                meta.add_person(a, PersonRole::Comment, "pdf:annot");
                            }
                            meta.comments.push(c);
                        }
                    }
                }
            }
        }
    });
    if found_js {
        meta.has_javascript = true;
    }
    for (name, ef) in files.into_iter().take(200) {
        let stream = ef.as_ref().map(|r| pdf.resolve(r));
        let mut size = None;
        let mut child: Option<Metadata> = None;
        if let Some(Obj::Stream(d, s, e)) = stream {
            size = dget(d, "Params")
                .map(|p| pdf.resolve(p))
                .and_then(|p| p.dict())
                .and_then(|p| dget(p, "Size"))
                .and_then(Obj::num)
                .map(|n| n as u64);
            if ctx.can_descend() && meta.embedded.len() < 200 {
                if let Some(data) = pdf.decode(d, *s, *e, ctx)? {
                    size = size.or(Some(data.len() as u64));
                    match ctx.extract_child(&data, &name) {
                        Some(Ok(m)) => child = Some(m),
                        Some(Err(e @ MetaError::ZipBomb(_))) => return Err(e),
                        Some(Err(e)) => meta.warnings.push(format!("{name}: {e}")),
                        None => {}
                    }
                }
            }
            if let Some(Obj::Name(st)) = dget(d, "Subtype") {
                meta.attachments.push(Attachment {
                    name: name.clone(),
                    size,
                    mime: Some(st.replace("#2F", "/")),
                });
            } else {
                meta.attachments.push(Attachment {
                    name: name.clone(),
                    size,
                    mime: None,
                });
            }
        } else {
            meta.attachments.push(Attachment {
                name: name.clone(),
                size,
                mime: None,
            });
        }
        if let Some(m) = child {
            meta.embedded.push(Embedded {
                name,
                metadata: Box::new(m),
            });
        }
    }

    // forensics: image XObjects, signatures, revisions, page content
    // (non-fatal: a budget overrun here keeps the metadata collected so far)
    signatures(&pdf, b, &mut meta);
    let mut r = images(&pdf, ctx, &mut meta);
    if r.is_ok() && !meta.encrypted {
        let mut cache = StreamCache::new();
        r = page_forensics(&pdf, ctx, &mut cache, &mut meta)
            .and_then(|()| revisions(&pdf, b, linearized, ctx, &mut cache, &mut meta));
    }
    if let Err(e) = r {
        meta.warnings.push(format!("PDF: форензика прервана: {e}"));
    }
    Ok(meta)
}

/// Returns page text: strings from Tj/TJ/'/" operators plus annotation comments.
pub fn text(b: &[u8], ctx: &Ctx) -> Result<String, MetaError> {
    let pdf = Pdf::parse(b, ctx)?;
    let mut out = String::new();
    let mut content_refs: Vec<u32> = Vec::new();
    for o in pdf.latest_objects() {
        if let Some(d) = o.obj.dict() {
            if dname(d, "Type") == Some("Page") {
                match dget(d, "Contents") {
                    Some(Obj::Ref(n, _)) => content_refs.push(*n),
                    Some(Obj::Arr(a)) => content_refs.extend(a.iter().filter_map(|x| {
                        if let Obj::Ref(n, _) = x {
                            Some(*n)
                        } else {
                            None
                        }
                    })),
                    _ => {}
                }
            }
            // Annotation text; signature dictionaries keep the binary PKCS#7 blob in
            // /Contents, which is not text (and carries certificate identifiers).
            let sig = dget(d, "ByteRange").is_some()
                || matches!(dname(d, "Type"), Some("Sig" | "DocTimeStamp"));
            if let (Some(Obj::Str(c)), false) = (dget(d, "Contents"), sig) {
                out.push_str(&pdf_str(c));
                out.push('\n');
            }
        }
    }
    content_refs.sort_unstable();
    content_refs.dedup();
    for n in content_refs {
        let Some(Obj::Stream(d, s, e)) = pdf.get(n) else {
            continue;
        };
        let Some(data) = pdf.decode(d, *s, *e, ctx)? else {
            continue;
        };
        let mut lx = Lex::new(&data, 0, 8);
        let mut operands: Vec<Obj> = Vec::new();
        while let Some(tok) = lx.parse(0) {
            match tok {
                Obj::Kw(k) => {
                    match k.as_str() {
                        "Tj" | "'" | "\"" => {
                            if let Some(Obj::Str(s)) = operands.last() {
                                out.push_str(&content_str(s));
                            }
                        }
                        "TJ" => {
                            if let Some(Obj::Arr(a)) = operands.last() {
                                for x in a {
                                    match x {
                                        Obj::Str(s) => out.push_str(&content_str(s)),
                                        Obj::Num(n) if *n < -200.0 => out.push(' '),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        "ET" | "T*" => out.push('\n'),
                        "Td" | "TD" => out.push(' '),
                        _ => {}
                    }
                    operands.clear();
                }
                other => {
                    if operands.len() < 64 {
                        operands.push(other);
                    }
                }
            }
            if lx.at_end() {
                break;
            }
        }
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_spends_budget_even_with_trailing_unsupported_filter() {
        use crate::Limits;
        use flate2::{write::ZlibEncoder, Compression};
        use std::cell::Cell;
        use std::io::Write;

        let payload = vec![b'X'; 512];
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&payload).unwrap();
        let compressed = enc.finish().unwrap();

        let limits = Limits {
            max_unzipped_total: 1024,
            ..Limits::default()
        };
        let budget = Cell::new(limits.max_unzipped_total);
        let ctx = Ctx::standalone(&limits, &budget);
        let pdf = Pdf {
            b: &compressed,
            objs: Vec::new(),
            latest: HashMap::new(),
            versions: HashMap::new(),
            trailers: Vec::new(),
        };
        let dict = vec![(
            "Filter".into(),
            Obj::Arr(vec![
                Obj::Name("FlateDecode".into()),
                Obj::Name("ASCII85Decode".into()),
            ]),
        )];
        let res = pdf.decode(&dict, 0, compressed.len(), &ctx).unwrap();
        assert!(res.is_none());
        assert_eq!(ctx.remaining(), 512);
    }
}
