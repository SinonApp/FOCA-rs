//! Full PDF rewrite for metadata removal.
//!
//! The cleaned file is built from scratch: only objects reachable from the document catalog of
//! the latest revision are written, renumbered from 1, with a single classic cross-reference
//! table. Older revisions (incremental-update tails), the trailer `Info` dictionary, object and
//! xref streams, and orphan objects are therefore never copied.
//!
//! Removed everywhere: `Metadata` (XMP), `PieceInfo`, `Thumb`, `LastModified`; signature
//! dictionaries and signature fields (with catalog `Perms`/`DSS` and `AcroForm/SigFlags`).
//! Optional: JavaScript actions, `AA`, non-`GoTo` `OpenAction` and the `JavaScript` name tree;
//! embedded files (`EmbeddedFiles`, `EF` file specifications, `FileAttachment` annotations, `AF`);
//! markup-annotation authors (`T`). Stream data is copied without re-encoding; images with a sole
//! `DCTDecode` filter are cleaned like standalone JPEGs. Encrypted files are refused.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use super::output::{CleanOptions, CleanOutput, CleanWarning};
use super::raster::clean_jpeg;
use crate::pdf::syntax::{dget, dname, Dict, Obj};
use crate::pdf::{count_eof, Pdf};
use crate::{Ctx, Limits, MetaError};

/// Keys removed from every dictionary.
const ALWAYS_DROP_KEYS: &[&str] = &["Metadata", "PieceInfo", "Thumb", "LastModified"];

/// Annotation subtypes whose `/T` entry is the author name (markup annotations, ISO 32000 12.5.6.2).
const MARKUP_SUBTYPES: &[&str] = &[
    "Text",
    "FreeText",
    "Line",
    "Square",
    "Circle",
    "Polygon",
    "PolyLine",
    "Highlight",
    "Underline",
    "Squiggly",
    "StrikeOut",
    "Stamp",
    "Caret",
    "Ink",
    "FileAttachment",
    "Sound",
    "Redact",
    "Popup",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drop {
    Signature,
    JavaScript,
    Embedded,
    Xmp,
    /// Dangling reference: the target object does not exist.
    Missing,
}

#[derive(Default)]
struct Stats {
    signatures: HashSet<u32>,
    direct_signatures: u32,
    javascript: u32,
    embedded: u32,
    authors: u32,
}

struct Cleaner<'p, 'a> {
    pdf: &'p Pdf<'a>,
    opts: &'p CleanOptions,
    has_sig: bool,
    stats: Stats,
}

impl Cleaner<'_, '_> {
    fn is_sig_field(&self, d: &Dict, depth: usize) -> bool {
        if dname(d, "FT") == Some("Sig") {
            return true;
        }
        // A widget kid of a signature field inherits /FT from its parent.
        if depth < 8 && dname(d, "Subtype") == Some("Widget") && dget(d, "FT").is_none() {
            if let Some(p) = dget(d, "Parent")
                .map(|p| self.pdf.resolve(p))
                .and_then(Obj::dict)
            {
                return self.is_sig_field(p, depth + 1);
            }
        }
        false
    }

    fn classify(&self, d: &Dict) -> Option<Drop> {
        let ty = dname(d, "Type");
        if matches!(ty, Some("Sig" | "DocTimeStamp"))
            || dget(d, "ByteRange").is_some()
            || self.is_sig_field(d, 0)
        {
            return Some(Drop::Signature);
        }
        if ty == Some("Metadata") || dname(d, "Subtype") == Some("XML") {
            return Some(Drop::Xmp);
        }
        if self.opts.remove_javascript
            && (dname(d, "S") == Some("JavaScript") || dget(d, "JS").is_some())
        {
            return Some(Drop::JavaScript);
        }
        if self.opts.remove_embedded_files
            && (ty == Some("EmbeddedFile")
                || dget(d, "EF").is_some()
                || dname(d, "Subtype") == Some("FileAttachment"))
        {
            return Some(Drop::Embedded);
        }
        None
    }

    /// Classifies the latest version of indirect object `num`; `None` keeps it.
    fn classify_ref(&self, num: u32) -> Option<Drop> {
        match self.pdf.get(num) {
            None => Some(Drop::Missing),
            Some(o) => o.dict().and_then(|d| self.classify(d)),
        }
    }

    fn note(&mut self, kind: Drop, num: Option<u32>) {
        match kind {
            Drop::Signature => match num {
                Some(n) => {
                    self.stats.signatures.insert(n);
                }
                None => self.stats.direct_signatures += 1,
            },
            Drop::JavaScript => self.stats.javascript += 1,
            Drop::Embedded => self.stats.embedded += 1,
            Drop::Xmp | Drop::Missing => {}
        }
    }

    /// Returns `None` if the value must be removed from its container.
    fn value(&mut self, o: &Obj, parent_key: &str) -> Option<Obj> {
        match o {
            Obj::Ref(n, _) => match self.classify_ref(*n) {
                Some(k) => {
                    self.note(k, Some(*n));
                    None
                }
                None => Some(Obj::Ref(*n, 0)),
            },
            Obj::Dict(d) => {
                if let Some(k) = self.classify(d) {
                    self.note(k, None);
                    return None;
                }
                Some(Obj::Dict(self.dict(d)))
            }
            Obj::Arr(a) => {
                // Name and number trees pair keys with values: keep positions.
                let positional = matches!(parent_key, "Names" | "Nums");
                let mut out = Vec::with_capacity(a.len());
                for x in a {
                    match self.value(x, "") {
                        Some(v) => out.push(v),
                        None if positional => out.push(Obj::Null),
                        None => {}
                    }
                }
                Some(Obj::Arr(out))
            }
            Obj::Kw(_) | Obj::Stream(..) => Some(Obj::Null),
            other => Some(other.clone()),
        }
    }

    fn dict(&mut self, d: &Dict) -> Dict {
        let markup = dname(d, "Subtype").is_some_and(|s| MARKUP_SUBTYPES.contains(&s))
            && dget(d, "FT").is_none();
        let mut out = Dict::with_capacity(d.len());
        for (k, v) in d {
            let k = k.as_str();
            let drop_key = ALWAYS_DROP_KEYS.contains(&k)
                || (self.has_sig && matches!(k, "Perms" | "DSS" | "SigFlags"))
                || (self.opts.remove_javascript && matches!(k, "AA" | "JavaScript"))
                || (self.opts.remove_javascript && k == "OpenAction" && self.is_action(v))
                || (self.opts.remove_embedded_files && matches!(k, "EmbeddedFiles" | "AF"));
            if drop_key {
                if k == "JavaScript" || k == "AA" || k == "OpenAction" {
                    self.stats.javascript += 1;
                } else if k == "EmbeddedFiles" {
                    self.stats.embedded += 1;
                }
                continue;
            }
            if markup && self.opts.remove_annotation_authors && k == "T" {
                self.stats.authors += 1;
                continue;
            }
            if let Some(v) = self.value(v, k) {
                out.push((k.to_string(), v));
            }
        }
        out
    }

    /// `OpenAction` is either a destination array or an action dictionary; any action other
    /// than `GoTo` is removed together with JavaScript.
    fn is_action(&self, v: &Obj) -> bool {
        match self.pdf.resolve(v) {
            Obj::Dict(d) => dname(d, "S") != Some("GoTo"),
            _ => false,
        }
    }
}

fn collect_refs(o: &Obj, out: &mut Vec<u32>) {
    match o {
        Obj::Ref(n, _) => out.push(*n),
        Obj::Arr(a) => a.iter().for_each(|x| collect_refs(x, out)),
        Obj::Dict(d) => d.iter().for_each(|(_, v)| collect_refs(v, out)),
        _ => {}
    }
}

fn pdf_version(b: &[u8]) -> String {
    let head = &b[..b.len().min(1024)];
    crate::util::find(head, b"%PDF-", 0)
        .map(|p| {
            head[p + 5..]
                .iter()
                .take(3)
                .take_while(|c| c.is_ascii_digit() || **c == b'.')
                .map(|&c| c as char)
                .collect::<String>()
        })
        .filter(|v| v.len() == 3 && v.as_bytes()[1] == b'.')
        .unwrap_or_else(|| "1.7".into())
}

/// Rewrites a PDF keeping only the content of the latest revision.
pub(crate) fn clean_pdf(
    b: &[u8],
    opts: &CleanOptions,
    limits: &Limits,
) -> Result<CleanOutput, MetaError> {
    let budget = Cell::new(limits.max_unzipped_total);
    let ctx = Ctx::standalone(limits, &budget);
    let pdf = Pdf::parse(b, &ctx)?;
    if pdf.is_encrypted() {
        return Err(MetaError::Unsupported(
            "PDF зашифрован: снимите пароль/шифрование перед очисткой".into(),
        ));
    }
    let root = pdf
        .root()
        .ok_or_else(|| MetaError::malformed("pdf", "не найден каталог документа"))?;
    let mut cl = Cleaner {
        pdf: &pdf,
        opts,
        has_sig: false,
        stats: Stats::default(),
    };
    cl.has_sig = pdf.latest_objects().any(|o| {
        o.obj
            .dict()
            .is_some_and(|d| cl.classify(d) == Some(Drop::Signature))
    });

    // Breadth-first walk from the catalog; objects get new numbers in visiting order.
    let mut renum: HashMap<u32, u32> = HashMap::new();
    let mut queue = VecDeque::from([root]);
    renum.insert(root, 1);
    let mut out_objs: Vec<(Obj, Option<Cow<[u8]>>)> = Vec::new();
    while let Some(num) = queue.pop_front() {
        let src = pdf.get(num).unwrap_or(&Obj::Null);
        let (obj, data) = match src {
            Obj::Stream(d, s, e) => {
                let mut nd = cl.dict(d);
                let raw = b.get(*s..*e).unwrap_or(&[]);
                let mut data = Cow::Borrowed(raw);
                if dname(d, "Filter") == Some("DCTDecode") && dname(d, "Subtype") == Some("Image") {
                    if let Ok(j) = clean_jpeg(raw) {
                        data = Cow::Owned(j);
                    }
                }
                nd.retain(|(k, _)| k != "Length");
                nd.push(("Length".into(), Obj::Num(data.len() as f64)));
                (Obj::Dict(nd), Some(data))
            }
            other => (cl.value(other, "").unwrap_or(Obj::Null), None),
        };
        let mut refs = Vec::new();
        collect_refs(&obj, &mut refs);
        for r in refs {
            if !renum.contains_key(&r) {
                let next = renum.len() as u32 + 1;
                renum.insert(r, next);
                queue.push_back(r);
            }
        }
        out_objs.push((obj, data));
    }

    let ver = pdf_version(b);
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    out.extend_from_slice(format!("%PDF-{ver}\n").as_bytes());
    out.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::with_capacity(out_objs.len());
    for (i, (obj, data)) in out_objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        write_obj(&mut out, obj, &renum);
        out.push(b'\n');
        if let Some(d) = data {
            out.extend_from_slice(b"stream\n");
            out.extend_from_slice(d);
            out.extend_from_slice(b"\nendstream\n");
        }
        out.extend_from_slice(b"endobj\n");
    }
    let id = Sha256::digest(&out);
    let id_hex: String = id.iter().take(16).fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    });
    let xref = out.len();
    let size = out_objs.len() + 1;
    let mut x = format!("xref\n0 {size}\n0000000000 65535 f\r\n");
    for o in &offsets {
        let _ = write!(x, "{o:010} 00000 n\r\n");
    }
    let _ = write!(
        x,
        "trailer\n<< /Size {size} /Root 1 0 R /ID [<{id_hex}> <{id_hex}>] >>\nstartxref\n{xref}\n%%EOF\n"
    );
    out.extend_from_slice(x.as_bytes());

    let mut warnings = Vec::new();
    let sigs = cl.stats.signatures.len() as u32 + cl.stats.direct_signatures;
    if sigs > 0 || cl.has_sig {
        warnings.push(CleanWarning::SignatureRemoved { count: sigs.max(1) });
    }
    let revs = count_eof(b).saturating_sub(1);
    let linearized = pdf.is_linearized();
    let revs = if linearized {
        revs.saturating_sub(1)
    } else {
        revs
    };
    if revs > 0 {
        warnings.push(CleanWarning::RevisionsCollapsed { count: revs });
    }
    if cl.stats.javascript > 0 {
        warnings.push(CleanWarning::JavascriptRemoved {
            count: cl.stats.javascript,
        });
    }
    if cl.stats.embedded > 0 {
        warnings.push(CleanWarning::EmbeddedFilesRemoved {
            count: cl.stats.embedded,
        });
    }
    if cl.stats.authors > 0 {
        warnings.push(CleanWarning::AnnotationAuthorsRemoved {
            count: cl.stats.authors,
        });
    }
    if !opts.remove_embedded_files && b_has(&pdf, "EmbeddedFile") {
        warnings.push(CleanWarning::EmbeddedFilesKept);
    }
    Ok(CleanOutput {
        bytes: out,
        warnings,
    })
}

fn b_has(pdf: &Pdf, ty: &str) -> bool {
    pdf.latest_objects()
        .any(|o| o.obj.dict().is_some_and(|d| dname(d, "Type") == Some(ty)))
}

fn write_num(out: &mut Vec<u8>, n: f64) {
    let s = if !n.is_finite() {
        "0".to_string()
    } else if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        let s = format!("{n:.6}");
        let s = s.trim_end_matches('0').trim_end_matches('.');
        if s.is_empty() || s == "-" {
            "0".into()
        } else {
            s.to_string()
        }
    };
    out.extend_from_slice(s.as_bytes());
}

fn write_name(out: &mut Vec<u8>, n: &str) {
    out.push(b'/');
    for &c in n.as_bytes() {
        let regular = (0x21..=0x7E).contains(&c)
            && !matches!(
                c,
                b'#' | b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
            );
        if regular {
            out.push(c);
        } else {
            out.extend_from_slice(format!("#{c:02X}").as_bytes());
        }
    }
}

fn write_obj(out: &mut Vec<u8>, o: &Obj, renum: &HashMap<u32, u32>) {
    match o {
        Obj::Null | Obj::Kw(_) | Obj::Stream(..) => out.extend_from_slice(b"null"),
        Obj::Bool(true) => out.extend_from_slice(b"true"),
        Obj::Bool(false) => out.extend_from_slice(b"false"),
        Obj::Num(n) => write_num(out, *n),
        Obj::Str(s) => {
            out.push(b'<');
            for c in s {
                out.extend_from_slice(format!("{c:02X}").as_bytes());
            }
            out.push(b'>');
        }
        Obj::Name(n) => write_name(out, n),
        Obj::Ref(n, _) => match renum.get(n) {
            Some(m) => out.extend_from_slice(format!("{m} 0 R").as_bytes()),
            None => out.extend_from_slice(b"null"),
        },
        Obj::Arr(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_obj(out, x, renum);
            }
            out.push(b']');
        }
        Obj::Dict(d) => {
            out.extend_from_slice(b"<<");
            for (k, v) in d {
                write_name(out, k);
                out.push(b' ');
                write_obj(out, v, renum);
                out.push(b' ');
            }
            out.extend_from_slice(b">>");
        }
    }
}
