//! Outlook messages (MS-OXMSG, an OLE2 compound file): subject, sender (SMTP and Exchange
//! X.500 addresses), recipients, submit/creation/modification times, transport headers
//! (`Received:` chain and the rest via the EML header mapper), body links and attachments,
//! including embedded messages, parsed recursively under the shared budget.

use std::io::{Cursor, Read, Seek};

use foca_core::{Attachment, DocFormat, Embedded, Metadata};

use crate::formats::mail::eml;
use crate::util::{clean_str, decode_text, filetime_to_iso, rd_u16le, rd_u64le, truncate, utf16le};
use crate::MAX_CHILDREN;
use crate::{Ctx, MetaError};

type Cf<'b> = cfb::CompoundFile<Cursor<&'b [u8]>>;

const MAX_RECIPIENTS: usize = 2000;
const MAX_TEXT: usize = 1 << 20;

fn read_stream<F: Read + Seek>(
    cf: &mut cfb::CompoundFile<F>,
    path: &str,
    ctx: &Ctx,
) -> Result<Option<Vec<u8>>, MetaError> {
    let Ok(mut s) = cf.open_stream(path) else {
        return Ok(None);
    };
    let len = s.len();
    if len > ctx.remaining() {
        return Err(MetaError::ZipBomb(format!(
            "MSG: stream {path} exceeds the budget"
        )));
    }
    let mut buf = Vec::with_capacity(len.min(1 << 20) as usize);
    let _ = (&mut s).take(len).read_to_end(&mut buf);
    ctx.spend(buf.len() as u64)?;
    Ok(Some(buf))
}

/// Child entry names of a storage: `(name, is_storage)`.
fn children(cf: &Cf, path: &str, max: usize) -> Vec<(String, bool)> {
    match cf.read_storage(path) {
        Ok(it) => it
            .take(max)
            .map(|e| (e.name().to_string(), e.is_storage()))
            .collect(),
        Err(_) => Vec::new(),
    }
}

struct Props<'p> {
    base: &'p str,
    names: &'p [(String, bool)],
}

impl Props<'_> {
    fn path(&self, name: &str) -> String {
        format!("{}/{name}", self.base.trim_end_matches('/'))
    }

    fn has(&self, name: &str) -> bool {
        self.names.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
    }

    /// Reads a string property (`001F` UTF-16LE or `001E` 8-bit).
    fn string(&self, cf: &mut Cf, id: u16, ctx: &Ctx) -> Result<Option<String>, MetaError> {
        let w = format!("__substg1.0_{id:04X}001F");
        if self.has(&w) {
            if let Some(b) = read_stream(cf, &self.path(&w), ctx)? {
                return Ok(clean_str(utf16le(&b).trim_end_matches('\0')));
            }
        }
        let a = format!("__substg1.0_{id:04X}001E");
        if self.has(&a) {
            if let Some(b) = read_stream(cf, &self.path(&a), ctx)? {
                let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                return Ok(clean_str(&decode_text(&b[..n])));
            }
        }
        Ok(None)
    }

    fn binary(&self, cf: &mut Cf, id: u16, ctx: &Ctx) -> Result<Option<Vec<u8>>, MetaError> {
        let n = format!("__substg1.0_{id:04X}0102");
        if !self.has(&n) {
            return Ok(None);
        }
        read_stream(cf, &self.path(&n), ctx)
    }

    /// Reads fixed-size properties from `__properties_version1.0` (`header` = 32 for the top
    /// message, 24 for embedded messages, 8 for recipients and attachments).
    fn fixed(
        &self,
        cf: &mut Cf,
        header: usize,
        ctx: &Ctx,
    ) -> Result<Vec<(u16, u16, u64)>, MetaError> {
        let mut out = Vec::new();
        let Some(b) = read_stream(cf, &self.path("__properties_version1.0"), ctx)? else {
            return Ok(out);
        };
        let mut off = header;
        while let (Some(ty), Some(id), Some(v)) = (
            rd_u16le(&b, off),
            rd_u16le(&b, off + 2),
            rd_u64le(&b, off + 8),
        ) {
            out.push((id, ty, v));
            off += 16;
            if out.len() > 10_000 {
                break;
            }
        }
        Ok(out)
    }
}

fn fixed_get(f: &[(u16, u16, u64)], id: u16) -> Option<u64> {
    f.iter().find(|(i, _, _)| *i == id).map(|(_, _, v)| *v)
}

fn is_x500(s: &str) -> bool {
    s.len() > 3 && s.as_bytes()[0] == b'/' && s[1..].to_ascii_lowercase().starts_with("o=")
}

fn put(meta: &mut Metadata, key: &str, v: &Option<String>) {
    if let Some(v) = v {
        meta.fields.insert(format!("msg:{key}"), truncate(v, 1024));
    }
}

struct Out {
    text: String,
}

fn message(
    cf: &mut Cf,
    base: &str,
    header: usize,
    ctx: &Ctx,
    out: &mut Out,
) -> Result<Metadata, MetaError> {
    let mut meta = Metadata::new(DocFormat::Msg);
    let names = children(cf, base, ctx.max_entries().saturating_add(1));
    if names.len() > ctx.max_entries() {
        return Err(MetaError::TooManyEntries("MSG: too many streams".into()));
    }
    let p = Props {
        base,
        names: &names,
    };
    let subject = p.string(cf, 0x0037, ctx)?;
    let sender_name = p.string(cf, 0x0C1A, ctx)?;
    let sender_smtp = p.string(cf, 0x5D01, ctx)?;
    let sender_email = p.string(cf, 0x0C1F, ctx)?;
    let repr_name = p.string(cf, 0x0042, ctx)?;
    let repr_smtp = p.string(cf, 0x5D02, ctx)?;
    let repr_email = p.string(cf, 0x0065, ctx)?;
    let headers_raw = p.string(cf, 0x007D, ctx)?;
    let message_id = p.string(cf, 0x1035, ctx)?;
    put(&mut meta, "message_class", &p.string(cf, 0x001A, ctx)?);
    put(&mut meta, "conversation_topic", &p.string(cf, 0x0070, ctx)?);
    put(&mut meta, "display_to", &p.string(cf, 0x0E04, ctx)?);
    put(&mut meta, "display_cc", &p.string(cf, 0x0E03, ctx)?);
    put(&mut meta, "display_bcc", &p.string(cf, 0x0E02, ctx)?);
    put(&mut meta, "creator_name", &p.string(cf, 0x3FF8, ctx)?);
    meta.last_modified_by = p.string(cf, 0x3FFA, ctx)?;
    for (key, v) in [
        ("sender_x500", &sender_email),
        ("sent_representing_x500", &repr_email),
    ] {
        if let Some(v) = v.as_ref().filter(|v| is_x500(v)) {
            meta.fields.insert(format!("msg:{key}"), truncate(v, 1024));
        }
    }

    // synthetic headers after the transport headers: the first occurrence wins
    let mut headers = headers_raw
        .as_deref()
        .map(|h| eml::parse_headers(h.as_bytes()))
        .unwrap_or_default();
    if let Some(h) = &headers_raw {
        meta.stats
            .insert("transport_header_bytes".into(), h.len() as u64);
    }
    let addr = |name: &Option<String>, smtp: &Option<String>, email: &Option<String>| {
        let a = smtp
            .clone()
            .or_else(|| email.clone().filter(|e| e.contains('@')));
        match (name, a) {
            (Some(n), Some(a)) => Some(format!("\"{n}\" <{a}>")),
            (Some(n), None) => Some(format!("\"{n}\"")),
            (None, Some(a)) => Some(format!("<{a}>")),
            (None, None) => None,
        }
    };
    if let Some(f) = addr(&sender_name, &sender_smtp, &sender_email) {
        headers.push(("from".into(), f));
    }
    if let Some(s) = addr(&repr_name, &repr_smtp, &repr_email) {
        if repr_name != sender_name || repr_smtp != sender_smtp {
            headers.push(("sender".into(), s));
        }
    }
    if let Some(s) = &subject {
        headers.push(("subject".into(), s.clone()));
    }
    if let Some(m) = &message_id {
        headers.push(("message-id".into(), m.clone()));
    }
    let fixed = p.fixed(cf, header, ctx)?;
    // recipients
    let mut nrecip = 0u64;
    for (name, is_storage) in &names {
        if !is_storage || !name.starts_with("__recip_version1.0_") {
            continue;
        }
        nrecip += 1;
        if nrecip as usize > MAX_RECIPIENTS {
            break;
        }
        let rbase = p.path(name);
        let rnames = children(cf, &rbase, 256);
        let rp = Props {
            base: &rbase,
            names: &rnames,
        };
        let dn = rp.string(cf, 0x3001, ctx)?;
        let smtp = rp.string(cf, 0x39FE, ctx)?;
        let email = rp.string(cf, 0x3003, ctx)?;
        if let Some(e) = email.as_ref().filter(|e| is_x500(e)) {
            meta.fields
                .insert(format!("msg:recipient_x500.{nrecip:02}"), truncate(e, 1024));
        }
        let rf = rp.fixed(cf, 8, ctx)?;
        let kind = match fixed_get(&rf, 0x0C15).map(|v| v as u32) {
            Some(2) => "cc",
            Some(3) => "bcc",
            _ => "to",
        };
        if let Some(a) = addr(&dn, &smtp, &email) {
            headers.push((kind.into(), a));
        }
    }
    if nrecip > 0 {
        meta.stats.insert("recipients".into(), nrecip);
    }
    eml::apply_headers(&mut meta, &headers, "msg");
    if let Some(n) = &sender_name {
        meta.author = Some(truncate(n, 256));
    }
    // dates
    if let Some(t) = fixed_get(&fixed, 0x0039).and_then(filetime_to_iso) {
        meta.created = Some(t);
    }
    if meta.created.is_none() {
        meta.created = fixed_get(&fixed, 0x3007).and_then(filetime_to_iso);
    }
    meta.modified = fixed_get(&fixed, 0x3008).and_then(filetime_to_iso);
    put(
        &mut meta,
        "delivery_time",
        &fixed_get(&fixed, 0x0E06).and_then(filetime_to_iso),
    );
    if let Some(t) = fixed_get(&fixed, 0x3007).and_then(filetime_to_iso) {
        meta.fields.insert("msg:creation_time".into(), t);
    }
    // bodies
    if let Some(s) = &subject {
        out.text.push_str(s);
        out.text.push('\n');
    }
    if let Some(body) = p.string(cf, 0x1000, ctx)? {
        eml::find_urls(&body, &mut meta.links);
        if out.text.len() < MAX_TEXT {
            out.text.push_str(&truncate(&body, MAX_TEXT));
            out.text.push('\n');
        }
    }
    let html = match p.binary(cf, 0x1013, ctx)? {
        Some(b) => Some(String::from_utf8_lossy(&b).into_owned()),
        None => p.string(cf, 0x1013, ctx)?,
    };
    if let Some(h) = html {
        eml::find_urls(&h, &mut meta.links);
    }
    // attachments
    for (name, is_storage) in &names {
        if !is_storage || !name.starts_with("__attach_version1.0_") {
            continue;
        }
        if meta.attachments.len() >= 1000 {
            break;
        }
        let abase = p.path(name);
        let anames = children(cf, &abase, 256);
        let ap = Props {
            base: &abase,
            names: &anames,
        };
        let fname = match ap.string(cf, 0x3707, ctx)? {
            Some(n) => Some(n),
            None => match ap.string(cf, 0x3704, ctx)? {
                Some(n) => Some(n),
                None => ap.string(cf, 0x3001, ctx)?,
            },
        };
        let mime = ap.string(cf, 0x370E, ctx)?;
        let fname = truncate(&fname.unwrap_or_else(|| name.clone()), 255);
        if let Some(data) = ap.binary(cf, 0x3701, ctx)? {
            meta.attachments.push(Attachment {
                name: fname.clone(),
                size: Some(data.len() as u64),
                mime: mime.map(|m| truncate(&m, 128)),
            });
            if ctx.can_descend() {
                ctx.attach_child(&mut meta, &data, &fname, &format!("attachment:{fname}"))?;
            }
            continue;
        }
        let sub = "__substg1.0_3701000D";
        if anames
            .iter()
            .any(|(n, s)| *s && n.eq_ignore_ascii_case(sub))
        {
            let mbase = ap.path(sub);
            let is_msg = children(cf, &mbase, 4096)
                .iter()
                .any(|(n, _)| n == "__properties_version1.0");
            meta.attachments.push(Attachment {
                name: fname.clone(),
                size: None,
                mime: Some(
                    if is_msg {
                        "message/rfc822"
                    } else {
                        "application/x-ole-storage"
                    }
                    .into(),
                ),
            });
            if is_msg && ctx.can_descend() && meta.embedded.len() < MAX_CHILDREN {
                let child = ctx.nested();
                let mut sink = Out {
                    text: String::new(),
                };
                match message(cf, &mbase, 24, &child, &mut sink) {
                    Ok(mut m) => {
                        crate::paths::finalize(&mut m);
                        eml::drop_message_ids(&mut m);
                        meta.embedded.push(Embedded {
                            name: format!("attachment:{fname}"),
                            metadata: Box::new(m),
                        });
                    }
                    Err(e @ MetaError::ZipBomb(_)) => return Err(e),
                    Err(e) => meta.warnings.push(format!("{fname}: {e}")),
                }
            }
        }
    }
    if !meta.attachments.is_empty() {
        meta.stats
            .insert("attachments".into(), meta.attachments.len() as u64);
    }
    Ok(meta)
}

fn parse(b: &[u8], ctx: &Ctx) -> Result<(Metadata, String), MetaError> {
    crate::guard("msg", || {
        let mut cf =
            cfb::CompoundFile::open(Cursor::new(b)).map_err(|e| MetaError::malformed("msg", e))?;
        let mut out = Out {
            text: String::new(),
        };
        let meta = message(&mut cf, "/", 32, ctx, &mut out)?;
        Ok((meta, out.text))
    })
}

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    parse(b, ctx).map(|(m, _)| m)
}

/// Returns the subject and the plain-text body.
pub fn text(b: &[u8], ctx: &Ctx) -> Result<String, MetaError> {
    parse(b, ctx).map(|(_, t)| t)
}

/// Returns `true` if the root storage names belong to an Outlook message.
pub(crate) fn is_msg(names: &[String]) -> bool {
    names.iter().any(|n| n == "__properties_version1.0")
        && names.iter().any(|n| n.starts_with("__substg1.0_"))
}
