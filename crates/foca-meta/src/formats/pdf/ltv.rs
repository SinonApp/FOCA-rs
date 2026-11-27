//! Increments written after a PDF signature that only add long-term validation data.
//!
//! PAdES-LTV tools append the Document Security Store (`/DSS` with `/VRI`, certificate, OCSP
//! and CRL streams), a document timestamp and an updated catalog after the signed bytes. That
//! is not a change of the signed document; anything touching pages, content streams,
//! annotations other than a signature widget, or form values is.

/// Objects defined in `b` (`N G obj ... endobj`): number and body.
fn objects(b: &[u8]) -> Vec<(u64, &[u8])> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(k) = find(&b[from..], b"obj") {
        let at = from + k;
        from = at + 3;
        // `obj` as a keyword (not `endobj`, not part of a name)
        if b.get(at + 3).is_some_and(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        let mut i = at;
        let skip_ws = |i: &mut usize| {
            while *i > 0 && b[*i - 1].is_ascii_whitespace() {
                *i -= 1;
            }
        };
        let digits = |i: &mut usize| {
            let e = *i;
            while *i > 0 && b[*i - 1].is_ascii_digit() {
                *i -= 1;
            }
            (*i < e).then(|| &b[*i..e])
        };
        let ws0 = i;
        skip_ws(&mut i);
        if i == ws0 || digits(&mut i).is_none() {
            continue;
        }
        let ws1 = i;
        skip_ws(&mut i);
        if i == ws1 {
            continue;
        }
        let Some(num) = digits(&mut i)
            .and_then(|d| std::str::from_utf8(d).ok())
            .and_then(|d| d.parse().ok())
        else {
            continue;
        };
        // (writers may append `1 0 obj` right after `%%EOF` without a line break)
        let start = at + 3;
        let end = find(&b[start..], b"endobj").map_or(b.len(), |e| start + e);
        out.push((num, &b[start..end]));
        from = end;
    }
    out
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// The dictionary part of an object body (before `stream`).
fn dict_part(body: &[u8]) -> &[u8] {
    match find(body, b"stream") {
        Some(i) => &body[..i],
        None => body,
    }
}

fn has(d: &[u8], key: &str) -> bool {
    let k = key.as_bytes();
    d.windows(k.len()).enumerate().any(|(i, w)| {
        w == k
            && d.get(i + k.len())
                .is_none_or(|c| !c.is_ascii_alphanumeric())
    })
}

fn type_is(d: &[u8], t: &str) -> bool {
    let compact: Vec<u8> = d
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let k = format!("/Type/{t}");
    has(&compact, &k)
}

/// Top-level entries of a dictionary (`<< /Key value ... >>`) without the keys an LTV update
/// may add or rewrite (`/DSS`, `/AcroForm`, `/Extensions`, `/Perms`, `/Annots`), values with
/// whitespace removed, sorted: two writers order and space the keys differently.
fn without_ltv_keys(d: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Some(start) = find(d, b"<<") else {
        return Vec::new();
    };
    let b = &d[start + 2..];
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let (mut depth, mut i) = (0i32, 0usize);
    let mut cur: Option<(Vec<u8>, Vec<u8>)> = None;
    while i < b.len() {
        let c = b[i];
        if depth == 0 && b[i..].starts_with(b">>") {
            break;
        }
        if depth == 0 && c == b'/' && cur.as_ref().is_none_or(|(_, v)| !v.is_empty()) {
            // a new key (a name value right after a key belongs to that key)
            let e = b[i + 1..]
                .iter()
                .position(|x| x.is_ascii_whitespace() || b"/<>[]()".contains(x))
                .map_or(b.len(), |p| i + 1 + p);
            if let Some(kv) = cur.take() {
                out.push(kv);
            }
            cur = Some((b[i..e].to_vec(), Vec::new()));
            i = e;
            continue;
        }
        match c {
            b'<' | b'[' | b'(' => depth += 1,
            b'>' | b']' | b')' => depth -= 1,
            _ => {}
        }
        if let Some((_, v)) = cur.as_mut() {
            if !c.is_ascii_whitespace() {
                v.push(c);
            }
        }
        i += 1;
    }
    if let Some(kv) = cur.take() {
        out.push(kv);
    }
    out.retain(|(k, _)| {
        ![
            &b"/DSS"[..],
            b"/AcroForm",
            b"/Extensions",
            b"/Perms",
            b"/Annots",
            b"/Metadata",
            b"/ModDate",
            b"/Producer",
        ]
        .contains(&k.as_slice())
    });
    out.sort();
    out
}

/// Returns `true` if every object written after the signed bytes only adds validation data:
/// the DSS and its VRI, certificate/OCSP/CRL streams (new objects), a document timestamp and
/// its widget, the AcroForm listing it, an updated catalog that differs only by those keys,
/// a page whose only change is its `/Annots`, XMP metadata and a bare Info dictionary.
pub(crate) fn ltv_only(signed: &[u8], tail: &[u8]) -> bool {
    let tail_objs = objects(tail);
    if tail_objs.is_empty() {
        return false;
    }
    // object streams can hide any change: not judged as validation data
    if find(tail, b"/ObjStm").is_some() {
        return false;
    }
    let old: Vec<(u64, &[u8])> = objects(signed);
    let previous = |n: u64| old.iter().rev().find(|(m, _)| *m == n).map(|(_, b)| *b);
    tail_objs.iter().all(|(n, body)| {
        let d = dict_part(body);
        let stream = find(body, b"stream").is_some();
        if type_is(d, "DSS")
            || [
                "/VRI", "/Certs", "/OCSPs", "/CRLs", "/Cert", "/OCSP", "/CRL",
            ]
            .iter()
            .any(|k| has(d, k))
        {
            return true;
        }
        if type_is(d, "Metadata") || type_is(d, "XRef") {
            return true;
        }
        if type_is(d, "DocTimeStamp")
            || (type_is(d, "Sig") && find(d, b"ETSI.RFC3161").is_some())
            || (has(d, "/FT") && find(d, b"/Sig").is_some())
        {
            return true;
        }
        if type_is(d, "Catalog") || has(d, "/Fields") {
            return previous(*n)
                .is_none_or(|p| without_ltv_keys(dict_part(p)) == without_ltv_keys(d));
        }
        if type_is(d, "Page") {
            return previous(*n)
                .is_some_and(|p| without_ltv_keys(dict_part(p)) == without_ltv_keys(d));
        }
        // rewritten without a change (keys in another order, a new modification date or XMP
        // stream reference)
        if !stream
            && previous(*n).is_some_and(|p| without_ltv_keys(dict_part(p)) == without_ltv_keys(d))
        {
            return true;
        }
        // a VRI dictionary: keys are certificate hashes
        let keys = without_ltv_keys(d);
        if !stream
            && !keys.is_empty()
            && keys
                .iter()
                .all(|(k, _)| k.len() == 41 && k[1..].iter().all(u8::is_ascii_hexdigit))
        {
            return true;
        }
        let trimmed = d.trim_ascii();
        // an indirect array of references (the DSS lists)
        if trimmed.starts_with(b"[") && trimmed.iter().all(|c| b"[]0123456789 R\r\n\t".contains(c))
        {
            return true;
        }
        // a bare Info dictionary (dates, producer)
        if !stream
            && trimmed.starts_with(b"<<")
            && !has(d, "/Type")
            && (has(d, "/CreationDate") || has(d, "/ModDate") || has(d, "/Producer"))
            && !has(d, "/Title")
            && !has(d, "/Author")
            && !has(d, "/Subject")
            && !has(d, "/Keywords")
        {
            return true;
        }
        // certificate, OCSP and CRL data: new untyped streams (a rewritten content stream keeps
        // the number of an existing one)
        stream && !has(d, "/Type") && !has(d, "/Subtype") && previous(*n).is_none()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED: &[u8] = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Annots [6 0 R] >>\nendobj\n4 0 obj\n<< /Length 20 >>\nstream\nBT (Signed text) TJ ET\nendstream\nendobj\n";

    #[test]
    fn dss_and_timestamp_increment_is_validation_data() {
        let tail = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R /DSS 10 0 R >>\nendobj\n10 0 obj\n<< /Type /DSS /Certs [ 11 0 R ] /OCSPs [ 12 0 R ] /VRI 13 0 R >>\nendobj\n13 0 obj\n<< /ABCDEF << /Cert [11 0 R] >> >>\nendobj\n11 0 obj\n<< /Filter /FlateDecode /Length 3 >>\nstream\nabc\nendstream\nendobj\n12 0 obj\n<< /Length 3 >>\nstream\nxyz\nendstream\nendobj\n14 0 obj\n<< /CreationDate (D:20261005173046+03'00') /Producer () >>\nendobj\nxref\n0 1\ntrailer\n<< /Root 1 0 R >>\nstartxref\n100\n%%EOF\n";
        assert!(ltv_only(SIGNED, tail));
    }

    #[test]
    fn content_page_or_annotation_change_is_a_modification() {
        // a content stream rewritten under its old number
        let content =
            b"4 0 obj\n<< /Length 18 >>\nstream\nBT (Changed) TJ ET\nendstream\nendobj\nxref\n";
        assert!(!ltv_only(SIGNED, content));
        // a page pointing to new contents
        let page =
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 9 0 R /Annots [6 0 R] >>\nendobj\n";
        assert!(!ltv_only(SIGNED, page));
        // a new comment annotation
        let annot = b"9 0 obj\n<< /Type /Annot /Subtype /FreeText /Contents (new) >>\nendobj\n";
        assert!(!ltv_only(SIGNED, annot));
        // a form value
        let field = b"7 0 obj\n<< /T (name) /V (Changed) >>\nendobj\n";
        assert!(!ltv_only(SIGNED, field));
        // the catalog switching to other pages
        let cat = b"1 0 obj\n<< /Type /Catalog /Pages 8 0 R /DSS 10 0 R >>\nendobj\n";
        assert!(!ltv_only(SIGNED, cat));
        // a new page object listing only a widget is fine, a page with new contents is not
        let widget_page =
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Annots [6 0 R 15 0 R] >>\nendobj\n15 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig /V 16 0 R >>\nendobj\n16 0 obj\n<< /Type /DocTimeStamp /SubFilter /ETSI.RFC3161 /Contents <00> >>\nendobj\n";
        assert!(ltv_only(SIGNED, widget_page));
        assert!(!ltv_only(SIGNED, b"   \n"));
    }
}
