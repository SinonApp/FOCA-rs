//! Digital signatures: CMS/PKCS#7 (PDF `/Contents`, VBA `vbaProjectSignature.bin`), OOXML
//! XML-DSig (`_xmlsignatures/*.xml`) and RFC 3161 time-stamp tokens.
//!
//! Only extraction and integrity of coverage are done: signer identity, embedded certificates,
//! claimed signing time, the TSA time stamp and (for PDF) whether `messageDigest` matches the
//! signed byte ranges. Certificate chains are never validated and nothing is fetched.
//!
//! CMS is decoded with a small bounded DER/BER reader (no recursion on attacker-controlled
//! depth beyond [`MAX_DEPTH`]); certificates are parsed with `x509-parser`.

use foca_core::{CertInfo, Signature, SignatureKind, Timestamp};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};

use crate::util::{find, truncate};

pub(crate) mod kep;

const MAX_DEPTH: usize = 32;
const MAX_CHILDREN: usize = 4096;
const MAX_CERTS: usize = 64;

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_TST_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";
const OID_CONTENT_TS: &str = "1.2.840.113549.1.9.16.2.20";
const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const OID_SDA: &str = "2.5.29.9";

/// One DER/BER element.
#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    body: &'a [u8],
    /// Whole element including the header.
    raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    fn constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    fn children(&self) -> Vec<Tlv<'a>> {
        let mut out = Vec::new();
        let mut rest = self.body;
        while !rest.is_empty() && out.len() < MAX_CHILDREN {
            // end-of-contents of an indefinite-length parent
            if rest.starts_with(&[0, 0]) {
                break;
            }
            match read_tlv(rest, 0) {
                Some((t, r)) => {
                    out.push(t);
                    rest = r;
                }
                None => break,
            }
        }
        out
    }

    /// Contents of an OCTET STRING, joining BER constructed segments.
    fn octets(&self) -> Vec<u8> {
        if !self.constructed() {
            return self.body.to_vec();
        }
        let mut v = Vec::new();
        for c in self.children() {
            if c.tag & 0x1F == 0x04 {
                v.extend(c.octets_shallow());
            }
        }
        v
    }

    fn octets_shallow(&self) -> &'a [u8] {
        self.body
    }
}

/// Returns the body length of an indefinite-length element by skipping nested elements.
fn indefinite_len(b: &[u8], depth: usize) -> Option<usize> {
    if depth > MAX_DEPTH {
        return None;
    }
    let mut pos = 0usize;
    let mut n = 0usize;
    loop {
        let rest = b.get(pos..)?;
        if rest.starts_with(&[0, 0]) {
            return Some(pos);
        }
        let (t, _) = read_tlv(rest, depth + 1)?;
        pos = pos.checked_add(t.raw.len())?;
        n += 1;
        if n > MAX_CHILDREN {
            return None;
        }
    }
}

/// Reads one element. Long-form tags are rejected; indefinite lengths are supported.
fn read_tlv(b: &[u8], depth: usize) -> Option<(Tlv<'_>, &[u8])> {
    if depth > MAX_DEPTH {
        return None;
    }
    let tag = *b.first()?;
    if tag & 0x1F == 0x1F {
        return None;
    }
    let l0 = *b.get(1)?;
    let (hdr, len, eoc) = if l0 < 0x80 {
        (2usize, usize::from(l0), 0usize)
    } else if l0 == 0x80 {
        if tag & 0x20 == 0 {
            return None;
        }
        let len = indefinite_len(b.get(2..)?, depth)?;
        (2, len, 2)
    } else {
        let n = usize::from(l0 & 0x7F);
        if n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*b.get(2 + i)?);
        }
        (2 + n, len, 0)
    };
    let end = hdr.checked_add(len)?;
    let body = b.get(hdr..end)?;
    let total = end.checked_add(eoc)?;
    let raw = b.get(..total)?;
    Some((Tlv { tag, body, raw }, b.get(total..)?))
}

fn oid_str(body: &[u8]) -> Option<String> {
    if body.is_empty() || body.len() > 64 {
        return None;
    }
    let mut parts: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    for &c in body {
        v = v.checked_shl(7)? | u64::from(c & 0x7F);
        if c & 0x80 == 0 {
            if parts.is_empty() {
                let (a, b) = if v < 40 {
                    (0, v)
                } else if v < 80 {
                    (1, v - 40)
                } else {
                    (2, v - 80)
                };
                parts.push(a);
                parts.push(b);
            } else {
                parts.push(v);
            }
            v = 0;
        }
    }
    Some(
        parts
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

fn oid_of(t: &Tlv) -> Option<String> {
    (t.tag == 0x06).then(|| oid_str(t.body)).flatten()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Converts DER UTCTime/GeneralizedTime to ISO 8601 (`2024-05-01T10:00:00Z`).
fn der_time(t: &Tlv) -> Option<String> {
    let s = std::str::from_utf8(t.body).ok()?;
    let (year, rest) = match t.tag {
        0x17 => {
            let yy: u32 = s.get(..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, s.get(2..)?)
        }
        0x18 => (s.get(..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let num = |r: &str, i: usize| -> Option<u32> { r.get(i..i + 2)?.parse().ok() };
    let (mo, d, h, mi) = (num(rest, 0)?, num(rest, 2)?, num(rest, 4)?, num(rest, 6)?);
    let sec = num(rest, 8).unwrap_or(0);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    Some(format!("{year:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{sec:02}Z"))
}

/// Unix seconds to ISO 8601 UTC.
fn iso_from_unix(ts: i64) -> Option<String> {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // civil_from_days (H. Hinnant)
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    if !(0..=9999).contains(&y) {
        return None;
    }
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    ))
}

/// Decodes an ASN.1 string value by tag (UTF8, Printable, IA5, Numeric, Teletex, BMP).
fn der_string(tag: u32, data: &[u8]) -> Option<String> {
    let s = match tag {
        12 | 18 | 19 | 22 | 26 => String::from_utf8_lossy(data).into_owned(),
        20 | 21 | 25 | 27 => data.iter().map(|&c| c as char).collect(),
        30 => crate::util::utf16be(data),
        28 => data
            .as_chunks::<4>()
            .0
            .iter()
            .filter_map(|c| char::from_u32(u32::from_be_bytes(*c)))
            .collect(),
        _ => return None,
    };
    crate::util::clean_str(&s).map(|s| truncate(&s, 512))
}

fn short_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.42" => "GN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "2.5.4.97" => "organizationIdentifier",
        "1.2.840.113549.1.9.1" => "E",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        _ => return None,
    })
}

/// Formats a name as a DN string, routing values through the КЕП rules and filling the identity fields of `info`.
fn name_fields(name: &X509Name, info: &mut CertInfo) -> String {
    let mut parts = Vec::new();
    for a in name.iter_attributes() {
        let oid = a.attr_type().to_id_string();
        let Some(v) = der_string(a.attr_value().tag().0, a.attr_value().data) else {
            continue;
        };
        let shown = kep::subject_attr(info, &oid, &v);
        let slot = match oid.as_str() {
            "2.5.4.3" => Some(&mut info.common_name),
            "2.5.4.4" => Some(&mut info.surname),
            "2.5.4.42" => Some(&mut info.given_name),
            "2.5.4.10" => Some(&mut info.organization),
            "2.5.4.11" => Some(&mut info.org_unit),
            "2.5.4.12" => Some(&mut info.title),
            "2.5.4.7" => Some(&mut info.locality),
            "2.5.4.6" => Some(&mut info.country),
            "1.2.840.113549.1.9.1" => Some(&mut info.email),
            _ => None,
        };
        if let Some(slot) = slot {
            if slot.is_none() {
                *slot = Some(shown.clone());
            }
        }
        let key = short_name(&oid).map_or(oid.clone(), str::to_string);
        parts.push(format!("{key}={shown}"));
        if parts.len() > 64 {
            break;
        }
    }
    truncate(&parts.join(", "), 2048)
}

/// Extracts identity fields from a DER certificate.
pub(crate) fn cert_info(der: &[u8]) -> Option<CertInfo> {
    let (_, c) = X509Certificate::from_der(der).ok()?;
    let mut info = CertInfo::default();
    info.subject = name_fields(c.subject(), &mut info);
    let mut iss = CertInfo::default();
    info.issuer = name_fields(c.issuer(), &mut iss);
    info.issuer_cn = iss.common_name.or(iss.organization);
    info.serial = hex(c.raw_serial());
    info.not_before = iso_from_unix(c.validity().not_before.timestamp());
    info.not_after = iso_from_unix(c.validity().not_after.timestamp());
    for ext in c.extensions() {
        if ext.oid.to_id_string() == OID_SDA {
            directory_attributes(ext.value, &mut info);
        }
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for g in &san.general_names {
                if let GeneralName::RFC822Name(m) = g {
                    if info.email.is_none() {
                        info.email = crate::util::clean_str(m);
                    }
                }
            }
        }
    }
    Some(info)
}

/// Parses `SubjectDirectoryAttributes ::= SEQUENCE OF Attribute`.
fn directory_attributes(value: &[u8], info: &mut CertInfo) {
    let Some((seq, _)) = read_tlv(value, 0) else {
        return;
    };
    for attr in seq.children() {
        let kids = attr.children();
        let (Some(oid), Some(set)) = (kids.first().and_then(oid_of), kids.get(1)) else {
            continue;
        };
        for v in set.children() {
            if let Some(s) = der_string(u32::from(v.tag & 0x1F), v.body) {
                kep::directory_attr(info, &oid, &s);
            }
        }
    }
}

fn digest_name(oid: &str) -> String {
    match oid {
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        "1.2.804.2.1.1.1.1.2.1" => "gost34311",
        "1.2.804.2.1.1.1.1.2.2.1" => "dstu7564-256",
        "1.2.804.2.1.1.1.1.2.2.2" => "dstu7564-384",
        "1.2.804.2.1.1.1.1.2.2.3" => "dstu7564-512",
        other => other,
    }
    .to_string()
}

/// Decoded CMS SignedData (first signer only).
#[derive(Default)]
pub(crate) struct Cms {
    pub signer: Option<CertInfo>,
    pub certificates: u32,
    pub signing_time: Option<String>,
    pub timestamp: Option<Timestamp>,
    pub digest_algorithm: Option<String>,
    digest_oid: Option<String>,
    message_digest: Option<Vec<u8>>,
    econtent_type: Option<String>,
    econtent: Option<Vec<u8>>,
}

/// A file that is a CMS SignedData with the document inside (Ukrainian КЕП `.p7s`, or a signed
/// `.pdf` that is really such a wrapper): the parsed signature and the inner bytes. Detected
/// by content (a DER/BER SEQUENCE that parses as SignedData with attached `data`), never by
/// the file name.
pub(crate) fn cms_wrapper(b: &[u8]) -> Option<(Cms, Vec<u8>)> {
    if b.first() != Some(&0x30) || !matches!(b.get(1), Some(0x80..=0x84)) {
        return None;
    }
    let mut cms = parse_cms(b)?;
    if cms.econtent_type.as_deref() != Some("1.2.840.113549.1.7.1") {
        return None;
    }
    let inner = cms.econtent.take().filter(|c| !c.is_empty())?;
    Some((cms, inner))
}

impl Cms {
    /// Compares `messageDigest` with the hash of `parts`. `None` if the algorithm is not
    /// supported here (SHA-1, DSTU/GOST) or there are no signed attributes.
    pub fn digest_matches(&self, parts: &[&[u8]]) -> Option<bool> {
        let md = self.message_digest.as_ref()?;
        let got: Vec<u8> = match self.digest_oid.as_deref()? {
            "2.16.840.1.101.3.4.2.1" => {
                let mut h = Sha256::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
            "2.16.840.1.101.3.4.2.2" => {
                let mut h = Sha384::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
            "2.16.840.1.101.3.4.2.3" => {
                let mut h = Sha512::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
            _ => return None,
        };
        Some(&got == md)
    }
}

fn attributes<'a>(set: &Tlv<'a>) -> Vec<(String, Vec<Tlv<'a>>)> {
    let mut out = Vec::new();
    for a in set.children() {
        let kids = a.children();
        if let (Some(oid), Some(vals)) = (kids.first().and_then(oid_of), kids.get(1)) {
            out.push((oid, vals.children()));
        }
    }
    out
}

/// Parses a DER/BER `ContentInfo` carrying `SignedData`.
pub(crate) fn parse_cms(der: &[u8]) -> Option<Cms> {
    parse_cms_depth(der, 0)
}

fn parse_cms_depth(der: &[u8], depth: usize) -> Option<Cms> {
    if depth > 2 {
        return None;
    }
    let (ci, _) = read_tlv(der, 0)?;
    let kids = ci.children();
    if kids.first().and_then(oid_of).as_deref() != Some(OID_SIGNED_DATA) {
        return None;
    }
    let sd = kids.get(1)?.children().into_iter().next()?;
    let sd_kids = sd.children();
    let mut cms = Cms::default();
    // encapContentInfo
    if let Some(encap) = sd_kids.get(2) {
        let e = encap.children();
        cms.econtent_type = e.first().and_then(oid_of);
        if let Some(wrap) = e.get(1).filter(|w| w.tag == 0xA0) {
            if let Some(os) = wrap.children().first() {
                cms.econtent = Some(os.octets());
            }
        }
    }
    let mut certs: Vec<(&[u8], Vec<u8>)> = Vec::new(); // raw, serial
    let mut signer_infos = None;
    for k in sd_kids.iter().skip(3) {
        match k.tag {
            0xA0 => {
                for c in k.children().into_iter().take(MAX_CERTS) {
                    if c.tag == 0x30 {
                        let serial = X509Certificate::from_der(c.raw)
                            .map(|(_, x)| x.raw_serial().to_vec())
                            .unwrap_or_default();
                        certs.push((c.raw, serial));
                    }
                }
            }
            0x31 => signer_infos = Some(*k),
            _ => {}
        }
    }
    cms.certificates = certs.len() as u32;
    let si = signer_infos.and_then(|s| s.children().into_iter().next());
    let mut signer_serial: Option<Vec<u8>> = None;
    if let Some(si) = si {
        let f = si.children();
        if let Some(sid) = f.get(1) {
            if sid.tag == 0x30 {
                signer_serial = sid
                    .children()
                    .get(1)
                    .filter(|s| s.tag == 0x02)
                    .map(|s| s.body.to_vec());
            }
        }
        if let Some(alg) = f.get(2).and_then(|a| a.children().first().and_then(oid_of)) {
            cms.digest_algorithm = Some(digest_name(&alg));
            cms.digest_oid = Some(alg);
        }
        for part in f.iter().skip(3) {
            if part.tag != 0xA0 && part.tag != 0xA1 {
                continue;
            }
            for (oid, vals) in attributes(part) {
                let Some(v) = vals.first() else { continue };
                match oid.as_str() {
                    OID_SIGNING_TIME => cms.signing_time = der_time(v),
                    OID_MESSAGE_DIGEST if v.tag == 0x04 => {
                        cms.message_digest = Some(v.body.to_vec())
                    }
                    OID_TST_TOKEN | OID_CONTENT_TS if cms.timestamp.is_none() => {
                        cms.timestamp = parse_timestamp_token_depth(v.raw, depth + 1);
                    }
                    _ => {}
                }
            }
        }
    }
    let signer_raw = certs
        .iter()
        .find(|(_, s)| signer_serial.as_ref().is_some_and(|x| x == s))
        .or_else(|| certs.first())
        .map(|(r, _)| *r);
    cms.signer = signer_raw.and_then(cert_info);
    Some(cms)
}

/// Parses an RFC 3161 `TimeStampToken` (a `ContentInfo` with `TSTInfo`).
pub(crate) fn parse_timestamp_token(der: &[u8]) -> Option<Timestamp> {
    parse_timestamp_token_depth(der, 1)
}

fn parse_timestamp_token_depth(der: &[u8], depth: usize) -> Option<Timestamp> {
    let cms = parse_cms_depth(der, depth)?;
    if cms.econtent_type.as_deref() != Some(OID_TST_INFO) {
        return None;
    }
    let tst = cms.econtent.as_deref()?;
    let (seq, _) = read_tlv(tst, 0)?;
    let f = seq.children();
    let mut ts = Timestamp {
        policy: f.get(1).and_then(oid_of),
        serial: f.get(3).filter(|s| s.tag == 0x02).map(|s| hex(s.body)),
        gen_time: f.get(4).and_then(der_time),
        tsa: None,
    };
    for k in f.iter().skip(5) {
        if k.tag == 0xA0 {
            // GeneralName; directoryName is [4] EXPLICIT Name
            if let Some(gn) = k.children().first() {
                if gn.tag == 0xA4 {
                    if let Some(n) = gn.children().first() {
                        if let Ok((_, name)) = X509Name::from_der(n.raw) {
                            let mut tmp = CertInfo::default();
                            let s = name_fields(&name, &mut tmp);
                            if !s.is_empty() {
                                ts.tsa = Some(s);
                            }
                        }
                    }
                } else if let Ok(s) = std::str::from_utf8(gn.body) {
                    ts.tsa = crate::util::clean_str(s);
                }
            }
        }
    }
    if ts.tsa.is_none() {
        ts.tsa = cms.signer.map(|s| s.subject).filter(|s| !s.is_empty());
    }
    Some(ts)
}

/// Builds a [`Signature`] from decoded CMS.
pub(crate) fn from_cms(kind: SignatureKind, source: &str, cms: &Cms) -> Signature {
    Signature {
        kind,
        source: source.to_string(),
        signer: cms.signer.clone(),
        certificates: cms.certificates,
        signing_time: cms.signing_time.clone(),
        timestamp: cms.timestamp.clone(),
        digest_algorithm: cms.digest_algorithm.clone(),
        sub_filter: None,
        name: None,
        reason: None,
        location: None,
        contact: None,
        byte_range: Vec::new(),
        bytes_after: None,
        modified_after_signing: false,
        digest_valid: None,
    }
}

/// Finds a `SignedData` `ContentInfo` inside an arbitrary blob (raw PKCS#7 or a
/// `DigSigInfoSerialized` wrapper) and parses it.
pub(crate) fn find_cms(blob: &[u8]) -> Option<Cms> {
    // OID 1.2.840.113549.1.7.2 encoded
    const SIGNED_DATA_OID: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];
    let mut from = 0;
    let mut tries = 0;
    while let Some(at) = find(blob, SIGNED_DATA_OID, from) {
        from = at + 1;
        tries += 1;
        if tries > 16 {
            break;
        }
        // the ContentInfo SEQUENCE header is 2..6 bytes before the OID
        for back in 2..=6usize {
            let Some(start) = at.checked_sub(back) else {
                continue;
            };
            if blob.get(start) != Some(&0x30) {
                continue;
            }
            if let Some(c) = parse_cms(&blob[start..]) {
                return Some(c);
            }
        }
    }
    None
}

/// Signature over a VBA project (`vbaProjectSignature.bin`, `vbaProjectSignatureAgile.bin`).
pub(crate) fn vba_signature(blob: &[u8], source: &str) -> Option<Signature> {
    let cms = find_cms(blob)?;
    Some(from_cms(SignatureKind::Vba, source, &cms))
}

/// Decodes base64, ignoring whitespace. Invalid input yields `None`.
pub(crate) fn base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            c if c.is_ascii_whitespace() => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// OOXML XML-DSig signature part.
pub(crate) fn xmldsig(root: &crate::xml::Element, source: &str) -> Option<Signature> {
    let certs: Vec<Vec<u8>> = root
        .descendants("X509Certificate")
        .into_iter()
        .take(MAX_CERTS)
        .filter_map(|e| base64(&e.text()))
        .collect();
    let signing_time = root
        .descendants("SigningTime")
        .first()
        .and_then(|e| e.text_opt())
        .or_else(|| {
            root.descendants("SignatureTime")
                .first()
                .and_then(|e| e.child("Value"))
                .and_then(|v| v.text_opt())
        })
        .map(|t| crate::util::normalize_date(&t).unwrap_or(t));
    let timestamp = root
        .descendants("EncapsulatedTimeStamp")
        .into_iter()
        .find_map(|e| base64(&e.text()).and_then(|d| parse_timestamp_token(&d)));
    if certs.is_empty() && signing_time.is_none() {
        return None;
    }
    let digest_algorithm = root
        .descendants("DigestMethod")
        .first()
        .and_then(|e| e.attr("Algorithm"))
        .map(|a| a.rsplit(['#', '/']).next().unwrap_or(a).to_string());
    let text = |l: &str| {
        root.descendants(l)
            .first()
            .and_then(|e| e.text_opt())
            .map(|s| truncate(&s, 512))
    };
    Some(Signature {
        kind: SignatureKind::Ooxml,
        source: source.to_string(),
        signer: certs.first().and_then(|c| cert_info(c)),
        certificates: certs.len() as u32,
        signing_time,
        timestamp,
        digest_algorithm,
        sub_filter: None,
        name: None,
        reason: text("SignatureComments"),
        location: text("City").or_else(|| text("CountryName")),
        contact: text("ClaimedRole"),
        byte_range: Vec::new(),
        bytes_after: None,
        modified_after_signing: false,
        digest_valid: None,
    })
}

/// Adds signer people, e-mails and organizations to the document metadata.
pub(crate) fn apply_signers(meta: &mut foca_core::Metadata, source: &str) {
    let signers: Vec<_> = meta
        .signatures
        .iter()
        .filter_map(|s| s.signer.clone())
        .collect();
    for c in signers {
        if let Some(n) = c.common_name.as_deref() {
            meta.add_person(n, foca_core::PersonRole::Other, source);
        }
        if let Some(e) = c.email.as_deref() {
            foca_core::Metadata::add_unique(&mut meta.emails, e);
        }
        if meta.company.is_none() {
            meta.company = c.organization.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_reader_bounds() {
        assert!(read_tlv(&[], 0).is_none());
        assert!(read_tlv(&[0x30], 0).is_none());
        assert!(read_tlv(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF], 0).is_none());
        assert!(read_tlv(&[0x30, 0x85, 1, 1, 1, 1, 1], 0).is_none());
        // indefinite length with nested EOC
        let (t, rest) = read_tlv(&[0x30, 0x80, 0x04, 0x01, 0xAA, 0, 0, 0x05], 0).unwrap();
        assert_eq!(t.children().len(), 1);
        assert_eq!(rest, &[0x05]);
        // runaway nested indefinite lengths do not overflow the stack
        let deep: Vec<u8> = std::iter::repeat_n([0x30u8, 0x80], 10_000)
            .flatten()
            .collect();
        assert!(read_tlv(&deep, 0).is_none());
        assert_eq!(
            oid_str(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]).as_deref(),
            Some(OID_SIGNED_DATA)
        );
        assert!(parse_cms(b"\x30\x03\x06\x01\x00").is_none());
        assert!(find_cms(&[0u8; 64]).is_none());
    }

    #[test]
    fn times() {
        assert_eq!(iso_from_unix(0).as_deref(), Some("1970-01-01T00:00:00Z"));
        assert_eq!(
            iso_from_unix(1_709_287_200).as_deref(),
            Some("2024-03-01T10:00:00Z")
        );
        let t = Tlv {
            tag: 0x17,
            body: b"240301100000Z",
            raw: b"",
        };
        assert_eq!(der_time(&t).as_deref(), Some("2024-03-01T10:00:00Z"));
        assert_eq!(base64("SGVs bG8=").as_deref(), Some(&b"Hello"[..]));
    }
}
