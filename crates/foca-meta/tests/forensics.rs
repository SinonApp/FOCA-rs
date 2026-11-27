//! Document forensics on generated fixtures (`tests/fixtures/forensics/make_forensics.py`):
//! PDF/OOXML/VBA signatures with Ukrainian qualified certificate fields and RFC 3161 time
//! stamps, edits after signing, incremental revisions with a text diff, bad redactions, scans
//! without a text layer, image XObjects, hidden Word text, hidden Excel rows/columns, pivot
//! cache and connection metadata.

use std::path::Path;

use foca_core::SignatureKind;
use foca_meta::{extract, Limits, Metadata};

fn load(name: &str) -> Metadata {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/forensics")
        .join(name);
    let b = std::fs::read(&p).unwrap_or_else(|e| panic!("{name}: {e}"));
    extract(&b, Some(name), &Limits::default()).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn json(m: &Metadata) -> String {
    serde_json::to_string(m).unwrap()
}

#[test]
fn pdf_signature_kep_and_tsa() {
    let m = load("signed.pdf");
    assert_eq!(m.signatures.len(), 1, "{:?}", m.warnings);
    let s = &m.signatures[0];
    assert_eq!(s.kind, SignatureKind::Pdf);
    assert_eq!(s.sub_filter.as_deref(), Some("ETSI.CAdES.detached"));
    assert_eq!(s.digest_algorithm.as_deref(), Some("sha256"));
    assert_eq!(s.digest_valid, Some(true));
    assert!(!s.modified_after_signing);
    assert_eq!(s.bytes_after, Some(0));
    assert!(s.signing_time.is_some());
    assert_eq!(s.reason.as_deref(), Some("Approval"));
    assert_eq!(s.location.as_deref(), Some("Kyiv"));
    assert_eq!(s.certificates, 2);
    let c = s.signer.as_ref().expect("signer");
    assert_eq!(c.common_name.as_deref(), Some("Іван Петренко"));
    assert_eq!(c.organization.as_deref(), Some("ТОВ Приклад"));
    assert_eq!(c.org_unit.as_deref(), Some("Відділ ІТ"));
    assert_eq!(c.title.as_deref(), Some("Директор"));
    assert_eq!(c.locality.as_deref(), Some("Київ"));
    assert_eq!(c.email.as_deref(), Some("ivan.petrenko@example.com"));
    assert_eq!(c.edrpou.as_deref(), Some("12345678"));
    assert_eq!(c.rnokpp_masked.as_deref(), Some("********99"));
    assert_eq!(c.rnokpp_valid, Some(true));
    assert_eq!(c.issuer_cn.as_deref(), Some("Example Test QTSP CA"));
    assert!(c.not_before.is_some() && !c.serial.is_empty());
    let ts = s.timestamp.as_ref().expect("tsa");
    assert!(ts.gen_time.is_some());
    assert_eq!(ts.policy.as_deref(), Some("1.2.3.4.1"));
    assert!(ts.tsa.as_deref().unwrap_or("").contains("Example Test TSA"));
    // the personal tax number is never stored in full
    assert!(!json(&m).contains("1234567899"));
    assert!(m.person_names().contains(&"Іван Петренко"));
    assert!(m.emails.iter().any(|e| e == "ivan.petrenko@example.com"));
}

/// A PAdES-LTV increment after the signature (DSS with certificate and OCSP streams, an
/// updated catalog and Info dates) is not a modification; a rewritten page content stream is.
#[test]
fn ltv_increment_after_signing_is_not_a_modification() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/forensics/signed.pdf");
    let base = std::fs::read(p).unwrap();
    let base_m = extract(&base, Some("signed.pdf"), &Limits::default()).unwrap();
    assert!(!base_m.signatures[0].modified_after_signing);
    let text = String::from_utf8_lossy(&base);
    // the catalog of the signed file, rewritten with a DSS entry (keys reordered)
    let root = text
        .split("/Root")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .unwrap()
        .to_string();
    let cat_start = text.find(&format!("\n{root} 0 obj")).unwrap() + 1;
    let cat_body = &text[cat_start..];
    let cat_body = &cat_body[cat_body.find("<<").unwrap()..cat_body.find("endobj").unwrap()];
    let cat = cat_body.trim().trim_end_matches(">>").to_string();
    let dss = format!(
        "{root} 0 obj\n{cat} /DSS 900 0 R >>\nendobj\n900 0 obj\n<< /Type /DSS /Certs [ 901 0 R ] /OCSPs [ 902 0 R ] >>\nendobj\n901 0 obj\n<< /Length 4 >>\nstream\n0abc\nendstream\nendobj\n902 0 obj\n<< /Filter /FlateDecode /Length 3 >>\nstream\nxyz\nendstream\nendobj\n903 0 obj\n<< /CreationDate (D:20261005173046+03'00') /Producer () >>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Root {root} 0 R >>\nstartxref\n0\n%%EOF\n"
    );
    let mut ltv = base.clone();
    ltv.extend_from_slice(dss.as_bytes());
    let m = extract(&ltv, Some("ltv.pdf"), &Limits::default()).unwrap();
    let s = &m.signatures[0];
    assert!(s.bytes_after.unwrap() > 100);
    assert!(!s.modified_after_signing, "DSS-only increment flagged");
    // a content stream of a page rewritten after signing
    let contents = text
        .split("/Contents")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .unwrap()
        .to_string();
    let change = format!(
        "{contents} 0 obj\n<< /Length 22 >>\nstream\nBT (Changed text) Tj ET\nendstream\nendobj\nxref\n0 1\ntrailer\n<< /Root {root} 0 R >>\nstartxref\n0\n%%EOF\n"
    );
    let mut edited = ltv.clone();
    edited.extend_from_slice(change.as_bytes());
    let m = extract(&edited, Some("edited.pdf"), &Limits::default()).unwrap();
    assert!(
        m.signatures[0].modified_after_signing,
        "content change not flagged"
    );
}

#[test]
fn pdf_modified_after_signing() {
    let m = load("signed_modified.pdf");
    let s = &m.signatures[0];
    assert!(s.modified_after_signing);
    assert!(s.bytes_after.unwrap_or(0) > 100);
    // the signed bytes themselves are intact
    assert_eq!(s.digest_valid, Some(true));
    assert_eq!(m.pdf_revisions.len(), 2);
    assert_eq!(
        m.pdf_revisions[1].author.as_deref(),
        Some("Mallory Example")
    );
}

#[test]
fn pdf_document_timestamp() {
    let m = load("timestamp.pdf");
    let s = &m.signatures[0];
    assert_eq!(s.sub_filter.as_deref(), Some("ETSI.RFC3161"));
    assert!(s
        .timestamp
        .as_ref()
        .and_then(|t| t.gen_time.as_ref())
        .is_some());
    assert!(!s.modified_after_signing);
}

#[test]
fn pdf_revisions_and_diff() {
    let m = load("revisions.pdf");
    assert_eq!(m.incremental_updates, Some(1));
    let r = &m.pdf_revisions;
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].author.as_deref(), Some("John Doe"));
    assert_eq!(r[1].author.as_deref(), Some("Jane Roe"));
    assert_eq!(r[1].producer.as_deref(), Some("Other Producer 2.0"));
    assert!(r[1].modified.is_some());
    assert!(
        r[1].removed_text
            .iter()
            .any(|l| l.contains("Salary of Ivan Petrenko")),
        "{r:?}"
    );
    assert!(r[1].added_text.iter().any(|l| l.contains("Final version")));
    assert!(!r[1].removed_text.iter().any(|l| l.contains("Approved")));
}

#[test]
fn pdf_bad_redaction() {
    let m = load("redacted.pdf");
    let b = &m.bad_redactions;
    // The white box over the phone number is a background, not a redaction: only dark fills count.
    assert_eq!(b.len(), 2, "{b:?}");
    assert!(b
        .iter()
        .any(|x| x.page == 1 && x.fill == "black" && x.text.contains("AB123456")));
    assert!(!b.iter().any(|x| x.fill == "white"), "{b:?}");
    assert!(b.iter().any(|x| x.page == 2 && x.text.contains("secret")));
    assert!(!b.iter().any(|x| x.text.contains("Public statement")));
    assert!(!m.scan_without_text);
}

#[test]
fn pdf_scan_and_image_xobject() {
    let m = load("scan.pdf");
    assert!(m.scan_without_text);
    let img = m
        .embedded
        .iter()
        .find(|e| e.name.contains("image-5"))
        .expect("image XObject");
    assert!(img.metadata.gps.is_some());
    // text documents are not scans
    assert!(!load("revisions.pdf").scan_without_text);
}

#[test]
fn docx_hidden_text_xmldsig_and_vba() {
    let m = load("signed_hidden.docx");
    let h: Vec<_> = m
        .hidden_content
        .iter()
        .filter(|h| h.kind == "vanish")
        .collect();
    assert_eq!(h.len(), 1, "{h:?}");
    assert!(h[0].text.contains("budget 2M UAH"));
    let x = m
        .signatures
        .iter()
        .find(|s| s.kind == SignatureKind::Ooxml)
        .expect("xml signature");
    assert_eq!(x.source, "_xmlsignatures/sig1.xml");
    assert_eq!(
        x.signing_time.as_deref().map(|t| &t[..10]),
        Some("2024-03-01")
    );
    assert_eq!(x.reason.as_deref(), Some("Approved for release"));
    assert_eq!(x.contact.as_deref(), Some("Chief Accountant"));
    assert!(x
        .timestamp
        .as_ref()
        .and_then(|t| t.gen_time.as_ref())
        .is_some());
    let c = x.signer.as_ref().expect("signer");
    assert_eq!(c.common_name.as_deref(), Some("John Doe"));
    // legacy SubjectDirectoryAttributes profile
    assert_eq!(c.edrpou.as_deref(), Some("87654321"));
    assert_eq!(c.rnokpp_masked.as_deref(), Some("********99"));
    let v = m
        .signatures
        .iter()
        .find(|s| s.kind == SignatureKind::Vba)
        .expect("vba signature");
    assert_eq!(
        v.signer.as_ref().and_then(|c| c.common_name.as_deref()),
        Some("Іван Петренко")
    );
    assert!(!json(&m).contains("1234567899"));
}

#[test]
fn xlsx_hidden_cells_pivot_connections_charts() {
    let m = load("hidden.xlsx");
    let rows = m
        .hidden_content
        .iter()
        .find(|h| h.kind == "row")
        .expect("hidden rows");
    assert_eq!(rows.location, "Payroll!3:4");
    assert!(rows.text.contains("Ivan Petrenko") && rows.text.contains("Bonus fund"));
    let cols = m
        .hidden_content
        .iter()
        .find(|h| h.kind == "column")
        .expect("hidden columns");
    assert_eq!(cols.location, "Payroll!C:D");
    assert!(cols.text.contains("Salary") && cols.text.contains("5000"));
    assert_eq!(
        m.fields
            .get("xl:pivotCache1:refreshedBy")
            .map(String::as_str),
        Some("Ivan Petrenko")
    );
    assert!(m.person_names().contains(&"Ivan Petrenko"));
    assert_eq!(
        m.fields
            .get("xl:connection:srv-sql01 Payroll:user")
            .map(String::as_str),
        Some("svc_report")
    );
    assert!(m
        .servers
        .iter()
        .any(|s| s.name == "srv-sql01.corp.example.com"));
    assert!(m
        .fields
        .get("xl:connection:srv-sql01 Payroll:odcFile")
        .is_some_and(|v| v.contains("ipetrenko")));
    assert!(m
        .fields
        .iter()
        .any(|(k, v)| k.ends_with(":externalRef") && v.contains("[budget.xlsx]")));
}

#[test]
fn truncated_fixtures_never_panic() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/forensics");
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "py") {
            continue;
        }
        let b = std::fs::read(&p).unwrap();
        let step = (b.len() / 97).max(1);
        for cut in (0..b.len()).step_by(step) {
            let _ = extract(&b[..cut], None, &Limits::default());
        }
        let mut x = b.clone();
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..200 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let i = (seed as usize) % x.len().max(1);
            if let Some(c) = x.get_mut(i) {
                *c ^= (seed >> 32) as u8 | 1;
            }
            let _ = extract(&x, None, &Limits::default());
        }
    }
}
