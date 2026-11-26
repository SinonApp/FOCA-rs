//! Offline import of a ZIP with 20 corpus documents: no network
//! request at all, the expected forensic findings, full-text search with masked snippets, and
//! full personal data values never reaching the project database, reports or logs.

use crate::common::*;
use serde_json::{json, Value};

fn crc32(b: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &x in b {
        c ^= x as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xedb8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// Minimal stored (uncompressed) ZIP writer.
fn zip(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let off = out.len() as u32;
        let crc = crc32(data);
        let n = name.as_bytes();
        let mut h = Vec::new();
        h.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        h.extend_from_slice(&20u16.to_le_bytes());
        h.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
        h.extend_from_slice(&0u16.to_le_bytes()); // stored
        h.extend_from_slice(&0u32.to_le_bytes()); // time/date
        h.extend_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.extend_from_slice(&(n.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(n);
        out.extend_from_slice(data);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&h[4..]);
        central.extend_from_slice(&[0u8; 10]); // comment length, disk, internal and external attributes
        central.extend_from_slice(&off.to_le_bytes());
        central.extend_from_slice(n);
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

const DOCS: &[(&str, &str)] = &[
    ("forensics/redacted.pdf", "Звіт/redacted.pdf"),
    ("forensics/signed.pdf", "Звіт/signed.pdf"),
    ("forensics/signed_modified.pdf", "signed_modified.pdf"),
    ("forensics/hidden.xlsx", "hidden.xlsx"),
    ("forensics/revisions.pdf", "revisions.pdf"),
    ("forensics/scan.pdf", "скани/паспорт_скан.pdf"),
    ("forensics/personal.docx", "особові/довідка.docx"),
    ("lnk/network.lnk", "Звіт.lnk"),
    ("mail/budget.eml", "пошта/budget.eml"),
    ("mail/budget.msg", "пошта/budget.msg"),
    ("pim/meeting.ics", "meeting.ics"),
    ("pim/contacts.vcf", "contacts.vcf"),
    ("media/iphone.mov", "iphone.mov"),
    ("visio/network.vsdx", "network.vsdx"),
    ("legacy/network.vsd", "network.vsd"),
    ("legacy/leaflet.pub", "leaflet.pub"),
    ("legacy/annual.indd", "annual.indd"),
    ("ooxml/contract.docx", "contract.docx"),
    ("pdf/report.pdf", "report.pdf"),
    ("remote/SRV-TS01.rdp", "SRV-TS01.rdp"),
];

/// Full personal data values planted in the corpus (synthetic, valid check digits).
const RAW_PII: &[&str] = &[
    "3012345670",
    "4111 1111 1111 1111",
    "4111111111111111",
    "UA213223130000026007233566001",
    "АВ 123456",
    "TINUA-1234567899",
    "1234567899",
];

fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_zip_import_without_network() {
    let e = env(0).await;
    let mut files: Vec<(String, Vec<u8>)> = DOCS
        .iter()
        .map(|(src, name)| {
            (
                name.to_string(),
                std::fs::read(corpus_dir().join(src)).unwrap(),
            )
        })
        .collect();
    assert_eq!(files.len(), 20);
    // A hostile member name: stored by hash, shown as a label, flagged on the archive.
    files.push(("../../evil.txt".into(), b"owned".to_vec()));
    let archive = zip(&files);
    let zpath = e.dir.path().join("picked-archive.zip");
    std::fs::write(&zpath, &archive).unwrap();

    e.clear_events();
    let r = e
        .call(
            "import_offline",
            json!({ "name": "Офлайн-тест", "paths": [zpath.to_string_lossy()] }),
        )
        .await;
    let id = r["project"].as_str().unwrap().to_string();
    // 20 documents + the evil member + the archive itself.
    assert_eq!(r["imported"].as_u64().unwrap(), 22, "{r}");
    assert_eq!(r["cancelled"], false);
    // Progress events.
    let ev = e.events();
    assert!(ev
        .iter()
        .any(|x| x["type"] == "import" && x["stage"] == "done"));

    // Not a single network request: neither the test server nor the request journal saw one.
    assert!(e.server.requests().is_empty(), "{:?}", e.server.requests());
    let log = e
        .call("request_log_get", json!({ "project": id, "limit": 100 }))
        .await;
    assert_eq!(log.as_array().map(Vec::len).unwrap_or(0), 0, "{log}");

    // Expected findings.
    let s = e.snap(&id).await;
    let f = s["findings"].as_array().unwrap();
    let find = |rule: &str| -> Vec<&Value> {
        f.iter()
            .filter(|x| x["provenance"]["rule"] == rule)
            .collect()
    };
    let br = find("doc.bad_redaction");
    assert!(!br.is_empty() && br[0]["sev"] == "crit", "{br:?}");
    let kep = find("doc.signer_identity");
    assert!(
        kep.iter()
            .any(|x| x["evidence"].as_str().unwrap().contains("РНОКПП: ********")),
        "{kep:?}"
    );
    assert!(!find("doc.modified_after_signing").is_empty());
    assert!(!find("doc.lnk_host_mac").is_empty());
    assert!(!find("mail.internal_relay").is_empty());
    assert!(!find("doc.hidden_content").is_empty());
    assert!(!find("doc.pdf_removed_text").is_empty());
    let scan = find("doc.scan_without_text");
    assert!(scan.iter().any(|x| x["sev"] == "high"), "{scan:?}");
    assert!(!find("zip.path_traversal").is_empty());
    let pii = find("pii");
    for kind in ["РНОКПП", "карты", "IBAN"] {
        assert!(
            pii.iter()
                .any(|x| x["title"].as_str().unwrap().contains(kind)),
            "{kind}: {pii:?}"
        );
    }
    // Names from the archive are labels, never paths.
    let names: Vec<&str> = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"evil.txt") && names.contains(&"паспорт_скан.pdf"),
        "{names:?}"
    );
    assert!(!e.dir.path().join("evil.txt").exists());

    // Full-text search finds the phrase, the snippet hides the values.
    let q = e
        .call("docs_search", json!({ "project": id, "q": "Отримувач" }))
        .await;
    assert!(q["total"].as_u64().unwrap() >= 1, "{q}");
    let snip = q["hits"][0]["snippet"].as_str().unwrap();
    assert!(snip.contains("{{h:"), "{snip}");
    assert!(!snip.contains("3012345670"), "{snip}");

    // Forensic details of one document.
    let doc = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "signed.pdf")
        .unwrap()["id"]
        .clone();
    let g = e.call("doc_get", json!({ "project": id, "id": doc })).await;
    let sig = &g["forensics"]["signatures"][0]["signer"];
    assert!(
        sig["rnokpp_masked"]
            .as_str()
            .unwrap()
            .starts_with("********"),
        "{g}"
    );

    // Report (RU, HTML) is built offline.
    let rep = e
        .call(
            "report_build",
            json!({ "project": id, "opts": { "tpl_id": "full", "fmt": "html", "lang": "RU", "min_sev": "info" } }),
        )
        .await;
    let html = std::fs::read_to_string(rep["path"].as_str().unwrap()).unwrap();
    assert!(html.contains("Форензика документов"));
    assert!(e.server.requests().is_empty());

    // No full personal data value in the project database, reports or logs (the stored
    // original documents under files/ are the evidence itself and are excluded).
    let mut all = Vec::new();
    walk(e.dir.path(), &mut all);
    for p in all {
        let rel = p
            .strip_prefix(e.dir.path())
            .unwrap()
            .to_string_lossy()
            .to_string();
        if rel.starts_with("files") || rel.ends_with(".zip") || rel == "engine.lock" {
            continue;
        }
        let b = std::fs::read(&p).unwrap();
        for v in RAW_PII {
            let needle = v.as_bytes();
            assert!(
                !b.windows(needle.len()).any(|w| w == needle),
                "{v} leaked into {rel}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_import_limits_and_rules() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let files: Vec<Value> = (0..5)
        .map(|i| {
            json!({ "name": format!("../n{i}.txt"),
                    "data": foca_core::b64::encode(format!("Проект Альфа {i}: наказ № 12{i}").as_bytes()) })
        })
        .collect();
    let r = e
        .call(
            "import_offline",
            json!({ "project": id, "files": files, "max_files": 3 }),
        )
        .await;
    assert_eq!(r["imported"].as_u64().unwrap(), 3, "{r}");
    assert_eq!(r["skipped"][0]["reason"], "too_many_files");
    let docx = std::fs::read(corpus_dir().join("forensics/personal.docx")).unwrap();
    e.call(
        "import_offline",
        json!({ "project": id, "files": [{ "name": "довідка.docx", "data": foca_core::b64::encode(&docx) }] }),
    )
    .await;
    // User rule → findings on the next analysis.
    let set = e
        .call(
            "rules_set",
            json!({ "project": id, "config": { "presets": [], "rules": [{ "id": "alpha", "title": "Альфа", "pattern": "довідка\\s+про\\s+доходи", "sev": "warn", "enabled": true, "case_insensitive": true, "mask": false }] } }),
        )
        .await;
    assert_eq!(set["config"]["rules"][0]["id"], "alpha");
    let s = e.snap(&id).await;
    assert!(s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["provenance"]["rule"] == "doc.user_rule"));
    // A bad pattern is rejected with bad_args and nothing is stored.
    let err = e
        .err(
            "rules_set",
            json!({ "project": id, "config": { "rules": [{ "id": "x", "title": "x", "pattern": "(", "sev": "low", "enabled": true }] } }),
        )
        .await;
    assert_eq!(err.code, "bad_args");
    let t = e
        .call(
            "rules_test",
            json!({ "pattern": "\\d{3}", "text": "наказ № 120" }),
        )
        .await;
    assert_eq!(t["count"], 1);
    assert_eq!(
        t["hits"][0]["start"].as_u64().unwrap(),
        "наказ № ".len() as u64
    );
}

struct MockIpnOcr(std::sync::atomic::AtomicUsize);

impl foca_engine::OcrProvider for MockIpnOcr {
    fn recognize(&self, req: foca_engine::OcrRequest) -> Result<foca_engine::OcrResult, String> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(req.mime, "application/pdf");
        Ok(foca_engine::OcrResult {
            text: "Довідка працівника: Олександр Іваненко, код РНОКПП 3012345670, маркер OCR_MARKER_KYIV".into(),
            pages: 1,
            engine: "mlkit-mock".into(),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_ocr_disabled_by_default_and_detects_masked_ipn_without_network() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let keys = std::sync::Arc::new(foca_engine::MemoryKeys::new());
    let ocr = std::sync::Arc::new(MockIpnOcr(std::sync::atomic::AtomicUsize::new(0)));
    let ocr_ref = ocr.clone();
    let (engine, _events, _pa) = open_with(dir.path(), &srv.url(), keys, move |cfg| {
        cfg.ocr = Some(ocr_ref);
    });

    let scan_pdf = corpus_dir().join("forensics/scan.pdf");
    let scan_path = scan_pdf.to_string_lossy().to_string();

    // 1. Default settings: ocr.enabled is false -> provider is never called.
    let settings = engine.invoke("settings_get", json!({})).await.unwrap();
    assert_eq!(settings["ocr"]["enabled"], false);
    let r_off = engine
        .invoke(
            "import_offline",
            json!({ "name": "OCR-Off", "paths": [scan_path.clone()] }),
        )
        .await
        .unwrap();
    let p_off = r_off["project"].as_str().unwrap().to_string();
    assert_eq!(ocr.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    let snap_off = engine
        .invoke("project_snapshot", json!({ "id": p_off }))
        .await
        .unwrap();
    assert!(snap_off["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["provenance"]["rule"] != "pii"));

    // 2. Enable offline OCR via settings_set -> scan.pdf is recognized, indexed in FTS5 and masked for PII.
    engine
        .invoke(
            "settings_set",
            json!({ "patch": { "ocr": { "enabled": true, "max_pages": 5, "max_mb": 10 } } }),
        )
        .await
        .unwrap();
    let r_on = engine
        .invoke(
            "import_offline",
            json!({ "name": "OCR-On", "paths": [scan_path] }),
        )
        .await
        .unwrap();
    let p_on = r_on["project"].as_str().unwrap().to_string();
    assert_eq!(ocr.0.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Zero network requests made during OCR import.
    assert!(srv.requests().is_empty());
    let req_log = engine
        .invoke("request_log_get", json!({ "project": p_on, "limit": 50 }))
        .await
        .unwrap();
    assert_eq!(req_log.as_array().unwrap().len(), 0);

    // FTS5 finds the OCR keyword, and PII snippet is masked.
    let fts = engine
        .invoke(
            "docs_search",
            json!({ "project": p_on, "q": "OCR_MARKER_KYIV" }),
        )
        .await
        .unwrap();
    assert_eq!(fts["total"], 1, "{fts}");
    let fts_str = serde_json::to_string(&fts).unwrap();
    assert!(
        !fts_str.contains("3012345670"),
        "raw IPN leaked in FTS: {fts_str}"
    );

    // PII finding for Ukrainian IPN (РНОКПП) is emitted and raw 3012345670 is masked everywhere.
    let snap_on = engine
        .invoke("project_snapshot", json!({ "id": p_on }))
        .await
        .unwrap();
    let has_ipn_finding = snap_on["findings"].as_array().unwrap().iter().any(|f| {
        f["provenance"]["rule"] == "pii" && f["title"].as_str().unwrap_or("").contains("РНОКПП")
    });
    assert!(has_ipn_finding, "expected РНОКПП PII finding from OCR text");
    let snap_str = serde_json::to_string(&snap_on).unwrap();
    assert!(
        !snap_str.contains("3012345670"),
        "raw IPN leaked in project snapshot"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_import_walks_folders_recursively() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("to-publish");
    std::fs::create_dir_all(root.join("sub/deeper")).unwrap();
    std::fs::write(root.join("a.txt"), "Наказ № 1").unwrap();
    std::fs::write(root.join("sub/b.txt"), "Наказ № 2").unwrap();
    std::fs::write(root.join("sub/deeper/c.txt"), "Наказ № 3").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&root, root.join("sub/loop")).unwrap();
    let r = e
        .call(
            "import_offline",
            json!({ "project": id, "paths": [root.to_string_lossy()] }),
        )
        .await;
    assert_eq!(r["imported"].as_u64().unwrap(), 3, "{r}");
    assert!(
        !r["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["reason"] == "not_a_file"),
        "{r}"
    );
}

/// A file that cannot be parsed ends in `error` with `error_kind: "parse"` and no HTTP status,
/// even when its error text mentions an HTTP code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_parse_failure_is_labelled_parse_error() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let broken = b"PK\x03\x04 not a real archive: HTTP 404".to_vec();
    let r = e
        .call(
            "import_offline",
            json!({ "project": id, "files": [{ "name": "broken.docx", "data": foca_core::b64::encode(&broken) }] }),
        )
        .await;
    assert_eq!(r["errors"].as_array().map(Vec::len), Some(1), "{r}");
    let s = e.snap(&id).await;
    let d = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "broken.docx")
        .unwrap()
        .clone();
    assert_eq!(d["status"], "error", "{d}");
    assert_eq!(d["error_kind"], "parse", "{d}");
    assert!(d.get("http_status").is_none(), "{d}");
    assert!(d["error_reason"].is_string(), "{d}");
}
