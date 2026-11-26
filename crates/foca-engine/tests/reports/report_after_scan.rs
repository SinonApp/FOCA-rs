//! Reports built after a passive scan must include the findings. After a scan every finding is new,
//! so a report draft defaulting to `confirmed: true` produced an empty findings section. Both opts
//! sets are exercised here, as sent by `reports.js`.

use crate::common;
use serde_json::{json, Value};

fn html_of(rep: &Value) -> String {
    let p = rep["path"].as_str().expect("report_build → path");
    std::fs::read_to_string(p).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_after_passive_scan_has_findings_docs_people_hosts() {
    let e = common::env(0).await;
    let id = e.project("Отчёт после скана").await;
    e.passive_scan(&id).await;
    let s = e.snap(&id).await;
    let findings = s["findings"].as_array().unwrap();
    let docs = s["docs"].as_array().unwrap();
    let people = s["people"].as_array().unwrap();
    let hosts = s["hosts"].as_array().unwrap();
    assert!(!findings.is_empty() && !docs.is_empty() && !people.is_empty() && !hosts.is_empty());
    assert!(
        findings.iter().all(|f| f["status"] != "confirmed"),
        "findings are new after the scan"
    );

    let ui = |confirmed: bool, min_sev: &str| {
        json!({ "project": id, "opts": {
            "tpl": "Полный отчёт пентеста", "tpl_id": "full", "fmt": "html", "lang": "RU",
            "min_sev": min_sev, "confirmed": confirmed, "picked_only": false, "picked": [],
            "sections": { "summary": true, "scope": true, "findings": true, "fixed": true, "people": true,
                          "infra": true, "docs": true, "log": false, "appx": true },
            "secrets": "partial", "company": "ТОВ «Кібер Аудит»", "logo": true } })
    };
    // legacy UI defaults: confirmed only, which yields no findings
    let old = e.call("report_build", ui(true, "low")).await;
    assert_eq!(old["result"]["finding_ids"].as_array().unwrap().len(), 0);

    // current defaults: everything except false positives, any severity
    let rep = e.call("report_build", ui(false, "all")).await;
    let ids = rep["result"]["finding_ids"].as_array().unwrap();
    let live = findings
        .iter()
        .filter(|f| f["status"] != "false" && f["status"] != "fixed")
        .count();
    assert_eq!(ids.len(), live, "{rep}");
    let html = html_of(&rep);
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    let title = findings[0]["title"].as_str().unwrap();
    assert!(
        html.contains(&esc(title)),
        "finding '{title}' missing from the report"
    );
    let doc = docs[0]["name"].as_str().unwrap();
    assert!(
        html.contains(&esc(doc)),
        "document {doc} missing from the report"
    );
    let person = people[0]["name"].as_str().unwrap();
    assert!(
        html.contains(&esc(person)),
        "person {person} missing from the report"
    );
    let host = hosts[0]["name"].as_str().unwrap();
    assert!(html.contains(host), "host {host} missing from the report");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn finding_playbook_returns_contextual_remediation_without_secrets() {
    let e = common::env(0).await;
    let id = e.project("Playbook").await;
    e.passive_scan(&id).await;
    let s = e.snap(&id).await;
    let f = &s["findings"][0];
    let fid = f["id"].as_u64().unwrap();
    let pb = e
        .call(
            "finding_playbook",
            json!({ "project": id, "id": fid, "lang": "uk" }),
        )
        .await;
    assert_eq!(pb["id"], fid);
    assert_eq!(pb["lang"], "uk");
    assert!(!pb["title"].as_str().unwrap().is_empty());
    assert!(!pb["steps"].as_array().unwrap().is_empty());
    assert!(!pb["verify"].as_array().unwrap().is_empty());
    // clean step titles (the UI numbers them) and localized labels for the codes
    let step = &pb["steps"][0];
    assert_eq!(step["step"], 1);
    assert!(!step["title"]
        .as_str()
        .unwrap()
        .starts_with(|c: char| c.is_ascii_digit()));
    assert_ne!(pb["effort_label"], pb["effort"], "{pb}");
    assert!(!pb["key_label"].as_str().unwrap().is_empty());
    let pb_json = serde_json::to_string(&pb).unwrap();
    for sec in s["secrets"].as_array().unwrap() {
        let rev = e
            .call("secret_reveal", json!({ "project": id, "id": sec["id"] }))
            .await;
        let raw = rev["value"].as_str().unwrap_or("");
        if raw.len() >= 8 {
            assert!(!pb_json.contains(raw), "secret leaked into playbook");
        }
    }
}

/// With the language left at `auto` the core follows the device locale the UI reported, not
/// Russian: playbook, report templates and the report default language.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_language_follows_device_locale() {
    let e = common::env(0).await;
    let id = e.project("Auto lang").await;
    e.passive_scan(&id).await;
    e.call("settings_set", json!({ "patch": { "lang": "auto" } }))
        .await;
    let b = e
        .call("i18n_bundle", json!({ "device_locale": "uk-UA" }))
        .await;
    assert_eq!(b["lang"], "uk");
    let fid = e.snap(&id).await["findings"][0]["id"].as_u64().unwrap();
    let pb = e
        .call("finding_playbook", json!({ "project": id, "id": fid }))
        .await;
    assert_eq!(pb["lang"], "uk", "{pb}");
    let tpl = e.call("report_templates", json!({})).await;
    let uk = e.call("report_templates", json!({ "lang": "uk" })).await;
    assert_eq!(tpl, uk);
    let rep = e
        .call(
            "report_build",
            json!({ "project": id, "opts": { "tpl_id": "full", "fmt": "md", "confirmed": false, "min_sev": "all" } }),
        )
        .await;
    assert_eq!(rep["lang"], "UA", "{rep}");

    // an explicit choice wins over the device locale
    e.call("settings_set", json!({ "patch": { "lang": "en" } }))
        .await;
    let pb = e
        .call("finding_playbook", json!({ "project": id, "id": fid }))
        .await;
    assert_eq!(pb["lang"], "en");
}

struct MockEcSigner;

impl foca_engine::ReportSigner for MockEcSigner {
    fn sign(&self, payload: &[u8]) -> Result<foca_engine::ReportSignature, String> {
        let mut h = foca_report::custody::sha256_hex(payload);
        h.push_str(":mock-ecdsa");
        Ok(foca_engine::ReportSignature {
            alg: "ECDSA-P256-SHA256".into(),
            key_alias: "focars_report_sign_p256".into(),
            sig_b64: foca_core::b64::encode(h.as_bytes()),
            pubkey_b64: foca_core::b64::encode(b"MOCK-SPKI-P256"),
        })
    }

    fn verify(&self, payload: &[u8], sig: &foca_engine::ReportSignature) -> Result<bool, String> {
        let expected = self.sign(payload)?;
        Ok(sig.sig_b64 == expected.sig_b64 && sig.pubkey_b64 == expected.pubkey_b64)
    }
}

/// Signs like [`MockEcSigner`] but can pretend that this device's key changed (report from another phone).
struct SwitchableSigner(std::sync::atomic::AtomicBool);

impl foca_engine::ReportSigner for SwitchableSigner {
    fn sign(&self, payload: &[u8]) -> Result<foca_engine::ReportSignature, String> {
        MockEcSigner.sign(payload)
    }

    fn verify(&self, payload: &[u8], sig: &foca_engine::ReportSignature) -> Result<bool, String> {
        Ok(self.verify_detail(payload, sig)?.own_key)
    }

    fn verify_detail(
        &self,
        payload: &[u8],
        sig: &foca_engine::ReportSignature,
    ) -> Result<foca_engine::SignatureCheck, String> {
        let valid = MockEcSigner.verify(payload, sig)?;
        let foreign = self.0.load(std::sync::atomic::Ordering::SeqCst);
        Ok(foca_engine::SignatureCheck {
            valid,
            own_key: valid && !foreign,
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_signed_on_another_device_is_valid_but_foreign() {
    let dir = tempfile::tempdir().unwrap();
    let srv = common::server(0).await;
    let keys = std::sync::Arc::new(foca_engine::MemoryKeys::new());
    let signer = std::sync::Arc::new(SwitchableSigner(Default::default()));
    let s2 = signer.clone();
    let (engine, _events, _pa) = common::open_with(dir.path(), &srv.url(), keys, move |cfg| {
        cfg.signer = Some(s2);
    });
    let p = engine
        .invoke(
            "project_create",
            json!({ "name": "Foreign", "targets": ["example.test"] }),
        )
        .await
        .unwrap();
    let id = p["id"].as_str().unwrap().to_string();
    engine
        .invoke(
            "report_build",
            json!({ "project": id, "custody": true, "opts": { "tpl_id": "full", "fmt": "html", "lang": "EN" } }),
        )
        .await
        .unwrap();
    let list = engine
        .invoke("report_list", json!({ "project": id }))
        .await
        .unwrap();
    let rid = list[0]["id"].as_u64().unwrap();

    let own = engine
        .invoke("report_verify", json!({ "project": id, "id": rid }))
        .await
        .unwrap();
    assert_eq!(own["status"], "verified_signed", "{own}");
    assert_eq!(own["signature_own_key"], true);
    let fp = own["key_fingerprint"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(fp.len(), 64, "{own}");

    signer.0.store(true, std::sync::atomic::Ordering::SeqCst);
    let foreign = engine
        .invoke("report_verify", json!({ "project": id, "id": rid }))
        .await
        .unwrap();
    assert_eq!(foreign["status"], "verified_foreign", "{foreign}");
    assert_eq!(foreign["ok"], true);
    assert_eq!(foreign["signature_valid"], true);
    assert_eq!(foreign["signature_own_key"], false);
    assert_eq!(foreign["key_fingerprint"], fp.as_str());

    // A broken signature under the foreign key is still tampering.
    let rpath = list[0]["path"].as_str().unwrap().to_string();
    let sig_path = format!("{rpath}.sig.json");
    let mut sig: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sig_path).unwrap()).unwrap();
    sig["signature"]["sig_b64"] = json!(foca_core::b64::encode(b"forged"));
    std::fs::write(&sig_path, serde_json::to_vec(&sig).unwrap()).unwrap();
    let bad = engine
        .invoke("report_verify", json!({ "project": id, "id": rid }))
        .await
        .unwrap();
    assert_eq!(bad["status"], "tampered", "{bad}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_build_with_custody_and_signer_writes_sidecars_and_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let srv = common::server(0).await;
    let keys = std::sync::Arc::new(foca_engine::MemoryKeys::new());
    let (engine, _events, _pa) = common::open_with(dir.path(), &srv.url(), keys, |cfg| {
        cfg.signer = Some(std::sync::Arc::new(MockEcSigner));
    });
    let p = engine
        .invoke(
            "project_create",
            json!({ "name": "Custody", "client": "ТОВ Тест", "targets": ["example.test"] }),
        )
        .await
        .unwrap();
    let id = p["id"].as_str().unwrap().to_string();
    engine
        .invoke(
            "report_build",
            json!({ "project": id, "custody": true, "opts": { "tpl_id": "full", "fmt": "html", "lang": "UK" } }),
        )
        .await
        .unwrap();
    let list = engine
        .invoke("report_list", json!({ "project": id }))
        .await
        .unwrap();
    let rid = list[0]["id"].as_u64().unwrap();
    let rpath = list[0]["path"].as_str().unwrap().to_string();
    assert!(std::path::Path::new(&format!("{rpath}.sha256")).exists());
    assert!(std::path::Path::new(&format!("{rpath}.sig.json")).exists());
    let html = std::fs::read_to_string(&rpath).unwrap();
    assert!(html.contains("Ланцюг збереження (Chain of Custody)"));

    let v_ok = engine
        .invoke("report_verify", json!({ "project": id, "id": rid }))
        .await
        .unwrap();
    assert_eq!(v_ok["ok"], true, "{v_ok}");
    assert_eq!(v_ok["status"], "verified_signed");
    assert_eq!(v_ok["hash_match"], true);
    assert_eq!(v_ok["signature_valid"], true);
    assert_eq!(v_ok["signature_alg"], "ECDSA-P256-SHA256");

    // Tamper 1 byte of the report file and verify detection.
    let mut bytes = std::fs::read(&rpath).unwrap();
    bytes.push(b' ');
    std::fs::write(&rpath, bytes).unwrap();
    let v_bad = engine
        .invoke("report_verify", json!({ "project": id, "id": rid }))
        .await
        .unwrap();
    assert_eq!(v_bad["ok"], false);
    assert_eq!(v_bad["status"], "tampered");
    assert_eq!(v_bad["hash_match"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_build_docx_succeeds_and_verifies() {
    let e = common::env(0).await;
    let id = e.project("DOCX").await;
    e.passive_scan(&id).await;
    let rep = e
        .call(
            "report_build",
            json!({
                "project": id,
                "template": "executive",
                "custody": true,
                "opts": { "fmt": "docx", "lang": "UK", "company": "ТОВ Аудит" }
            }),
        )
        .await;
    assert_eq!(rep["fmt"], "docx");
    assert!(rep["name"].as_str().unwrap().ends_with(".docx"));
    let p = rep["path"].as_str().unwrap();
    let bytes = std::fs::read(p).unwrap();
    assert!(bytes.starts_with(b"PK"));
    let ver = e
        .call("report_verify", json!({ "project": id, "id": rep["id"] }))
        .await;
    assert_eq!(ver["ok"], true);
    assert_eq!(ver["status"], "verified_hash");
    assert_eq!(ver["custody"]["format"], "docx");

    // Exports via engine: STIX 2.1, Nuclei and httpx.
    let stix = e
        .call(
            "export_build",
            json!({ "project": id, "kind": "all", "fmt": "stix", "opts": { "pretty": true, "secrets": true } }),
        )
        .await;
    assert!(stix["name"].as_str().unwrap().contains("_stix_"));
    assert_eq!(stix["secrets"], false);
    let stix_json: Value =
        serde_json::from_slice(&std::fs::read(stix["path"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(stix_json["type"], "bundle");

    for fmt in ["nuclei", "httpx"] {
        let ex = e
            .call(
                "export_build",
                json!({ "project": id, "kind": "all", "fmt": fmt, "opts": {} }),
            )
            .await;
        assert!(ex["name"].as_str().unwrap().ends_with(".txt"));
        assert!(ex["count"].as_u64().unwrap() > 0);
    }
}
