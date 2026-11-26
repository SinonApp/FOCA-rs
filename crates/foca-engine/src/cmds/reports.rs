//! Report and export commands: building, listing, verifying and deleting reports, the
//! analytics views shown with them, and exports.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::analysis::facts::{self};
use crate::engine::{lock, safe_report_leaf};
use crate::services::ai::{AI_SUMMARY_DATA_KEY, AI_SUMMARY_KEY};
use crate::services::ai_text::{client_and_domain, unredact_client};
use crate::util::{self, arg_str};
use crate::{CmdError, CmdResult, Engine};

/// Template ids accepted by `report_build.template` (see `report_templates`).
pub(crate) const REPORT_TEMPLATES: [&str; 4] = ["full", "executive", "compliance", "lab"];

fn sidecar_path(report_path: &std::path::Path, suffix: &str) -> PathBuf {
    let mut os = report_path.as_os_str().to_os_string();
    os.push(".");
    os.push(suffix);
    PathBuf::from(os)
}

#[cfg(feature = "report")]
fn parse_sha256_sidecar(text: &str, expected_name: &str) -> Option<String> {
    foca_report::custody::parse_sha256_sidecar(text, Some(expected_name))
}

#[cfg(not(feature = "report"))]
fn parse_sha256_sidecar(text: &str, expected_name: &str) -> Option<String> {
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let hex = parts.next()?.trim();
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let name = parts.next().unwrap_or("").trim().trim_start_matches('*');
        if !name.is_empty() && name != expected_name {
            continue;
        }
        return Some(hex.to_ascii_lowercase());
    }
    None
}

#[cfg(feature = "report")]
fn canonical_custody_payload(custody_val: &Value) -> Vec<u8> {
    if let Ok(rec) =
        serde_json::from_value::<foca_report::custody::CustodyRecord>(custody_val.clone())
    {
        return foca_report::custody::sign_payload(&rec);
    }
    serde_json::to_vec(custody_val).unwrap_or_default()
}

#[cfg(not(feature = "report"))]
fn canonical_custody_payload(custody_val: &Value) -> Vec<u8> {
    serde_json::to_vec(custody_val).unwrap_or_default()
}

impl Engine {
    fn builder(&self) -> Result<Arc<dyn crate::ReportBuilder>, CmdError> {
        lock(&self.inner.reports)
            .clone()
            .ok_or_else(|| CmdError::new("unavailable", "Сборщик отчётов не подключён"))
    }

    pub(crate) fn report_list(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let db = self.db(&id)?;
        let r = lock(&db).reports()?;
        let mut v = serde_json::to_value(r)?;
        self.add_report_paths(&id, &mut v);
        Ok(v)
    }

    /// `insights_get { project, layers?, min_group? }`: org chart, lineage, anomalies, KEV,
    /// internal network map, clustered graph view, chronology by year and the 7×24 activity.
    pub(crate) fn insights_get(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let db = self.db(&id)?;
        let db = lock(&db);
        let c = crate::analysis::insights::compute(&db, self.now())?;
        Ok(crate::analysis::insights::view(&c, a))
    }

    /// `chain_get { project, from_id | node, limit? }`: readable paths from a finding (its
    /// document, computer, person or host) or a graph node to the infrastructure.
    pub(crate) fn chain_get(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let db = self.db(&id)?;
        let db = lock(&db);
        let start = match arg_str(a, "node").filter(|s| !s.is_empty()) {
            Some(n) => n.to_string(),
            None => {
                let seq = util::arg_u64(a, "from_id")
                    .or_else(|| util::arg_u64(a, "id"))
                    .ok_or_else(|| CmdError::new("bad_args", "нет from_id или node"))?;
                let map = facts::assign_fids(&db)?;
                let h = map
                    .hash_of(seq)
                    .ok_or_else(|| CmdError::not_found(format!("Находка {seq} не найдена")))?;
                let f = db
                    .findings()?
                    .into_iter()
                    .find(|f| f.id == h)
                    .ok_or_else(|| CmdError::not_found(format!("Находка {seq} не найдена")))?;
                foca_analysis::chain::start_of(&f).ok_or_else(|| {
                    CmdError::not_found("У находки нет документа, компьютера, человека или хоста")
                })?
            }
        };
        let limit = util::arg_u64(a, "limit").unwrap_or(3) as usize;
        let c = crate::analysis::insights::compute(&db, self.now())?;
        Ok(crate::analysis::insights::chains(&c, &start, limit))
    }

    /// `attack_paths_get { project }` → ranked compromise chains and remediation choke points.
    pub(crate) fn attack_paths_get(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let db = self.db(&id)?;
        let db = lock(&db);
        let c = crate::analysis::insights::compute(&db, self.now())?;
        let rep = crate::analysis::insights::attack_paths_report(&c);
        serde_json::to_value(rep).map_err(Into::into)
    }

    pub(crate) fn report_build(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let b = self.builder()?;
        let (snap, _) = self.core_snapshot(&id)?;
        let db = self.db(&id)?;
        let log = lock(&db).requests(None, false)?;
        let mut want_custody = a.get("custody").and_then(Value::as_bool).unwrap_or(false);
        let mut opts = a.get("opts").cloned().unwrap_or(json!({}));
        if let Some(o) = opts.as_object_mut() {
            o.remove("size");
            o.remove("now");
            if let Some(c) = o.get("custody").and_then(Value::as_bool) {
                want_custody = c;
            } else if want_custody {
                o.insert("custody".into(), json!(true));
            }
            // `template` (top level, optional) wins over `opts.tpl_id`/`opts.tpl`.
            if let Some(t) = arg_str(a, "template").filter(|t| !t.is_empty()) {
                if !REPORT_TEMPLATES.contains(&t) {
                    return Err(CmdError::new(
                        "bad_args",
                        format!("неизвестный шаблон отчёта: {t}"),
                    ));
                }
                o.insert("template".into(), json!(t));
            }
            let explicit_lang = o
                .get("lang")
                .and_then(Value::as_str)
                .and_then(foca_core::Lang::parse);
            if explicit_lang.is_none() {
                o.insert("lang".into(), json!(self.ui_lang().ui()));
            }
        }
        // The executor (header/cover) defaults to the name saved in Settings → Report; nothing is
        // hard-coded, an empty name stays empty.
        if let Some(o) = opts.as_object_mut() {
            let given = o
                .get("company")
                .and_then(Value::as_str)
                .is_some_and(|c| !c.trim().is_empty());
            if !given {
                let st = self.store().settings_get().unwrap_or_default();
                if let Some(c) = st["report"]["company"]
                    .as_str()
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                {
                    o.insert("company".into(), json!(c));
                }
            }
        }
        if let Some(o) = opts.as_object_mut() {
            if !o.contains_key(AI_SUMMARY_DATA_KEY) {
                if let Some(mut sum) = lock(&db).setting(AI_SUMMARY_KEY)?.filter(|v| !v.is_null()) {
                    // The provider saw [CLIENT]/[CLIENT-DOMAIN]; the report names the client.
                    let (client, dom) = client_and_domain(&snap);
                    if let Some(t) = sum["text"].as_str() {
                        sum["text"] = json!(unredact_client(t, &client, &dom));
                    }
                    o.insert(AI_SUMMARY_DATA_KEY.into(), sum);
                }
            }
        }
        let vis = self.report_visuals(&id, &snap);
        let built = b.build_report(&snap, &log, &vis, &opts, self.now())?;
        let dir = self.inner.cfg.data_dir.join("reports").join(&id);
        std::fs::create_dir_all(&dir)?;
        let report_path = dir.join(&built.file_name);
        std::fs::write(&report_path, &built.bytes)?;
        self.write_report_sidecars(&report_path, &built, want_custody)?;
        let mut rec: foca_core::api::Report = serde_json::from_value(built.record)?;
        rec.created_at = self.now_iso();
        let saved = lock(&db).report_add(&rec)?;
        let mut v = json!([serde_json::to_value(saved)?]);
        self.add_report_paths(&id, &mut v);
        Ok(v[0].take())
    }

    /// `report_templates { lang? }`: `[{ id, title, description }]` in the UI language (`lang`
    /// argument, else the effective UI language from `ui_lang`).
    #[cfg(feature = "report")]
    pub(crate) fn report_templates(&self, a: &Value) -> CmdResult {
        let lang = arg_str(a, "lang")
            .and_then(foca_core::Lang::parse)
            .unwrap_or_else(|| self.ui_lang());
        Ok(foca_report::report_templates(lang))
    }

    #[cfg(not(feature = "report"))]
    pub(crate) fn report_templates(&self, _a: &Value) -> CmdResult {
        Err(CmdError::new("unavailable", "Сборщик отчётов не подключён"))
    }

    /// Report diagrams (`foca_report::Visuals` as JSON); `null` without data or on error (the
    /// report is still built, just without the diagram sections).
    #[cfg(feature = "report")]
    fn report_visuals(&self, id: &str, snap: &foca_core::api::Snapshot) -> Value {
        let Ok(db) = self.db(id) else {
            return Value::Null;
        };
        let db = lock(&db);
        match crate::analysis::insights::compute(&db, self.now()) {
            Ok(c) => {
                let v = crate::analysis::insights::visuals(&c, &snap.findings);
                if v.is_empty() {
                    Value::Null
                } else {
                    serde_json::to_value(v).unwrap_or(Value::Null)
                }
            }
            Err(_) => Value::Null,
        }
    }

    #[cfg(not(feature = "report"))]
    fn report_visuals(&self, _id: &str, _snap: &foca_core::api::Snapshot) -> Value {
        Value::Null
    }

    pub(crate) fn report_delete(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let rid = util::arg_u64(a, "id").ok_or_else(|| CmdError::new("bad_args", "нет id"))?;
        let db = self.db(&id)?;
        let db = lock(&db);
        if let Some(r) = db.reports()?.into_iter().find(|r| r.id == rid) {
            if safe_report_leaf(&r.name).is_none() {
                return Err(CmdError::new("bad_args", "Недопустимое имя файла отчёта"));
            }
            let p = self.report_file(&id, &r.name);
            let _ = std::fs::remove_file(&p);
            let _ = std::fs::remove_file(sidecar_path(&p, "sha256"));
            let _ = std::fs::remove_file(sidecar_path(&p, "sig.json"));
        }
        Ok(json!({ "ok": db.report_delete(rid)? }))
    }

    fn write_report_sidecars(
        &self,
        report_path: &std::path::Path,
        built: &crate::BuiltReport,
        want_custody: bool,
    ) -> Result<(), CmdError> {
        let actual_hex = util::hex(&util::sha256(&built.bytes));
        let clean_name: String = built
            .file_name
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        std::fs::write(
            sidecar_path(report_path, "sha256"),
            format!("{actual_hex}  {clean_name}\n"),
        )?;
        let signer = self.current_signer();
        if want_custody || signer.is_some() {
            let custody_val = built.custody.clone().unwrap_or_else(|| {
                json!({
                    "schema": "foca-custody/v1",
                    "report_file": built.file_name,
                    "report_sha256": actual_hex,
                })
            });
            let payload = if !built.custody_payload.is_empty() {
                built.custody_payload.clone()
            } else {
                serde_json::to_vec(&custody_val).unwrap_or_default()
            };
            let payload_sha256 = util::hex(&util::sha256(&payload));
            let signature = signer.as_ref().and_then(|s| match s.sign(&payload) {
                Ok(sig) => Some(sig),
                Err(e) => {
                    tracing::warn!(target: "foca::engine", "подпись отчёта: {e}");
                    None
                }
            });
            let mut manifest = json!({
                "schema": "foca-custody-manifest/v1",
                "payload_sha256": payload_sha256,
                "custody": custody_val,
            });
            if let Some(sig) = signature {
                manifest["signature"] = serde_json::to_value(sig)?;
            }
            let bytes = serde_json::to_vec_pretty(&manifest)?;
            std::fs::write(sidecar_path(report_path, "sig.json"), bytes)?;
        }
        Ok(())
    }

    /// `report_verify { project, id | name }`: checks report `.sha256` sidecar and `.sig.json`
    /// signature/custody manifest integrity.
    pub(crate) fn report_verify(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let rid = util::arg_u64(a, "id");
        let name = arg_str(a, "name").filter(|s| !s.is_empty());
        if rid.is_none() && name.is_none() {
            return Err(CmdError::new("bad_args", "нужен id или name отчёта"));
        }
        let db = self.db(&id)?;
        let reports = lock(&db).reports()?;
        let r = reports
            .into_iter()
            .find(|r| rid.is_some_and(|x| r.id == x) || name.is_some_and(|n| r.name == n))
            .ok_or_else(|| CmdError::not_found("Отчёт не найден"))?;
        if safe_report_leaf(&r.name).is_none() {
            return Err(CmdError::new("bad_args", "Недопустимое имя файла отчёта"));
        }
        let path = self.report_file(&id, &r.name);
        if !path.exists() {
            return Ok(json!({
                "ok": false,
                "id": r.id,
                "name": r.name,
                "exists": false,
                "actual_sha256": Value::Null,
                "expected_sha256": Value::Null,
                "hash_match": false,
                "sidecar_present": false,
                "sig_present": false,
                "signature_alg": Value::Null,
                "signature_valid": Value::Null,
                "key_alias": Value::Null,
                "key_fingerprint": Value::Null,
                "signature_own_key": Value::Null,
                "custody": Value::Null,
                "status": "missing",
            }));
        }
        let bytes = std::fs::read(&path)?;
        let actual_sha256 = util::hex(&util::sha256(&bytes));

        let sha_path = sidecar_path(&path, "sha256");
        let sidecar_present = sha_path.exists();
        let sidecar_hex = if sidecar_present {
            std::fs::read_to_string(&sha_path)
                .ok()
                .and_then(|t| parse_sha256_sidecar(&t, &r.name))
        } else {
            None
        };

        let sig_path = sidecar_path(&path, "sig.json");
        let sig_present = sig_path.exists();
        let mut manifest_report_hex: Option<String> = None;
        let mut manifest_payload_ok = false;
        let mut custody_val = Value::Null;
        let mut sig_alg: Option<String> = None;
        let mut key_alias: Option<String> = None;
        let mut sig_valid: Option<bool> = None;
        let mut own_key: Option<bool> = None;
        let mut key_fingerprint: Option<String> = None;

        if sig_present {
            if let Ok(raw) = std::fs::read(&sig_path) {
                if let Ok(v) = serde_json::from_slice::<Value>(&raw) {
                    custody_val = v.get("custody").cloned().unwrap_or(Value::Null);
                    manifest_report_hex = custody_val
                        .get("report_sha256")
                        .and_then(Value::as_str)
                        .map(str::to_ascii_lowercase);
                    let claimed_payload_hex = v
                        .get("payload_sha256")
                        .and_then(Value::as_str)
                        .map(str::to_ascii_lowercase);
                    let canonical_payload = canonical_custody_payload(&custody_val);
                    let actual_payload_hex = util::hex(&util::sha256(&canonical_payload));
                    manifest_payload_ok = claimed_payload_hex
                        .as_deref()
                        .is_some_and(|h| h == actual_payload_hex);

                    if let Some(sig_v) = v.get("signature").filter(|s| !s.is_null()) {
                        if let Ok(sig) =
                            serde_json::from_value::<crate::ReportSignature>(sig_v.clone())
                        {
                            sig_alg = Some(sig.alg.clone());
                            key_alias = Some(sig.key_alias.clone());
                            key_fingerprint = foca_core::b64::decode(&sig.pubkey_b64)
                                .filter(|k| !k.is_empty())
                                .map(|k| util::hex(&util::sha256(&k)));
                            if !manifest_payload_ok {
                                sig_valid = Some(false);
                            } else if let Some(signer) = self.current_signer() {
                                // A report signed on another device carries that device's key: a
                                // valid signature under it is not tampering.
                                match signer.verify_detail(&canonical_payload, &sig) {
                                    Ok(c) => {
                                        sig_valid = Some(c.valid);
                                        own_key = Some(c.own_key);
                                    }
                                    Err(_) => sig_valid = Some(false),
                                }
                            }
                        } else {
                            sig_valid = Some(false);
                        }
                    }
                }
            }
        }

        let sidecar_ok = sidecar_hex.as_ref().map(|h| h == &actual_sha256);
        let manifest_ok = manifest_report_hex
            .as_ref()
            .map(|h| h == &actual_sha256 && manifest_payload_ok);
        let expected_sha256 = manifest_report_hex.or(sidecar_hex);

        let any_bad_sidecar = sidecar_present && sidecar_ok != Some(true);
        let any_bad_manifest = sig_present && manifest_ok != Some(true);
        let any_bad_sig = sig_valid == Some(false);
        let tampered = any_bad_sidecar || any_bad_manifest || any_bad_sig;

        let hash_match = !tampered && (sidecar_ok == Some(true) || manifest_ok == Some(true));
        let status = if tampered {
            "tampered"
        } else if hash_match && sig_alg.is_some() && sig_valid == Some(true) {
            if own_key == Some(false) {
                "verified_foreign"
            } else {
                "verified_signed"
            }
        } else if hash_match {
            "verified_hash"
        } else {
            "unsigned"
        };
        let ok = matches!(
            status,
            "verified_signed" | "verified_foreign" | "verified_hash"
        );

        Ok(json!({
            "ok": ok,
            "id": r.id,
            "name": r.name,
            "exists": true,
            "actual_sha256": actual_sha256,
            "expected_sha256": expected_sha256,
            "hash_match": hash_match,
            "sidecar_present": sidecar_present,
            "sig_present": sig_present,
            "signature_alg": sig_alg,
            "signature_valid": sig_valid,
            "key_alias": key_alias,
            "key_fingerprint": key_fingerprint,
            "signature_own_key": own_key,
            "custody": custody_val,
            "status": status,
        }))
    }

    pub(crate) fn export_build(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let b = self.builder()?;
        let (snap, _) = self.core_snapshot(&id)?;
        let db = self.db(&id)?;
        let log = lock(&db).requests(None, false)?;
        let kind = arg_str(a, "kind").unwrap_or("all");
        let fmt = arg_str(a, "fmt").unwrap_or("csv");
        let opts = a.get("opts").cloned().unwrap_or(json!({}));
        let x = b.export(&snap, &log, kind, fmt, &opts)?;
        let dir = &self.inner.cfg.export_dir;
        std::fs::create_dir_all(dir)?;
        let path = dir.join(&x.file_name);
        std::fs::write(&path, &x.bytes)?;
        // `path` is the real file path (private export directory); `saved_as` is where the file ends up after
        // Save to files (platform_save: MediaStore Download/FOCA-rs; the system may append " (1)")
        Ok(
            json!({ "name": x.file_name, "path": path.to_string_lossy(), "saved_as": format!("Download/FOCA-rs/{}", x.file_name),
            "size": crate::util::size_label(x.bytes.len()), "count": x.count, "secrets": x.secrets, "pii_redacted": x.pii_redacted }),
        )
    }

    pub(crate) fn wordlist_preview(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let kind = arg_str(a, "kind")
            .unwrap_or("logins")
            .trim()
            .to_ascii_lowercase();
        if !matches!(kind.as_str(), "logins" | "context") {
            return Err(CmdError::new("bad_args", format!("вид словаря {kind}")));
        }
        let limit = a
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(100)
            .clamp(1, 500) as usize;
        let opts = foca_analysis::wordlist::WordlistOptions {
            ad_domain: arg_str(a, "ad_domain")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from),
            include_service: a
                .get("include_service")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            lowercase: a.get("lowercase").and_then(Value::as_bool).unwrap_or(true),
            include_years: a
                .get("include_years")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            max_entries: 5000,
        };
        let (snap, _) = self.core_snapshot(&id)?;
        let (ad_domain, patterns, full) = if kind == "logins" {
            foca_analysis::wordlist::generate_logins(&snap, &opts)
        } else {
            let ad = foca_analysis::wordlist::infer_ad_domain(&snap);
            let ctx = foca_analysis::wordlist::generate_context(&snap, &opts);
            (ad, Vec::new(), ctx)
        };
        let total = full.len();
        let items: Vec<String> = full.into_iter().take(limit).collect();
        Ok(json!({
            "kind": kind,
            "count": items.len(),
            "total": total,
            "ad_domain": ad_domain,
            "patterns": patterns,
            "items": items,
        }))
    }
}
