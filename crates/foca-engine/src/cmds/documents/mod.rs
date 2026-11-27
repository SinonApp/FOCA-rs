//! Document and secret commands: files, deletion, local import, secret reveal and breach checks.

pub(crate) mod reextract;

use std::sync::Arc;
use std::time::Duration;

use foca_core::{DocStatus, Scope};
use foca_search::store::StoreSink;
use foca_store::{AddDoc, ProjectDb};
use serde_json::{json, Value};

use crate::analysis::facts::{self};
use crate::dto::evidence_secrets;
use crate::engine::lock;
use crate::util::{self, arg_ids};
use crate::{CmdError, CmdResult, Engine};

impl Engine {
    /// `doc_file { project, id }` returns `{ path, name, size }`, the document file in project storage
    /// (for Share and Save to files: the bridge only accepts files from the data directory).
    pub(crate) fn doc_file(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let n = util::arg_u64(a, "id").ok_or_else(|| CmdError::new("bad_args", "нет id"))?;
        let db = self.db(&id)?;
        let docs = lock(&db).documents(true)?;
        let d = docs
            .into_iter()
            .find(|d| d.doc.id == n)
            .ok_or_else(|| CmdError::not_found(format!("Документ {n} не найден")))?;
        let path = crate::cmds::documents::reextract::resolve_local(
            &self.inner.cfg.data_dir,
            &id,
            d.local_path.as_deref(),
        )
        .map(|p| p.to_string_lossy().into_owned())
        .ok_or_else(|| CmdError::not_found("Файл документа ещё не скачан"))?;
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Ok(json!({ "path": path, "name": d.doc.name, "size": size }))
    }

    pub(crate) fn doc_delete(&self, a: &Value, delete: bool) -> CmdResult {
        let id = self.project_arg(a)?;
        let ids = arg_ids(a, "ids");
        let db = self.db(&id)?;
        let db = lock(&db);
        let n = if delete {
            db.delete_documents(&ids)?
        } else {
            db.restore_documents(&ids)?
        };
        // derived entities are rebuilt from the remaining documents
        if n > 0 {
            crate::analysis::insights::reanalyze(&db, None)?;
        }
        Ok(if delete {
            json!({ "deleted": n })
        } else {
            json!({ "restored": n })
        })
    }

    fn resolve_secret_value(db: &ProjectDb, raw: &Value) -> Result<(Value, String), CmdError> {
        if let Some(s) = raw.as_str().filter(|s| s.starts_with('f')) {
            let (f, k) = s[1..]
                .split_once(':')
                .and_then(|(f, k)| Some((f.parse::<u64>().ok()?, k.parse::<usize>().ok()?)))
                .ok_or_else(|| CmdError::not_found(format!("Секрет {s} не найден")))?;
            let map = facts::assign_fids(db)?;
            let h = map
                .hash_of(f)
                .ok_or_else(|| CmdError::not_found(format!("Секрет {s} не найден")))?;
            let ev = crate::dto::protect_evidence(
                &db.finding(h)?.evidence,
                &crate::settings::secret_values(db),
            );
            let v = evidence_secrets(&ev)
                .into_iter()
                .nth(k)
                .ok_or_else(|| CmdError::not_found(format!("Секрет {s} не найден")))?;
            return Ok((json!(s), v));
        }
        let n = raw
            .as_u64()
            .or_else(|| raw.as_str().and_then(|s| s.parse().ok()))
            .ok_or_else(|| CmdError::new("bad_args", "нет id"))?;
        let list = db.entity("secrets")?;
        let x = list
            .as_array()
            .and_then(|l| l.iter().find(|x| x["id"].as_u64() == Some(n)))
            .ok_or_else(|| CmdError::not_found(format!("Секрет {n} не найден")))?;
        let val = x["value"].as_str().unwrap_or("").to_string();
        Ok((json!(n), val))
    }

    pub(crate) fn secret_reveal(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let db = self.db(&id)?;
        let db = lock(&db);
        let raw = a.get("id").cloned().unwrap_or(Value::Null);
        let (rid, val) = Self::resolve_secret_value(&db, &raw)?;
        Ok(json!({ "id": rid, "value": val }))
    }

    /// `secret_hibp_check { project, id }`: opt-in check of a stored secret against
    /// HIBP Pwned Passwords (sends only 5-char SHA-1 prefix; logs to `request_log`).
    pub(crate) async fn secret_hibp_check(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let db = self.db(&id)?;
        let raw = a.get("id").cloned().unwrap_or(Value::Null);
        let (rid, val) = {
            let db_g = lock(&db);
            Self::resolve_secret_value(&db_g, &raw)?
        };
        let sink = Arc::new(StoreSink { db, scan_id: None });
        let net = self.net_client(Scope::default(), sink)?;
        let base = self
            .inner
            .cfg
            .endpoints
            .sources
            .get("hibp")
            .map(String::as_str);
        let res = foca_net::hibp::check_pwned_password(&net, &val, base, Duration::from_secs(10))
            .await
            .map_err(|e| CmdError::new("net", e.to_string()))?;
        Ok(json!({
            "id": rid,
            "pwned": res.pwned,
            "count": res.count,
            "prefix": res.prefix,
        }))
    }

    /// Imports local files into a project without network access: copy to storage, metadata, analysis.
    /// An extra command outside the contract table, `doc_import { project, paths }` (CLI, tests, Open file).
    pub(crate) async fn doc_import(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let paths: Vec<String> = a
            .get("paths")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let ids = self.import_files(&id, &paths).await?;
        Ok(json!({ "imported": ids.len(), "ids": ids }))
    }

    pub async fn import_files(
        &self,
        project: &str,
        paths: &[String],
    ) -> Result<Vec<u64>, CmdError> {
        let db = self.db(project)?;
        let dir = self
            .inner
            .cfg
            .data_dir
            .join("files")
            .join(project)
            .join("files");
        std::fs::create_dir_all(&dir)?;
        let ocr_cfg = crate::services::ocr::OcrSettings::from_settings(
            &self.store().settings_get().unwrap_or_default(),
        );
        let ocr_prov = self.current_ocr();
        let max_file = foca_meta::Limits::default().max_file;
        let mut out = Vec::new();
        for p in paths {
            let meta = std::fs::metadata(p)?;
            if meta.len() > max_file {
                return Err(CmdError::new(
                    "too_large",
                    format!(
                        "Файл слишком велик ({} байт, лимит {} байт)",
                        meta.len(),
                        max_file
                    ),
                ));
            }
            let bytes = std::fs::read(p)?;
            let sha = util::hex(&util::sha256(&bytes));
            let name = std::path::Path::new(p)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".into());
            let ext = name
                .rsplit_once('.')
                .map(|x| x.1.to_lowercase())
                .unwrap_or_default();
            let dst = dir.join(format!("{sha}.{ext}"));
            std::fs::write(&dst, &bytes)?;
            let added = lock(&db).add_document(&AddDoc {
                url: None,
                name: name.clone(),
                source: "local".into(),
                status: DocStatus::Downloaded,
                size: bytes.len() as u64,
                sha256: Some(sha),
                local_path: Some(dst.to_string_lossy().into_owned()),
                ..Default::default()
            })?;
            let ocr_c = ocr_cfg.clone();
            let ocr_p = ocr_prov.clone();
            let r = tokio::task::spawn_blocking(move || {
                crate::util::catch_panic(|| {
                    let lim = foca_meta::Limits::default();
                    let m =
                        foca_meta::extract(&bytes, Some(&name), &lim).map_err(|e| e.to_string())?;
                    let mut t = foca_meta::text(&bytes, &lim).ok();
                    if let Some(ot) = crate::services::ocr::maybe_ocr(
                        &ocr_c,
                        ocr_p.as_deref(),
                        &dst,
                        &name,
                        &bytes,
                        t.as_deref(),
                    ) {
                        t = Some(ot);
                    }
                    Ok::<_, String>((m, t))
                })
            })
            .await
            .map_err(CmdError::internal)?;
            let d = lock(&db);
            match r {
                Ok((m, t)) => d.set_analyzed(added.id, &m, t.as_deref())?,
                Err(e) => d.set_doc_error(added.id, &e)?,
            }
            out.push(added.id);
        }
        crate::analysis::insights::reanalyze(&lock(&db), None)?;
        Ok(out)
    }
}
