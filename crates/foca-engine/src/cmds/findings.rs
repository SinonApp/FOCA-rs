//! Finding commands: status, edits, photos and playbooks.

use std::path::PathBuf;

use foca_core::api::Photo;
use foca_core::FindingStatus;
use foca_store::FindingPatch;
use serde_json::{json, Value};

use crate::analysis::facts::{self, FidMap};
use crate::engine::lock;
use crate::util::{self, arg_str, req_str};
use crate::{CmdError, CmdResult, Engine};

fn fstatus(s: &str) -> Result<FindingStatus, CmdError> {
    if !["new", "confirmed", "false", "accepted", "fixed"].contains(&s) {
        return Err(CmdError::new("bad_status", s));
    }
    s.parse()
        .map_err(|e: String| CmdError::new("bad_status", e))
}

fn photo_time(t: time::OffsetDateTime) -> String {
    format!(
        "{:02}.{:02}, {:02}:{:02}",
        t.day(),
        u8::from(t.month()),
        t.hour(),
        t.minute()
    )
}

impl Engine {
    fn finding_hash(
        &self,
        db: &foca_store::ProjectDb,
        a: &Value,
    ) -> Result<(u64, FidMap), CmdError> {
        let seq = util::arg_u64(a, "id").ok_or_else(|| CmdError::new("bad_args", "нет id"))?;
        let map = facts::assign_fids(db)?;
        let h = map
            .hash_of(seq)
            .ok_or_else(|| CmdError::not_found(format!("Находка {seq} не найдена")))?;
        Ok((h, map))
    }

    fn finding_json(
        db: &foca_store::ProjectDb,
        map: &FidMap,
        f: &foca_core::api::Finding,
    ) -> CmdResult {
        let mut v = serde_json::to_value(f)?;
        let id = map.get(f.id);
        v["id"] = json!(id);
        let ev = crate::dto::protect_evidence(&f.evidence, &crate::settings::secret_values(db));
        v["evidence"] = json!(ev);
        v["standards"] = crate::dto::standards_json(&f.provenance.rule);
        Ok(v)
    }

    pub(crate) fn finding_set_status(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let st = fstatus(req_str(a, "status")?)?;
        let db = self.db(&id)?;
        let db = lock(&db);
        let (h, map) = self.finding_hash(&db, a)?;
        let f = db.finding_update(
            h,
            &FindingPatch {
                status: Some(st),
                ..Default::default()
            },
        )?;
        Self::finding_json(&db, &map, &f)
    }

    /// `finding_playbook { project, id, lang? }`: contextual remediation playbook for one finding.
    /// The full CVE list of a product version from the offline NVD table, one page at a time
    /// (`cve_list`, `docs/API.md`): `product` is `CveSummary.product` (CPE keys, comma
    /// separated), `version` its version, `until_year` the document-year limit of software seen
    /// in documents.
    pub(crate) fn cve_list(&self, a: &Value) -> CmdResult {
        let product = req_str(a, "product")?;
        let keys: Vec<String> = product
            .split(',')
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .map(str::to_string)
            .collect();
        let q = foca_analysis::cve::CveQuery {
            keys,
            version: arg_str(a, "version").map(str::to_string),
            until_year: a["until_year"].as_u64().and_then(|y| u16::try_from(y).ok()),
            ..Default::default()
        };
        let offset = a["offset"].as_u64().unwrap_or(0) as usize;
        let limit = a["limit"].as_u64().unwrap_or(50).clamp(1, 200) as usize;
        let page = foca_analysis::cve::db()
            .list_page(&q, offset, limit)
            .ok_or_else(|| CmdError::new("not_found", "продукт не найден в базе NVD"))?;
        Ok(json!(page))
    }

    pub(crate) fn finding_playbook(&self, a: &Value) -> CmdResult {
        let pid = self.project_arg(a)?;
        let lang = arg_str(a, "lang")
            .and_then(foca_core::Lang::parse)
            .unwrap_or_else(|| self.ui_lang())
            .code()
            .to_string();
        let db = self.db(&pid)?;
        let db = lock(&db);
        let (h, map) = self.finding_hash(&db, a)?;
        let f = db.finding(h)?;
        let docs = db.documents(true)?;
        let doc_names: Vec<String> = f
            .provenance
            .docs
            .iter()
            .filter_map(|did| docs.iter().find(|d| d.doc.id == *did))
            .map(|d| {
                if d.doc.name.is_empty() {
                    d.doc.url.clone().unwrap_or_default()
                } else {
                    d.doc.name.clone()
                }
            })
            .collect();
        let pb = foca_analysis::playbooks::for_finding(&f, &doc_names, &lang);
        let mut v = serde_json::to_value(pb)?;
        v["id"] = json!(map.get(f.id));
        v["host"] = json!(f.host);
        Ok(v)
    }

    pub(crate) fn finding_update(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let p = a.get("patch").cloned().unwrap_or(json!({}));
        if let Some(s) = p.get("status").and_then(Value::as_str) {
            fstatus(s)?;
        }
        let patch: FindingPatch = serde_json::from_value(p)?;
        let db = self.db(&id)?;
        let db = lock(&db);
        let (h, map) = self.finding_hash(&db, a)?;
        let f = db.finding_update(h, &patch)?;
        Self::finding_json(&db, &map, &f)
    }

    pub(crate) fn finding_photo_add(&self, a: &Value) -> CmdResult {
        let id = self.project_arg(a)?;
        let db = self.db(&id)?;
        let db = lock(&db);
        let (h, map) = self.finding_hash(&db, a)?;
        let mut photos = db.finding(h)?.photos;
        let now = self.now();
        let mut name = arg_str(a, "name").map(String::from).unwrap_or_else(|| {
            format!(
                "IMG_{:04}{:02}{:02}_{:02}{:02}.jpg",
                now.year(),
                u8::from(now.month()),
                now.day(),
                now.hour(),
                now.minute()
            )
        });
        // The file itself (picked photo or camera shot, copied to a private directory) goes to the
        // project storage at `<data>/files/<project>/photos/<name>`; `photos` holds the stored file name.
        if let Some(src) = arg_str(a, "path").filter(|p| !p.is_empty()) {
            let meta = std::fs::metadata(src)
                .map_err(|e| CmdError::new("bad_args", format!("фото {src}: {e}")))?;
            if !meta.is_file() || meta.len() > 25 * 1024 * 1024 {
                return Err(CmdError::new("bad_args", "фото: файл до 25 МБ"));
            }
            let dir = self.photo_dir(&id);
            std::fs::create_dir_all(&dir)?;
            let base: String = std::path::Path::new(&name)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "photo.jpg".into())
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || ".-_".contains(c) {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            let (stem, ext) = base.rsplit_once('.').unwrap_or((base.as_str(), "jpg"));
            let mut fname = base.clone();
            let mut k = 1;
            while dir.join(&fname).exists() {
                k += 1;
                fname = format!("{stem}_{k}.{ext}");
            }
            std::fs::copy(src, dir.join(&fname))?;
            name = fname;
        }
        photos.push(Photo {
            name,
            time: photo_time(now),
            from: arg_str(a, "from").unwrap_or("камера").into(),
        });
        let f = db.finding_update(
            h,
            &FindingPatch {
                photos: Some(photos),
                ..Default::default()
            },
        )?;
        Self::finding_json(&db, &map, &f)
    }

    /// Returns the directory with the project's photo evidence.
    pub(crate) fn photo_dir(&self, project: &str) -> PathBuf {
        self.inner
            .cfg
            .data_dir
            .join("files")
            .join(project)
            .join("photos")
    }
}
