//! Extraction outcome of stored documents (parse errors, extraction revisions) and the helpers
//! of document re-analysis (`project_reextract` in the engine).

use rusqlite::params;

use crate::project::{DocErrorKind, ProjectDb, EXTRACTOR};
use crate::Result;

/// Extraction revision of a stored document (see `foca_core::extractor`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocRev {
    pub id: u64,
    /// `FORMAT_REV` that analysed the document; 0 = before revisions were recorded.
    pub rev: u32,
    /// Application version that analysed it.
    pub ver: Option<String>,
    /// Mark of the last re-analysis run that processed it.
    pub mark: Option<String>,
}

impl ProjectDb {
    /// Records a parse/import failure of a stored document (the only kind current callers
    /// produce: failed downloads create no document row).
    pub fn set_doc_error(&self, id: u64, msg: &str) -> Result<()> {
        self.set_doc_error_kind(id, DocErrorKind::Parse, msg)
    }

    /// Records a document error of the given kind.
    pub fn set_doc_error_kind(&self, id: u64, kind: DocErrorKind, msg: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE documents SET status = 'error', error = ?2, error_kind = ?3,
                 extractor_rev = CASE WHEN ?3 = 'parse' THEN ?4 ELSE extractor_rev END,
                 extractor_ver = CASE WHEN ?3 = 'parse' THEN ?5 ELSE extractor_ver END
             WHERE id = ?1",
            params![id as i64, msg, kind.as_str(), EXTRACTOR.0, EXTRACTOR.1],
        )?;
        Ok(())
    }

    /// Extraction revision and re-analysis mark of every document (deleted ones included).
    pub fn doc_revs(&self) -> Result<Vec<DocRev>> {
        let mut st = self.conn().prepare(
            "SELECT id, extractor_rev, extractor_ver, reextract_mark FROM documents ORDER BY id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(DocRev {
                id: r.get::<_, i64>(0)? as u64,
                rev: r.get::<_, Option<i64>>(1)?.map_or(0, |v| v as u32),
                ver: r.get(2)?,
                mark: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Marks a document as processed by the re-analysis run `mark` (a resumed run skips it).
    pub fn set_reextract_mark(&self, id: u64, mark: &str) -> Result<()> {
        self.conn().execute(
            "UPDATE documents SET reextract_mark = ?2 WHERE id = ?1",
            params![id as i64, mark],
        )?;
        Ok(())
    }

    /// Points a document at a freshly downloaded copy of its file. The id, triage and flags stay;
    /// SHA-256 and size follow the new file. Returns `false` (nothing changed) when another
    /// document already holds that SHA-256: the copy is a duplicate of it.
    pub fn relink_file(&self, id: u64, sha256: &str, size: u64, local_path: &str) -> Result<bool> {
        if self.doc_by_sha(sha256)?.is_some_and(|o| o != id) {
            return Ok(false);
        }
        let n = self.conn().execute(
            "UPDATE documents SET sha256 = ?2, size = ?3, local_path = ?4, downloaded_at = ?5 WHERE id = ?1",
            params![id as i64, sha256, size as i64, local_path, self.now()],
        )?;
        Ok(n > 0)
    }

    /// Id, severity, status and presence in the latest analysis of every stored finding (for
    /// before/after comparisons; findings hidden with deleted documents are left out).
    pub fn finding_states(&self) -> Result<Vec<(u64, String, String, bool)>> {
        let hidden = self.findings_of_deleted_docs()?;
        let mut st = self.conn().prepare(
            "SELECT id, COALESCE(sev_override, sev), status, present FROM findings ORDER BY id",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)? != 0,
            ))
        })?;
        Ok(rows
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter(|f| !hidden.contains(&f.0))
            .collect())
    }
}
