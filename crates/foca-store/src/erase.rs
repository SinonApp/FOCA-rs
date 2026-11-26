//! Deleting one scan of a project (`scan_delete`): everything that exists only because of that
//! scan goes, results also produced by other scans stay with their history recomputed.
//!
//! What ties data to a scan in the project file:
//! - `scans` row, per-scan rows of the `settings` table (keys `<prefix>.<scan id>` or
//!   `<prefix>:<scan id>`), `request_log.scan_id`, `tasks.scan_id`;
//! - documents first downloaded by the scan (`documents.first_scan`) and their files; a document
//!   that a later scan still listed in its snapshot stays and moves to that scan;
//! - infrastructure rows last written by the scan (`infra.scan`);
//! - findings first seen in the scan (`findings.first_scan`) or fixed by it (`fixed_scan`).
//!
//! Entities (people, e-mails, paths, hosts, metadata summaries) are derived from documents and
//! network facts, so the caller re-runs the analysis between the two phases below; that also
//! tells which findings are still backed by data of other scans.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::Finding;
use rusqlite::{params, Connection, ToSql};
use serde_json::Value;

use crate::project::REOPENED_TAG;
use crate::{ProjectDb, Result, StoreError};

/// What [`ProjectDb::scan_delete`] removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanErase {
    /// Documents first downloaded by the scan and listed by no later scan (rows removed).
    pub docs: Vec<u64>,
    /// Files of those documents that no remaining document uses; the caller wipes them.
    pub files: Vec<String>,
    /// Request log rows of the scan.
    pub requests: usize,
    /// Download queue rows of the scan.
    pub tasks: usize,
    /// Infrastructure rows that only the scan had written.
    pub infra: usize,
    /// Findings that existed only because of the scan (rows removed).
    pub findings: Vec<u64>,
    /// Remaining scans that started after the deleted one, oldest first.
    pub later: Vec<String>,
}

/// True for a project setting key that belongs to one scan: `<prefix>.<id>` or `<prefix>:<id>`.
fn scan_setting_key(key: &str, scan_id: &str) -> bool {
    key.strip_suffix(scan_id)
        .is_some_and(|p| !p.is_empty() && (p.ends_with('.') || p.ends_with(':')))
}

/// Values of a one-column query.
fn column<T: rusqlite::types::FromSql>(
    conn: &Connection,
    sql: &str,
    args: &[&dyn ToSql],
) -> Result<Vec<T>> {
    let mut st = conn.prepare(sql)?;
    let v = st
        .query_map(args, |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(v)
}

/// Rows of a two-column query.
fn pairs<A: rusqlite::types::FromSql, B: rusqlite::types::FromSql>(
    conn: &Connection,
    sql: &str,
    args: &[&dyn ToSql],
) -> Result<Vec<(A, B)>> {
    let mut st = conn.prepare(sql)?;
    let v = st
        .query_map(args, |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(v)
}

impl ProjectDb {
    /// Implements the store side of `scan_delete`. Phase one removes the scan record, its request
    /// log, queue rows, per-scan settings, the documents it downloaded and the infrastructure rows
    /// only it wrote, and moves "fixed in this scan" to the next scan (or back to `new` when no
    /// later scan confirms it). `reanalyze` then runs (the engine prunes its own per-scan state and
    /// re-runs the analysis there). Phase two removes findings first seen in the scan that no
    /// remaining data backs and gives the survivors their new first scan.
    ///
    /// Works for a scan without a record (a running scan the engine has just cancelled).
    pub fn scan_delete<E: From<StoreError>>(
        &self,
        scan_id: &str,
        reanalyze: impl FnOnce(&ProjectDb, &ScanErase) -> std::result::Result<(), E>,
    ) -> std::result::Result<ScanErase, E> {
        let mut out = self.erase_scan_rows(scan_id)?;
        reanalyze(self, &out)?;
        out.findings = self.settle_scan_findings(scan_id, &out.later)?;
        Ok(out)
    }

    /// Remaining scan ids in history order, without `scan_id`, and the index where it stood.
    fn scan_order_without(&self, scan_id: &str) -> Result<(Vec<String>, usize)> {
        let all: Vec<String> = column(
            self.conn(),
            "SELECT id FROM scans ORDER BY started_at, id",
            &[],
        )?;
        let pos = all.iter().position(|s| s == scan_id).unwrap_or(all.len());
        Ok((all.into_iter().filter(|s| s != scan_id).collect(), pos))
    }

    /// Documents first downloaded by the scan: the ones a later scan listed move to that scan,
    /// the rest are returned for removal.
    fn scan_docs(&self, scan_id: &str, later: &[String]) -> Result<Vec<(u64, Option<String>)>> {
        let conn = self.conn();
        let mut listed: BTreeMap<u64, String> = BTreeMap::new();
        for sid in later.iter().rev() {
            let snap: Vec<Option<String>> = column(
                conn,
                "SELECT snapshot_json FROM scans WHERE id = ?1",
                &[sid],
            )?;
            let docs = snap
                .into_iter()
                .flatten()
                .filter_map(|j| serde_json::from_str::<Value>(&j).ok())
                .filter_map(|v| serde_json::from_value::<Vec<u64>>(v["docs"].clone()).ok())
                .flatten();
            for d in docs {
                listed.insert(d, sid.clone());
            }
        }
        let rows: Vec<(i64, Option<String>)> = pairs(
            conn,
            "SELECT id, local_path FROM documents WHERE first_scan = ?1",
            &[&scan_id],
        )?;
        let mut gone = Vec::new();
        for (id, path) in rows {
            match listed.get(&(id as u64)) {
                Some(next) => {
                    conn.execute(
                        "UPDATE documents SET first_scan = ?2 WHERE id = ?1",
                        params![id, next],
                    )?;
                }
                None => gone.push((id as u64, path)),
            }
        }
        Ok(gone)
    }

    fn set_tags(&self, id: u64, tags: &[String], extra: &str) -> Result<()> {
        self.conn().execute(
            &format!("UPDATE findings SET tags_json = ?2{extra} WHERE id = ?1"),
            params![id as i64, serde_json::to_string(tags)?],
        )?;
        Ok(())
    }

    fn erase_scan_rows(&self, scan_id: &str) -> Result<ScanErase> {
        let (order, pos) = self.scan_order_without(scan_id)?;
        let prev = pos.checked_sub(1).and_then(|i| order.get(i)).cloned();
        let later: Vec<String> = order[pos.min(order.len())..].to_vec();
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        let docs = self.scan_docs(scan_id, &later)?;
        let ids: Vec<u64> = docs.iter().map(|d| d.0).collect();
        // Queue rows of kept documents stay (they mark the URL as known), unattributed.
        let mut tasks = conn.execute(
            "DELETE FROM tasks WHERE scan_id = ?1 AND doc_id IS NULL",
            [scan_id],
        )?;
        for id in &ids {
            tasks += conn.execute("DELETE FROM tasks WHERE doc_id = ?1", [*id as i64])?;
            conn.execute("DELETE FROM documents WHERE id = ?1", [*id as i64])?;
        }
        conn.execute(
            "UPDATE tasks SET scan_id = NULL WHERE scan_id = ?1",
            [scan_id],
        )?;
        let mut files: Vec<String> = Vec::new();
        for p in docs.iter().filter_map(|d| d.1.as_deref()) {
            let shared: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM documents WHERE local_path = ?1)",
                [p],
                |r| r.get(0),
            )?;
            if !shared && !files.iter().any(|f| f == p) {
                files.push(p.to_string());
            }
        }
        let requests = conn.execute("DELETE FROM request_log WHERE scan_id = ?1", [scan_id])?;
        // A row last written by this scan may have existed before it: it then stays, attributed
        // to the previous scan. Without an earlier scan nothing else produced it.
        let infra = match &prev {
            Some(p) => {
                conn.execute(
                    "UPDATE infra SET scan = ?2 WHERE scan = ?1",
                    params![scan_id, p],
                )?;
                0
            }
            None => conn.execute("DELETE FROM infra WHERE scan = ?1", [scan_id])?,
        };
        // "Fixed in this scan": the next scan confirms the fix unless the finding came back later
        // (reopened tag); without such a scan the finding was never fixed.
        let fixed: Vec<i64> = column(
            conn,
            "SELECT id FROM findings WHERE fixed_scan = ?1",
            &[&scan_id],
        )?;
        for id in fixed {
            let tags = self.finding(id as u64)?.tags;
            let reopened = tags.iter().any(|t| t == REOPENED_TAG);
            match later.first().filter(|_| !reopened) {
                Some(next) => {
                    conn.execute(
                        "UPDATE findings SET fixed_scan = ?2 WHERE id = ?1",
                        params![id, next],
                    )?;
                }
                None => {
                    let tags: Vec<String> =
                        tags.into_iter().filter(|t| t != REOPENED_TAG).collect();
                    self.set_tags(id as u64, &tags, ", status = 'new', fixed_scan = NULL")?;
                }
            }
        }
        // A finding fixed in the now last scan and reopened afterwards was reopened by this scan.
        if let Some(last) = order.last().filter(|_| pos >= order.len()) {
            let rows: Vec<i64> = column(
                conn,
                "SELECT id FROM findings WHERE status = 'fixed' AND fixed_scan = ?1",
                &[last],
            )?;
            for id in rows {
                let tags = self.finding(id as u64)?.tags;
                if tags.iter().any(|t| t == REOPENED_TAG) {
                    let tags: Vec<String> =
                        tags.into_iter().filter(|t| t != REOPENED_TAG).collect();
                    self.set_tags(id as u64, &tags, "")?;
                }
            }
        }
        let keys: Vec<String> = column(conn, "SELECT key FROM settings", &[])?;
        for k in keys.iter().filter(|k| scan_setting_key(k, scan_id)) {
            conn.execute("DELETE FROM settings WHERE key = ?1", [k])?;
        }
        conn.execute("DELETE FROM scans WHERE id = ?1", [scan_id])?;
        tx.commit()?;
        Ok(ScanErase {
            docs: ids,
            files,
            requests,
            tasks,
            infra,
            findings: Vec::new(),
            later,
        })
    }

    /// Phase two of [`Self::scan_delete`], after the re-analysis.
    fn settle_scan_findings(&self, scan_id: &str, later: &[String]) -> Result<Vec<u64>> {
        let (order, _) = self.scan_order_without(scan_id)?;
        let rank: BTreeMap<&str, usize> = order
            .iter()
            .enumerate()
            .map(|(i, s)| (s.as_str(), i))
            .collect();
        let conn = self.conn();
        let doc_scan: BTreeMap<u64, Option<String>> =
            pairs::<i64, Option<String>>(conn, "SELECT id, first_scan FROM documents", &[])?
                .into_iter()
                .map(|(id, s)| (id as u64, s))
                .collect();
        let rows: Vec<(i64, String)> = pairs(
            conn,
            "SELECT id, data_json FROM findings WHERE first_scan = ?1",
            &[&scan_id],
        )?;
        let absent: BTreeSet<i64> = column::<i64>(
            conn,
            "SELECT id FROM findings WHERE first_scan = ?1 AND present = 0",
            &[&scan_id],
        )?
        .into_iter()
        .collect();
        let tx = conn.unchecked_transaction()?;
        let mut gone = Vec::new();
        for (id, data) in rows {
            let evidence: BTreeSet<u64> = serde_json::from_str::<Finding>(&data)
                .map(|f| Self::finding_doc_ids(&f))
                .unwrap_or_default();
            let backed = evidence.iter().any(|d| doc_scan.contains_key(d));
            if absent.contains(&id) && !backed {
                conn.execute("DELETE FROM findings WHERE id = ?1", [id])?;
                gone.push(id as u64);
                continue;
            }
            // Earliest scan among the remaining evidence documents, else the next scan.
            let first = evidence
                .iter()
                .filter_map(|d| doc_scan.get(d).cloned().flatten())
                .filter(|s| rank.contains_key(s.as_str()))
                .min_by_key(|s| rank[s.as_str()])
                .or_else(|| later.first().cloned());
            conn.execute(
                "UPDATE findings SET first_scan = ?2, data_json = json_set(data_json, '$.first_scan', ?2) WHERE id = ?1",
                params![id, first],
            )?;
        }
        tx.commit()?;
        Ok(gone)
    }
}

#[cfg(test)]
mod tests {
    use super::scan_setting_key;

    #[test]
    fn per_scan_setting_keys() {
        assert!(scan_setting_key("engine.scan.s-1", "s-1"));
        assert!(scan_setting_key("scan_opts:s-1", "s-1"));
        assert!(!scan_setting_key("engine.scan.xs-1", "s-1"));
        assert!(!scan_setting_key("s-1", "s-1"));
        assert!(!scan_setting_key("engine.net", "s-1"));
    }
}
