//! Re-analysis of stored documents (`project_reextract`): current parsers over kept files,
//! missing files downloaded again, triage kept, a killed run resumed, scans have priority.

use std::time::Duration;

use crate::common::*;
use serde_json::{json, Value};

fn sql(dir: &std::path::Path, project: &str) -> rusqlite::Connection {
    rusqlite::Connection::open(dir.join(format!("{project}.foca"))).unwrap()
}

/// Simulates documents analysed by an older version (no recorded extraction revision).
fn age_documents(dir: &std::path::Path, project: &str) {
    sql(dir, project)
        .execute(
            "UPDATE documents SET extractor_rev = NULL, extractor_ver = NULL, reextract_mark = NULL",
            [],
        )
        .unwrap();
}

fn revs(dir: &std::path::Path, project: &str) -> Vec<(i64, Option<i64>)> {
    let c = sql(dir, project);
    let mut st = c
        .prepare("SELECT id, extractor_rev FROM documents ORDER BY id")
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Title prefix of the bad redaction finding (`doc.bad_redaction`).
const BAD_REDACTION: &str = "Плохое замазывание";

fn finding_ids(s: &Value) -> Vec<Value> {
    s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].clone())
        .collect()
}

async fn report_md(e: &Env, id: &str) -> String {
    let rep = e
        .call(
            "report_build",
            json!({ "project": id, "opts": { "fmt": "md", "lang": "RU", "min_sev": "all",
                "confirmed": false } }),
        )
        .await;
    std::fs::read_to_string(rep["path"].as_str().unwrap()).unwrap()
}

/// A finding an older parser produced and the current one does not (a bad redaction stored by an
/// older version) leaves the project after a re-analysis: the list, the counts, the summary and
/// the report. Findings that still exist keep their triage, and a later scan neither brings the
/// retired finding back nor marks it fixed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reextract_retires_findings_the_current_parsers_no_longer_produce() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let files: Vec<String> = ["pdf/report.pdf", "ooxml/contract.docx"]
        .iter()
        .map(|f| corpus_dir().join(f).to_string_lossy().into_owned())
        .collect();
    e.call("doc_import", json!({ "project": id, "paths": files }))
        .await;
    let c = sql(e.dir.path(), &id);
    let pdf: i64 = c
        .query_row(
            "SELECT id FROM documents WHERE name = 'report.pdf'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // What an older parser stored for the PDF: a fragment under a filled rectangle.
    let old = json!([{ "page": 1, "text": "Total 42", "fill": "black", "rect": [10.0, 10.0, 90.0, 20.0] }]);
    c.execute(
        "UPDATE documents SET metadata_json = json_set(metadata_json, '$.bad_redactions', json(?2))
         WHERE id = ?1",
        rusqlite::params![pdf, old.to_string()],
    )
    .unwrap();
    drop(c);
    age_documents(e.dir.path(), &id);
    // The older version analysed that data (a delete and a restore run the analysis).
    let other = if pdf == 1 { 2 } else { 1 };
    e.call("doc_delete", json!({ "project": id, "ids": [other] }))
        .await;
    e.call("doc_restore", json!({ "project": id, "ids": [other] }))
        .await;
    let s = e.snap(&id).await;
    let all = s["findings"].as_array().unwrap();
    let stale = all
        .iter()
        .find(|f| f["title"].as_str().unwrap_or("").starts_with(BAD_REDACTION))
        .unwrap_or_else(|| panic!("the old data gives the finding: {all:?}"))["id"]
        .clone();
    let kept = all
        .iter()
        .find(|f| f["id"] != stale)
        .expect("another finding")["id"]
        .clone();
    e.call(
        "finding_update",
        json!({ "project": id, "id": kept, "patch": { "status": "confirmed",
            "notes": [{ "text": "seen", "who": "qa", "time": "2026-11-20T10:00:00Z" }] } }),
    )
    .await;
    assert!(
        report_md(&e, &id).await.contains(BAD_REDACTION),
        "the old report has it"
    );

    let r = e
        .call(
            "project_reextract",
            json!({ "project": id, "mode": "stored", "wait": true }),
        )
        .await;
    let sm = &r["summary"];
    assert_eq!(sm["reparsed"], 2, "{sm}");
    assert!(sm["removed_findings"].as_u64().unwrap() >= 1, "{sm}");

    let s2 = e.snap(&id).await;
    let ids = finding_ids(&s2);
    assert!(
        !ids.contains(&stale),
        "the finding the current parser does not produce is gone: {:?}",
        s2["findings"]
    );
    let f = s2["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == kept)
        .expect("a finding that still exists stays");
    assert_eq!(f["status"], "confirmed");
    assert_eq!(f["notes"][0]["text"], "seen");
    // the summary counts what the lists show
    let live = s2["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["status"] != "false")
        .count();
    assert_eq!(sm["after"]["findings_total"], live, "{sm}");
    // the report has no retired finding
    let md = report_md(&e, &id).await;
    assert!(
        !md.contains(BAD_REDACTION),
        "report keeps a retired finding"
    );

    // A scan afterwards neither brings it back nor lists it as fixed.
    e.passive_scan(&id).await;
    let s3 = e.snap(&id).await;
    assert!(
        !finding_ids(&s3).contains(&stale),
        "a retired finding stays retired after a scan: {:?}",
        s3["findings"]
    );
}

async fn wait_done(e: &Env, project: &str) -> Value {
    for _ in 0..2000 {
        if let Some(ev) = e
            .events()
            .into_iter()
            .rev()
            .find(|v| v["type"] == "reextract" && v["project"] == project && v["stage"] != "file")
            .filter(|v| {
                ["done", "cancelled", "yielded", "error"]
                    .contains(&v["stage"].as_str().unwrap_or(""))
            })
        {
            return ev;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the re-analysis did not finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reextract_reparses_stored_files_and_keeps_triage() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let files: Vec<String> = ["ooxml/contract.docx", "pdf/report.pdf", "ole/legacy.doc"]
        .iter()
        .map(|f| corpus_dir().join(f).to_string_lossy().into_owned())
        .collect();
    e.call("doc_import", json!({ "project": id, "paths": files }))
        .await;
    let s = e.snap(&id).await;
    let f0 = s["findings"][0]["id"].clone();
    e.call(
        "finding_update",
        json!({ "project": id, "id": f0, "patch": { "status": "confirmed",
            "notes": [{ "text": "seen", "who": "qa", "time": "2026-11-20T10:00:00Z" }] } }),
    )
    .await;
    e.call("doc_delete", json!({ "project": id, "ids": [3] }))
        .await;
    age_documents(e.dir.path(), &id);
    // A text excerpt that an older parser got wrong.
    sql(e.dir.path(), &id)
        .execute("UPDATE documents SET text_excerpt = NULL WHERE id = 2", [])
        .unwrap();

    let st = e.call("reextract_status", json!({ "project": id })).await;
    assert_eq!(st["format_rev"], foca_core::extractor::FORMAT_REV);
    // the deleted document is not offered
    assert_eq!(st["outdated"]["total"], 2, "{st}");
    assert_eq!(st["outdated"]["files"], 2, "{st}");
    assert!(st["running"].is_null() && st["pending"].is_null(), "{st}");

    e.clear_events();
    let r = e
        .call(
            "project_reextract",
            json!({ "project": id, "mode": "stored", "wait": true }),
        )
        .await;
    assert_eq!(r["stage"], "done", "{r}");
    let sm = &r["summary"];
    assert_eq!(sm["reparsed"], 2, "{sm}");
    assert_eq!(sm["no_file"], 0);
    assert_eq!(sm["processed"], 2);
    assert!(
        sm["after"]["text"].as_u64() > sm["before"]["text"].as_u64(),
        "text came back: {sm}"
    );
    assert!(sm["before"]["findings"]["crit"].is_u64(), "{sm}");
    let evs: Vec<Value> = e
        .events()
        .into_iter()
        .filter(|v| v["type"] == "reextract")
        .collect();
    assert!(evs
        .iter()
        .any(|v| v["stage"] == "file" && v["name"] == "report.pdf"));
    assert_eq!(evs.last().unwrap()["stage"], "done");

    // every live document carries the current revision, the deleted one keeps none
    let rv = revs(e.dir.path(), &id);
    assert_eq!(rv[0].1, Some(foca_core::extractor::FORMAT_REV as i64));
    assert_eq!(rv[1].1, Some(foca_core::extractor::FORMAT_REV as i64));
    assert_eq!(rv[2].1, None);
    let s2 = e.snap(&id).await;
    let f = s2["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == f0)
        .unwrap();
    assert_eq!(f["status"], "confirmed");
    assert_eq!(f["notes"][0]["text"], "seen");
    let d3 = s2["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == 3)
        .unwrap();
    assert_eq!(d3["deleted"], true, "deletion flag kept");
    let st = e.call("reextract_status", json!({ "project": id })).await;
    assert_eq!(st["outdated"]["total"], 0, "{st}");
    assert_eq!(st["last"]["reparsed"], 2);
    // nothing to cancel now
    let c = e.call("reextract_cancel", json!({ "project": id })).await;
    assert_eq!(c["cancelled"], false);
    let bad = e
        .err(
            "project_reextract",
            json!({ "project": id, "mode": "everything" }),
        )
        .await;
    assert_eq!(bad.code, "bad_args");
    // only outdated documents: none left
    let none = e
        .err(
            "project_reextract",
            json!({ "project": id, "outdated": true }),
        )
        .await;
    assert_eq!(none.code, "nothing");
    sql(e.dir.path(), &id)
        .execute("UPDATE documents SET extractor_rev = NULL WHERE id = 2", [])
        .unwrap();
    let r = e
        .call(
            "project_reextract",
            json!({ "project": id, "outdated": true, "wait": true }),
        )
        .await;
    assert_eq!(r["summary"]["total"], 1, "{r}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn killed_run_resumes_from_the_marks() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    let files: Vec<String> = [
        "ooxml/contract.docx",
        "pdf/report.pdf",
        "ooxml/schedule.xlsx",
    ]
    .iter()
    .map(|f| corpus_dir().join(f).to_string_lossy().into_owned())
    .collect();
    e.call("doc_import", json!({ "project": id, "paths": files }))
        .await;
    age_documents(e.dir.path(), &id);
    // the state a kill leaves after the first document: the run record and one mark
    let run = json!({ "mark": "r1-killed", "mode": "stored", "ids": [], "started": "2026-11-20T10:00:00",
        "total": 3, "done": 1, "tally": { "reparsed": 1 },
        "before": { "docs": 3, "text": 3, "people": 0, "emails": 0, "phones": 0,
            "findings": {}, "findings_total": 0, "live": [] } });
    let c = sql(e.dir.path(), &id);
    c.execute(
        "INSERT INTO settings (key, value_json) VALUES ('reextract.run', ?1)",
        [run.to_string()],
    )
    .unwrap();
    c.execute(
        "UPDATE documents SET reextract_mark = 'r1-killed' WHERE id = 1",
        [],
    )
    .unwrap();
    drop(c);
    // reopen the engine as after a process restart
    e.engine.abandon().await;
    let (en, ev, _) = open(e.dir.path(), &e.server.url(), e.keys.clone());
    let st = en
        .invoke("reextract_status", json!({ "project": id }))
        .await
        .unwrap();
    assert_eq!(st["pending"]["done"], 1, "{st}");
    let r = en
        .invoke("project_reextract", json!({ "project": id, "wait": true }))
        .await
        .unwrap();
    let sm = &r["summary"];
    assert_eq!(sm["processed"], 3, "{sm}");
    assert_eq!(sm["reparsed"], 3, "{sm}");
    assert!(
        sm["new_findings"].as_u64().unwrap() > 0,
        "findings of the run: {sm}"
    );
    // the document done before the kill was not parsed again
    let rv = revs(e.dir.path(), &id);
    assert_eq!(rv[0].1, None, "{rv:?}");
    assert_eq!(rv[1].1, Some(foca_core::extractor::FORMAT_REV as i64));
    let names: Vec<String> = ev
        .lock()
        .unwrap()
        .iter()
        .filter(|v| v["type"] == "reextract" && v["stage"] == "file")
        .map(|v| v["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, ["report.pdf", "schedule.xlsx"]);
    let st = en
        .invoke("reextract_status", json!({ "project": id }))
        .await
        .unwrap();
    assert!(st["pending"].is_null(), "{st}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_files_are_downloaded_again_only_when_asked() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.passive_scan(&id).await;
    let s = e.snap(&id).await;
    let n = s["docs"].as_array().unwrap().len();
    assert!(n >= 2, "the stand serves documents");
    // files of the first document are gone (cleaned storage, restored backup)
    let path: String = sql(e.dir.path(), &id)
        .query_row("SELECT local_path FROM documents WHERE id = 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    age_documents(e.dir.path(), &id);
    let st = e.call("reextract_status", json!({ "project": id })).await;
    assert_eq!(st["outdated"]["missing"], 1, "{st}");
    assert!(
        st["outdated"]["missing_bytes"].as_u64().unwrap() > 0,
        "{st}"
    );

    let r = e
        .call(
            "project_reextract",
            json!({ "project": id, "mode": "stored", "ids": [1, 2], "wait": true }),
        )
        .await;
    assert_eq!(r["summary"]["no_file"], 1, "{r}");
    assert_eq!(r["summary"]["reparsed"], 1, "{r}");
    assert_eq!(r["summary"]["total"], 2, "selection only: {r}");

    let r = e
        .call(
            "project_reextract",
            json!({ "project": id, "mode": "stored_and_missing", "ids": [1], "wait": true }),
        )
        .await;
    assert_eq!(r["summary"]["downloaded"], 1, "{r}");
    assert!(std::path::Path::new(&path).is_file(), "the file is back");
    let s2 = e.snap(&id).await;
    assert_eq!(
        s2["docs"].as_array().unwrap().len(),
        n,
        "same documents, same ids"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_while_a_scan_runs() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    *e.pause_at.lock().unwrap() = Some("meta".into());
    e.call(
        "scan_start",
        json!({ "project": id, "profile": "passive", "sources": ["wayback"] }),
    )
    .await;
    e.wait_paused("meta").await;
    let err = e.err("project_reextract", json!({ "project": id })).await;
    assert_eq!(err.code, "busy");
    let st = e.call("reextract_status", json!({ "project": id })).await;
    assert_eq!(st["scan_running"], true);
    e.call("scan_stop", json!({})).await;
    *e.pause_at.lock().unwrap() = None;
    e.wait().await;
    // started in the background after the scan: the done event carries the summary
    e.clear_events();
    let r = e.call("project_reextract", json!({ "project": id })).await;
    assert_eq!(r["started"], true, "{r}");
    let done = wait_done(&e, &id).await;
    assert_eq!(done["stage"], "done", "{done}");
    assert!(done["summary"]["after"]["docs"].is_u64());
}
