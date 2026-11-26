//! Document hygiene in the engine: `hygiene_get` grades for a project and for a single
//! file outside any project, `doc_clean` with the before/after self-check (`verify`), grades before
//! and after, cleaning warnings (signature removed) and the clean copy of a shared file.

use crate::common::*;
use serde_json::{json, Value};

const GRADES: &[&str] = &["A", "B", "C", "D", "E", "F"];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn project_grades_and_clean_with_self_check() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.passive_scan(&id).await;
    let h = e.call("hygiene_get", json!({ "project": id })).await;
    let docs = h["docs"].as_array().unwrap();
    assert!(!docs.is_empty(), "{h}");
    for d in docs {
        assert!(GRADES.contains(&d["grade"].as_str().unwrap()), "{d}");
        assert!(d["id"].is_u64() && d["name"].is_string(), "{d}");
    }
    assert_eq!(h["set"]["documents"].as_u64().unwrap() as usize, docs.len());
    assert!(GRADES.contains(&h["set"]["grade"].as_str().unwrap()));
    // a document with an author gets the "people" issue with an automatic fix
    let docx = docs.iter().find(|d| d["name"] == "contract.docx").unwrap();
    let people = docx["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["code"] == "people")
        .unwrap_or_else(|| panic!("{docx}"));
    assert_eq!(people["fix"]["auto"], true, "{people}");
    // filtered by ids
    let one = e
        .call(
            "hygiene_get",
            json!({ "project": id, "ids": [docx["id"].clone()] }),
        )
        .await;
    assert_eq!(one["docs"].as_array().unwrap().len(), 1);
    // doc_clean: self-check and grades
    let cl = e
        .call(
            "doc_clean",
            json!({ "project": id, "ids": [docx["id"].clone()] }),
        )
        .await;
    let c = &cl["cleaned"][0];
    assert_eq!(c["name"], "contract_clean.docx");
    let v = &c["verify"];
    assert_eq!(v["valid"], true, "{c}");
    assert!(v["changes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["field"] == "author" && x["change"] == "removed"));
    let before = GRADES
        .iter()
        .position(|g| *g == c["grade_before"].as_str().unwrap())
        .unwrap();
    let after = GRADES
        .iter()
        .position(|g| *g == c["grade_after"].as_str().unwrap())
        .unwrap();
    assert!(after <= before, "{c}");
    assert!(c["size"].as_u64().unwrap() > 0);
    let path = c["path"].as_str().unwrap();
    assert!(std::path::Path::new(path).is_file());
    // unknown options are rejected
    let er = e
        .err(
            "doc_clean",
            json!({ "project": id, "ids": [docx["id"].clone()], "options": { "remove_javascript": "x" } }),
        )
        .await;
    assert_eq!(er.code, "bad_args");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_file_grade_and_clean_without_project() {
    let e = env(0).await;
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("in.pdf");
    std::fs::copy(corpus_dir().join("forensics/signed.pdf"), &src).unwrap();
    let src_s = src.to_string_lossy().to_string();
    let h = e
        .call(
            "hygiene_get",
            json!({ "path": src_s, "name": "../../Договір.pdf" }),
        )
        .await;
    let d = &h["docs"][0];
    assert_eq!(d["name"], "Договір.pdf", "path parts are dropped: {d}");
    assert!(d["id"].is_null());
    assert!(
        d["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["code"] == "signed"),
        "{d}"
    );
    let cl = e
        .call("doc_clean", json!({ "path": src_s, "name": "Договір.pdf" }))
        .await;
    let c = &cl["cleaned"][0];
    assert_eq!(c["name"], "Договір_clean.pdf");
    assert_eq!(c["source"], "Договір.pdf");
    let warn: Vec<&str> = c["verify"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(warn.contains(&"signature_removed"), "{c}");
    assert_eq!(c["verify"]["valid"], true, "{c}");
    let out = e
        .dir
        .path()
        .join("clean")
        .join("shared")
        .join("Договір_clean.pdf");
    assert!(out.is_file());
    assert_eq!(c["path"], Value::String(out.to_string_lossy().into_owned()));
    // the original stays untouched
    assert_eq!(
        std::fs::read(&src).unwrap(),
        std::fs::read(corpus_dir().join("forensics/signed.pdf")).unwrap()
    );
    // missing file
    let er = e
        .err("doc_clean", json!({ "path": dir.path().join("nope.pdf") }))
        .await;
    assert_eq!(er.code, "not_found");
    let er = e
        .err(
            "hygiene_get",
            json!({ "path": dir.path().to_string_lossy() }),
        )
        .await;
    assert_eq!(er.code, "bad_args");
}
