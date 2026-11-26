//! Files for Share/Save: the report path (`Report.path`), the real export path (`path` plus
//! `saved_as`), the document file (`doc_file`), and photo evidence copied into the project.

use crate::common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_export_doc_and_photo_files_live_in_data_dir() {
    let e = env(0).await;
    let id = e.project("example.test").await;
    e.passive_scan(&id).await;
    let data = e.dir.path().canonicalize().unwrap();
    let inside = |p: &str| {
        let c = std::path::Path::new(p).canonicalize().unwrap();
        c.starts_with(&data) && c.is_file()
    };
    // report: path in the response, in report_list and in the snapshot
    let r = e
        .call("report_build", json!({ "project": id, "opts": { "tpl": "brief", "tpl_id": "brief", "fmt": "md", "lang": "RU" } }))
        .await;
    assert!(inside(r["path"].as_str().unwrap()), "{r}");
    let list = e.call("report_list", json!({ "project": id })).await;
    assert_eq!(list[0]["path"], r["path"]);
    assert_eq!(e.snap(&id).await["reports"][0]["path"], r["path"]);
    // export: the real path plus where it will be saved
    let x = e
        .call(
            "export_build",
            json!({ "project": id, "kind": "findings", "fmt": "md", "opts": {} }),
        )
        .await;
    assert!(inside(x["path"].as_str().unwrap()), "{x}");
    assert_eq!(
        x["saved_as"],
        format!("Download/FOCA-rs/{}", x["name"].as_str().unwrap())
    );
    // document
    let s = e.snap(&id).await;
    let d = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["status"] == "analyzed")
        .unwrap();
    let f = e
        .call("doc_file", json!({ "project": id, "id": d["id"] }))
        .await;
    assert!(inside(f["path"].as_str().unwrap()));
    assert_eq!(f["name"], d["name"]);
    assert_eq!(
        e.err("doc_file", json!({ "project": id, "id": 99999 }))
            .await
            .code,
        "not_found"
    );
    // photo: copied to files/<project>/photos; identical names do not overwrite each other
    let src = e.dir.path().join("picked.jpg");
    std::fs::write(&src, b"\xff\xd8\xff photo").unwrap();
    let fid = s["findings"][0]["id"].clone();
    let a = json!({ "project": id, "id": fid, "name": "IMG 1.jpg", "from": "галерея", "path": src.to_string_lossy() });
    e.call("finding_photo_add", a.clone()).await;
    let f2 = e.call("finding_photo_add", a).await;
    let ph = f2["photos"].as_array().unwrap();
    assert_eq!(ph.len(), 2);
    assert_eq!(ph[0]["name"], "IMG_1.jpg");
    assert_eq!(ph[1]["name"], "IMG_1_2.jpg");
    let dir = e.dir.path().join("files").join(&id).join("photos");
    assert!(dir.join("IMG_1.jpg").is_file() && dir.join("IMG_1_2.jpg").is_file());
    let bad = json!({ "project": id, "id": fid, "path": "/nonexistent/x.jpg" });
    assert_eq!(e.err("finding_photo_add", bad).await.code, "bad_args");
}
