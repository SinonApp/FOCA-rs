//! In-place upgrade from 2.0.0-beta.2 (e490fee): every project of the old data directory is
//! still listed, with its data, flags and settings, after the new engine opens it.

use std::collections::HashSet;

use crate::common::*;
use serde_json::{json, Value};

/// Keys of the project summary cached in the index by beta.2 (no `reference` yet).
const BETA2_SUMMARY_KEYS: &[&str] = &[
    "id",
    "name",
    "client",
    "created_at",
    "archived",
    "last_scan_at",
    "last_profile",
    "scans",
    "docs",
    "findings",
    "risk",
    "scanning",
    "progress",
];

/// Rewrites every cached summary in the index to the beta.2 shape.
fn downgrade_index(dir: &std::path::Path) {
    let db = rusqlite::Connection::open(dir.join("projects.db")).unwrap();
    let rows: Vec<(String, String)> = db
        .prepare("SELECT id, summary_json FROM projects")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    for (id, js) in rows {
        let mut v: Value = serde_json::from_str(&js).unwrap();
        v.as_object_mut()
            .unwrap()
            .retain(|k, _| BETA2_SUMMARY_KEYS.contains(&k.as_str()));
        db.execute(
            "UPDATE projects SET summary_json = ?2 WHERE id = ?1",
            rusqlite::params![id, v.to_string()],
        )
        .unwrap();
    }
}

fn by_id<'a>(list: &'a Value, id: &str) -> &'a Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == id)
        .unwrap_or_else(|| panic!("{id} missing from {list}"))
}

#[tokio::test]
async fn beta2_data_dir_keeps_every_project_after_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let srv = server(0).await;
    let keys = std::sync::Arc::new(foca_engine::MemoryKeys::new());
    let (en, _ev, _) = open(dir.path(), &srv.url(), keys.clone());
    let call = |en: &foca_engine::Engine, cmd: &'static str, a: Value| {
        let en = en.clone();
        async move {
            en.invoke(cmd, a)
                .await
                .unwrap_or_else(|e| panic!("{cmd}: {e}"))
        }
    };

    let normal = call(
        &en,
        "project_create",
        json!({ "name": "Normal", "client": "ACME", "targets": ["example.test"] }),
    )
    .await;
    let normal = normal["id"].as_str().unwrap().to_string();
    let arch = call(
        &en,
        "project_create",
        json!({ "name": "Old archived", "targets": ["old.test"] }),
    )
    .await;
    let arch = arch["id"].as_str().unwrap().to_string();
    call(
        &en,
        "project_update",
        json!({ "id": arch, "patch": { "archived": true } }),
    )
    .await;
    let r1 = call(&en, "demo_case_import", json!({ "name": "Reference case" })).await;
    let r2 = call(
        &en,
        "demo_case_import",
        json!({ "name": "My work on the reference" }),
    )
    .await;
    let (ref1, ref2) = (
        r1["project"].as_str().unwrap().to_string(),
        r2["project"].as_str().unwrap().to_string(),
    );
    let newer = call(
        &en,
        "project_create",
        json!({ "name": "Opened by a newer build", "targets": ["new.test"] }),
    )
    .await;
    let newer = newer["id"].as_str().unwrap().to_string();
    call(
        &en,
        "settings_set",
        json!({ "patch": { "lang": "en", "last_project": normal } }),
    )
    .await;
    let before = call(&en, "project_list", json!({})).await;
    // the app process ends (releases the data directory lock)
    en.abandon().await;
    drop(en);

    // The data directory as beta.2 left it, plus one project already migrated by a newer build.
    downgrade_index(dir.path());
    let newer_file = dir.path().join(format!("{newer}.foca"));
    rusqlite::Connection::open(&newer_file)
        .unwrap()
        .pragma_update(None, "user_version", 99)
        .unwrap();
    let newer_bytes = std::fs::read(&newer_file).unwrap();

    let (en, _ev, _) = open(dir.path(), &srv.url(), keys);
    let list = call(&en, "project_list", json!({})).await;
    let ids: HashSet<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["id"].as_str())
        .collect();
    assert_eq!(ids.len(), 5, "{list}");
    for id in [&normal, &ref1, &ref2] {
        let (b, a) = (by_id(&before, id), by_id(&list, id));
        for k in [
            "name",
            "client",
            "archived",
            "docs",
            "findings",
            "scans",
            "reference",
        ] {
            assert_eq!(a[k], b[k], "{id}.{k}");
        }
    }
    assert_eq!(by_id(&list, &arch)["archived"], true);
    assert_eq!(by_id(&list, &ref1)["reference"], true);
    assert!(by_id(&list, &ref1)["docs"].as_u64().unwrap() > 0);
    assert_eq!(by_id(&list, &normal)["reference"], false);
    // A database from a newer build stays listed, fails to open with an error, and is untouched.
    assert_eq!(by_id(&list, &newer)["name"], "Opened by a newer build");
    assert!(en
        .invoke("project_open", json!({ "id": newer }))
        .await
        .is_err());
    assert_eq!(std::fs::read(&newer_file).unwrap(), newer_bytes);

    let st = call(&en, "settings_get", json!({})).await;
    assert_eq!(st["last_project"], normal.as_str());
    assert_eq!(st["lang"], "en");
    let snap = call(&en, "project_snapshot", json!({ "id": ref2 })).await;
    assert!(!snap["docs"].as_array().unwrap().is_empty());
}
