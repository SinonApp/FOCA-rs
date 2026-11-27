//! In-place upgrade from the released 2.0.0-beta.4: a data directory written by that binary
//! (`tests/fixtures/upgrade/beta4-data.tar.gz`, synthetic data, see the README there) opens with
//! the current engine with every project, document, triage, setting and AI summary intact, the
//! schema migrates once, and re-analysis improves the documents without losing anything.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::common::*;
use serde_json::{json, Value};

const PROJECT: &str = "upgrade-fixture";

/// Unpacks a gzip-compressed ustar archive (regular files and directories only).
fn untar_gz(archive: &Path, into: &Path) {
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(archive).unwrap())
        .read_to_end(&mut raw)
        .unwrap();
    let field = |b: &[u8]| {
        let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
        String::from_utf8_lossy(&b[..end]).trim().to_string()
    };
    let mut at = 0;
    while at + 512 <= raw.len() {
        let h = &raw[at..at + 512];
        if h.iter().all(|c| *c == 0) {
            break;
        }
        let (name, prefix) = (field(&h[0..100]), field(&h[345..500]));
        let size = usize::from_str_radix(&field(&h[124..136]), 8).unwrap();
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        assert!(!path.contains(".."), "{path}");
        let dst = into.join(&path);
        match h[156] {
            b'5' => std::fs::create_dir_all(&dst).unwrap(),
            b'0' | 0 => {
                std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
                std::fs::write(&dst, &raw[at + 512..at + 512 + size]).unwrap();
            }
            t => panic!("unexpected tar entry type {t} for {path}"),
        }
        at += 512 + size.div_ceil(512) * 512;
    }
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upgrade/beta4-data.tar.gz")
}

fn user_version(p: &Path) -> i64 {
    rusqlite::Connection::open(p)
        .unwrap()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}

async fn call(en: &foca_engine::Engine, cmd: &str, a: Value) -> Value {
    en.invoke(cmd, a.clone())
        .await
        .unwrap_or_else(|e| panic!("{cmd} {a}: {e}"))
}

/// Triage, notes and documents as the user sees them.
fn user_state(s: &Value) -> (Vec<Value>, Vec<Value>) {
    let docs = s["docs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| json!([d["id"], d["name"], d["deleted"]]))
        .collect();
    let triage = s["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["status"] != "new" || f["notes"].as_array().is_some_and(|n| !n.is_empty()))
        .map(|f| json!([f["id"], f["status"], f["notes"]]))
        .collect();
    (docs, triage)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn beta4_data_dir_survives_the_update_and_reanalysis() {
    let tmp = tempfile::tempdir().unwrap();
    untar_gz(&fixture(), tmp.path());
    let data = tmp.path().join("data");
    let foca = data.join(format!("{PROJECT}.foca"));
    assert_eq!(
        user_version(&foca),
        10,
        "the fixture is a beta.4 project file"
    );
    let srv = server(0).await;
    let keys = std::sync::Arc::new(foca_engine::MemoryKeys::new());
    let (en, _ev, _) = open(&data, &srv.url(), keys.clone());

    let list = call(&en, "project_list", json!({})).await;
    let p = list
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == PROJECT)
        .unwrap_or_else(|| panic!("{list}"));
    assert_eq!(p["name"], "Upgrade fixture");
    assert_eq!(p["client"], "Example Org");
    assert_eq!(p["docs"], 5);

    let s = call(&en, "project_snapshot", json!({ "id": PROJECT })).await;
    assert_eq!(user_version(&foca), 11, "migrated on open");
    let (docs, triage) = user_state(&s);
    assert_eq!(docs.len(), 5);
    assert_eq!(
        docs.iter()
            .map(|d| d[1].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "contract.docx",
            "report.pdf",
            "legacy.doc",
            "schedule.xlsx",
            "scan.pdf"
        ]
    );
    assert_eq!(triage.len(), 2, "{triage:?}");
    assert_eq!(triage[0][1], "confirmed");
    assert_eq!(triage[0][2][0]["text"], "Checked with the owner");
    assert_eq!(triage[1][1], "false");
    assert!(s["people"].as_array().unwrap().len() >= 7);
    let scope = call(&en, "scope_get", json!({ "project": PROJECT })).await;
    assert!(scope.to_string().contains("example.com"), "{scope}");

    let st = call(&en, "settings_get", json!({})).await;
    assert_eq!(st["net"]["rps"], 3);
    assert_eq!(st["net"]["timeout"], 17);
    assert_eq!(st["power"]["mob_limit"], 321);
    assert_eq!(st["power"]["wifi_only"], false);
    assert_eq!(st["ai"]["provider"], "custom");
    let terms = call(&en, "terms_get", json!({})).await;
    assert_eq!(terms["accepted"], true, "terms stay accepted");
    let ai = call(&en, "ai_summaries_list", json!({ "project": PROJECT })).await;
    assert_eq!(ai["items"].as_array().unwrap().len(), 1, "{ai}");
    assert!(ai["items"][0]["text"]
        .as_str()
        .unwrap()
        .contains("Synthetic AI summary"));
    let sig = call(&en, "signatures_status", json!({})).await;
    assert_eq!(sig["signature_valid"], true, "{sig}");
    assert_eq!(
        sig["last_check"]["outcome"], "up_to_date",
        "beta.4 check record read"
    );

    // The data directory was written under another path: files are found where they are now.
    let f = call(&en, "doc_file", json!({ "project": PROJECT, "id": 1 })).await;
    assert!(
        Path::new(f["path"].as_str().unwrap()).starts_with(&data),
        "{f}"
    );

    // A second start applies nothing again and changes nothing.
    en.abandon().await;
    let (en, _ev, _) = open(&data, &srv.url(), keys.clone());
    assert_eq!(user_version(&foca), 11);
    let s2 = call(&en, "project_snapshot", json!({ "id": PROJECT })).await;
    assert_eq!(user_state(&s2), user_state(&s));

    // Every beta.4 document counts as analysed by an older extraction.
    let rs = call(&en, "reextract_status", json!({ "project": PROJECT })).await;
    assert_eq!(rs["outdated"]["total"], 5, "{rs}");
    assert_eq!(rs["outdated"]["files"], 5, "{rs}");
    let r = call(
        &en,
        "project_reextract",
        json!({ "project": PROJECT, "mode": "stored", "wait": true }),
    )
    .await;
    let sm = &r["summary"];
    assert_eq!(sm["reparsed"], 5, "{sm}");
    assert!(
        sm["after"]["text"].as_u64() >= sm["before"]["text"].as_u64(),
        "{sm}"
    );
    let s3 = call(&en, "project_snapshot", json!({ "id": PROJECT })).await;
    assert_eq!(user_state(&s3), user_state(&s), "documents and triage kept");
    let rs = call(&en, "reextract_status", json!({ "project": PROJECT })).await;
    assert_eq!(rs["outdated"]["total"], 0, "{rs}");

    // The encrypted bundle exported by beta.4 imports.
    let bundle = data.join("exports/Upgrade_fixture_2026-11-27.foca.enc");
    let imp = call(
        &en,
        "project_import_encrypted",
        json!({ "path": bundle.to_string_lossy(), "password": "upgrade-pass", "new_name": "From beta.4" }),
    )
    .await;
    let nid = imp["project"]["id"]
        .as_str()
        .or_else(|| imp["id"].as_str())
        .map(String::from)
        .unwrap_or_else(|| panic!("{imp}"));
    let si = call(&en, "project_snapshot", json!({ "id": nid })).await;
    assert_eq!(si["docs"].as_array().unwrap().len(), 5);
    assert_eq!(user_state(&si).1.len(), 2, "triage travels in the bundle");
}
