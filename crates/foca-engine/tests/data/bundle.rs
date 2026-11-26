//! Encrypted portable `.foca.enc` project container integration tests.

use std::sync::Arc;

use foca_engine::{Engine, EngineConfig, MemoryEvents, MemoryKeys};
use serde_json::json;

#[tokio::test]
async fn encrypted_bundle_roundtrip_wrong_password_and_tamper_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let eng = Engine::open(
        EngineConfig::new(dir.path()),
        Arc::new(MemoryKeys::new()),
        Arc::new(MemoryEvents::new()),
    )
    .unwrap();

    let demo = eng
        .invoke("demo_case_import", json!({}))
        .await
        .expect("demo_case_import");
    let orig_id = demo["project"].as_str().unwrap().to_string();
    let orig_snap = eng
        .invoke("project_snapshot", json!({ "id": orig_id }))
        .await
        .unwrap();
    let orig_findings = orig_snap["findings"].as_array().unwrap().len();
    let orig_docs = orig_snap["docs"].as_array().unwrap().len();
    assert!(orig_docs > 0 && orig_findings > 0);

    let exp = eng
        .invoke(
            "project_export_encrypted",
            json!({
                "project": orig_id,
                "password": "StrongAuditPassword!2026",
                "include_files": true
            }),
        )
        .await
        .expect("export .foca.enc");
    let enc_path = exp["path"].as_str().unwrap().to_string();
    assert!(enc_path.ends_with(".foca.enc"));
    assert_eq!(exp["include_files"], true);
    let inputs_sha = exp["inputs_sha256"].as_str().unwrap().to_string();
    assert_eq!(inputs_sha.len(), 64);

    // Password must never appear in settings or logs
    let settings = eng.invoke("settings_get", json!({})).await.unwrap();
    assert!(!settings.to_string().contains("StrongAuditPassword"));

    // Wrong password must fail with bad_password
    let wrong = eng
        .invoke(
            "project_import_encrypted",
            json!({ "path": enc_path, "password": "WrongPassword!2026" }),
        )
        .await
        .unwrap_err();
    assert_eq!(wrong.code, "bad_password");

    // Tampered 1 byte in ciphertext must fail with tampered_bundle
    let mut tampered_bytes = std::fs::read(&enc_path).unwrap();
    let last = tampered_bytes.len() - 1;
    tampered_bytes[last] ^= 0x01;
    let tampered_path = dir.path().join("tampered.foca.enc");
    std::fs::write(&tampered_path, &tampered_bytes).unwrap();
    let tampered = eng
        .invoke(
            "project_import_encrypted",
            json!({
                "path": tampered_path.to_string_lossy(),
                "password": "StrongAuditPassword!2026"
            }),
        )
        .await
        .unwrap_err();
    assert_eq!(tampered.code, "tampered_bundle");

    // Valid import creates a brand new project without overwriting the original
    let imp = eng
        .invoke(
            "project_import_encrypted",
            json!({
                "path": enc_path,
                "password": "StrongAuditPassword!2026",
                "new_name": "Импортированный аудит"
            }),
        )
        .await
        .expect("import .foca.enc");
    let new_id = imp["project"]["id"].as_str().unwrap().to_string();
    assert_ne!(
        new_id, orig_id,
        "import must never overwrite original project"
    );
    assert_eq!(imp["custody"]["inputs_sha256"], inputs_sha);

    let new_snap = eng
        .invoke("project_snapshot", json!({ "id": new_id }))
        .await
        .unwrap();
    assert_eq!(new_snap["docs"].as_array().unwrap().len(), orig_docs);
    assert_eq!(
        new_snap["findings"].as_array().unwrap().len(),
        orig_findings
    );
}
