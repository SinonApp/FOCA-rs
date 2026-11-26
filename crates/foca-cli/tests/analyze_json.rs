//! `foca analyze --json` must never print a raw secret unless `--reveal-secrets` is given.

use std::process::Command;

const PLANTED: &str = "Plant3d#Secr9!";

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let ica = format!(
        "[WFClient]\nVersion=2\n\n[ApplicationServers]\nBooks=\n\n[Books]\n\
         Address=10.10.1.40:1494\nUsername=o.kovalenko\nDomain=CONTOSO\n\
         ClearPassword={PLANTED}\n"
    );
    std::fs::write(dir.path().join("books.ica"), ica).unwrap();
    dir
}

fn analyze(dir: &std::path::Path, extra: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_foca"))
        .arg("analyze")
        .arg("--json")
        .args(extra)
        .arg(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn analyze_json_masks_secrets_in_every_field() {
    let dir = fixture();
    let json = analyze(dir.path(), &[]);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        !v["secrets"].as_array().unwrap().is_empty(),
        "fixture secret not detected: {json}"
    );
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["evidence"].as_str().unwrap_or("").contains("{{s:")),
        "no secret marker in findings: {json}"
    );
    assert!(!json.contains(PLANTED), "raw secret leaked: {json}");
    assert!(
        !json.contains("Plant3d"),
        "raw secret prefix leaked: {json}"
    );
}

#[test]
fn analyze_json_reveals_secrets_only_on_request() {
    let dir = fixture();
    let json = analyze(dir.path(), &["--reveal-secrets"]);
    assert!(json.contains(PLANTED), "{json}");
}
