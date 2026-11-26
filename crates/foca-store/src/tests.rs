//! Store tests on a temporary directory.

use std::sync::Arc;

use foca_core::api::{Note, Report, Scan, ScopeDto, SNAPSHOT_KEYS};
use foca_core::{
    DocFormat, DocStatus, FindingStatus, ManualClock, Metadata, PathKind, PathRef, PersonRef,
    PersonRole, Severity,
};
use time::macros::datetime;

use super::*;

fn store(dir: &std::path::Path) -> Store {
    Store::open_with_clock(
        dir,
        Arc::new(ManualClock::new(datetime!(2026-11-20 12:00 UTC))),
    )
    .unwrap()
}

fn new_project(s: &Store) -> ProjectSummary {
    s.create_project(&NewProject {
        name: "contoso.example".into(),
        client: "ТОВ «Контосо Енерджі»".into(),
        targets: vec!["contoso.example".into(), "203.0.113.0/24".into()],
        excludes: vec!["mail.contoso.example".into()],
    })
    .unwrap()
}

fn meta(author: &str, app: &str) -> Metadata {
    let mut m = Metadata::new(DocFormat::Docx);
    m.author = Some(author.into());
    m.application = Some(app.into());
    m.software = vec![app.into()];
    m.created = Some("2024-03-01T08:15:00Z".into());
    m.people = vec![PersonRef {
        name: author.into(),
        role: PersonRole::Author,
        source: "core.xml".into(),
    }];
    m.paths = vec![PathRef {
        path: r"\\SRV-FILE01\public\x.dotx".into(),
        kind: PathKind::Unc,
        user: None,
        host: Some("SRV-FILE01".into()),
        source: "template".into(),
    }];
    m
}

fn add_analyzed(db: &ProjectDb, n: u64, m: &Metadata, text: Option<&str>) -> u64 {
    let d = db
        .add_document(&AddDoc {
            url: Some(format!("https://files.contoso.example/d{n}.docx")),
            name: format!("d{n}.docx"),
            source: "crawler".into(),
            first_scan: Some("s1".into()),
            status: DocStatus::Downloaded,
            size: 4096,
            sha256: Some(format!("{n:064x}")),
            ..Default::default()
        })
        .unwrap();
    db.set_analyzed(d.id, m, text).unwrap();
    d.id
}

#[test]
fn create_open_list_and_pragmas() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let p = new_project(&s);
    assert_eq!(p.id, "contoso.example");
    assert_eq!(p.risk, None, "no scans yet, so risk is null");
    assert_eq!((p.docs, p.findings, p.scans), (0, 0, 0));
    let p2 = new_project(&s);
    assert_eq!(p2.id, "contoso.example-2");
    let cyr = s
        .create_project(&NewProject {
            name: "Приклад Логістик".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(cyr.id, "pryklad-lohistyk");
    assert!(tmp.path().join("pryklad-lohistyk.foca").exists());
    drop(s);
    // reopen the store
    let s = store(tmp.path());
    let list = s.list_projects().unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].id, "pryklad-lohistyk", "newest first");
    let db = s.open_project("contoso.example").unwrap();
    let jm: String = db
        .conn()
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(jm, "wal");
    let fk: i64 = db
        .conn()
        .pragma_query_value(None, "foreign_keys", |r| r.get(0))
        .unwrap();
    assert_eq!(fk, 1);
    assert_eq!(
        db.schema_version().unwrap() as usize,
        schema::PROJECT_MIGRATIONS.len()
    );
    let sc = db.scope_get().unwrap();
    assert_eq!(sc.targets[0].kind, "domain");
    assert_eq!(sc.targets[1].kind, "cidr");
    let core = db.core_scope().unwrap();
    assert!(core.allows_host("portal.contoso.example"));
    assert!(!core.allows_host("mail.contoso.example"));
    assert!(
        !core.active_phase(),
        "only a scan run sets the active stage"
    );
    assert!(matches!(
        s.open_project("nope"),
        Err(StoreError::NotFound(_))
    ));
    // update and delete
    let u = s
        .update_project(
            "contoso.example",
            &ProjectPatch {
                archived: Some(true),
                notes: Some("x".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(u.archived);
    let dup = s.duplicate_project("contoso.example").unwrap();
    assert!(dup.client.ends_with("(копия)"));
    assert_eq!(
        s.open_project(&dup.id).unwrap().scope_get().unwrap().excl,
        vec!["mail.contoso.example"]
    );
    s.delete_project("contoso.example-2").unwrap();
    assert!(!tmp.path().join("contoso.example-2.foca").exists());
    assert_eq!(s.list_projects().unwrap().len(), 3);
}

#[test]
fn migration_v10_rewrites_the_old_empty_value_mark() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("old.foca");
    let old = format!(
        r#"[{{"name":"a.k.ua","ip":"{0}","note":"x {0} y"}}]"#,
        '\u{2014}'
    );
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        schema::migrate_to(&c, schema::PROJECT_MIGRATIONS, 9).unwrap();
        c.execute(
            "INSERT INTO project (id, name, created_at, updated_at) VALUES ('old', 'Old', 'x', 'x')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO entities (kind, json, updated_at) VALUES ('hosts', ?1, 'x')",
            [&old],
        )
        .unwrap();
    }
    let clock: Arc<dyn foca_core::Clock> =
        Arc::new(ManualClock::new(datetime!(2026-11-20 12:00 UTC)));
    let db = ProjectDb::open(&path, clock).unwrap();
    let raw: String = db
        .conn()
        .query_row("SELECT json FROM entities WHERE kind = 'hosts'", [], |r| {
            r.get(0)
        })
        .unwrap();
    // Only a whole value equal to the mark changes; text that merely contains it stays.
    assert!(raw.contains(r#""ip":"-""#), "{raw}");
    assert!(raw.contains(&format!("x {} y", '\u{2014}')), "{raw}");
}

#[test]
fn migration_from_v1_keeps_data() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("old.foca");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        schema::migrate_to(&c, schema::PROJECT_MIGRATIONS, 1).unwrap();
        c.execute(
            "INSERT INTO project (id, name, created_at, updated_at) VALUES ('old', 'Old', 'x', 'x')",
            [],
        )
        .unwrap();
        c.execute(
            r#"INSERT INTO scope (id, json) VALUES (1, '{"client":"К","num":"ПТ-1","from":"2026-11-01","to":"2026-11-30","forbid":["DoS"],"allow_active":true,"targets":[{"v":"k.ua","type":"domain","active":true},{"v":"x.ua","type":"domain","active":false}],"excl":[]}')"#,
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO documents (name, sha256, status) VALUES ('a.pdf', 'aa', 'downloaded')",
            [],
        )
        .unwrap();
        c.execute(
            r#"INSERT INTO settings (key, value_json) VALUES ('engine.active_acks', '[{"at":"x"}]')"#,
            [],
        )
        .unwrap();
        assert_eq!(schema::user_version(&c).unwrap(), 1);
    }
    let clock: Arc<dyn foca_core::Clock> =
        Arc::new(ManualClock::new(datetime!(2026-11-20 12:00 UTC)));
    let db = ProjectDb::open(&path, clock.clone()).unwrap();
    assert_eq!(db.schema_version().unwrap(), 10);
    // v7: the infrastructure table exists and starts empty in an old project
    assert!(db.infra_all().unwrap().is_empty());
    db.infra_put(
        "saas",
        "k.ua",
        &serde_json::json!({ "domain": "k.ua" }),
        Some("s1"),
    )
    .unwrap();
    assert_eq!(db.infra_list("saas").unwrap().len(), 1);
    // v4 drops the contract fields from the scope; v5 drops the active-checks switch, per-target
    // "active" marks and the confirmation log. Targets and exclusions survive.
    let raw: String = db
        .conn()
        .query_row("SELECT json FROM scope WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    assert!(
        !raw.contains("num")
            && !raw.contains("forbid")
            && !raw.contains("2026-11-30")
            && !raw.contains("active"),
        "{raw}"
    );
    let sc = db.scope_get().unwrap();
    assert_eq!(sc.client, "К");
    assert_eq!(sc.targets.len(), 2, "{raw}");
    assert_eq!(sc.targets[0].v, "k.ua");
    assert!(db.setting("engine.active_acks").unwrap().is_none());
    let docs = db.documents(true).unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].doc.name, "a.pdf");
    assert!(docs[0].text.is_none(), "new text_excerpt column");
    // A file newer than the program is an error, not silent corruption.
    db.conn().pragma_update(None, "user_version", 99).unwrap();
    drop(db);
    assert!(matches!(
        ProjectDb::open(&path, clock),
        Err(StoreError::Version { found: 99, .. })
    ));
}

#[test]
fn dedup_by_sha256() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let db = s.open_project(&new_project(&s).id).unwrap();
    let a = db
        .add_document(&AddDoc {
            url: Some("https://a/x.pdf".into()),
            name: "x.pdf".into(),
            sha256: Some("ab".repeat(32)),
            status: DocStatus::Downloaded,
            ..Default::default()
        })
        .unwrap();
    assert!(!a.existing);
    let b = db
        .add_document(&AddDoc {
            url: Some("https://b/copy.pdf".into()),
            name: "copy.pdf".into(),
            sha256: Some("ab".repeat(32)),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        b,
        DocAdded {
            id: a.id,
            existing: true
        }
    );
    // the same URL without a hash is not duplicated either
    let q1 = db
        .add_document(&AddDoc {
            url: Some("https://c/y.pdf".into()),
            name: "y.pdf".into(),
            ..Default::default()
        })
        .unwrap();
    let q2 = db
        .add_document(&AddDoc {
            url: Some("https://c/y.pdf".into()),
            name: "y.pdf".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(q1.id, q2.id);
    // the download turns out to be a copy of the first document: the queue record merges into it
    let r = db
        .set_downloaded(q1.id, &"ab".repeat(32), 10, Some("/tmp/y.pdf"), None)
        .unwrap();
    assert_eq!(
        r,
        DocAdded {
            id: a.id,
            existing: true
        }
    );
    assert_eq!(db.documents(true).unwrap().len(), 1);
}

const SECRET_TEXT: &str = "Data Source=SRV-SQL02;User ID=sa;Password=Kont0so#2024!;";

#[test]
fn finding_triage_survives_reanalysis() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let db = s.open_project(&new_project(&s).id).unwrap();
    add_analyzed(
        &db,
        1,
        &meta("Андрій Бондар", "Microsoft Office Word 15.0000"),
        Some("Data Source=SRV-SQL02;User ID=sa;Password=Kont0so#2024!;"),
    );
    add_analyzed(&db, 2, &meta("a.bondar", "Microsoft Excel 14.0300"), None);
    db.scan_start("s1", "std", false).unwrap();
    let a1 = db.run_analysis(Some("s1")).unwrap();
    assert!(!a1.findings.is_empty());
    let n1 = db.findings().unwrap().len();
    let secret = db
        .findings()
        .unwrap()
        .into_iter()
        .find(|f| f.provenance.rule == "secret")
        .unwrap();
    db.finding_set_status(secret.id, "confirmed").unwrap();
    db.finding_update(
        secret.id,
        &FindingPatch {
            sev: Some(Severity::High),
            notes: Some(vec![Note {
                text: "проверено".into(),
                who: "Вы".into(),
                time: "20.11, 12:00".into(),
            }]),
            tags: Some(vec!["в отчёт".into()]),
            ..Default::default()
        },
    )
    .unwrap();
    let eol = db
        .findings()
        .unwrap()
        .into_iter()
        .find(|f| f.provenance.rule == "eol-software")
        .unwrap();
    db.finding_set_status(eol.id, "false").unwrap();
    assert!(matches!(
        db.finding_set_status(eol.id, "bogus"),
        Err(StoreError::BadStatus(_))
    ));
    // re-analysis creates no duplicates and keeps triage
    db.run_analysis(Some("s2")).unwrap();
    let all = db.findings().unwrap();
    assert_eq!(all.len(), n1);
    let f = all.iter().find(|f| f.id == secret.id).unwrap();
    assert_eq!(f.status, FindingStatus::Confirmed);
    assert_eq!(f.sev, Severity::High, "user severity override is preserved");
    assert_eq!(f.notes.len(), 1);
    assert!(f.tags.contains(&"в отчёт".to_string()));
    assert_eq!(f.first_scan.as_deref(), Some("s1"));
    assert_eq!(
        all.iter().find(|f| f.id == eol.id).unwrap().status,
        FindingStatus::FalsePositive
    );
    // deleting the document with the secret hides the finding but does not mark it fixed
    db.delete_documents(&[1]).unwrap();
    db.run_analysis(Some("s3")).unwrap();
    let f = db.finding(secret.id).unwrap();
    assert_eq!(f.status, FindingStatus::Confirmed);
    assert_eq!(f.fixed_scan, None);
    assert!(!db.findings().unwrap().iter().any(|x| x.id == secret.id));
    // undo brings the finding back with its triage intact
    db.undo_last().unwrap();
    db.run_analysis(Some("s4")).unwrap();
    assert_eq!(
        db.finding(secret.id).unwrap().status,
        FindingStatus::Confirmed
    );
    assert!(db.findings().unwrap().iter().any(|x| x.id == secret.id));
    let sum = s.refresh_summary(&db).unwrap();
    assert_eq!(sum.scans, 1);
    assert!(sum.risk.is_some());
}

#[test]
fn resume_queue_after_crash() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let id = new_project(&s).id;
    {
        let db = s.open_project(&id).unwrap();
        for i in 0..5 {
            let r = db
                .task_enqueue(
                    "download",
                    &format!("https://x/{i}.pdf"),
                    "wayback",
                    Some("s1"),
                )
                .unwrap();
            assert!(r.is_some());
        }
        assert!(db
            .task_enqueue("download", "https://x/0.pdf", "cc", None)
            .unwrap()
            .is_none());
        let got = db.task_claim("download", 2).unwrap();
        assert_eq!(got.len(), 2);
        assert!(got
            .iter()
            .all(|t| t.state == TaskState::Downloading && t.attempts == 1));
        db.task_done(got[0].id, None).unwrap();
        // simulate a crash with one task left in `downloading`
    }
    let db = s.open_project(&id).unwrap();
    let c = db.task_counts().unwrap();
    assert_eq!((c.queued, c.downloading, c.done), (3, 1, 1));
    assert_eq!(db.tasks_resume().unwrap(), 4);
    assert_eq!(db.task_counts().unwrap().downloading, 0);
    // the same task is claimed again; attempts accumulate and it fails after the limit
    let t = db.task_claim("download", 1).unwrap().remove(0);
    assert_eq!(t.url, "https://x/1.pdf");
    assert_eq!(t.attempts, 2);
    assert_eq!(
        db.task_failed(t.id, "timeout", 3).unwrap(),
        TaskState::Queued
    );
    let t = db.task_claim("download", 1).unwrap().remove(0);
    assert_eq!(t.attempts, 3);
    assert_eq!(
        db.task_failed(t.id, "timeout", 3).unwrap(),
        TaskState::Failed
    );
    assert_eq!(
        db.task(t.id).unwrap().last_error.as_deref(),
        Some("timeout")
    );
    assert_eq!(db.tasks(Some(TaskState::Failed)).unwrap().len(), 1);
}

#[test]
fn undo_doc_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let db = s.open_project(&new_project(&s).id).unwrap();
    let a = add_analyzed(
        &db,
        1,
        &meta("a.bondar", "Microsoft Office Word 15.0000"),
        None,
    );
    let b = add_analyzed(
        &db,
        2,
        &meta("o.kovalenko", "Microsoft Excel 14.0300"),
        None,
    );
    db.run_analysis(None).unwrap();
    assert_eq!(db.delete_documents(&[a, b, 999]).unwrap(), 2);
    assert_eq!(db.delete_documents(&[a]).unwrap(), 0, "not deleted twice");
    let snap = db.snapshot(Value::Null, Value::Null).unwrap();
    assert!(snap.docs.iter().all(|d| d.deleted));
    assert_eq!(db.summary().unwrap().docs, 0);
    let e = db.undo_last().unwrap().unwrap();
    assert_eq!(e.action, "doc_delete");
    assert!(db.undo_last().unwrap().is_none());
    let snap = db.snapshot(Value::Null, Value::Null).unwrap();
    assert!(snap.docs.iter().all(|d| !d.deleted));
    assert_eq!(snap.docs[0].author.as_deref(), Some("a.bondar"));
    assert_eq!(db.restore_documents(&[a]).unwrap(), 0);
    db.delete_documents(&[b]).unwrap();
    assert_eq!(db.purge_deleted("2099-01-01").unwrap(), 1);
}

#[test]
fn snapshot_json_has_contract_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let id = new_project(&s).id;
    let db = s.open_project(&id).unwrap();
    add_analyzed(
        &db,
        1,
        &meta("Андрій Бондар", "Microsoft Office Word 15.0000"),
        Some("password: Buh2023!"),
    );
    db.add_document(&AddDoc {
        url: Some("https://files.contoso.example/q.pdf".into()),
        name: "q.pdf".into(),
        ..Default::default()
    })
    .unwrap();
    db.scan_start("s1", "std", false).unwrap();
    db.run_analysis(Some("s1")).unwrap();
    let snapshot = db.scan_snapshot().unwrap();
    db.scan_save(&Scan {
        id: "s1".into(),
        profile_id: "std".into(),
        status: "done".into(),
        started_at: "2026-11-20T12:00:00".into(),
        finished_at: Some("2026-11-20T12:20:00".into()),
        minutes: 20,
        targets: vec!["contoso.example".into()],
        egress: "Напрямую (реальный IP)".into(),
        docs: 2,
        snapshot,
        ..Default::default()
    })
    .unwrap();
    db.report_add(&Report {
        name: "Отчёт_пентест_contoso.example_v1.html".into(),
        tpl: "Полный отчёт пентеста".into(),
        fmt: "html".into(),
        lang: "RU".into(),
        ..Default::default()
    })
    .unwrap();
    db.log_request(&RequestLog {
        module: "crawler".into(),
        method: "GET".into(),
        url: "https://files.contoso.example/q.pdf".into(),
        host: "files.contoso.example".into(),
        status: Some(200),
        bytes: 1234,
        active: true,
        scan_id: Some("s1".into()),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(db.requests(Some("s1"), true).unwrap()[0].bytes, 1234);
    // brute-force annotation: the latest unannotated entry per URL; size only if the log lacked it
    for _ in 0..2 {
        db.log_request(&RequestLog {
            module: "fuzz".into(),
            method: "GET".into(),
            url: "https://files.contoso.example/zz9/".into(),
            host: "files.contoso.example".into(),
            status: Some(200),
            active: true,
            scan_id: Some("s1".into()),
            ..Default::default()
        })
        .unwrap();
    }
    let items = vec![(
        "https://files.contoso.example/zz9/".to_string(),
        "soft404".to_string(),
        Some("text/html".to_string()),
        5120,
    )];
    assert_eq!(db.annotate_requests(Some("s1"), "fuzz", &items).unwrap(), 1);
    let fz: Vec<RequestLog> = db
        .requests(Some("s1"), true)
        .unwrap()
        .into_iter()
        .filter(|r| r.module == "fuzz")
        .collect();
    assert_eq!(fz[0].note, None);
    assert_eq!(fz[1].note.as_deref(), Some("soft404"));
    assert_eq!(fz[1].ctype.as_deref(), Some("text/html"));
    assert_eq!(fz[1].bytes, 5120);
    assert!(db.requests(Some("other"), false).unwrap().is_empty());
    s.key_set("shodan", "Kx9fSECRETVALUEc8e4").unwrap();
    let snap = s.project_open(&id).unwrap();
    let v = serde_json::to_value(&snap).unwrap();
    for k in SNAPSHOT_KEYS {
        assert!(v.get(k).is_some(), "missing snapshot key {k}");
    }
    let has = |path: &str, keys: &[&str]| {
        let obj = v.pointer(path).unwrap_or_else(|| panic!("missing {path}"));
        for k in keys {
            assert!(obj.get(k).is_some(), "{path}: missing field {k}: {obj}");
        }
    };
    has(
        "/project",
        &[
            "id",
            "name",
            "client",
            "domain",
            "created_at",
            "archived",
            "notes",
        ],
    );
    has("/scope", &["client", "targets", "excl"]);
    has("/scope/targets/0", &["v", "type"]);
    has(
        "/docs/0",
        &[
            "id",
            "ext",
            "name",
            "url",
            "host",
            "title",
            "size",
            "first_scan",
            "deleted",
            "status",
            "author",
            "last_modified_by",
            "software",
            "created_at",
            "modified_at",
            "folder",
            "printer",
            "company",
            "camera",
            "gps",
            "revisions",
            "rdp",
            "lnk",
            "flags",
            "thumb_diff",
        ],
    );
    assert_eq!(v["docs"][1]["status"], "queued");
    has(
        "/people/0",
        &[
            "login", "name", "role", "pc", "color", "src", "src_kind", "docs",
        ],
    );
    has(
        "/software/0",
        &[
            "id", "name", "ver", "kind", "released", "eol_date", "eol", "cve", "cves", "dev",
            "docs",
        ],
    );
    has(
        "/hosts/0",
        &[
            "name",
            "ip",
            "role",
            "tech",
            "cloud",
            "services",
            "source",
            "internal",
            "sev",
            "first_scan",
        ],
    );
    has("/pcs/0", &["name", "kind", "users", "ip", "source", "docs"]);
    has("/paths/0", &["path", "docs", "user", "host"]);
    has(
        "/secrets/0",
        &["id", "type", "value", "doc", "where", "sev"],
    );
    has(
        "/findings/0",
        &[
            "id",
            "title",
            "sev",
            "status",
            "host",
            "category",
            "source",
            "module",
            "active",
            "time",
            "first_scan",
            "fixed_scan",
            "tags",
            "cve",
            "cvss",
            "mitre",
            "description",
            "recommendation",
            "evidence",
            "request",
            "url",
            "doc",
            "notes",
            "photos",
            "rel",
        ],
    );
    has("/findings/0/rel", &["people", "pcs", "docs"]);
    has("/events/0", &["y", "m", "ic", "k", "t", "s", "ref"]);
    has(
        "/scans/0",
        &[
            "id",
            "profile_id",
            "profile",
            "active",
            "trigger",
            "status",
            "started_at",
            "finished_at",
            "minutes",
            "targets",
            "egress",
            "sources",
            "docs",
            "snapshot",
        ],
    );
    assert_eq!(v["scans"][0]["profile"], "Стандартный");
    has(
        "/scans/0/snapshot",
        &["docs", "people", "hosts", "findings"],
    );
    has(
        "/reports/0",
        &[
            "id",
            "name",
            "tpl",
            "fmt",
            "lang",
            "created_at",
            "size",
            "opts",
        ],
    );
    has(
        "/settings",
        &["net", "keys", "power", "sec", "work_hours", "last_project"],
    );
    assert_eq!(v["settings"]["last_project"], id.as_str());
    // the API key secret is not stored, only its mask
    assert_eq!(v["settings"]["keys"]["shodan"]["mask"], "Kx9f…c8e4");
    let idx = std::fs::read(tmp.path().join("projects.db")).unwrap();
    let wal = std::fs::read(tmp.path().join("projects.db-wal")).unwrap_or_default();
    let hay = [idx, wal].concat();
    assert!(!hay.windows(11).any(|w| w == b"SECRETVALUE"));
    assert!(v["leaks"].is_object());
    assert_eq!(v["scan"]["running"], false);
    // project list: risk computed, scans present
    let p = s.refresh_summary(&db).unwrap();
    assert_eq!(p.scans, 1);
    assert_eq!(p.last_profile.as_deref(), Some("Стандартный"));
    assert!(p.risk.is_some());
    // scope through the UI API
    let sc = db
        .scope_set(&ScopeDto {
            basis: "Письмо владельца от 01.11".into(),
            ..db.scope_get().unwrap()
        })
        .unwrap();
    assert_eq!(sc.basis, "Письмо владельца от 01.11");
}

#[test]
fn settings_merge_and_strip() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let v = s
        .settings_set(&serde_json::json!({
            "net": { "proxy_on": true },
            "keys": { "brave": { "status": "ok", "mask": "BSAq…ab12", "value": "BSAqTOPSECRETab12" } }
        }))
        .unwrap();
    assert_eq!(v["net"]["proxy_on"], true);
    assert_eq!(v["net"]["threads"], 4, "deep merge");
    assert!(v["keys"]["brave"].get("value").is_none());
    assert_eq!(s.key_set("brave", "").unwrap()["status"], "none");
}

#[test]
fn report_result_snapshot_roundtrip_and_settings_reset() {
    let dir = tempfile::tempdir().unwrap();
    let s = store(dir.path());
    let p = new_project(&s);
    let db = s.open_project(&p.id).unwrap();
    let r = db
        .report_add(&Report {
            name: "Data_x_v1.csv".into(),
            result: serde_json::json!({ "finding_ids": [3, 1], "total": 2, "risk": null }),
            ..Default::default()
        })
        .unwrap();
    db.report_add(&Report {
        name: "old.md".into(),
        ..Default::default()
    })
    .unwrap();
    let list = db.reports().unwrap();
    let got = list.iter().find(|x| x.id == r.id).unwrap();
    assert_eq!(got.result["finding_ids"], serde_json::json!([3, 1]));
    assert!(list
        .iter()
        .find(|x| x.name == "old.md")
        .unwrap()
        .result
        .is_null());
    s.settings_set(&serde_json::json!({ "net": { "proxy_on": true }, "last_project": "x" }))
        .unwrap();
    let back = s.settings_reset().unwrap();
    assert_eq!(back["net"]["proxy_on"], false);
    assert!(back["last_project"].is_null());
}

#[test]
fn archive_copy_keeps_original_host() {
    use crate::project::archive_original;
    assert_eq!(
        archive_original("https://web.archive.org/web/20240301000000id_/https://a.ua/x.pdf"),
        Some("https://a.ua/x.pdf")
    );
    assert_eq!(
        archive_original("http://127.0.0.1:8788/web/2024/http://b.ua/y"),
        Some("http://b.ua/y")
    );
    assert_eq!(archive_original("https://a.ua/web/docs/x.pdf"), None);
    assert_eq!(archive_original("https://a.ua/x.pdf"), None);
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let db = s.open_project(&new_project(&s).id).unwrap();
    db.add_document(&AddDoc {
        url: Some("https://web.archive.org/web/20240301000000id_/https://www.a.ua/x.pdf".into()),
        name: "x.pdf".into(),
        status: DocStatus::Downloaded,
        ..Default::default()
    })
    .unwrap();
    let d = &db.documents(true).unwrap()[0];
    assert_eq!(d.doc.host.as_deref(), Some("www.a.ua"));
}

/// A document deleted by the user does not make its findings fixed; findings backed only by
/// that document are hidden (triage kept) and reappear once the document is restored.
#[test]
fn deleting_document_does_not_mark_its_findings_fixed() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let db = s.open_project(&new_project(&s).id).unwrap();
    let d1 = add_analyzed(
        &db,
        1,
        &meta("Андрій Бондар", "Microsoft Office Word 15.0000"),
        Some("Data Source=SRV-SQL02;User ID=sa;Password=Kont0so#2024!;"),
    );
    add_analyzed(&db, 2, &meta("a.bondar", "Microsoft Excel 14.0300"), None);
    db.scan_start("s1", "std", false).unwrap();
    db.run_analysis(Some("s1")).unwrap();
    let fl = db.findings().unwrap();
    let secret = fl
        .iter()
        .find(|f| f.provenance.rule == "secret")
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "{:?}",
                fl.iter()
                    .map(|f| (&f.provenance.rule, &f.provenance.docs))
                    .collect::<Vec<_>>()
            )
        });
    assert!(ProjectDb::finding_doc_ids(&secret).contains(&d1));
    db.delete_documents(&[d1]).unwrap();
    db.run_analysis(Some("s2")).unwrap();
    let all = db.findings().unwrap();
    assert!(
        all.iter().all(|f| f.status != FindingStatus::Fixed),
        "{:?}",
        all.iter().map(|f| (&f.title, f.status)).collect::<Vec<_>>()
    );
    assert!(
        !all.iter().any(|f| f.id == secret.id),
        "finding of a deleted document is hidden"
    );
    // restored: the finding is listed again and is not fixed
    db.restore_documents(&[d1]).unwrap();
    db.run_analysis(Some("s3")).unwrap();
    let f = db.finding(secret.id).unwrap();
    assert_ne!(f.status, FindingStatus::Fixed);
    assert!(db.findings().unwrap().iter().any(|x| x.id == secret.id));
}

/// A software finding shared by several documents stays fixed on rescan: an archive copy leaves
/// the status alone, and a live-site hit keeps the user's status and adds the reopened tag.
#[test]
fn fixed_status_survives_rescan_archive_and_live() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let db = s.open_project(&new_project(&s).id).unwrap();
    // web archive (Wayback) copy containing a secret
    let d = db
        .add_document(&AddDoc {
            url: Some("https://web.archive.org/web/2024id_/https://contoso.example/a.docx".into()),
            name: "a.docx".into(),
            source: "wayback".into(),
            first_scan: Some("s1".into()),
            status: DocStatus::Downloaded,
            size: 4096,
            sha256: Some(format!("{:064x}", 7)),
            ..Default::default()
        })
        .unwrap();
    db.set_analyzed(
        d.id,
        &meta("Андрій Бондар", "Microsoft Office Word 15.0000"),
        Some(SECRET_TEXT),
    )
    .unwrap();
    db.scan_start("s1", "std", false).unwrap();
    db.run_analysis(Some("s1")).unwrap();
    let fl = db.findings().unwrap();
    let secret = fl
        .iter()
        .find(|f| f.provenance.rule == "eol-software")
        .unwrap()
        .clone();
    db.finding_set_status(secret.id, "fixed").unwrap();
    db.run_analysis(Some("s2")).unwrap();
    let f = db.finding(secret.id).unwrap();
    assert_eq!(
        f.status,
        FindingStatus::Fixed,
        "an archive copy does not reopen a fixed finding"
    );
    assert!(!f.tags.iter().any(|t| t == crate::project::REOPENED_TAG));
    // the same secret in a document from the live site
    add_analyzed(
        &db,
        9,
        &meta("Андрій Бондар", "Microsoft Office Word 15.0000"),
        Some(SECRET_TEXT),
    );
    db.run_analysis(Some("s3")).unwrap();
    let f = db.finding(secret.id).unwrap();
    assert_eq!(
        f.status,
        FindingStatus::Fixed,
        "user status is not reset to new"
    );
    assert!(
        f.tags.iter().any(|t| t == crate::project::REOPENED_TAG),
        "{:?}",
        f.tags
    );
    assert!(crate::project::is_archive_doc(
        "crawler",
        "http://127.0.0.1:1/web/2025id_/http://example.test/a.pdf"
    ));
    assert!(!crate::project::is_archive_doc(
        "crawler",
        "https://files.contoso.example/d1.docx"
    ));
}

#[test]
fn concurrent_wal_writers_no_sqlite_busy() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let p = new_project(&s);
    drop(s);

    let dir = tmp.path().to_path_buf();
    let pid = p.id.clone();
    let handles: Vec<_> = (0..4)
        .map(|tid| {
            let d = dir.clone();
            let id = pid.clone();
            std::thread::spawn(move || {
                let st = Store::open(&d).unwrap();
                let pdb = st.open_project(&id).unwrap();
                for j in 0..8u64 {
                    let n = (tid as u64) * 100 + j;
                    st.settings_set(&serde_json::json!({
                        "monitor_status": { format!("w{tid}"): { "seq": j } }
                    }))
                    .unwrap();
                    pdb.add_document(&AddDoc {
                        url: Some(format!("https://files.contoso.example/w{n}.pdf")),
                        name: format!("w{n}.pdf"),
                        source: "crawler".into(),
                        status: DocStatus::Queued,
                        ..Default::default()
                    })
                    .unwrap();
                }
            })
        })
        .collect();

    for h in handles {
        h.join()
            .expect("worker thread completed without SQLITE_BUSY");
    }
    let st = Store::open(tmp.path()).unwrap();
    let pdb = st.open_project(&p.id).unwrap();
    assert_eq!(pdb.documents(false).unwrap().len(), 32);
}

#[test]
fn infra_records_upsert_list_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let db = s.open_project(&new_project(&s).id).unwrap();
    let v = |n: u32| serde_json::json!({ "host": "a.test", "n": n });
    db.infra_put("cert", "a.test:443", &v(1), Some("s1"))
        .unwrap();
    db.infra_put("cert", "a.test:443", &v(2), Some("s2"))
        .unwrap();
    db.infra_put("cert", "b.test:443", &v(3), None).unwrap();
    db.infra_put("role", "a.test", &v(4), None).unwrap();
    let certs = db.infra_list("cert").unwrap();
    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0].0, "a.test:443");
    assert_eq!(certs[0].1["n"], 2, "upsert replaces the record");
    assert_eq!(db.infra_get("role", "a.test").unwrap().unwrap()["n"], 4);
    assert!(db.infra_get("role", "x").unwrap().is_none());
    let all = db.infra_all().unwrap();
    assert_eq!(
        all.keys().cloned().collect::<Vec<_>>(),
        vec!["cert", "role"]
    );
    assert!(db.infra_delete("cert", "b.test:443").unwrap());
    assert!(!db.infra_delete("cert", "b.test:443").unwrap());
    assert_eq!(db.infra_list("cert").unwrap().len(), 1);
}

// ---------------- Full-text search (schema v8) ----------------

fn fts_doc(db: &ProjectDb, n: u64, name: &str, text: &str) -> u64 {
    let id = db
        .add_document(&AddDoc {
            url: Some(format!("https://files.contoso.example/f{n}")),
            name: name.into(),
            source: "crawler".into(),
            status: DocStatus::Downloaded,
            ..AddDoc::default()
        })
        .unwrap()
        .id;
    db.set_analyzed(id, &Metadata::new(DocFormat::Docx), Some(text))
        .unwrap();
    id
}

#[test]
fn fts_search_phrases_prefixes_cyrillic() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let p = new_project(&s);
    let db = s.open_project(&p.id).unwrap();
    let a = fts_doc(
        &db,
        1,
        "Наказ_15.docx",
        "НАКАЗ № 15\nПро затвердження плану робіт на 2026 рік. Відповідальний: Тестова Особа.",
    );
    let b = fts_doc(
        &db,
        2,
        "Звіт.pdf",
        "Звіт про виконання плану. Мʼясокомбінат, Київ.",
    );
    let o = SearchOpts::default();
    // Case-insensitive Cyrillic, prefix on the last term.
    let r = db.search_text("план", &o).unwrap();
    assert_eq!(r.total, 2);
    let r = db.search_text("ЗАТВЕРДЖ", &o).unwrap();
    assert_eq!(r.hits.len(), 1);
    assert_eq!(r.hits[0].doc, a);
    assert!(
        r.hits[0].snippet.contains("{{h:затвердження}}"),
        "{}",
        r.hits[0].snippet
    );
    // Phrase.
    let r = db.search_text("\"плану робіт\"", &o).unwrap();
    assert_eq!(r.hits.iter().map(|h| h.doc).collect::<Vec<_>>(), [a]);
    assert!(db
        .search_text("\"робіт плану\"", &o)
        .unwrap()
        .hits
        .is_empty());
    // Apostrophe variants fold alike; Cyrillic letters are case-folded but й/ї stay distinct.
    assert_eq!(db.search_text("м'ясокомбінат", &o).unwrap().total, 1);
    assert_eq!(db.search_text("КИЇВ", &o).unwrap().total, 1);
    assert_eq!(db.search_text("киів", &o).unwrap().total, 0);
    // Name match, exclusion.
    let r = db.search_text("наказ_15", &o).unwrap();
    assert!(r.hits[0].in_name);
    let r = db.search_text("плану -звіт", &o).unwrap();
    assert_eq!(r.hits.iter().map(|h| h.doc).collect::<Vec<_>>(), [a]);
    // Hostile input never errors.
    for q in [
        "\"",
        "NEAR(",
        "a:b",
        "*",
        "-",
        "))((",
        "AND OR NOT",
        "\u{2}x\u{3}",
        "'; DROP TABLE documents; --",
    ] {
        db.search_text(q, &o).unwrap();
    }
    assert!(db.search_text("", &o).unwrap().query.is_empty());
    let _ = b;
    db.fts_check().unwrap();
}

#[test]
fn fts_follows_delete_restore_update_purge() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let p = new_project(&s);
    let db = s.open_project(&p.id).unwrap();
    let a = fts_doc(&db, 1, "a.docx", "унікальнеслово перше");
    let o = SearchOpts::default();
    assert_eq!(db.search_text("унікальнеслово", &o).unwrap().total, 1);
    db.delete_documents(&[a]).unwrap();
    assert_eq!(db.search_text("унікальнеслово", &o).unwrap().total, 0);
    let all = SearchOpts {
        include_deleted: true,
        ..SearchOpts::default()
    };
    let r = db.search_text("унікальнеслово", &all).unwrap();
    assert!(r.hits[0].deleted);
    db.undo_last().unwrap();
    assert_eq!(db.search_text("унікальнеслово", &o).unwrap().total, 1);
    // Re-analysis replaces the indexed text.
    db.set_analyzed(a, &Metadata::new(DocFormat::Docx), Some("інший текст"))
        .unwrap();
    assert_eq!(db.search_text("унікальнеслово", &o).unwrap().total, 0);
    assert_eq!(db.search_text("інший", &o).unwrap().total, 1);
    // Hard delete removes the row from the index.
    db.delete_documents(&[a]).unwrap();
    db.purge_deleted("9999").unwrap();
    assert_eq!(db.search_text("інший", &all).unwrap().total, 0);
    db.fts_check().unwrap();
    db.fts_rebuild().unwrap();
    db.fts_check().unwrap();
}

#[test]
fn fts_snippets_mask_secrets_and_pii() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let p = new_project(&s);
    let db = s.open_project(&p.id).unwrap();
    fts_doc(
        &db,
        1,
        "dostup.docx",
        "Доступ до сервера: password = Kont0so#2024! Картка 4111 1111 1111 1111 для оплати хостингу.",
    );
    let r = db.search_text("хостингу", &SearchOpts::default()).unwrap();
    let h = &r.hits[0];
    assert!(!h.snippet.contains("Kont0so#2024!"), "{}", h.snippet);
    assert!(!h.snippet.contains("4111 1111 1111 1111"), "{}", h.snippet);
    // The card number is masked before storage; the snippet flags the mask.
    assert!(
        h.masked.iter().any(|l| l.starts_with("pii")),
        "{:?}",
        h.masked
    );
    assert!(
        h.masked.iter().any(|l| l.starts_with("secret:")),
        "{:?}",
        h.masked
    );
}

#[test]
fn migration_v7_to_v8_indexes_existing_text() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("v7.foca");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        schema::migrate_to(&c, schema::PROJECT_MIGRATIONS, 7).unwrap();
        c.execute(
            "INSERT INTO project (id, name, created_at, updated_at) VALUES ('v7', 'V7', 'x', 'x')",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO scope (id, json) VALUES (1, '{}')", [])
            .unwrap();
        c.execute(
            "INSERT INTO documents (name, sha256, status, text_excerpt) VALUES
             ('old.docx', 'aa', 'analyzed', 'Старий документ про бюджет'),
             ('none.pdf', 'bb', 'downloaded', NULL),
             ('trash.docx', 'cc', 'analyzed', 'бюджет у кошику')",
            [],
        )
        .unwrap();
        c.execute(
            "UPDATE documents SET deleted_at = '2026-01-01' WHERE name = 'trash.docx'",
            [],
        )
        .unwrap();
    }
    let clock: Arc<dyn foca_core::Clock> =
        Arc::new(ManualClock::new(datetime!(2026-11-20 12:00 UTC)));
    let db = ProjectDb::open(&path, clock).unwrap();
    assert_eq!(db.schema_version().unwrap(), 10);
    let r = db.search_text("бюджет", &SearchOpts::default()).unwrap();
    assert_eq!(r.total, 1);
    assert_eq!(r.hits[0].name, "old.docx");
    db.fts_check().unwrap();
    // A document added after the migration is indexed by the trigger.
    fts_doc(&db, 9, "new.docx", "новий бюджет");
    assert_eq!(
        db.search_text("бюджет", &SearchOpts::default())
            .unwrap()
            .total,
        2
    );
}

#[test]
fn rules_config_stored_and_validated() {
    use foca_analysis::rules::{RulesConfig, UserRule};
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let p = new_project(&s);
    let db = s.open_project(&p.id).unwrap();
    assert_eq!(db.rules_config().unwrap(), RulesConfig::default());
    let good = RulesConfig {
        presets: vec!["crypto".into()],
        rules: vec![UserRule {
            id: "proj".into(),
            title: "Код проєкту".into(),
            pattern: r"PRJ-\d{4}".into(),
            ..UserRule::default()
        }],
    };
    db.set_rules_config(&good).unwrap();
    assert_eq!(db.rules_config().unwrap(), good);
    assert_eq!(db.rule_set().unwrap().scan("див. PRJ-0042", "x").len(), 1);
    let mut bad = good.clone();
    bad.rules[0].pattern = "(a+".into();
    let e = db.set_rules_config(&bad).unwrap_err();
    assert_eq!(e.code(), "bad_args");
    assert!(e.to_string().contains("proj"));
    assert_eq!(db.rules_config().unwrap(), good, "nothing stored on error");
}

#[test]
fn failed_import_leaves_no_broken_index_row() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let p = new_project(&s);
    let src = s.file_of(&p.id).unwrap();
    // A database that opens and migrates fine but cannot be summarised.
    let broken = tmp.path().join("broken.sqlite");
    std::fs::copy(&src, &broken).unwrap();
    {
        let c = rusqlite::Connection::open(&broken).unwrap();
        c.execute_batch("PRAGMA journal_mode=DELETE; DROP TABLE documents;")
            .unwrap();
    }
    let bytes = std::fs::read(&broken).unwrap();
    std::fs::remove_file(&broken).unwrap();
    let files_before = std::fs::read_dir(tmp.path()).unwrap().count();
    assert!(s.import_project_db(&bytes, Some("broken")).is_err());
    let list = s.list_projects().expect("index must stay readable");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, p.id);
    assert_eq!(
        std::fs::read_dir(tmp.path()).unwrap().count(),
        files_before,
        "the imported file must be removed on failure"
    );
}

#[test]
fn project_wipe_streams_with_bounded_buffer() {
    struct Probe {
        total: u64,
        max: usize,
        nonzero: bool,
    }
    impl std::io::Write for Probe {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.total += b.len() as u64;
            self.max = self.max.max(b.len());
            self.nonzero |= b.iter().any(|&x| x != 0);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let len = 3 * WIPE_CHUNK as u64 + 17;
    let mut p = Probe {
        total: 0,
        max: 0,
        nonzero: false,
    };
    zero_fill(&mut p, len).unwrap();
    assert_eq!(p.total, len);
    assert!(p.max <= WIPE_CHUNK);
    assert!(!p.nonzero);

    // End to end: the project file is overwritten and removed.
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let pr = new_project(&s);
    let path = s.file_of(&pr.id).unwrap();
    assert!(path.exists());
    s.delete_project(&pr.id).unwrap();
    assert!(!path.exists());
    assert!(s.list_projects().unwrap().is_empty());
}

#[test]
fn out_of_scope_tag_follows_latest_result() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let p = new_project(&s);
    let db = s.open_project(&p.id).unwrap();
    let oos = foca_analysis::findings::OUT_OF_SCOPE_TAG;
    let finding = |tags: Vec<String>| foca_core::api::Finding {
        id: 77,
        title: "Shodan CVE".into(),
        sev: Severity::High,
        status: foca_core::FindingStatus::New,
        host: "cdn.example.net".into(),
        category: "vuln".into(),
        source: String::new(),
        module: String::new(),
        active: false,
        time: String::new(),
        first_scan: None,
        fixed_scan: None,
        tags,
        cve: vec![],
        cvss: None,
        mitre: String::new(),
        description: String::new(),
        recommendation: String::new(),
        evidence: String::new(),
        request: String::new(),
        url: None,
        doc: None,
        notes: vec![],
        photos: vec![],
        rel: Default::default(),
        provenance: Default::default(),
    };
    let mut a = foca_analysis::Analysis {
        findings: vec![finding(vec![oos.into()])],
        ..Default::default()
    };
    db.apply_analysis(&a, Some("s1")).unwrap();
    assert!(db.finding(77).unwrap().tags.iter().any(|t| t == oos));
    assert_eq!(
        foca_analysis::findings::risk(&db.findings().unwrap(), true).score,
        Some(0)
    );
    // Back in scope on the next scan: the marker is dropped.
    a.findings = vec![finding(vec![])];
    db.apply_analysis(&a, Some("s2")).unwrap();
    assert!(!db.finding(77).unwrap().tags.iter().any(|t| t == oos));

    // A user tag and a legacy Russian tag stored by an older version.
    db.finding_update(
        77,
        &FindingPatch {
            tags: Some(vec!["клиент".into(), "секрет".into(), "вне скоупа".into()]),
            ..Default::default()
        },
    )
    .unwrap();
    // Read: legacy tags come back as codes, the user tag stays.
    assert_eq!(db.finding(77).unwrap().tags, ["клиент", "secret", oos]);
    // Rescan: the CDN edge tag reaches the stored row, the stale scope marker goes.
    a.findings = vec![finding(vec!["cdn_edge:cloudflare".into()])];
    db.apply_analysis(&a, Some("s3")).unwrap();
    assert_eq!(
        db.finding(77).unwrap().tags,
        ["клиент", "secret", "cdn_edge:cloudflare"]
    );
    // The provider changes: the old edge tag is replaced, not kept next to the new one.
    a.findings = vec![finding(vec!["cdn_edge:fastly".into()])];
    db.apply_analysis(&a, Some("s4")).unwrap();
    assert_eq!(
        db.finding(77).unwrap().tags,
        ["клиент", "secret", "cdn_edge:fastly"]
    );
}

#[test]
fn error_docs_carry_reason_and_http_status() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let db = s.open_project(&new_project(&s).id).unwrap();
    let add = |n: &str| {
        db.add_document(&AddDoc {
            url: Some(format!("https://a/{n}")),
            name: n.into(),
            sha256: Some(format!("{:064x}", n.len())),
            status: DocStatus::Downloaded,
            ..Default::default()
        })
        .unwrap()
        .id
    };
    let (a, b, c) = (add("a.pdf"), add("bb.pdf"), add("ccc.pdf"));
    let (p, l) = (add("dddd.pdf"), add("eeeee.pdf"));
    db.set_doc_error_kind(a, crate::DocErrorKind::Http, "HTTP 404")
        .unwrap();
    db.set_doc_error(b, "не удалось разобрать файл: повреждён")
        .unwrap();
    // a parse error whose text mentions an HTTP code is still a parse error without a status
    db.set_doc_error(p, "не удалось разобрать файл: HTTP 404 в теле")
        .unwrap();
    // a row written before the error kind existed reads as a parse error
    db.set_doc_error(l, "HTTP 500 legacy").unwrap();
    db.conn()
        .execute(
            "UPDATE documents SET error_kind = NULL WHERE id = ?1",
            [l as i64],
        )
        .unwrap();
    let docs = db.ui_docs().unwrap();
    let get = |id: u64| docs.iter().find(|d| d.id == id).unwrap().clone();
    assert_eq!(get(a).status, "error");
    assert_eq!(get(a).error_kind.as_deref(), Some("http"));
    assert_eq!(get(a).http_status, Some(404));
    assert_eq!(get(a).error_reason.as_deref(), Some("HTTP 404"));
    assert_eq!(get(b).error_kind.as_deref(), Some("parse"));
    assert_eq!(get(b).http_status, None);
    assert!(get(b).error_reason.unwrap().contains("повреждён"));
    assert_eq!(get(p).error_kind.as_deref(), Some("parse"));
    assert_eq!(get(p).http_status, None, "status only for HTTP failures");
    assert_eq!(get(l).error_kind.as_deref(), Some("parse"));
    assert_eq!(get(l).http_status, None);
    let ok = get(c);
    assert!(ok.http_status.is_none() && ok.error_reason.is_none() && ok.error_kind.is_none());
    let v = serde_json::to_value(&ok).unwrap();
    assert!(
        v.get("error_reason").is_none() && v.get("error_kind").is_none(),
        "absent on healthy documents"
    );
    let v = serde_json::to_value(get(b)).unwrap();
    assert_eq!(v["error_kind"], "parse");
    assert_eq!(
        crate::project::http_status_of("download: HTTP 503 Service Unavailable"),
        Some(503)
    );
    assert_eq!(crate::project::http_status_of("HTTP 99"), None);
}

/// A downloaded, analyzed document first found in `scan`, with a real file in `dir`.
fn scan_doc(db: &ProjectDb, dir: &std::path::Path, n: u64, scan: &str, text: Option<&str>) -> u64 {
    let path = dir.join(format!("d{n}.docx"));
    std::fs::write(&path, b"document body").unwrap();
    let d = db
        .add_document(&AddDoc {
            url: Some(format!("https://files.contoso.example/d{n}.docx")),
            name: format!("d{n}.docx"),
            source: "crawler".into(),
            first_scan: Some(scan.into()),
            status: DocStatus::Downloaded,
            size: 4096,
            sha256: Some(format!("{n:064x}")),
            local_path: Some(path.to_string_lossy().into_owned()),
            ..Default::default()
        })
        .unwrap();
    db.set_analyzed(
        d.id,
        &meta("Андрій Бондар", "Microsoft Office Word 15.0000"),
        text,
    )
    .unwrap();
    db.task_enqueue(
        "download",
        &format!("https://files.contoso.example/d{n}.docx"),
        "crawler",
        Some(scan),
    )
    .unwrap();
    db.log_request(&RequestLog {
        module: "crawler".into(),
        method: "GET".into(),
        url: format!("https://files.contoso.example/d{n}.docx"),
        host: "files.contoso.example".into(),
        status: Some(200),
        scan_id: Some(scan.into()),
        ..Default::default()
    })
    .unwrap();
    d.id
}

fn save_scan(db: &ProjectDb, id: &str, started: &str) {
    db.scan_save(&Scan {
        id: id.into(),
        profile_id: "std".into(),
        status: "done".into(),
        started_at: started.into(),
        finished_at: Some(started.into()),
        ..Default::default()
    })
    .unwrap();
}

fn reanalyze(db: &ProjectDb, _: &ScanErase) -> Result<()> {
    db.run_analysis(None).map(|_| ())
}

/// Deleting the first of two scans: its own document, file, requests, queue rows, settings and
/// scan-only finding go; a finding the second scan also produced stays with first scan moved.
#[test]
fn scan_delete_keeps_shared_findings_and_drops_the_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let db = s.open_project(&new_project(&s).id).unwrap();
    let files = tmp.path().join("files");
    std::fs::create_dir_all(&files).unwrap();
    save_scan(&db, "s1", "2026-11-01T10:00:00");
    let d1 = scan_doc(&db, &files, 1, "s1", Some(SECRET_TEXT));
    db.run_analysis(Some("s1")).unwrap();
    save_scan(&db, "s2", "2026-11-02T10:00:00");
    let d2 = scan_doc(&db, &files, 2, "s2", None);
    db.run_analysis(Some("s2")).unwrap();
    db.set_setting("engine.scan.s1", &serde_json::json!({ "added": {} }))
        .unwrap();
    db.set_setting("engine.scan.s2", &serde_json::json!({ "added": {} }))
        .unwrap();
    let all = db.findings().unwrap();
    let secret = all
        .iter()
        .find(|f| f.provenance.rule == "secret")
        .unwrap()
        .clone();
    let eol = all
        .iter()
        .find(|f| f.provenance.rule == "eol-software")
        .unwrap()
        .clone();
    assert_eq!(secret.first_scan.as_deref(), Some("s1"));
    assert_eq!(eol.first_scan.as_deref(), Some("s1"));
    assert!(ProjectDb::finding_doc_ids(&eol).contains(&d2));
    // triage on the shared finding survives the deletion
    db.finding_set_status(eol.id, "confirmed").unwrap();

    let out = db.scan_delete("s1", reanalyze).unwrap();
    assert_eq!(out.docs, vec![d1]);
    assert_eq!(out.requests, 1);
    assert_eq!(out.tasks, 1);
    assert_eq!(out.later, vec!["s2".to_string()]);
    assert_eq!(out.findings, vec![secret.id]);
    assert_eq!(out.files.len(), 1);
    assert!(out.files[0].ends_with("d1.docx"));

    assert!(db.scans().unwrap().iter().all(|x| x.id != "s1"));
    let docs = db.documents(true).unwrap();
    assert_eq!(docs.iter().map(|d| d.doc.id).collect::<Vec<_>>(), vec![d2]);
    assert!(db.requests(Some("s1"), false).unwrap().is_empty());
    assert_eq!(db.requests(Some("s2"), false).unwrap().len(), 1);
    assert_eq!(db.tasks(None).unwrap().len(), 1);
    assert!(db.setting("engine.scan.s1").unwrap().is_none());
    assert!(db.setting("engine.scan.s2").unwrap().is_some());
    assert!(matches!(
        db.finding(secret.id),
        Err(StoreError::NotFound(_))
    ));
    let kept = db.finding(eol.id).unwrap();
    assert_eq!(kept.first_scan.as_deref(), Some("s2"));
    assert_eq!(kept.status, FindingStatus::Confirmed);
    // the analysis no longer sees the deleted document's author text or file
    assert!(db
        .findings()
        .unwrap()
        .iter()
        .all(|f| !ProjectDb::finding_doc_ids(f).contains(&d1)));

    // a document of a deleted scan that a later scan still listed stays, moved to that scan
    save_scan(&db, "s3", "2026-11-03T10:00:00");
    let d3 = scan_doc(&db, &files, 3, "s3", Some(SECRET_TEXT));
    db.run_analysis(Some("s3")).unwrap();
    let mut s4 = Scan {
        id: "s4".into(),
        profile_id: "std".into(),
        status: "done".into(),
        started_at: "2026-11-04T10:00:00".into(),
        ..Default::default()
    };
    s4.snapshot.docs = vec![d2, d3];
    db.scan_save(&s4).unwrap();
    let out = db.scan_delete("s3", reanalyze).unwrap();
    assert!(out.docs.is_empty() && out.files.is_empty());
    let d = db.document(d3).unwrap();
    assert_eq!(d.first_scan.as_deref(), Some("s4"));
    let secret3 = db
        .findings()
        .unwrap()
        .into_iter()
        .find(|f| f.provenance.rule == "secret")
        .unwrap();
    assert_eq!(secret3.first_scan.as_deref(), Some("s4"));
}

/// A finding fixed by the deleted (last) scan is no longer fixed; one fixed by a scan followed by
/// another moves its fix to the next scan.
#[test]
fn scan_delete_recomputes_fixed_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let db = s.open_project(&new_project(&s).id).unwrap();
    let files = tmp.path().join("files");
    std::fs::create_dir_all(&files).unwrap();
    for (id, t) in [
        ("s1", "2026-11-01T10:00:00"),
        ("s2", "2026-11-02T10:00:00"),
        ("s3", "2026-11-03T10:00:00"),
    ] {
        save_scan(&db, id, t);
    }
    scan_doc(&db, &files, 1, "s1", Some(SECRET_TEXT));
    db.run_analysis(Some("s1")).unwrap();
    let fl = db.findings().unwrap();
    let (a, b) = (fl[0].id, fl[1].id);
    db.conn()
        .execute(
            "UPDATE findings SET status = 'fixed', fixed_scan = 's3', tags_json = '[\"reopened\"]' WHERE id = ?1",
            [a as i64],
        )
        .unwrap();
    db.conn()
        .execute(
            "UPDATE findings SET status = 'fixed', fixed_scan = 's2' WHERE id = ?1",
            [b as i64],
        )
        .unwrap();
    db.scan_delete("s3", reanalyze).unwrap();
    let fa = db.finding(a).unwrap();
    assert_eq!((fa.status, fa.fixed_scan), (FindingStatus::New, None));
    assert!(!fa.tags.iter().any(|t| t == crate::project::REOPENED_TAG));
    db.scan_delete("s2", reanalyze).unwrap();
    let fb = db.finding(b).unwrap();
    assert_eq!((fb.status, fb.fixed_scan), (FindingStatus::New, None));
    assert_eq!(db.scans().unwrap().len(), 1);
}

#[test]
fn reference_case_is_marked_in_the_summary() {
    let tmp = tempfile::tempdir().unwrap();
    let s = store(tmp.path());
    let p = new_project(&s);
    let db = s.open_project(&p.id).unwrap();
    assert!(!db.summary().unwrap().reference);
    // a case imported before the marker existed: its documents come from the reference archive
    db.add_document(&AddDoc {
        name: "a.docx".into(),
        source: format!("zip:{}", crate::project::REFERENCE_CASE_ARCHIVE),
        status: DocStatus::Downloaded,
        sha256: Some(format!("{:064x}", 5)),
        ..Default::default()
    })
    .unwrap();
    assert!(db.summary().unwrap().reference);
    let p2 = new_project(&s);
    let db2 = s.open_project(&p2.id).unwrap();
    db2.set_setting(crate::project::REFERENCE_CASE_KEY, &serde_json::json!(true))
        .unwrap();
    assert!(db2.is_reference_case().unwrap());
}
