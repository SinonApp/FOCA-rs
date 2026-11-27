//! `analyze` tests on synthetic documents.

use super::*;
use foca_core::{Camera, Gps, PathKind, PathRef, PersonRef, ServerRef};
use time::macros::datetime;

fn doc(id: u64, name: &str, meta: Metadata) -> Document {
    Document {
        id,
        name: name.into(),
        ext: name.rsplit('.').next().unwrap_or("").into(),
        url: Some(format!("https://files.contoso.example/docs/{name}")),
        size: 2048,
        sha256: format!("{id:064x}"),
        status: DocStatus::Analyzed,
        metadata: Some(meta),
        ..Default::default()
    }
}

fn person(name: &str, role: PersonRole) -> PersonRef {
    PersonRef {
        name: name.into(),
        role,
        source: "test".into(),
    }
}

fn office(author: &str, lmb: &str, app: &str) -> Metadata {
    let mut m = Metadata::new(DocFormat::Docx);
    m.author = Some(author.into());
    m.last_modified_by = Some(lmb.into());
    m.application = Some(app.into());
    m.software = vec![app.into()];
    m.created = Some("2024-03-01T08:15:00Z".into());
    m.modified = Some("2024-03-14T18:42:00+02:00".into());
    m.people = vec![
        person(author, PersonRole::Author),
        person(lmb, PersonRole::LastModifiedBy),
    ];
    m
}

fn prev_now() -> PrevState {
    PrevState {
        now: Some(datetime!(2026-11-20 12:00 UTC)),
        scan_id: Some("s1".into()),
        ..Default::default()
    }
}

fn scope() -> Scope {
    Scope::from_lines("contoso.example", "mail.contoso.example").0
}

fn sample() -> Vec<Document> {
    let mut a = office("Андрій Бондар", "a.bondar", "Microsoft Office Word 15.0000");
    a.paths = vec![PathRef {
        path: r"\\SRV-FILE01\public\Шаблони\Договір.dotx".into(),
        kind: PathKind::Unc,
        user: None,
        host: Some("SRV-FILE01".into()),
        source: "template".into(),
    }];
    a.servers = vec![ServerRef {
        name: "SRV-FILE01".into(),
        source: "path".into(),
    }];
    a.emails = vec!["o.kovalenko@contoso.example".into()];
    a.revisions = vec![foca_core::RevisionRef {
        kind: RevisionKind::Delete,
        author: Some("a.bondar".into()),
        date: Some("2024-03-14T17:02:00Z".into()),
        text: "1 250 000 грн".into(),
    }];
    let b = office(
        "Олена Коваленко",
        "Administrator",
        "Microsoft Excel 14.0300",
    );
    let mut c = Metadata::new(DocFormat::Jpeg);
    c.camera = Some(Camera {
        make: Some("Apple".into()),
        model: Some("iPhone 13 Pro".into()),
        owner: Some("v.tkachenko".into()),
        ..Default::default()
    });
    c.fields.insert("exif:Software".into(), "16.6".into());
    c.gps = Some(Gps {
        lat: 47.92,
        lon: 33.43,
        alt: None,
    });
    c.created = Some("2024-08-02T11:05:33".into());
    c.servers = vec![ServerRef {
        name: "ENG-WS11".into(),
        source: "exif:HostComputer".into(),
    }];
    c.people = vec![person("v.tkachenko", PersonRole::Owner)];
    vec![
        doc(1, "contract.docx", a),
        doc(2, "budget.xlsx", b),
        doc(3, "photo.jpg", c),
    ]
}

#[test]
fn end_to_end_entities() {
    let docs = sample();
    let texts = [
        Some("Data Source=SRV-SQL02;User ID=sa;Password=Kont0so#2024!;"),
        None,
        None,
    ];
    let inputs: Vec<DocInput> = docs
        .iter()
        .zip(texts)
        .map(|(d, t)| DocInput::new(d).with_text(t))
        .collect();
    let a = analyze(&inputs, &scope(), &prev_now());
    let logins: Vec<&str> = a.people.iter().map(|p| p.login.as_str()).collect();
    assert!(logins.contains(&"a.bondar"), "{logins:?}");
    assert!(logins.contains(&"o.kovalenko"), "{logins:?}");
    assert!(logins.contains(&"v.tkachenko"), "{logins:?}");
    let admin = a
        .people
        .iter()
        .find(|p| p.service)
        .expect("service account");
    assert_eq!(admin.name, "Administrator");
    let vt = a.people.iter().find(|p| p.login == "v.tkachenko").unwrap();
    assert_eq!(vt.pc.as_deref(), Some("ENG-WS11"));
    let d1 = &a.docs[0];
    assert_eq!(d1.author.as_deref(), Some("a.bondar"));
    assert_eq!(d1.software.as_deref(), Some("word2013"));
    assert_eq!(d1.modified_at.as_deref(), Some("2024-03-14T18:42:00"));
    assert_eq!(d1.folder.as_deref(), Some(r"\\SRV-FILE01\public\Шаблони"));
    for f in ["path", "secret", "eol", "revisions"] {
        assert!(d1.flags.iter().any(|x| x == f), "{f}: {:?}", d1.flags);
    }
    assert_eq!(a.docs[2].software.as_deref(), Some("ios166"));
    assert!(a.docs[2].flags.contains(&"gps".to_string()));
    assert_eq!(a.gps.len(), 1);
    // Hosts.
    let h = a
        .hosts
        .iter()
        .find(|h| h.name == "files.contoso.example")
        .unwrap();
    assert_eq!(h.scope, "in_scope");
    assert!(a.hosts.iter().any(|h| h.name == "SRV-SQL02" && h.internal));
    assert!(a.pcs.iter().any(|p| p.name == "ENG-WS11" && p.kind == "ws"));
    // Secret.
    let s = a.secrets.iter().find(|s| s.kind == "conn").unwrap();
    assert_eq!(s.value.expose(), "Kont0so#2024!");
    let fid = s.finding.expect("secret is linked to a finding");
    let f = a.findings.iter().find(|f| f.id == fid).unwrap();
    assert_eq!(f.sev, Severity::Critical);
    assert!(f.evidence.contains("{{s:"));
    assert_eq!(f.provenance.rule, "secret");
    // Software and EOL.
    let w = a.software.iter().find(|s| s.id == "word2013").unwrap();
    assert!(w.eol);
    assert!(a
        .findings
        .iter()
        .any(|f| f.provenance.rule == "eol-software" && f.title.contains("Word 2013")));
    assert!(a.findings.iter().any(|f| f.provenance.rule == "gps"));
    assert!(a.findings.iter().any(|f| f.provenance.rule == "revisions"));
    assert!(a.risk.score.unwrap() > 0);
    assert!(a.graph.neighbors("person:a.bondar").contains(&"doc:1"));
    assert_eq!(a.activity.tz.as_deref(), Some("UTC+2"));
    // The 7×24 activity grid agrees with the hour and weekday totals.
    let m = &a.activity.matrix;
    assert_eq!((m.len(), m[0].len()), (7, 24));
    for (w, row) in m.iter().enumerate() {
        assert_eq!(row.iter().sum::<u32>(), a.activity.weekdays[w]);
    }
    for h in 0..24 {
        assert_eq!(m.iter().map(|r| r[h]).sum::<u32>(), a.activity.hours[h]);
    }
    assert_eq!(m.iter().flatten().sum::<u32>(), a.activity.total);
    // JSON shape.
    let v = serde_json::to_value(&a.docs[0]).unwrap();
    for k in [
        "id", "ext", "status", "author", "software", "flags", "rdp", "lnk", "gps",
    ] {
        assert!(v.get(k).is_some(), "doc.{k}");
    }
}

#[test]
fn triage_survives_rescan_and_resolved() {
    let docs = sample();
    let inputs: Vec<DocInput> = docs.iter().map(DocInput::new).collect();
    let a1 = analyze(&inputs, &scope(), &prev_now());
    let target = a1
        .findings
        .iter()
        .find(|f| f.provenance.rule == "gps")
        .unwrap()
        .id;
    let mut prev = a1.prev_state(Some("s2".into()), Some(datetime!(2026-11-21 9:00 UTC)));
    let pf = prev.findings.get_mut(&target).unwrap();
    pf.status = FindingStatus::FalsePositive;
    pf.notes.push(Note {
        text: "проверено".into(),
        who: "Вы".into(),
        time: "21.11".into(),
    });
    let first_time = pf.time.clone();
    // Rescan of the same documents in a different order.
    let mut inputs2 = inputs.clone();
    inputs2.reverse();
    let a2 = analyze(&inputs2, &scope(), &prev);
    assert_eq!(a1.findings.len(), a2.findings.len(), "no duplicates");
    let f = a2.findings.iter().find(|f| f.id == target).unwrap();
    assert_eq!(f.status, FindingStatus::FalsePositive);
    assert_eq!(f.notes.len(), 1);
    assert_eq!(Some(f.time.clone()), first_time);
    assert_eq!(f.first_scan.as_deref(), Some("s1"));
    assert!(
        a2.risk.score <= a1.risk.score,
        "false positives do not count"
    );
    // The photo is deleted, so the GPS finding disappears.
    let mut inputs3 = inputs.clone();
    inputs3[2].deleted = true;
    let a3 = analyze(&inputs3, &scope(), &a1.prev_state(None, prev.now));
    assert!(a3.resolved.contains(&target));
    assert!(a3.docs[2].deleted);
    assert!(a3.gps.is_empty());
}

#[test]
fn not_analyzed_docs_have_no_metadata_fields() {
    let mut d = sample().remove(0);
    d.status = DocStatus::Queued;
    let a = analyze(&[DocInput::new(&d)], &scope(), &prev_now());
    assert_eq!(a.docs[0].status, "queued");
    assert!(a.docs[0].author.is_none() && a.docs[0].flags.is_empty());
    assert!(a.people.is_empty() && a.findings.is_empty());
    assert_eq!(a.risk.level, RiskLevel::Low);
    let empty = analyze(&[], &scope(), &PrevState::default());
    assert_eq!(empty.risk.level, RiskLevel::None);
}

/// Synthetic load of 1000 documents; must finish in under 1 s in release:
/// `cargo test -p foca-analysis --release -- --ignored bench_1000`.
#[test]
#[ignore]
fn bench_1000() {
    let first = [
        "Олена",
        "Ігор",
        "Марина",
        "Андрій",
        "Тетяна",
        "Віктор",
        "Сергій",
        "Юлія",
    ];
    let last = [
        "Коваленко",
        "Петренко",
        "Шевчук",
        "Бондар",
        "Мельник",
        "Ткаченко",
        "Лисенко",
    ];
    let apps = [
        "Microsoft Office Word 15.0000",
        "Microsoft Excel 14.0300",
        "LibreOffice/7.2.5.2$Windows_X86_64",
        "Microsoft® Word 2019",
        "Adobe Acrobat Pro XI 11.0.23",
    ];
    let mut docs = Vec::new();
    let mut texts = Vec::new();
    for i in 0..1000u64 {
        let f = first[(i % 8) as usize];
        let l = last[(i / 8 % 7) as usize];
        let mut m = office(
            &format!("{f} {l}"),
            &format!("u{}", i % 50),
            apps[(i % 5) as usize],
        );
        m.paths = vec![PathRef {
            path: format!(r"\\SRV-FILE0{}\share\{i}.docx", i % 3),
            kind: PathKind::Unc,
            user: None,
            host: Some(format!("SRV-FILE0{}", i % 3)),
            source: "t".into(),
        }];
        docs.push(doc(i + 1, &format!("d{i}.docx"), m));
        texts.push(format!(
            "Документ {i}. Контакт: user{i}@contoso.example. Сервер 10.0.{}.{}. {}",
            i % 200,
            i % 250,
            "Звичайний текст договору без секретів. ".repeat(40)
        ));
    }
    let inputs: Vec<DocInput> = docs
        .iter()
        .zip(texts.iter())
        .map(|(d, t)| DocInput::new(d).with_text(Some(t)))
        .collect();
    let t = std::time::Instant::now();
    let a = analyze(&inputs, &scope(), &prev_now());
    let el = t.elapsed();
    eprintln!(
        "1000 документов: {el:?}, людей {}, находок {}, секретов {}",
        a.people.len(),
        a.findings.len(),
        a.secrets.len()
    );
    assert_eq!(a.docs.len(), 1000);
    if !cfg!(debug_assertions) {
        assert!(el.as_millis() < 1000, "{el:?}");
    }
}

/// EOL based on historic data (a web archive document or one older than 3 years) is one
/// severity level lower and marked as historic with the year (seen in practice: Photoshop
/// CC 2014 from Wayback).
#[test]
fn eol_from_historic_docs_downgraded() {
    let mut fresh = office("a.bondar", "a.bondar", "Microsoft Office Word 2013");
    fresh.created = Some("2026-01-10T08:00:00Z".into());
    fresh.modified = fresh.created.clone();
    let mut old = office("o.kovalenko", "o.kovalenko", "Microsoft Office Word 2007");
    old.created = Some("2017-05-02T08:00:00Z".into());
    old.modified = Some("2017-05-03T08:00:00Z".into());
    let mut arch = doc(
        3,
        "photo2.docx",
        office("v.t", "v.t", "Microsoft Office Outlook 2007"),
    );
    arch.url = Some(
        "https://web.archive.org/web/20211010102734id_/http://contoso.example/photo2.docx".into(),
    );
    let docs = [doc(1, "new.docx", fresh), doc(2, "old.docx", old), arch];
    let inputs: Vec<DocInput> = docs.iter().map(DocInput::new).collect();
    let a = analyze(&inputs, &scope(), &prev_now());
    let eol = |n: &str| {
        a.findings
            .iter()
            .find(|f| f.provenance.rule == "eol-software" && f.title.contains(n))
            .unwrap_or_else(|| panic!("no EOL finding {n}"))
    };
    let w13 = eol("Word 2013");
    assert_eq!(w13.sev, Severity::Medium);
    assert!(!w13.evidence.contains("Исторические"));
    let w07 = eol("Word 2007");
    assert_eq!(w07.sev, Severity::Low);
    assert!(
        w07.evidence.contains("Исторические данные (2017)"),
        "{}",
        w07.evidence
    );
    let o07 = eol("Outlook 2007");
    assert_eq!(o07.sev, Severity::Low, "web archive document");
    assert!(o07.evidence.contains("Исторические данные ("));
}

#[test]
fn new_format_findings_pdb_ai_geodata_sourcemap_connections() {
    let mut exe = Metadata::new(DocFormat::Exe);
    exe.paths = vec![PathRef {
        path: r"C:\Users\jdeveloper\source\repos\Billing\obj\Release\Billing.pdb".into(),
        kind: PathKind::Windows,
        user: Some("jdeveloper".into()),
        host: None,
        source: "pe:pdb".into(),
    }];
    let mut png = Metadata::new(DocFormat::Png);
    png.ai_generated = Some(foca_core::AiGenerated {
        generator: Some("ComfyUI".into()),
        model: Some("sdxl-base".into()),
        prompt: Some("a quiet office".into()),
        source: "png:workflow".into(),
    });
    let mut kml = Metadata::new(DocFormat::Kml);
    kml.geo_points = vec![foca_core::GeoPoint {
        lat: 50.45,
        lon: 30.52,
        alt: None,
        time: None,
        name: Some("Depot 1".into()),
        source: "kml:coordinates".into(),
    }];
    let mut map = Metadata::new(DocFormat::SourceMap);
    map.stats.insert("sources_content".into(), 3);
    let mut xlsx = Metadata::new(DocFormat::Xlsx);
    xlsx.connections = vec![foca_core::DataConnection {
        kind: "oledb".into(),
        name: Some("Sales".into()),
        server: Some("sql01.corp.example".into()),
        database: Some("Sales".into()),
        user: Some("report_ro".into()),
        has_password: true,
        source: "xl/connections.xml".into(),
        ..Default::default()
    }];
    let docs = [
        doc(1, "Billing.dll", exe),
        doc(2, "office.png", png),
        doc(3, "depots.kml", kml),
        doc(4, "app.js.map", map),
        doc(5, "sales.xlsx", xlsx),
    ];
    let inputs: Vec<DocInput> = docs.iter().map(DocInput::new).collect();
    let a = analyze(&inputs, &scope(), &prev_now());
    let by = |rule: &str| {
        a.findings
            .iter()
            .find(|f| f.provenance.rule == rule)
            .unwrap_or_else(|| {
                panic!(
                    "{rule}: {:?}",
                    a.findings
                        .iter()
                        .map(|f| &f.provenance.rule)
                        .collect::<Vec<_>>()
                )
            })
    };
    assert!(by("doc.pdb_user").evidence.contains("jdeveloper"));
    let ai = by("doc.ai_generated");
    assert!(ai.evidence.contains("ComfyUI / sdxl-base"));
    assert!(
        !ai.evidence.contains("quiet office"),
        "prompt must stay out of findings"
    );
    assert!(by("doc.geodata").evidence.contains("Depot 1"));
    assert!(by("doc.sourcemap").evidence.contains("sourcesContent: 3"));
    let c = by("doc.data_connection");
    assert_eq!(c.sev, Severity::High);
    assert!(
        c.evidence.contains("server=sql01.corp.example") && c.evidence.contains("password=***")
    );
}
