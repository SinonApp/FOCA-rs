//! Analytics end to end: `analyze` → `insights::build` over a synthetic organization
//! (fictional people and `*.example.test` names) and over the whole `tests/corpus`.

use std::path::{Path, PathBuf};

use foca_analysis::chain::{self, ChainOpts};
use foca_analysis::correlate::LinkKind;
use foca_analysis::graphview::{self, Layer};
use foca_analysis::insights;
use foca_analysis::netmap::{NetKind, PkiInput};
use foca_analysis::{analyze, DocInput, PrevState};
use foca_core::{
    CertInfo, DocFormat, DocStatus, Document, Metadata, PathKind, PathRef, PersonRole, Scope,
    Signature, SignatureKind, XmpIds,
};
use time::macros::datetime;

fn doc(id: u64, name: &str, m: Metadata) -> Document {
    Document {
        id,
        name: name.into(),
        ext: name.rsplit('.').next().unwrap_or("").into(),
        sha256: format!("sha-{id}"),
        status: DocStatus::Analyzed,
        metadata: Some(m),
        ..Default::default()
    }
}

fn path(p: &str, kind: PathKind, user: Option<&str>) -> PathRef {
    PathRef {
        path: p.into(),
        kind,
        user: user.map(str::to_string),
        host: None,
        source: "test".into(),
    }
}

fn org_docs() -> Vec<Document> {
    let mut a = Metadata::new(DocFormat::Docx);
    a.author = Some("Іван Петренко".into());
    a.last_modified_by = Some("Іван Петренко".into());
    a.add_person("Іван Петренко", PersonRole::Author, "core.xml:dc:creator");
    a.company = Some("ТОВ «Приклад»".into());
    a.created = Some("2024-03-01T09:00:00Z".into());
    a.modified = Some("2024-03-02T10:00:00Z".into());
    a.application = Some("Microsoft Office Word".into());
    a.paths = vec![
        path(
            r"C:\Users\i.petrenko\Documents\Buh\zvit.docx",
            PathKind::Windows,
            Some("i.petrenko"),
        ),
        path(
            r"\\SRV-FS01.corp.example.test\Buh\2024\zvit.docx",
            PathKind::Unc,
            None,
        ),
    ];
    a.printers = vec![r"\\PRN01.corp.example.test\HP-Buh-2F".into()];
    a.rsids = ["00A1B2C3", "00A1B2C4", "00A1B2C5"]
        .map(String::from)
        .to_vec();

    let mut b = a.clone();
    b.rsids.push("00F00001".into());
    b.created = Some("2024-03-05T09:00:00Z".into());
    b.modified = Some("2024-03-04T09:00:00Z".into());

    let mut c = Metadata::new(DocFormat::Pdf);
    c.author = Some("Олена Коваленко".into());
    c.add_person("Олена Коваленко", PersonRole::Author, "pdf:Info:Author");
    c.created = Some("2024-04-01T09:00:00Z".into());
    c.xmp_ids = Some(XmpIds {
        document_id: Some("xmp.did:11112222".into()),
        instance_id: Some("xmp.iid:33334444".into()),
        ..Default::default()
    });
    c.signatures = vec![Signature {
        kind: SignatureKind::Pdf,
        source: "pdf:obj 12".into(),
        signer: Some(CertInfo {
            common_name: Some("Олена Коваленко".into()),
            organization: Some("ТОВ «Приклад»".into()),
            org_unit: Some("Відділ кадрів".into()),
            title: Some("Начальник відділу кадрів".into()),
            edrpou: Some("00000000".into()),
            ..Default::default()
        }),
        certificates: 1,
        signing_time: None,
        timestamp: None,
        digest_algorithm: None,
        sub_filter: None,
        name: None,
        reason: None,
        location: None,
        contact: None,
        byte_range: vec![],
        bytes_after: None,
        modified_after_signing: false,
        digest_valid: None,
    }];
    let mut d = Metadata::new(DocFormat::Pdf);
    d.author = Some("Олена Коваленко".into());
    d.add_person("Олена Коваленко", PersonRole::Author, "pdf:Info:Author");
    d.xmp_ids = Some(XmpIds {
        document_id: Some("xmp.did:55556666".into()),
        instance_id: Some("xmp.iid:77778888".into()),
        derived_from_instance_id: Some("xmp.iid:33334444".into()),
        ..Default::default()
    });
    d.paths = vec![path(
        r"\\SRV-FS01.corp.example.test\HR\nakaz.pdf",
        PathKind::Unc,
        None,
    )];
    vec![
        doc(1, "zvit.docx", a),
        doc(2, "zvit-final.docx", b),
        doc(3, "nakaz.pdf", c),
        doc(4, "nakaz-copy.pdf", d),
    ]
}

#[test]
fn synthetic_organization() {
    let docs = org_docs();
    let inputs: Vec<DocInput> = docs.iter().map(DocInput::new).collect();
    let prev = PrevState {
        now: Some(datetime!(2026-11-22 12:00 UTC)),
        ..Default::default()
    };
    let a = analyze(&inputs, &Scope::default(), &prev);
    let pki = vec![PkiInput {
        url: "ldap:///CN=Example-CA,CN=AIA,CN=Public%20Key%20Services,DC=corp,DC=example,DC=test"
            .into(),
        source: "ca_issuers".into(),
        host: Some("ca01.corp.example.test".into()),
        ldap_dn: Some("CN=Example-CA,DC=corp,DC=example,DC=test".into()),
        ad_domain: Some("corp.example.test".into()),
    }];
    let ins = insights::build(&inputs, &a, &pki, datetime!(2026-11-22 12:00 UTC));

    // Correlation.
    let l = ins
        .correlation
        .links
        .iter()
        .find(|l| (l.from, l.to) == (2, 1))
        .expect("rsid link");
    assert_eq!(l.kind, LinkKind::DerivedFrom);
    let l = ins
        .correlation
        .links
        .iter()
        .find(|l| (l.from, l.to) == (4, 3))
        .expect("xmp link");
    assert_eq!(l.basis, "xmp_derived_instance");
    assert_eq!(ins.correlation.lineages.len(), 2);

    // Org chart.
    let login_of = |name: &str| {
        a.people
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.login.clone())
            .unwrap_or_else(|| panic!("no person {name}: {:?}", a.people))
    };
    let ivan = login_of("Іван Петренко");
    let olena = login_of("Олена Коваленко");
    let fin = ins
        .org
        .departments
        .iter()
        .find(|d| d.id == "dept:finance")
        .expect("finance");
    assert!(fin.members.iter().any(|m| m.login == ivan), "{fin:?}");
    let hr = ins
        .org
        .departments
        .iter()
        .find(|d| d.id == "dept:hr")
        .expect("hr");
    assert!(hr
        .members
        .iter()
        .any(|m| m.login == olena && m.confidence >= 85));
    let op = ins.org.people.iter().find(|p| p.login == olena).unwrap();
    assert_eq!(op.primary_role, "approver");
    assert_eq!(op.department.as_deref(), Some("dept:hr"));
    assert_eq!(ins.org.organizations.len(), 1);
    assert_eq!(ins.org.organizations[0].edrpou.as_deref(), Some("00000000"));

    // Anomalies: document 2 was "created" after it was modified.
    assert!(ins
        .anomalies
        .iter()
        .any(|x| x.doc == 2 && x.code == "created_after_modified"));

    // KEV: Word is in the snapshot, the claim stays "possible".
    let k = ins
        .kev
        .iter()
        .find(|k| k.product_key == "ms_office")
        .expect("kev office");
    assert!(k.total > 0 && k.confidence == "possible");

    // Network map.
    let nm = &ins.netmap;
    let dom = nm.node("domain:corp.example.test").expect("domain");
    assert!(dom.sources.iter().any(|s| s.kind == "pki_ldap"));
    let fs = nm
        .of_kind(NetKind::Server)
        .find(|n| n.label.eq_ignore_ascii_case("SRV-FS01.corp.example.test"))
        .expect("file server");
    assert!(fs.roles.contains(&"file".to_string()));
    assert_eq!(fs.parent.as_deref(), Some("domain:corp.example.test"));
    assert!(fs.shares.iter().any(|s| s.ends_with("\\Buh")));
    assert!(nm
        .of_kind(NetKind::Server)
        .any(|n| n.roles.contains(&"pki".to_string())));
    assert!(nm
        .of_kind(NetKind::Server)
        .any(|n| n.roles.contains(&"print".to_string())));

    // Chain from document 4 to the domain through the file server.
    let c = chain::find(&ins.graph, "doc:4", &ChainOpts::default())
        .unwrap_or_else(|| panic!("no chain: {:#?}", ins.graph));
    assert_eq!(c.target_kind, "domain", "{c:?}");
    assert!(c.steps.iter().any(|s| s.node.kind == "host"));

    // Graph view.
    let v = graphview::view(&ins.graph, &[], graphview::MIN_GROUP);
    assert!(!v.nodes.is_empty());
    let only = graphview::view(&ins.graph, &[Layer::Docs], 0);
    assert!(only.nodes.iter().all(|n| n.layer == Layer::Docs));
    // Serializable for the UI.
    assert!(serde_json::to_string(&ins)
        .unwrap()
        .contains("derived_from"));
}

fn corpus_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus");
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            let n = p.to_string_lossy().to_string();
            if p.is_dir() {
                stack.push(p);
            } else if !(n.ends_with(".json") || n.ends_with(".md") || n.ends_with(".py")) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn corpus_smoke() {
    let lim = foca_meta::Limits::default();
    let docs: Vec<Document> = corpus_files()
        .iter()
        .enumerate()
        .filter_map(|(i, f)| {
            let b = std::fs::read(f).ok()?;
            let name = f.file_name()?.to_string_lossy().to_string();
            let m = foca_meta::extract(&b, Some(&name), &lim).ok()?;
            Some(doc(i as u64 + 1, &name, m))
        })
        .collect();
    let inputs: Vec<DocInput> = docs.iter().map(DocInput::new).collect();
    let now = datetime!(2026-11-20 12:00 UTC);
    let prev = PrevState {
        now: Some(now),
        ..Default::default()
    };
    let a = analyze(&inputs, &Scope::default(), &prev);
    let ins = insights::build(&inputs, &a, &[], now);
    // The .rdp/.ica and .lnk samples leak servers and a workstation.
    let servers: Vec<&str> = ins
        .netmap
        .of_kind(NetKind::Server)
        .map(|n| n.label.as_str())
        .collect();
    assert!(
        servers.iter().any(|s| s.eq_ignore_ascii_case("SRV-TS01")
            || s.to_ascii_lowercase().starts_with("srv-ts01")),
        "{servers:?}"
    );
    assert!(ins.netmap.of_kind(NetKind::Workstation).count() > 0);
    // Every non-root node has a parent that exists.
    for n in &ins.netmap.nodes {
        if let Some(p) = &n.parent {
            assert!(ins.netmap.node(p).is_some(), "dangling parent {p}");
        }
    }
    // Every graph edge connects existing nodes.
    let ids: std::collections::BTreeSet<&str> =
        ins.graph.nodes.iter().map(|n| n.id.as_str()).collect();
    for e in &ins.graph.edges {
        assert!(ids.contains(e.from.as_str()) && ids.contains(e.to.as_str()));
    }
    // A chain exists from the RDP file.
    let rdp = docs.iter().find(|d| d.name == "SRV-TS01.rdp").unwrap();
    let c = chain::find(
        &ins.graph,
        &format!("doc:{}", rdp.id),
        &ChainOpts::default(),
    );
    assert!(c.is_some_and(|c| c.hops >= 1));
    if std::env::var("FOCA_PRINT_INSIGHTS").is_ok() {
        println!("{}", serde_json::to_string_pretty(&ins).unwrap());
    }
}
