//! Shared fixture (a snapshot of the `tests/corpus` corpus: foca-meta → foca-store/foca-analysis
//! → `Snapshot`) and helpers for the report integration tests.

#![allow(dead_code, unused_imports)]

pub use std::io::Read;
pub use std::path::{Path, PathBuf};
pub use std::sync::{Arc, OnceLock};

pub use foca_core::api::Snapshot;
pub use foca_core::{DocStatus, FindingStatus, ManualClock, Severity};
pub use foca_report::data::{risk_of, RequestEntry};
pub use foca_report::{
    build_report_with_log, export_with_log, ExportFormat, ExportKind, ExportOptions, Lang, Logo,
    ReportFormat, ReportOptions, SecretMode, Sections, Template,
};
pub use serde_json::Value;
pub use time::macros::datetime;
pub use time::OffsetDateTime;

pub const NOW: OffsetDateTime = datetime!(2026-11-20 12:00 UTC);

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

pub fn corpus_files() -> Vec<PathBuf> {
    let dir = root().join("../../tests/corpus");
    let mut out = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if n.ends_with(".json") || n.ends_with(".md") || n.ends_with(".py") {
                continue;
            }
            out.push(p);
        }
    }
    out.sort();
    out
}

pub struct Fixture {
    pub snap: Snapshot,
    pub log: Vec<RequestEntry>,
}

/// Builds a project from the corpus: import, analysis, scan, finding triage, request log.
pub fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let tmp = tempfile::tempdir().unwrap();
        let st = foca_store::Store::open_with_clock(tmp.path(), Arc::new(ManualClock::new(NOW)))
            .unwrap();
        let p = st
            .create_project(&foca_store::NewProject {
                name: "contoso.example".into(),
                client: "ТОВ «Контосо Енерджі»".into(),
                targets: vec![
                    "contoso.example".into(),
                    "*.contoso-group.example".into(),
                    "203.0.113.0/24".into(),
                ],
                excludes: vec!["mail.contoso.example".into(), "10.10.1.0/24".into()],
            })
            .unwrap();
        let db = st.open_project(&p.id).unwrap();
        db.scope_set(&foca_core::api::ScopeDto {
            basis: "Письменное разрешение владельца от 01.11.2026".into(),
            ..db.scope_get().unwrap()
        })
        .unwrap();
        db.scan_start("s1", "std", false).unwrap();
        let l = foca_meta::Limits::default();
        let base = root().join("../../tests/corpus");
        for f in corpus_files() {
            let bytes = std::fs::read(&f).unwrap();
            let rel = f
                .strip_prefix(&base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let name = f.file_name().unwrap().to_string_lossy().to_string();
            let r = db
                .add_document(&foca_store::AddDoc {
                    url: Some(format!("https://files.contoso.example/corpus/{rel}")),
                    name: name.clone(),
                    source: "crawler".into(),
                    first_scan: Some("s1".into()),
                    status: DocStatus::Downloaded,
                    size: bytes.len() as u64,
                    sha256: Some(foca_report::custody::sha256_hex(&bytes)),
                    ..Default::default()
                })
                .unwrap();
            if r.existing {
                continue;
            }
            match foca_meta::extract(&bytes, Some(&name), &l) {
                Ok(m) => {
                    let t = foca_meta::text(&bytes, &l).ok();
                    db.set_analyzed(r.id, &m, t.as_deref()).unwrap();
                }
                Err(e) => db.set_doc_error(r.id, &e.to_string()).unwrap(),
            }
        }
        db.run_analysis(Some("s1")).unwrap();
        let snapshot = db.scan_snapshot().unwrap();
        db.scan_save(&foca_core::api::Scan {
            id: "s1".into(),
            profile_id: "std".into(),
            profile: "Стандартный".into(),
            trigger: "manual".into(),
            status: "done".into(),
            started_at: "2026-11-20T11:40:00".into(),
            finished_at: Some("2026-11-20T12:00:00".into()),
            minutes: 20,
            targets: vec!["contoso.example".into()],
            egress: "Напрямую (реальный IP)".into(),
            snapshot,
            ..Default::default()
        })
        .unwrap();
        // Triage: critical findings confirmed, one fixed, one false positive.
        let mut fs = db.findings().unwrap();
        fs.sort_by(|a, b| b.sev.rank().cmp(&a.sev.rank()).then(a.id.cmp(&b.id)));
        for f in fs.iter().filter(|f| f.sev == Severity::Critical) {
            db.finding_set_status(f.id, "confirmed").unwrap();
        }
        let highs: Vec<_> = fs.iter().filter(|f| f.sev == Severity::High).collect();
        if let Some(f) = highs.first() {
            db.finding_set_status(f.id, "confirmed").unwrap();
        }
        if let Some(f) = highs.get(1) {
            db.finding_set_status(f.id, "fixed").unwrap();
        }
        if let Some(f) = fs.iter().rfind(|f| f.sev == Severity::Low) {
            db.finding_set_status(f.id, "false").unwrap();
        }
        let req = |module: &str, url: &str, host: &str, active: bool, err: Option<&str>| {
            db.log_request(&foca_store::RequestLog {
                scan_id: Some("s1".into()),
                module: module.into(),
                method: "GET".into(),
                url: url.into(),
                host: host.into(),
                status: if err.is_none() { Some(200) } else { None },
                bytes: if err.is_none() { 2048 } else { 0 },
                active,
                error: err.map(String::from),
                ..Default::default()
            })
            .unwrap();
        };
        req(
            "wayback",
            "https://web.archive.org/cdx/search/cdx?url=contoso.example/*",
            "web.archive.org",
            false,
            None,
        );
        req(
            "crtsh",
            "https://crt.sh/?q=%25.contoso.example&output=json",
            "crt.sh",
            false,
            None,
        );
        req(
            "crawler",
            "https://www.contoso.example/docs/",
            "www.contoso.example",
            true,
            None,
        );
        req(
            "httpmap",
            "https://portal.contoso.example/",
            "portal.contoso.example",
            true,
            None,
        );
        req(
            "httpmap",
            "https://mail.contoso.example/owa/",
            "mail.contoso.example",
            true,
            Some("out_of_scope"),
        );
        let snap = st.project_snapshot(&p.id).unwrap();
        let log = db
            .requests(None, false)
            .unwrap()
            .into_iter()
            .map(|r| RequestEntry {
                blocked: RequestEntry::is_blocked_code(r.error.as_deref()),
                time: r.time,
                scan_id: r.scan_id,
                module: r.module,
                method: r.method,
                url: r.url,
                host: r.host,
                status: r.status,
                bytes: r.bytes,
                active: r.active,
                error: r.error,
                note: r.note,
                ctype: r.ctype,
            })
            .collect();
        Fixture { snap, log }
    })
}

pub fn opts(fmt: ReportFormat) -> ReportOptions {
    ReportOptions {
        fmt,
        sections: Sections::all(),
        company: "ТОВ «Кібер Аудит»".into(),
        // The goldens were written with hidden secrets; the app default is full values.
        secrets: SecretMode::Hide,
        ..Default::default()
    }
}

pub fn build(snap: &Snapshot, o: &ReportOptions) -> foca_report::ReportArtifact {
    build_report_with_log(snap, &fixture().log, o, NOW)
}

pub fn text(a: &foca_report::ReportArtifact) -> String {
    String::from_utf8(a.bytes.clone()).unwrap()
}

pub fn golden(name: &str, got: &str) {
    let path = root().join("tests/golden").join(name);
    let update = std::env::var("UPDATE_GOLDEN").is_ok_and(|v| v == "1");
    if update || !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, got).unwrap();
        assert!(
            update,
            "golden file {name} was missing and has been created; review it"
        );
        return;
    }
    let exp = std::fs::read_to_string(&path).unwrap();
    if exp != got {
        let line = exp
            .lines()
            .zip(got.lines())
            .position(|(a, b)| a != b)
            .unwrap_or(exp.lines().count().min(got.lines().count()));
        panic!(
            "{name} расходится с эталоном (строка {}):\n  было:  {:?}\n  стало: {:?}\n\
             обновить: UPDATE_GOLDEN=1 cargo test -p foca-report --test report",
            line + 1,
            exp.lines().nth(line),
            got.lines().nth(line)
        );
    }
}

/// Secret values from the corpus that must be hidden (excluding host addresses and very
/// short values).
pub fn secret_values(snap: &Snapshot) -> Vec<String> {
    let host_like = |v: &str| {
        v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
            && (v.matches('.').count() >= 2 || v.parse::<std::net::IpAddr>().is_ok())
    };
    let mut v: Vec<String> = snap
        .secrets
        .iter()
        .filter(|s| s.kind != "host")
        .map(|s| s.value.expose().to_string())
        .chain(
            snap.findings
                .iter()
                .filter(|f| f.category != "dns" && f.category != "web")
                .flat_map(|f| foca_report::mask::secrets_in(&f.evidence)),
        )
        .filter(|s| s.chars().count() >= 6 && !host_like(s))
        .collect();
    v.sort();
    v.dedup();
    v
}

// ---------------------------------------------------------------- golden

/// Tags the renderer may emit; anything else is unescaped input.
pub const TAGS: &[&str] = &[
    "html", "head", "meta", "title", "style", "body", "header", "footer", "nav", "section",
    "article", "div", "span", "h1", "h2", "h3", "h4", "p", "b", "small", "br", "ul", "ol", "li",
    "dl", "dt", "dd", "table", "thead", "tbody", "tr", "th", "td", "pre", "a", "img", "svg",
    "text", "rect",
];

pub fn tags(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = html.as_bytes();
    for (i, _) in html.match_indices('<') {
        let rest = &b[i + 1..];
        let rest = rest.strip_prefix(b"/").unwrap_or(rest);
        let name: String = rest
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric())
            .map(|c| (*c as char).to_ascii_lowercase())
            .collect();
        out.push(name);
    }
    out
}

pub fn assert_safe_html(h: &str) {
    assert!(h.starts_with("<!DOCTYPE html>"));
    for t in tags(h) {
        assert!(
            t.is_empty() || t == "doctype" || TAGS.contains(&t.as_str()),
            "unexpected tag <{t}>"
        );
    }
    let lower = h.to_lowercase();
    for bad in [
        "<script",
        "<link",
        "<iframe",
        "<object",
        "<embed",
        "@import",
        "url(",
        "src=\"http",
        "src='http",
        "href=\"javascript",
        "href=\"data",
        "javascript:alert",
    ] {
        // `javascript:…` is allowed only as escaped text, never inside an attribute.
        if bad == "javascript:alert" {
            continue;
        }
        assert!(!lower.contains(bad), "found {bad:?} in HTML");
    }
    // No event handlers in any real tag (`<` in text is escaped).
    for (i, _) in lower.match_indices('<') {
        let tag = &lower[i..i + lower[i..].find('>').unwrap_or(lower.len() - i)];
        let b = tag.as_bytes();
        for (j, _) in tag.match_indices(" on") {
            let name: String = b[j + 3..]
                .iter()
                .take_while(|c| c.is_ascii_alphabetic())
                .map(|c| *c as char)
                .collect();
            assert!(
                name.is_empty() || b.get(j + 3 + name.len()) != Some(&b'='),
                "handler on{name} in tag {tag:?}"
            );
        }
    }
    // Links are http(s) only, images are data:image only.
    for (i, _) in lower.match_indices("href=\"") {
        let v = &lower[i + 6..];
        assert!(
            v.starts_with("http://") || v.starts_with("https://") || v.starts_with('#'),
            "link {:?}",
            &v[..v.len().min(40)]
        );
    }
    for (i, _) in lower.match_indices("src=\"") {
        assert!(
            lower[i + 5..].starts_with("data:image/"),
            "resource outside data:"
        );
    }
}

/// A snapshot with hostile strings in all typical fields.
/// True if Markdown contains an HTML tag start that is not backslash-escaped.
pub fn raw_md_tag(md: &str, tag: &str) -> bool {
    let lower = md.to_lowercase();
    lower
        .match_indices(tag)
        .any(|(i, _)| i == 0 || !lower[..i].ends_with('\\'))
}

pub fn hostile() -> Snapshot {
    let mut s = fixture().snap.clone();
    s.project.name = "</title><script>alert(1)</script>".into();
    s.scope.client = "\"><img src=x onerror=alert(1)>".into();
    s.docs[0].author = Some("<script>alert('a')</script>".into());
    s.docs[0].title = "<svg onload=alert(1)>".into();
    s.docs[0].url = "javascript:alert(document.cookie)".into();
    s.people[0].name = "<b onmouseover=alert(1)>Олена</b>".into();
    s.hosts[0].name = "x\"><iframe src=//evil>".into();
    let f = &mut s.findings[0];
    f.title = "\"><img src=x onerror=alert(1)>".into();
    f.url = Some("javascript:alert(1)".into());
    f.description = "<script>steal()</script> | col | `code` [x](javascript:alert(1))".into();
    f.evidence = "</pre><script>x()</script>".into();
    f.mitre = "T1592 <a href=javascript:alert(1)>".into();
    s.findings[1].url = Some("https://portal.contoso.example/login?next=/".into());
    s
}

pub fn csv_cells(s: &str) -> Vec<Vec<String>> {
    // Minimal RFC 4180 parser for the checks.
    let s = s.trim_start_matches('\u{feff}');
    let mut rows = vec![vec![String::new()]];
    let mut q = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        let row = rows.last_mut().unwrap();
        match (q, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                row.last_mut().unwrap().push('"');
            }
            (true, '"') => q = false,
            (true, c) => row.last_mut().unwrap().push(c),
            (false, '"') => q = true,
            (false, ',') => row.push(String::new()),
            (false, '\r') => {}
            (false, '\n') => rows.push(vec![String::new()]),
            (false, c) => row.last_mut().unwrap().push(c),
        }
    }
    if rows.last().is_some_and(|r| r.len() == 1 && r[0].is_empty()) {
        rows.pop();
    }
    rows
}

pub fn all_outputs(snap: &Snapshot, secrets: SecretMode) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for fmt in [
        ReportFormat::Html,
        ReportFormat::Md,
        ReportFormat::Csv,
        ReportFormat::Json,
    ] {
        let o = ReportOptions {
            secrets,
            ..opts(fmt)
        };
        out.push((format!("{fmt:?}"), text(&build(snap, &o))));
    }
    let eo = ExportOptions {
        include_secrets: secrets == SecretMode::Full,
        ..Default::default()
    };
    for kind in [
        ExportKind::Findings,
        ExportKind::Docs,
        ExportKind::Paths,
        ExportKind::All,
    ] {
        for fmt in [
            ExportFormat::List,
            ExportFormat::Json,
            ExportFormat::Md,
            ExportFormat::Graphml,
            ExportFormat::MaltegoCsv,
        ] {
            let a = export_with_log(snap, &fixture().log, kind, fmt, &eo);
            out.push((
                format!("{kind:?}/{fmt:?}"),
                String::from_utf8(a.bytes).unwrap(),
            ));
        }
    }
    // The whole-project CSV export is a ZIP; unpack it.
    let z = export_with_log(
        snap,
        &fixture().log,
        ExportKind::All,
        ExportFormat::Csv,
        &eo,
    );
    assert!(z.file_name.ends_with(".zip"));
    let mut ar = zip::ZipArchive::new(std::io::Cursor::new(z.bytes)).unwrap();
    for i in 0..ar.len() {
        let mut f = ar.by_index(i).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        out.push((format!("zip/{}", f.name().unwrap()), s));
    }
    out
}

pub fn check(schema: &Value, root: &Value, v: &Value, path: &str) {
    let schema = match schema.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let key = r.trim_start_matches("#/$defs/");
            &root["$defs"][key]
        }
        None => schema,
    };
    if let Some(t) = schema.get("type") {
        let types: Vec<&str> = match t {
            Value::String(s) => vec![s.as_str()],
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            _ => vec![],
        };
        let ok = types.iter().any(|t| match *t {
            "object" => v.is_object(),
            "array" => v.is_array(),
            "string" => v.is_string(),
            "integer" => v.is_u64() || v.is_i64(),
            "number" => v.is_number(),
            "boolean" => v.is_boolean(),
            "null" => v.is_null(),
            _ => false,
        });
        assert!(ok, "{path}: type of {v} is not {types:?}");
    }
    if let Some(e) = schema.get("enum").and_then(Value::as_array) {
        assert!(e.contains(v), "{path}: {v} is outside the enum");
    }
    if let Some(c) = schema.get("const") {
        assert_eq!(c, v, "{path}");
    }
    if let (Some(props), Some(obj)) = (
        schema.get("properties").and_then(Value::as_object),
        v.as_object(),
    ) {
        for k in schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let k = k.as_str().unwrap();
            assert!(obj.contains_key(k), "{path}: missing key {k}");
        }
        for (k, x) in obj {
            let s = props
                .get(k)
                .unwrap_or_else(|| panic!("{path}: key {k} is not described in the schema"));
            check(s, root, x, &format!("{path}.{k}"));
        }
        // The schema is complete: every property is required (a stable key set).
        let req: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for k in props.keys() {
            assert!(req.contains(&k.as_str()), "{path}: {k} is not in required");
        }
    }
    if let (Some(items), Some(arr)) = (schema.get("items"), v.as_array()) {
        for (i, x) in arr.iter().enumerate() {
            check(items, root, x, &format!("{path}[{i}]"));
        }
    }
}

/// Synthetic network/recon/port findings with Russian texts in the shape the core writes.
pub fn net_findings(snap: &mut Snapshot) {
    let base = snap.findings[0].clone();
    let mk = |id: u64, rule: &str, title: &str, desc: &str, rec: &str, ev: &str| {
        let mut f = base.clone();
        f.id = id;
        f.provenance.rule = rule.into();
        f.title = title.into();
        f.description = desc.into();
        f.recommendation = rec.into();
        f.evidence = ev.into();
        f.status = FindingStatus::New;
        f
    };
    snap.findings.extend([
        mk(9001, "ports-exposed", "Открытый сервис Redis из интернета: h.contoso.example:6379",
            "Порт 6379/tcp (Redis) на h.contoso.example (203.0.113.7) принимает соединения из интернета. Redis из интернета часто работает без пароля: чтение/запись данных и выполнение команд на сервере. Redis ответил на PING без пароля: авторизация не требуется.",
            "Привяжите Redis к 127.0.0.1/внутренней сети, включите protected-mode и ACL/пароль, закройте порт.",
            "h.contoso.example:6379 открыт (redis): +PONG"),
        mk(9002, "ports-outdated", "Устаревшая версия сервиса: jQuery 1.8.2 (h.contoso.example:80)",
            "Сервис на h.contoso.example:80 сообщает версию jQuery 1.8.2: версия 1.8.2 старее 3.5.0.",
            "Обновите ПО до поддерживаемой версии и скройте версию в баннере (ServerTokens Prod / server_tokens off).", ""),
        mk(9003, "recon.outdated_tech", "Устаревшая версия AngularJS 1.5.0",
            "AngularJS (JS-фреймворк): AngularJS 1.x не поддерживается с января 2022. Старые версии содержат публично известные уязвимости.",
            "Обновить компонент до поддерживаемой версии; скрыть версию в заголовках/метатегах.", ""),
        mk(9004, "mail-dmarc_missing", "Нет DMARC: подделка писем от домена возможна",
            "Для _dmarc.contoso.example нет записи v=DMARC1.",
            "Настроить SPF с -all и DMARC p=reject после анализа отчётов rua.", "SPF: нет\nDMARC: нет"),
        mk(9005, "fuzz-git", "Открытый репозиторий .git: /.git/HEAD",
            "Каталог .git доступен из интернета: по нему можно восстановить исходный код сайта и историю изменений, включая случайно закоммиченные пароли.\n\nАдрес: https://contoso.example/.git/HEAD\nОтвет: HTTP 200, 23 байт, text/plain.",
            "Закрыть доступ к каталогу .git на веб-сервере, удалить его из веб-корня и сменить пароли и ключи, которые когда-либо попадали в историю репозитория.", "ref: refs/heads/main"),
        mk(9006, "dangling-cname", "Висящий CNAME → возможен subdomain takeover",
            "CNAME → old.azurewebsites.net (Azure) не существует: имя можно занять у провайдера",
            "Удалить запись CNAME или повторно занять имя ресурса за компанией.", ""),
    ]);
}

pub const EXTRA_TEMPLATES: [(Template, &str); 3] = [
    (Template::Executive, "executive"),
    (Template::Compliance, "compliance"),
    (Template::Lab, "lab"),
];

pub fn tpl_opts(tpl: Template, lang: Lang, fmt: ReportFormat) -> ReportOptions {
    ReportOptions {
        tpl,
        lang,
        sections: Sections::for_template(tpl),
        ..opts(fmt)
    }
}

/// Report references (`F-n`) in the order they appear in the text.
pub fn finding_refs(s: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for (i, _) in s.match_indices("F-") {
        // Skip `UTF-8` and similar tokens.
        if s[..i]
            .chars()
            .next_back()
            .is_some_and(char::is_alphanumeric)
        {
            continue;
        }
        let n: String = s[i + 2..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(n) = n.parse() {
            out.push(n);
        }
    }
    out
}

pub fn docx_xml(a: &foca_report::ReportArtifact) -> String {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(a.bytes.clone())).unwrap();
    let mut x = String::new();
    z.by_name("word/document.xml")
        .unwrap()
        .read_to_string(&mut x)
        .unwrap();
    x
}

pub fn with_ai(fmt: ReportFormat, lang: Lang, include: bool) -> ReportOptions {
    ReportOptions {
        lang,
        ai_summary: Some(foca_report::AiSummary {
            text: "## Key risks\n1. **Secrets** in `documents` <script>alert(1)</script>\n\
                   - Printer \\\\srv01 & <img src=x onerror=alert(2)>\n\n## Recommendations\nRotate keys."
                .into(),
            provider: "anthropic".into(),
            model: "claude-x".into(),
            created: "2026-11-25T10:00:00Z".into(),
        }),
        include_ai_summary: include,
        ..opts(fmt)
    }
}

/// Section between `start` and the next `## ` heading.
pub fn md_section(md: &str, start: &str) -> String {
    let i = md.find(start).expect("section");
    let rest = &md[i + start.len()..];
    let end = rest.find("\n## ").map_or(rest.len(), |e| e + 1);
    format!("{start}{}", &rest[..end])
}
