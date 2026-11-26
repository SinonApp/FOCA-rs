//! Report integration tests: Hosts, ports, infrastructure, website recon and request log sections.

mod common;

use common::*;

/// Website and technologies section (`snapshot.recon`): HTML/MD/JSON in three languages,
/// secrets only masked, hostile strings escaped.
#[test]
fn website_recon_section() {
    let mut s = fixture().snap.clone();
    s.recon = serde_json::json!({
        "at": "2026-11-20T12:00:00", "level": "external",
        "sites": [{ "host": "contoso.example", "via": "archive", "favicon": { "url": "https://contoso.example/favicon.ico",
            "mmh3": -1643577382, "md5": "a9c49ce5", "queries": [{ "engine": "shodan", "q": "http.favicon.hash:-1643577382" }] } }],
        "tech": [{ "name": "jQuery", "version": "1.8.2", "category": "JS-библиотека", "outdated": "версия 1.8.2 старее 3.5.0", "host": "contoso.example" },
                 { "name": "<script>x()</script>", "version": null, "category": "CMS", "outdated": null, "host": "contoso.example" }],
        "analytics": [{ "kind": "ga4", "id": "G-ABC123", "host": "contoso.example" }],
        "hidden_paths": [{ "path": "/admin/", "reason": "админка", "source": "x", "host": "contoso.example" }],
        "sitemap": [], "sitemap_total": 0, "security": [],
        "endpoints": [{ "url": "https://contoso.example/api/v1/users", "kind": "api", "method": "GET", "source": "fetch", "host": "contoso.example" }],
        "endpoints_total": 1,
        "secrets": [{ "kind": "aws_access_key", "title": "Ключ доступа AWS", "mask": "AKIA…8N", "source": "https://contoso.example/app.js", "line": 1, "sev": "high", "host": "contoso.example" }],
        "buckets": [{ "provider": "aws_s3", "label": "Amazon S3", "name": "contoso-backup", "url": null, "status": "unchecked", "keys": null, "sources": [] }],
        "code": null
    });
    let h = text(&build(&s, &opts(ReportFormat::Html)));
    assert_safe_html(&h);
    assert!(h.contains("Сайт и технологии") && h.contains("jQuery") && h.contains("Устарело"));
    assert!(h.contains("http.favicon.hash:-1643577382") && h.contains("AKIA…8N"));
    assert!(h.contains("&lt;script&gt;x()&lt;/script&gt;"));
    let md = text(&build(&s, &opts(ReportFormat::Md)));
    assert!(md.contains("### Сайт и технологии") && md.contains("contoso-backup"));
    let en = text(&build(
        &s,
        &ReportOptions {
            lang: Lang::En,
            ..opts(ReportFormat::Html)
        },
    ));
    assert!(en.contains("Website and technologies") && en.contains("Outdated"));
    let uk = text(&build(
        &s,
        &ReportOptions {
            lang: Lang::Uk,
            ..opts(ReportFormat::Md)
        },
    ));
    assert!(uk.contains("Сайт і технології"));
    let j: Value = serde_json::from_slice(&build(&s, &opts(ReportFormat::Json)).bytes).unwrap();
    assert_eq!(j["website"]["technologies"][0]["name"], "jQuery");
    assert_eq!(j["website"]["secrets"][0]["mask"], "AKIA…8N");
    // Without recon data there is no section (golden files stay unchanged).
    let plain = text(&build(&fixture().snap, &opts(ReportFormat::Html)));
    assert!(!plain.contains("webrecon"));
}

/// Port table in the hosts section (`snapshot.ports`): HTML/MD/JSON in three languages,
/// source (own scan or InternetDB cache), sensitive service; no subsection without ports.
#[test]
fn hosts_ports_table() {
    let mut s = fixture().snap.clone();
    s.ports = serde_json::json!([{ "host": "portal.contoso.example", "ip": "203.0.113.12",
        "ports_scan": { "spec": "топ-100", "open": 2 },
        "ports": [
            { "port": 3389, "proto": "tcp", "service": "rdp", "banner": null, "product": null, "version": null, "source": "scan", "unconfirmed": false, "outdated": null, "sensitive": "RDP" },
            { "port": 22, "proto": "tcp", "service": "ssh", "banner": "SSH-2.0-OpenSSH_6.6.1p1", "product": "OpenSSH", "version": "6.6.1p1", "source": "scan", "unconfirmed": false, "outdated": null, "sensitive": null },
            { "port": 8080, "proto": "tcp", "service": "<b>http</b>", "source": "internetdb", "unconfirmed": true }
        ] }]);
    let h = text(&build(&s, &opts(ReportFormat::Html)));
    assert_safe_html(&h);
    assert!(
        h.contains("Открытые порты")
            && h.contains("3389/tcp")
            && h.contains("RDP: открыт из интернета")
    );
    assert!(
        h.contains("OpenSSH 6.6.1p1")
            && h.contains("кэш InternetDB")
            && h.contains("не подтверждён сканом")
    );
    assert!(h.contains("&lt;b&gt;http&lt;/b&gt;"));
    let md = text(&build(&s, &opts(ReportFormat::Md)));
    assert!(
        md.contains("### Открытые порты") && md.contains("| portal.contoso.example | 22/tcp |")
    );
    let en = text(&build(
        &s,
        &ReportOptions {
            lang: Lang::En,
            ..opts(ReportFormat::Html)
        },
    ));
    assert!(en.contains("Open ports") && en.contains("InternetDB cache"));
    let uk = text(&build(
        &s,
        &ReportOptions {
            lang: Lang::Uk,
            ..opts(ReportFormat::Md)
        },
    ));
    assert!(uk.contains("Відкриті порти"));
    let j: Value = serde_json::from_slice(&build(&s, &opts(ReportFormat::Json)).bytes).unwrap();
    assert_eq!(j["ports"][0]["ports"][0]["port"], 3389);
    assert_eq!(j["ports"][0]["ports"][0]["sensitive"], "RDP");
    let plain = text(&build(&fixture().snap, &opts(ReportFormat::Html)));
    assert!(!plain.contains("id=\"ports\""));
}

/// Infrastructure subsections (`snapshot.infra`): certificates with their audit, mail
/// policies, SaaS / clouds and out-of-scope candidates in three languages; escaped; absent
/// without data; infrastructure findings translated by rule.
#[test]
fn infra_sections() {
    let mut s = fixture().snap.clone();
    s.infra = serde_json::json!({
        "cert": [{ "host": "portal.contoso.example", "port": 443, "mode": "tls", "version": "TLSv1_2",
            "chain": [{ "issuer": { "cn": "<i>Corp CA</i>" } }], "days_left": -3,
            "trust": { "status": "self_signed" }, "issues": [{ "code": "cert_expired" }, { "code": "cert_self_signed" }] }],
        "mail_policy": [{ "domain": "contoso.example", "mta_sts": null, "tls_rpt": null, "bimi": null,
            "caa": [{ "flags": 0, "tag": "issue", "value": "letsencrypt.org" }], "dnssec": "unsigned" }],
        "saas": [{ "domain": "contoso.example", "hits": [{ "id": "google", "name": "Google" },
            { "id": "microsoft365", "name": "Microsoft 365" }, { "id": "google", "name": "Google" }] }],
        "tenant": [{ "domain": "contoso.example", "openid": { "tenant_id": "6babcaad-604b-40ac-a9d7-9fd97c0b779f" },
            "realm": { "namespace": "managed" } }],
        "cdn": [{ "host": "www.contoso.example", "name": "Cloudflare" }],
        "oos": [{ "host": "contoso-group.example", "kind": "org_pivot", "via": "Contoso LLC" }],
    });
    let h = text(&build(&s, &opts(ReportFormat::Html)));
    assert_safe_html(&h);
    for want in [
        "Сертификаты TLS",
        "portal.contoso.example:443",
        "-3 дн.",
        "Самоподписанный",
        "cert_expired",
        "Почтовые политики",
        "letsencrypt.org",
        "SaaS и облака",
        "Microsoft 365",
        "Cloudflare",
        "Кандидаты вне скоупа",
        "contoso-group.example",
        "Та же организация (O=)",
    ] {
        assert!(h.contains(want), "{want}");
    }
    assert!(h.contains("&lt;i&gt;Corp CA&lt;/i&gt;"));
    let md = text(&build(&s, &opts(ReportFormat::Md)));
    assert!(md.contains("### Сертификаты TLS") && md.contains("| contoso-group.example |"));
    assert!(
        md.contains("| SaaS | Google, Microsoft 365 |"),
        "SaaS names not deduplicated"
    );
    let en = text(&build(
        &s,
        &ReportOptions {
            lang: Lang::En,
            ..opts(ReportFormat::Html)
        },
    ));
    assert!(
        en.contains("TLS certificates")
            && en.contains("Out-of-scope candidates")
            && en.contains("Self-signed")
    );
    let uk = text(&build(
        &s,
        &ReportOptions {
            lang: Lang::Uk,
            ..opts(ReportFormat::Md)
        },
    ));
    assert!(uk.contains("Сертифікати TLS") && uk.contains("Кандидати поза скоупом"));
    let j: Value = serde_json::from_slice(&build(&s, &opts(ReportFormat::Json)).bytes).unwrap();
    assert_eq!(j["infra"]["oos"][0][0], "contoso-group.example");
    let plain = text(&build(&fixture().snap, &opts(ReportFormat::Html)));
    assert!(!plain.contains("id=\"certs\""));
}

/// An unreliable scan (the device network accepts every connection) is flagged in the ports
/// subsection in all three languages, even when the host has no ports (and thus no table).
#[test]
fn ports_unreliable_note() {
    let mut s = fixture().snap.clone();
    s.ports = serde_json::json!([{ "host": "portal.contoso.example", "ip": "203.0.113.12",
        "ports_scan": { "spec": "топ-100", "open": 0, "unreliable": "canary" }, "ports": [] }]);
    let h = text(&build(&s, &opts(ReportFormat::Html)));
    assert_safe_html(&h);
    assert!(h.contains("Скан портов недостоверен") && h.contains("portal.contoso.example"));
    assert!(!h.contains("<th>Порт</th>"), "no empty table");
    let md = text(&build(&s, &opts(ReportFormat::Md)));
    assert!(md.contains("Скан портов недостоверен"));
    for (l, w) in [
        (Lang::Uk, "Сканування портів недостовірне"),
        (Lang::En, "Port scan unreliable"),
    ] {
        let x = text(&build(
            &s,
            &ReportOptions {
                lang: l,
                ..opts(ReportFormat::Html)
            },
        ));
        assert!(x.contains(w), "{w}");
    }
}

/// The report shows the scan start date instead of the internal scan id.
#[test]
fn scan_ids_shown_as_dates() {
    let base = fixture().snap.clone();
    let mut snap = base.clone();
    for f in &mut snap.findings {
        if f.status == FindingStatus::Fixed {
            f.fixed_scan = Some("s1".into());
        }
    }
    for (lang, want) in [
        (Lang::Ru, "20.11.2026 11:40"),
        (Lang::En, "2026-11-20 11:40"),
    ] {
        for fmt in [ReportFormat::Html, ReportFormat::Md] {
            let o = ReportOptions { lang, ..opts(fmt) };
            let (t0, t1) = (text(&build(&base, &o)), text(&build(&snap, &o)));
            assert!(
                t1.matches(want).count() > t0.matches(want).count(),
                "{lang:?} {fmt:?}: fixed finding has no scan date"
            );
            assert_eq!(
                t1.matches("s1").count(),
                t0.matches("s1").count(),
                "{lang:?} {fmt:?}: raw scan id"
            );
        }
    }
}

/// The hosts scope column shows a localized status for every host (never the raw `in_scope`
/// code or an empty cell), and the request log counts target hosts separately from
/// third-party services.
#[test]
fn hosts_scope_labels_and_log_host_split() {
    let mut s = fixture().snap.clone();
    let codes = ["in_scope", "out_of_scope", "excluded", ""];
    for (h, c) in s.hosts.iter_mut().zip(codes.iter().cycle()) {
        h.scope = (*c).into();
    }
    let e = |host: &str, active: bool| RequestEntry {
        time: "2026-11-20T09:27:00Z".into(),
        module: if active { "crawler" } else { "crt" }.into(),
        method: "GET".into(),
        url: format!("https://{host}/"),
        host: host.into(),
        active,
        ..Default::default()
    };
    let log = vec![
        e("contoso.example", true),
        e("www.contoso.example", true),
        e("crt.sh", false),
        e("web.archive.org", false),
        e("api.hackertarget.com", false),
    ];
    let o = ReportOptions {
        lang: Lang::Uk,
        ..opts(ReportFormat::Html)
    };
    let h = text(&build_report_with_log(&s, &log, &o, NOW));
    assert!(!h.contains(">in_scope<") && !h.contains(">out_of_scope<"));
    assert!(h.contains(">у скоупі<") && h.contains(">поза скоупом<") && h.contains(">виключено<"));
    assert!(h.contains("<dt>Хости цілі</dt><dd>2</dd>"), "target hosts");
    assert!(
        h.contains("<dt>Сторонні сервіси (хости)</dt><dd>3</dd>"),
        "third-party services"
    );
    let md = text(&build_report_with_log(
        &s,
        &log,
        &ReportOptions {
            lang: Lang::Uk,
            ..opts(ReportFormat::Md)
        },
        NOW,
    ));
    assert!(md.contains("Хости цілі: 2") && md.contains("у скоупі"));
}

/// Discarded brute-force responses in the log show size/type and a soft-404 note instead of
/// a bare 200 (a fuzz run against a site answering 200 to everything produced thousands of
/// them).
#[test]
fn fuzz_soft404_marked_in_log() {
    let s = fixture().snap.clone();
    let e = |url: &str, note: Option<&str>| RequestEntry {
        time: "2026-11-20T09:33:00Z".into(),
        module: "fuzz".into(),
        method: "GET".into(),
        url: url.into(),
        host: "contoso.example".into(),
        status: Some(200),
        bytes: 48_213,
        active: true,
        note: note.map(str::to_string),
        ctype: Some("text/html; charset=utf-8".into()),
        ..Default::default()
    };
    let log = vec![
        e(
            "https://contoso.example/tatb94seo6loqak8",
            Some("calibration"),
        ),
        e("https://contoso.example/backup.zip", Some("soft404")),
        e("https://contoso.example/.git/HEAD", None),
    ];
    let o = ReportOptions {
        lang: Lang::Uk,
        ..opts(ReportFormat::Html)
    };
    let h = text(&build_report_with_log(&s, &log, &o, NOW));
    assert!(h.contains("<th>Розмір / тип</th>") || h.contains(">Розмір / тип<"));
    assert!(h.contains("48 КБ · text/html"));
    assert!(h.contains("soft-404, відкинуто") && h.contains("калібрування (випадковий шлях)"));
    let j = text(&build_report_with_log(
        &s,
        &log,
        &opts(ReportFormat::Json),
        NOW,
    ));
    assert!(j.contains("\"note\": \"soft404\""));
}

/// Software in the report: full names instead of keys (`word2007`), version as
/// `2007 (12)`, a localized "version unknown" without a version, a dash when there is no CVE
/// data, and a localized "date unknown" for EOL without a date.
#[test]
fn software_labels_versions_cve_and_eol() {
    use foca_core::api::Software;
    let mut s = fixture().snap.clone();
    let sw = |id: &str, name: &str, ver: &str, eol: Option<&str>, docs: u32| Software {
        id: id.into(),
        name: name.into(),
        ver: ver.into(),
        kind: "office".into(),
        eol: eol.is_some(),
        eol_date: eol.filter(|d| !d.is_empty()).map(str::to_string),
        docs,
        ..Default::default()
    };
    s.software = vec![
        sw("word", "Microsoft Office Word", "", None, 6),
        sw(
            "word2007",
            "Microsoft Office Word 2007",
            "12",
            Some("2017-10-10"),
            1,
        ),
        sw("ps2014", "Adobe Photoshop CC 2014", "CC 2014", Some(""), 1),
        sw(
            "outlook2007",
            "Microsoft Office Outlook 2007",
            "12",
            Some("2017-10-10"),
            1,
        ),
    ];
    let first = s.docs.iter().position(|d| !d.deleted).unwrap();
    s.docs[first].software = Some("word2007".into());
    let o = ReportOptions {
        lang: Lang::Uk,
        ..opts(ReportFormat::Html)
    };
    let h = text(&build(&s, &o));
    assert!(
        !h.contains(">word2007<") && !h.contains(">ps2014<"),
        "internal software keys"
    );
    assert!(h.contains("Microsoft Office Word 2007 (12)") && !h.contains("Word 2007 12<"));
    assert!(h.contains("Microsoft Office Word (версія невідома)"));
    assert!(
        h.contains(
            "<td>Adobe Photoshop CC 2014</td><td>дата невідома</td><td class=\"num\">-</td>"
        ) || (h.contains("дата невідома") && h.contains(">-<")),
        "EOL without date / CVE not checked"
    );
    // Top software: Word versions are listed next to each other.
    let a = h.find("Microsoft Office Word (версія невідома)").unwrap();
    let b = h[a..].find("Microsoft Office Word 2007 (12)").unwrap();
    assert!(
        !h[a..a + b].contains("Outlook"),
        "Word versions are adjacent"
    );
    let j = text(&build(&s, &opts(ReportFormat::Json)));
    assert!(j.contains("\"cve\": null"));
}

#[test]
fn host_software_fills_summary_and_port_versions() {
    let mut s = fixture().snap.clone();
    s.hosts[0].name = "www.example.com".into();
    s.hosts[0].tech = "Apache HTTP Server 2.4.58, PHP 8.1.2".into();
    s.ports = serde_json::json!([{ "host": "www.example.com", "ip": "192.0.2.10",
        "ports": [
            { "port": 443, "proto": "tcp", "service": "https", "source": "internetdb" },
            { "port": 3389, "proto": "tcp", "service": "rdp", "source": "internetdb" }
        ] }]);
    s.recon = serde_json::json!({ "tech": [
        { "name": "jQuery", "version": "1.12.4", "category": "js", "outdated": "1.12.4 < 3.5.0", "host": "www.example.com" }
    ] });
    for fmt in [ReportFormat::Md, ReportFormat::Html] {
        let o = ReportOptions {
            lang: Lang::En,
            ..opts(fmt)
        };
        let a = build(&s, &o);
        let body = text(&a);
        assert!(body.contains("Software on hosts"), "{fmt:?}");
        assert!(
            body.contains("PHP 8.1.2") && body.contains("jQuery 1.12.4"),
            "{fmt:?}"
        );
        let cpe = "Apache HTTP Server 2.4.58, PHP 8.1.2 (CPE)";
        assert!(
            body.contains(cpe),
            "{fmt:?}: port version not filled from CPE"
        );
        assert!(a.summary.software as usize >= s.software.len() + 3);
    }
    let md = text(&build(
        &s,
        &ReportOptions {
            lang: Lang::En,
            ..opts(ReportFormat::Md)
        },
    ));
    let eol = md.split("### Outdated software").nth(1).unwrap();
    let eol = eol.split("\n### ").next().unwrap();
    assert!(eol.contains("| jQuery 1.12.4 |"), "{eol}");
    // RDP has no matching technology: the version cell stays empty.
    assert!(md.contains("| www.example.com | 3389/tcp | rdp |  |"));
}
