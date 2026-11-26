//! Report integration tests: English/Ukrainian localization and local time display.

mod common;

use common::*;

/// Infrastructure finding texts are translated by rule (`infra.<code>`) and the shared templates.
#[test]
fn infra_findings_translated() {
    let mut s = fixture().snap.clone();
    let mut f = s.findings[0].clone();
    f.id = 999_001;
    f.title = "Просроченный TLS-сертификат на portal.contoso.example:443".into();
    f.description = "Обнаружено при проверке portal.contoso.example:443: expired 3 days ago".into();
    f.recommendation =
        "Продлить сертификат до истечения срока и настроить автоматическое продление (ACME)."
            .into();
    f.provenance.rule = "infra.cert_expired".into();
    f.sev = foca_core::Severity::High;
    s.findings.push(f);
    let en = text(&build(
        &s,
        &ReportOptions {
            lang: Lang::En,
            ..opts(ReportFormat::Html)
        },
    ));
    assert!(en.contains("Expired TLS certificate on portal.contoso.example:443"));
    assert!(en.contains("Found when checking portal.contoso.example:443: expired 3 days ago"));
    assert!(en.contains("automatic renewal (ACME)"));
    let uk = text(&build(
        &s,
        &ReportOptions {
            lang: Lang::Uk,
            ..opts(ReportFormat::Html)
        },
    ));
    assert!(uk.contains("Прострочений TLS-сертифікат на portal.contoso.example:443"));
}

/// EN/UK reports translate finding texts (analysis, secrets, recon, ports, mail, fuzz):
/// once project data is stripped, EN has no Cyrillic and UK has no Russian letters or words.
#[test]
fn en_uk_reports_localized() {
    let mut snap = fixture().snap.clone();
    net_findings(&mut snap);
    // Project data (file names, people, hosts, software, client, …) stays as is; strip it.
    let mut data: Vec<String> = vec![
        snap.project.name.clone(),
        snap.project.client.clone(),
        "ТОВ «Кібер Аудит»".into(),
    ];
    let v = serde_json::to_value(&snap).unwrap();
    fn walk(v: &Value, key: &str, out: &mut Vec<String>) {
        match v {
            Value::String(s)
                if ![
                    "description",
                    "recommendation",
                    "evidence",
                    "source",
                    "tags",
                    "category",
                    "role",
                ]
                .contains(&key) =>
            {
                out.push(s.clone())
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, key, out)),
            Value::Object(o) => o
                .iter()
                .filter(|(k, _)| k.as_str() != "findings")
                .for_each(|(k, x)| walk(x, k, out)),
            _ => {}
        }
    }
    walk(&v, "", &mut data);
    // Secret locations (document fields) are data.
    for f in &snap.findings {
        data.extend(f.provenance.fields.iter().cloned());
        data.extend(
            f.provenance
                .fields
                .iter()
                .map(|x| x.trim_start_matches("поле ").to_string()),
        );
        if f.provenance.rule == "hidden-sheets" {
            let sheets = f.title.split_once(": ").map(|(_, b)| b).unwrap_or("");
            data.extend(sheets.split(", ").map(str::to_string));
        }
    }
    let cyr = |c: char| ('\u{400}'..='\u{4ff}').contains(&c);
    data.retain(|s| s.chars().count() >= 3 && s.chars().any(cyr));
    data.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for (lang, fmt) in [
        (Lang::En, ReportFormat::Html),
        (Lang::En, ReportFormat::Md),
        (Lang::Uk, ReportFormat::Html),
    ] {
        let a = build(&snap, &ReportOptions { lang, ..opts(fmt) });
        // Evidence is quoted from documents (data); its labels are covered by `ftext::tests`.
        let mut t = String::new();
        let mut in_ev = false;
        for l in text(&a).lines() {
            let open = l.contains("<pre class=\"ev\">") || l.trim_start().starts_with("```");
            if open && !in_ev {
                in_ev = !(l.contains("</pre>") || (l.matches("```").count() > 1));
                continue;
            }
            if in_ev {
                in_ev = !(l.contains("</pre>") || l.trim_start().starts_with("```"));
                continue;
            }
            t.push_str(l);
            t.push('\n');
        }
        for d in &data {
            for form in [
                d.clone(),
                foca_report::safe::html(d),
                foca_report::safe::md(d),
            ] {
                t = t.replace(&form, " ");
            }
        }
        let bad: Vec<&str> = t
            .lines()
            .filter(|l| match lang {
                Lang::En => l.chars().any(cyr),
                _ => {
                    l.chars().any(|c| "ыэъёЫЭЪЁ".contains(c))
                        || [
                            " и ",
                            " что ",
                            " или ",
                            " это ",
                            " документов",
                            " сотрудников",
                            " быть ",
                            " есть ",
                            "Удалить",
                            "Обновить",
                        ]
                        .iter()
                        .any(|w| l.contains(w))
                }
            })
            .collect();
        assert!(
            bad.is_empty(),
            "{lang:?} {fmt:?}: {} lines with Russian text, e.g.:\n{}",
            bad.len(),
            bad.iter().take(12).copied().collect::<Vec<_>>().join("\n")
        );
    }
}

/// All report times are device local time: the log (UTC with zone) is converted to the zone
/// of `now`, and the zone is printed on the cover, so log and first-seen times agree.
#[test]
fn log_times_in_device_local_zone() {
    let s = fixture().snap.clone();
    let log = vec![RequestEntry {
        time: "2026-11-20T09:27:00Z".into(),
        module: "crawler".into(),
        method: "GET".into(),
        url: "https://contoso.example/".into(),
        host: "contoso.example".into(),
        active: true,
        ..Default::default()
    }];
    let now = NOW.to_offset(time::macros::offset!(+2));
    let o = ReportOptions {
        lang: Lang::Uk,
        ..opts(ReportFormat::Html)
    };
    let h = text(&build_report_with_log(&s, &log, &o, now));
    assert!(
        h.contains("20.11.2026 11:27") && !h.contains("09:27"),
        "log in local time"
    );
    assert!(h.contains("<dt>Часовий пояс (час пристрою)</dt><dd>UTC+2</dd>"));
    let md = text(&build_report_with_log(
        &s,
        &log,
        &ReportOptions {
            lang: Lang::Uk,
            ..opts(ReportFormat::Md)
        },
        now,
    ));
    assert!(
        md.contains("UTC") && md.contains("11:27") && !md.contains("09:27"),
        "{md}"
    );
    let j = text(&build_report_with_log(
        &s,
        &log,
        &opts(ReportFormat::Json),
        now,
    ));
    assert!(
        j.contains("\"generated_at\": \"2026-11-20T14:00:00+02:00\""),
        "generated_at with zone"
    );
}

/// The request log in UK/EN reports contains no Russian strings from the core (network
/// errors, banner retries, filtered timeouts, NS zone labels, …).
#[test]
fn log_errors_localized_uk_en() {
    let s = fixture().snap.clone();
    let e = |url: &str, err: Option<&str>| RequestEntry {
        time: "2026-11-20T09:27:00Z".into(),
        module: "ports".into(),
        method: "TCP".into(),
        url: url.into(),
        host: "contoso.example".into(),
        active: true,
        error: err.map(str::to_string),
        ..Default::default()
    };
    let log = vec![
        e(
            "https://contoso.example/",
            Some("network: сеть: Connection refused (os error 111)"),
        ),
        e("tcp://contoso.example:8888 (повтор для баннера)", None),
        e(
            "tcp://contoso.example:22",
            Some("timeout: нет ответа (фильтр)"),
        ),
        e("tcp://contoso.example:25", Some("timeout: таймаут")),
        e(
            "dns+tcp://ns1.example.net:53/contoso.example/AXFR#ns-зоны-цели",
            Some("network: сеть: трансфер отклонён: Query Refused"),
        ),
        e(
            "https://contoso.example/big",
            Some("too_large: превышен лимит размера 3145728 байт"),
        ),
        e(
            "https://contoso.example/x",
            Some("recon: нет ответа за отведённое время"),
        ),
    ];
    let section = |h: &str| {
        let a = h.find("id=\"log\"").expect("log section");
        h[a..a + h[a..].find("</section>").unwrap()].to_string()
    };
    let uk = section(&text(&build_report_with_log(
        &s,
        &log,
        &ReportOptions {
            lang: Lang::Uk,
            ..opts(ReportFormat::Html)
        },
        NOW,
    )));
    let bad: Vec<char> = uk.chars().filter(|c| "ыэъёЫЭЪЁ".contains(*c)).collect();
    assert!(
        bad.is_empty(),
        "Russian letters in the UK log: {bad:?}\n{uk}"
    );
    for w in [
        "сеть",
        "повтор для баннера",
        "нет ответа",
        "превышен",
        "зоны",
    ] {
        assert!(!uk.contains(w), "{w}");
    }
    assert!(uk.contains("refused: мережа: Connection refused") && uk.contains("#ns-зони-цілі"));
    let en = section(&text(&build_report_with_log(
        &s,
        &log,
        &ReportOptions {
            lang: Lang::En,
            ..opts(ReportFormat::Html)
        },
        NOW,
    )));
    assert!(
        !en.chars()
            .any(|c| matches!(c, 'а'..='я' | 'А'..='Я' | 'ё' | 'і' | 'ї' | 'є')),
        "{en}"
    );
    assert!(
        en.contains("refused: network: Connection refused")
            && en.contains("(banner retry)")
            && en.contains("too_large: size limit of 3145728 bytes exceeded")
    );
}

/// Request log errors stored as Russian text by the network layer (rows of a real phone export).
const RU_LOG_ERRORS: &[(&str, &str)] = &[
    ("too_large: превышен лимит размера 256 байт", "too_large"),
    ("timeout: таймаут", "timeout"),
    (
        "limit: сервис уже ответил 429 в этом скане, запрос не отправлен",
        "limit",
    ),
    ("network: сеть: трансфер отклонён: Query Refused", "network"),
    (
        "network: сеть: error sending request for url (https://contoso.example/)",
        "network",
    ),
    (
        "out_of_scope: вне скоупа: mta-sts.sinon.app (нет в целях или в исключениях)",
        "out_of_scope",
    ),
];

/// Russian-only letters and words of the network error texts; none may reach a UK export.
const RU_MARKERS: &[&str] = &[
    "ы",
    "э",
    "ъ",
    "ё",
    "сеть",
    "таймаут",
    "превышен",
    "лимит размера",
    "сервис",
    "ответил",
    "отклонён",
    "вне скоупа",
    "нет в целях",
    "исключениях",
];

/// The CSV log export writes `error` as `<code>: <detail>` in the export language.
#[test]
fn log_export_errors_in_export_language() {
    let s = fixture().snap.clone();
    let log: Vec<RequestEntry> = RU_LOG_ERRORS
        .iter()
        .map(|(err, _)| RequestEntry {
            time: "2026-11-26T21:55:00Z".into(),
            module: "mail".into(),
            method: "GET".into(),
            url: "https://contoso.example/".into(),
            host: "contoso.example".into(),
            error: Some(err.to_string()),
            ..Default::default()
        })
        .collect();
    for lang in [Lang::En, Lang::Uk] {
        let a = export_with_log(
            &s,
            &log,
            ExportKind::Log,
            ExportFormat::Csv,
            &ExportOptions {
                lang,
                bom: false,
                ..Default::default()
            },
        );
        let csv = String::from_utf8(a.bytes).unwrap();
        let mut lines = csv.lines();
        let header: Vec<&str> = lines.next().unwrap().split(',').collect();
        let col = header
            .iter()
            .position(|h| *h == "error")
            .expect("error column");
        // The error is the last column; a cell with a comma is quoted.
        let errors: Vec<&str> = lines
            .map(|l| match l.strip_suffix('"') {
                Some(q) => &q[q.rfind(",\"").unwrap() + 2..],
                None => l.rsplit(',').next().unwrap(),
            })
            .collect();
        assert_eq!(col, header.len() - 1, "{csv}");
        assert_eq!(errors.len(), RU_LOG_ERRORS.len(), "{csv}");
        for (cell, (raw, code)) in errors.iter().zip(RU_LOG_ERRORS) {
            assert!(
                *cell == *code || cell.starts_with(&format!("{code}: ")),
                "{lang:?} {raw} -> {cell}"
            );
            if lang == Lang::En {
                assert!(
                    !cell
                        .chars()
                        .any(|c| matches!(c, 'а'..='я' | 'А'..='Я' | 'ё' | 'і' | 'ї' | 'є')),
                    "{raw} -> {cell}"
                );
            } else {
                for w in RU_MARKERS {
                    assert!(!cell.contains(w), "{w}: {raw} -> {cell}");
                }
            }
        }
        if lang == Lang::En {
            assert!(
                csv.contains("too_large: size limit of 256 bytes exceeded"),
                "{csv}"
            );
            assert!(
                csv.contains("network: transfer refused: Query Refused"),
                "{csv}"
            );
            assert!(
                csv.contains("out_of_scope: mta-sts.sinon.app (not among the targets or excluded)"),
                "{csv}"
            );
            assert!(
                csv.contains("limit: the service already answered 429"),
                "{csv}"
            );
        } else {
            assert!(csv.contains("timeout: тайм-аут"), "{csv}");
            assert!(
                csv.contains("network: мережа: трансфер відхилено: Query Refused"),
                "{csv}"
            );
        }
    }
}

/// A project with a scope-blocked MTA-STS fetch (finding and log row stored by an older core),
/// missing security headers and a camera from EXIF renders without Russian in EN and UK.
#[test]
fn scope_blocked_mail_headers_and_camera_localized() {
    use foca_report::svg::timeline::{Lane, Timeline, TimelineEvent};
    use foca_report::svg::Visuals;
    let mut s = fixture().snap.clone();
    let oos = "вне скоупа: mta-sts.contoso.example (нет в целях или в исключениях)";
    let mut f = s.findings[0].clone();
    f.id = 999_101;
    f.title = "Запись MTA-STS есть, но файл политики недоступен".into();
    f.description = oos.into();
    f.evidence = String::new();
    f.provenance.rule = "mail-mta_sts_policy_unreachable".into();
    s.findings.push(f);
    let mut h = s.findings[0].clone();
    h.id = 999_102;
    h.evidence = "URL: https://contoso.example/\nStrict-Transport-Security: (нет)\nContent-Security-Policy: есть\nX-Frame-Options: (нет)".into();
    s.findings.push(h);
    s.software.push(foca_core::api::Software {
        id: "sony".into(),
        name: "Sony (камера)".into(),
        kind: "camera".into(),
        docs: 1,
        ..Default::default()
    });
    let vis = Visuals {
        timeline: Timeline {
            events: vec![TimelineEvent {
                lane: Lane::Software,
                year: 2024,
                label: "Sony (камера)".into(),
            }],
        },
        ..Visuals::default()
    };
    let log = vec![RequestEntry {
        time: "2026-11-26T21:55:00Z".into(),
        module: "mail".into(),
        method: "GET".into(),
        url: "https://mta-sts.contoso.example/.well-known/mta-sts.txt".into(),
        host: "mta-sts.contoso.example".into(),
        blocked: true,
        error: Some(format!("out_of_scope: {oos}")),
        ..Default::default()
    }];
    for lang in [Lang::En, Lang::Uk] {
        for fmt in [ReportFormat::Md, ReportFormat::Html] {
            let r = text(&foca_report::build_report_with_visuals(
                &s,
                &log,
                &vis,
                &ReportOptions { lang, ..opts(fmt) },
                NOW,
            ));
            for w in [
                "(нет)",
                ": есть",
                "вне скоупа",
                "нет в целях",
                "исключениях",
                "Цифровая",
                "неизвестна",
                "файл политики",
            ] {
                assert!(!r.contains(w), "{lang:?} {fmt:?}: {w}");
            }
            if lang == Lang::En {
                assert!(!r.contains("(камера)"), "{fmt:?}");
                assert!(r.contains("mta-sts.contoso.example (not among the targets or excluded)"));
                assert!(r.contains("Strict-Transport-Security: (none)"), "{fmt:?}");
                assert!(r.contains("Sony (camera)"), "{fmt:?}");
            } else {
                assert!(r.contains("немає серед цілей або у винятках"), "{fmt:?}");
                assert!(r.contains("Strict-Transport-Security: (немає)"), "{fmt:?}");
            }
        }
    }
}

#[test]
fn english_report_date_and_no_evidence_repeating_description() {
    let mut s = fixture().snap.clone();
    let f = &mut s.findings[0];
    f.description = "Header Strict-Transport-Security is missing.".into();
    f.evidence = f.description.clone();
    f.url = Some("https://www.example.com/".into());
    let en = text(&build(
        &s,
        &ReportOptions {
            lang: Lang::En,
            ..opts(ReportFormat::Md)
        },
    ));
    assert!(en.contains("20 Nov 2026"), "EN date not localized");
    assert!(
        !en.contains("20.11.2026 ("),
        "EN report keeps DD.MM.YYYY date"
    );
    let ru = text(&build(&s, &opts(ReportFormat::Md)));
    assert!(ru.contains("20.11.2026"));
    let card = ru
        .split("### ")
        .find(|c| c.contains("Strict-Transport-Security"))
        .unwrap();
    assert_eq!(
        card.matches("Strict-Transport-Security is missing").count(),
        1,
        "{card}"
    );
    assert!(card.contains("https://www.example.com/"));
}
