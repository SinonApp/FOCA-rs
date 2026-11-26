//! Metadata anomalies: internal contradictions that point to a forged or
//! re-saved document, a wrong clock, or a copy of an older file.
//!
//! Checks per document:
//! * `created_after_modified`: creation date later than the modification date;
//! * `future_date`: a date later than "now";
//! * `date_mismatch`: PDF Info / EXIF dates disagree with the XMP dates by more than a day;
//! * `history_after_modified`, `history_before_created` - `xmpMM:History` events outside the
//!   document lifetime;
//! * `history_agent_mismatch`: the last `xmpMM:History` tool belongs to another product family
//!   than the declared Creator/Producer/CreatorTool;
//! * `software_newer_than_document`: the creating software was released after the creation
//!   year (needs the release year from `signatures/software.toml`);
//! * `edit_time_exceeds_lifetime`: total editing time longer than created → modified;
//! * `comment_before_created`: comments or tracked changes dated before the document itself.
//!
//! Dates without a zone are compared with a ±14 h tolerance. Every anomaly carries the field
//! names and values it is based on.

use foca_core::{DocStatus, Metadata, Severity};
use serde::Serialize;
use time::OffsetDateTime;

use crate::software::{self, Signatures};
use crate::util::instant;
use crate::DocInput;

/// One anomaly of one document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Anomaly {
    pub doc: u64,
    /// Machine-readable code (see the module docs); the finding rule would be `doc.anomaly.<code>`.
    pub code: String,
    /// Suggested severity: these are signals for an analyst, not vulnerabilities.
    pub sev: Severity,
    /// 0-100: how sure the check is that the contradiction is real (not a zone artefact).
    pub confidence: u8,
    /// Russian title (the core language).
    pub title: String,
    /// Russian explanation with the values.
    pub detail: String,
    /// Metadata fields involved, e.g. `created`, `xmp:CreateDate`.
    pub fields: Vec<String>,
}

/// Zone tolerance for dates without an offset.
const TZ_SLACK: i64 = 14 * 3_600;
/// Seconds of slack for "created after modified" (save rounding).
const SAVE_SLACK: i64 = 120;
const DAY: i64 = 86_400;

/// Difference `b - a` in seconds and the tolerance that applies.
fn diff(a: &str, b: &str) -> Option<(i64, i64)> {
    let (ta, za) = instant(a)?;
    let (tb, zb) = instant(b)?;
    let slack = if za && zb { 0 } else { TZ_SLACK };
    Some((tb - ta, slack))
}

fn days(secs: i64) -> i64 {
    secs.abs() / DAY
}

/// Product family of a software string, for the history/producer comparison.
fn family(s: &str) -> Option<&'static str> {
    let l = s.to_lowercase();
    const F: &[(&str, &str)] = &[
        ("photoshop", "adobe-photoshop"),
        ("lightroom", "adobe-lightroom"),
        ("illustrator", "adobe-illustrator"),
        ("indesign", "adobe-indesign"),
        ("acrobat", "adobe-acrobat"),
        ("distiller", "adobe-acrobat"),
        ("pdfmaker", "adobe-acrobat"),
        ("bridge", "adobe-bridge"),
        ("microsoft", "microsoft"),
        ("word", "microsoft"),
        ("excel", "microsoft"),
        ("powerpoint", "microsoft"),
        ("libreoffice", "libreoffice"),
        ("openoffice", "libreoffice"),
        ("gimp", "gimp"),
        ("inkscape", "inkscape"),
        ("coreldraw", "corel"),
        ("corel", "corel"),
        ("foxit", "foxit"),
        ("nitro", "nitro"),
        ("pdf-xchange", "pdfxchange"),
        ("ghostscript", "ghostscript"),
        ("quartz", "apple"),
        ("macos", "apple"),
        ("mac os", "apple"),
        ("ios", "apple"),
        ("skia", "google"),
        ("chrome", "google"),
        ("abbyy", "abbyy"),
        ("finereader", "abbyy"),
    ];
    F.iter().find(|(k, _)| l.contains(k)).map(|(_, f)| *f)
}

/// Families that legitimately co-occur (Acrobat edits a Word PDF; Photoshop files go through
/// Bridge/Lightroom; a PDF printed from anything by Distiller).
fn compatible(a: &str, b: &str) -> bool {
    a == b
        || (a.starts_with("adobe-") && b.starts_with("adobe-"))
        || [a, b].contains(&"adobe-acrobat")
}

fn year_of(raw: &str) -> Option<i32> {
    crate::util::local_iso(raw).and_then(|l| l[..4].parse().ok())
}

/// Finds the anomalies of one document.
pub fn check(doc: u64, m: &Metadata, now: OffsetDateTime) -> Vec<Anomaly> {
    let mut out: Vec<Anomaly> = Vec::new();
    let mut add =
        |code: &str, sev: Severity, conf: u8, title: &str, detail: String, fields: &[&str]| {
            out.push(Anomaly {
                doc,
                code: code.into(),
                sev,
                confidence: conf,
                title: title.into(),
                detail,
                fields: fields.iter().map(|s| s.to_string()).collect(),
            });
        };
    let created = m.created.as_deref();
    let modified = m.modified.as_deref();

    // created > modified
    if let (Some(c), Some(md)) = (created, modified) {
        if let Some((d, slack)) = diff(md, c) {
            if d > SAVE_SLACK + slack {
                add(
                    "created_after_modified",
                    Severity::Low,
                    if slack == 0 { 90 } else { 70 },
                    "Дата создания позже даты изменения",
                    format!("Создан {c}, изменён {md}: дату правили вручную, файл скопирован с другого компьютера или часы были сбиты"),
                    &["created", "modified"],
                );
            }
        }
    }

    // Dates in the future.
    let now_secs = now.unix_timestamp();
    let mut dates: Vec<(&str, &str)> = Vec::new();
    for (k, v) in [
        ("created", created),
        ("modified", modified),
        ("printed", m.printed.as_deref()),
    ] {
        if let Some(v) = v {
            dates.push((k, v));
        }
    }
    for k in ["xmp:CreateDate", "xmp:ModifyDate", "xmp:MetadataDate"] {
        if let Some(v) = m.xmp.get(k) {
            dates.push((k, v));
        }
    }
    let future: Vec<String> = dates
        .iter()
        .filter(|(_, v)| {
            instant(v).is_some_and(|(t, z)| t > now_secs + DAY + if z { 0 } else { TZ_SLACK })
        })
        .map(|(k, v)| format!("{k} = {v}"))
        .collect();
    if !future.is_empty() {
        add(
            "future_date",
            Severity::Low,
            90,
            "Дата документа в будущем",
            format!(
                "{}: часы компьютера автора были сбиты или дату подделали",
                future.join("; ")
            ),
            &dates.iter().map(|d| d.0).collect::<Vec<_>>(),
        );
    }

    // PDF Info / EXIF vs XMP.
    let pairs = [
        ("created", created, "xmp:CreateDate"),
        ("modified", modified, "xmp:ModifyDate"),
    ];
    for (name, main, xk) in pairs {
        let (Some(a), Some(b)) = (main, m.xmp.get(xk)) else {
            continue;
        };
        if let Some((d, slack)) = diff(a, b) {
            if d.abs() > DAY + slack {
                let src = if m.format.is_image() { "EXIF" } else { "Info" };
                add(
                    "date_mismatch",
                    Severity::Low,
                    if slack == 0 { 85 } else { 70 },
                    "Даты в метаданных не совпадают",
                    format!(
                        "{src} {name} = {a}, XMP {xk} = {b} (разница {} дн.): один блок метаданных правили отдельно от другого",
                        days(d)
                    ),
                    &[name, xk],
                );
            }
        }
    }
    if m.format.is_image() {
        if let (Some(orig), Some(gps)) = (
            m.fields.get("exif:DateTimeOriginal"),
            m.fields.get("exif:GPSDateStamp"),
        ) {
            let (orig, gps) = (orig.trim_matches('"'), gps.trim_matches('"'));
            if let (Some(a), Some(b)) = (
                crate::util::local_iso(orig),
                crate::util::local_iso(&gps.replace(':', "-")),
            ) {
                if a[..10] != b[..10] {
                    if let Some((d, _)) = diff(&a, &b) {
                        if d.abs() > 2 * DAY {
                            add(
                                "date_mismatch",
                                Severity::Low,
                                60,
                                "Дата снимка не совпадает с датой GPS",
                                format!("DateTimeOriginal = {orig}, GPSDateStamp = {gps}"),
                                &["exif:DateTimeOriginal", "exif:GPSDateStamp"],
                            );
                        }
                    }
                }
            }
        }
    }

    // XMP history vs lifetime and tools.
    let hist: Vec<(&str, &str)> = m
        .xmp_history
        .iter()
        .filter_map(|e| {
            e.when
                .as_deref()
                .map(|w| (w, e.software_agent.as_deref().unwrap_or("")))
        })
        .collect();
    if let Some(md) = modified {
        let late: Vec<&str> = hist
            .iter()
            .filter(|(w, _)| diff(md, w).is_some_and(|(d, s)| d > 3_600 + s))
            .map(|(w, _)| *w)
            .collect();
        if let Some(w) = late.last() {
            add(
                "history_after_modified",
                Severity::Low,
                75,
                "История правок XMP позже даты изменения",
                format!("Событие xmpMM:History {w} позже modified = {md}: дату изменения правили вручную"),
                &["xmpMM:History", "modified"],
            );
        }
    }
    if let Some(c) = created {
        let early: Vec<&str> = hist
            .iter()
            .filter(|(w, _)| diff(w, c).is_some_and(|(d, s)| d > DAY + s))
            .map(|(w, _)| *w)
            .collect();
        if let Some(w) = early.first() {
            add(
                "history_before_created",
                Severity::Info,
                70,
                "История правок XMP начинается раньше даты создания",
                format!("Событие xmpMM:History {w} раньше created = {c}: файл создан из более старого документа (Save As / копия)"),
                &["xmpMM:History", "created"],
            );
        }
    }
    if let Some(last_agent) = m
        .xmp_history
        .iter()
        .rev()
        .filter_map(|e| e.software_agent.as_deref())
        .find(|a| !a.trim().is_empty())
    {
        let declared: Vec<&str> = [
            m.application.as_deref(),
            m.producer.as_deref(),
            m.xmp.get("xmp:CreatorTool").map(String::as_str),
        ]
        .into_iter()
        .flatten()
        .collect();
        if let Some(fh) = family(last_agent) {
            let fams: Vec<&str> = declared.iter().filter_map(|d| family(d)).collect();
            if !fams.is_empty() && !fams.iter().any(|f| compatible(f, fh)) {
                add(
                    "history_agent_mismatch",
                    Severity::Low,
                    65,
                    "История XMP противоречит программе-создателю",
                    format!(
                        "Последнее событие xmpMM:History сделано в «{last_agent}», а в метаданных указано: {}. Файл пересохраняли в другой программе или поля подменили",
                        declared.join(", ")
                    ),
                    &["xmpMM:History", "Creator/Producer"],
                );
            }
        }
    }

    // Software released after the creation year.
    if let Some(cy) = created.and_then(year_of) {
        let sigs = Signatures::builtin();
        let mut seen = false;
        for cand in software::candidates(m) {
            if seen {
                break;
            }
            if let Some(s) = sigs.match_software(&cand) {
                if let Some(r) = s.released.filter(|r| *r > cy) {
                    seen = true;
                    add(
                        "software_newer_than_document",
                        Severity::Low,
                        80,
                        "Программа вышла позже даты создания",
                        format!("{} выпущена в {r} г., а документ создан в {cy} г.: дата создания подделана или унаследована от исходного файла", s.name),
                        &["created", "application"],
                    );
                }
            }
        }
    }

    // Editing time longer than the lifetime.
    if let (Some(c), Some(md), Some(et)) = (created, modified, m.edit_time_secs) {
        if let Some((d, slack)) = diff(c, md) {
            let et = et as i64;
            if d >= 0 && et > d + slack + 3_600 && et < 10 * 365 * DAY {
                add(
                    "edit_time_exceeds_lifetime",
                    Severity::Info,
                    55,
                    "Время правки больше срока жизни документа",
                    format!("Общее время правки {} мин, а между созданием и изменением {} мин: документ скопирован из другого (Save As сохраняет счётчик)", et / 60, d / 60),
                    &["edit_time", "created", "modified"],
                );
            }
        }
    }

    // Comments/revisions dated before the document.
    if let Some(c) = created {
        let early = m
            .comments
            .iter()
            .filter_map(|x| x.date.as_deref())
            .chain(m.revisions.iter().filter_map(|r| r.date.as_deref()))
            .filter(|d| diff(d, c).is_some_and(|(x, s)| x > DAY + s))
            .min_by_key(|d| instant(d).map(|t| t.0));
        if let Some(d) = early {
            add(
                "comment_before_created",
                Severity::Info,
                70,
                "Комментарии старше документа",
                format!("Комментарий или исправление от {d}, а документ создан {c}: файл сделан из более раннего документа вместе с правками"),
                &["comments", "created"],
            );
        }
    }
    out
}

/// Anomalies of all analysed documents, ordered by document and code.
pub fn detect(inputs: &[DocInput], now: OffsetDateTime) -> Vec<Anomaly> {
    let mut out: Vec<Anomaly> = inputs
        .iter()
        .filter(|i| !i.deleted && i.doc.status == DocStatus::Analyzed)
        .filter_map(|i| i.doc.metadata.as_ref().map(|m| check(i.doc.id, m, now)))
        .flatten()
        .collect();
    out.sort_by(|a, b| (a.doc, &a.code).cmp(&(b.doc, &b.code)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_core::{CommentRef, DocFormat, XmpEvent};
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-22 12:00 UTC);

    fn codes(m: &Metadata) -> Vec<String> {
        check(1, m, NOW).into_iter().map(|a| a.code).collect()
    }

    #[test]
    fn clean_document_has_no_anomalies() {
        let mut m = Metadata::new(DocFormat::Pdf);
        m.created = Some("2024-03-14T10:00:00+02:00".into());
        m.modified = Some("2024-03-14T12:00:00+02:00".into());
        m.xmp
            .insert("xmp:CreateDate".into(), "2024-03-14T08:00:00Z".into());
        m.application = Some("Microsoft® Word 2016".into());
        m.producer = Some("Microsoft® Word 2016".into());
        assert!(codes(&m).is_empty(), "{:?}", codes(&m));
    }

    #[test]
    fn detects_contradictions() {
        let mut m = Metadata::new(DocFormat::Pdf);
        m.created = Some("2015-06-01T10:00:00+03:00".into());
        m.modified = Some("2015-05-01T10:00:00+03:00".into());
        m.printed = Some("2031-01-01T00:00:00Z".into());
        m.xmp
            .insert("xmp:CreateDate".into(), "2014-01-01T10:00:00+03:00".into());
        m.application = Some("Microsoft® Word 2019".into());
        m.xmp_history = vec![XmpEvent {
            when: Some("2015-07-01T10:00:00+03:00".into()),
            software_agent: Some("Adobe Photoshop CC 2015 (Windows)".into()),
            ..Default::default()
        }];
        m.comments = vec![CommentRef {
            author: Some("Іван Петренко".into()),
            initials: None,
            date: Some("2013-01-01T00:00:00Z".into()),
            text: "ok".into(),
            source: "comments.xml".into(),
        }];
        let c = codes(&m);
        for want in [
            "created_after_modified",
            "future_date",
            "date_mismatch",
            "history_after_modified",
            "history_agent_mismatch",
            "software_newer_than_document",
            "comment_before_created",
        ] {
            assert!(c.iter().any(|x| x == want), "missing {want} in {c:?}");
        }
    }

    #[test]
    fn zone_tolerance() {
        let mut m = Metadata::new(DocFormat::Docx);
        // Local creation time vs. UTC modification: 3 h apart, within the zone slack.
        m.created = Some("2024-03-14T13:00:00".into());
        m.modified = Some("2024-03-14T10:00:00Z".into());
        m.edit_time_secs = Some(600);
        assert!(codes(&m).is_empty());
        m.edit_time_secs = Some(400_000);
        m.modified = Some("2024-03-15T10:00:00Z".into());
        assert_eq!(codes(&m), vec!["edit_time_exceeds_lifetime"]);
    }
}
