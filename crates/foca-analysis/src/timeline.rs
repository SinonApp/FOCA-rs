//! Timeline (events from document dates) and activity: hours, weekdays and the time zone
//! inferred from date offsets.

use std::collections::BTreeMap;

use foca_core::api::{Event, EventRef, Printer, Software};
use serde::Serialize;

use crate::util::{tz_label, weekday, ymdh};
use crate::DocFacts;

/// Author activity based on document creation and modification dates.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Activity {
    /// Timestamps per hour 0-23 (document local time).
    pub hours: Vec<u32>,
    /// Timestamps per weekday, 0 = Monday.
    pub weekdays: Vec<u32>,
    /// Joint distribution: seven rows (0 = Monday) of 24 hourly counts. Row sums equal
    /// `weekdays`, column sums equal `hours`.
    pub matrix: Vec<Vec<u32>>,
    pub total: u32,
    /// Timestamps outside 08:00-19:00 or on weekends.
    pub out_of_hours: u32,
    /// Most frequent time zone among the date offsets (`UTC+2`), if any.
    pub tz: Option<String>,
    pub tz_counts: BTreeMap<String, u32>,
}

pub fn activity(docs: &[DocFacts]) -> Activity {
    let mut a = Activity {
        hours: vec![0; 24],
        weekdays: vec![0; 7],
        matrix: vec![vec![0; 24]; 7],
        ..Default::default()
    };
    let mut tz: BTreeMap<i32, u32> = BTreeMap::new();
    for d in docs.iter().filter(|d| d.analyzed) {
        for dt in [&d.created, &d.modified].into_iter().flatten() {
            let Some((y, m, day, h)) = ymdh(dt) else {
                continue;
            };
            // Exactly 00:00:00 usually means a date without a time.
            if dt.ends_with("T00:00:00") {
                continue;
            }
            let w = weekday(y, m, day);
            a.hours[h as usize % 24] += 1;
            a.weekdays[w as usize % 7] += 1;
            a.matrix[w as usize % 7][h as usize % 24] += 1;
            a.total += 1;
            if !(8..19).contains(&h) || w >= 5 {
                a.out_of_hours += 1;
            }
        }
        for &o in &d.offsets {
            *tz.entry(o).or_default() += 1;
        }
    }
    // UTC ("Z") often means "zone not recorded"; use it only if nothing else is present.
    let best = tz
        .iter()
        .filter(|(o, _)| **o != 0)
        .max_by(|a, b| a.1.cmp(b.1).then(a.0.cmp(b.0)))
        .or_else(|| tz.iter().max_by_key(|(_, n)| **n));
    a.tz = best.map(|(o, _)| tz_label(*o));
    a.tz_counts = tz.into_iter().map(|(o, n)| (tz_label(o), n)).collect();
    a
}

fn ev(
    date: &str,
    ic: &str,
    k: &str,
    t: String,
    s: String,
    sev: Option<&str>,
    doc: u64,
) -> Option<Event> {
    let (y, m, _, _) = ymdh(date)?;
    Some(Event {
        y,
        m: format!("{m:02}"),
        ic: ic.into(),
        k: k.into(),
        t,
        s,
        sev: sev.map(str::to_string),
        reference: EventRef {
            kind: "doc".into(),
            id: doc,
        },
    })
}

/// Builds timeline events (the `Event` format from docs/API.md).
pub fn events(docs: &[DocFacts], software: &[Software], printers: &[Printer]) -> Vec<Event> {
    let mut an: Vec<&DocFacts> = docs
        .iter()
        .filter(|d| d.analyzed && d.created.is_some())
        .collect();
    an.sort_by(|a, b| a.created.cmp(&b.created).then(a.id.cmp(&b.id)));
    let mut out = Vec::new();
    let Some(first) = an.first() else {
        return out;
    };
    let swname = |id: &str| {
        software
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.name.clone())
            .unwrap_or_default()
    };
    let date = |d: &DocFacts| d.created.clone().unwrap_or_default();
    out.extend(ev(
        &date(first),
        "doc",
        "Документы",
        "Самый ранний документ в выборке".into(),
        match first.software.first() {
            Some(s) => format!("{} · {}", first.name, swname(s)),
            None => first.name.clone(),
        },
        None,
        first.id,
    ));
    // Software events use the modification date: the last save is the actual work in that
    // software, while the creation date is often inherited from an old template.
    let sdate = |d: &DocFacts| {
        d.modified
            .clone()
            .or_else(|| d.created.clone())
            .unwrap_or_default()
    };
    for s in software {
        let mut ds: Vec<&&DocFacts> = an
            .iter()
            .filter(|d| d.software.contains(&s.id))
            .filter(|d| {
                // Not before the software was released (clocks and templates lie).
                s.released.is_none_or(|y| {
                    sdate(d)
                        .get(..4)
                        .and_then(|x| x.parse::<i32>().ok())
                        .is_none_or(|dy| dy >= y)
                })
            })
            .collect();
        ds.sort_by(|a, b| sdate(a).cmp(&sdate(b)).then(a.id.cmp(&b.id)));
        let (Some(f), Some(l)) = (ds.first(), ds.last()) else {
            continue;
        };
        if f.id != first.id {
            out.extend(ev(
                &sdate(f),
                "app",
                "ПО",
                format!("Первый документ из {}", s.name),
                if s.ver.is_empty() {
                    f.name.clone()
                } else {
                    format!("{} · {}", f.name, s.ver)
                },
                Some("ok"),
                f.id,
            ));
        }
        if s.eol {
            if let Some(eol) = &s.eol_date {
                if sdate(l).get(..10).is_some_and(|d| d > eol.as_str()) {
                    out.extend(ev(
                        &sdate(l),
                        "alert",
                        "ПО",
                        format!("{} используется после окончания поддержки", s.name),
                        format!("Последний документ: {} · поддержка до {eol}", l.name),
                        Some("warn"),
                        l.id,
                    ));
                }
            }
        }
    }
    // Office suite generation changes.
    let mut cur: Option<(i32, String)> = None;
    for d in &an {
        for sid in &d.software {
            let Some(s) = software.iter().find(|s| &s.id == sid && s.kind == "office") else {
                continue;
            };
            let Some(rel) = s.released else { continue };
            match &cur {
                Some((r, name)) if rel > *r => {
                    out.extend(ev(
                        &date(d),
                        "app",
                        "ПО",
                        format!("Смена версии Office: {name} → {}", s.name),
                        format!("Первый документ: {}", d.name),
                        None,
                        d.id,
                    ));
                    cur = Some((rel, s.name.clone()));
                }
                None => cur = Some((rel, s.name.clone())),
                _ => {}
            }
        }
    }
    // Infrastructure: first mentions of servers in paths and of printers.
    let mut seen_hosts: Vec<String> = Vec::new();
    for d in &an {
        for h in &d.path_hosts {
            if !seen_hosts.contains(h) {
                seen_hosts.push(h.clone());
                let p = d
                    .paths
                    .iter()
                    .find(|p| p.contains(h.as_str()))
                    .cloned()
                    .unwrap_or_default();
                out.extend(ev(
                    &date(d),
                    "server",
                    "Инфраструктура",
                    format!("В путях появляется \\\\{h}"),
                    p,
                    None,
                    d.id,
                ));
            }
        }
    }
    for p in printers {
        if let Some(d) = an.iter().find(|d| d.printers.contains(&p.name)) {
            let short = p.name.rsplit('\\').next().unwrap_or(&p.name).to_string();
            out.extend(ev(
                &date(d),
                "printer",
                "Инфраструктура",
                format!("Принтер {short}"),
                format!("Первый документ: {}", d.name),
                None,
                d.id,
            ));
        }
    }
    for d in an.iter().filter(|d| d.gps.is_some()).take(3) {
        let (la, lo) = d.gps.unwrap_or_default();
        out.extend(ev(
            &date(d),
            "pin",
            "Утечка",
            format!("Фото с GPS-координатами: {la:.4}, {lo:.4}"),
            format!("{} · {}", d.name, d.camera.as_deref().unwrap_or("")),
            Some("warn"),
            d.id,
        ));
    }
    out.sort_by(|a, b| a.y.cmp(&b.y).then(a.m.cmp(&b.m)));
    out
}
