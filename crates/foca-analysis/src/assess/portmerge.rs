//! One finding per rule and host: probes of the same host on several ports (TLS on 443, 2083,
//! 2087, 8443; site recon on `host` and `host:8080`) report the same issue once per port. The
//! copies are merged into one finding that lists the ports, so the findings screen, the risk
//! score, alerts and every report format count the issue once.
//!
//! The merged finding id is `finding_id(rule, host)`: it does not depend on which ports answered
//! in a scan. Triage (status, severity override, notes, photos, tags) of the per-port findings of
//! earlier scans moves to the merged finding; their ids are returned as absorbed so the store
//! drops them instead of reporting them as fixed.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::Finding;
use foca_core::FindingStatus;

use crate::findings::finding_id;
use crate::PrevFinding;

/// Rules with one finding per site (the object is the site itself): every copy on another port
/// of the host is a duplicate, whatever the title says.
const PER_SITE: &[&str] = &[
    "recon.sourcemap",
    "recon.analytics_pivots",
    "recon.favicon",
    "recon.robots_hidden",
    "recon.code_mentions",
    "recon.bucket_refs",
];

/// Rules whose per-port copies describe one issue of the host (one certificate, one TLS
/// configuration, one site). Port findings (`ports-*`) are per service and stay separate.
fn mergeable(rule: &str) -> bool {
    rule.starts_with("infra.tls_")
        || rule.starts_with("infra.cert_")
        || rule == "recon.outdated_tech"
        || PER_SITE.contains(&rule)
}

/// Splits `host:port` (not IPv6 literals).
fn split_port(s: &str) -> Option<(&str, u16)> {
    let (h, p) = s.rsplit_once(':')?;
    if h.is_empty() || h.contains(':') || p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    p.parse().ok().map(|p| (h, p))
}

/// Host and port of a finding: from `host` (`a.example:8080`) or from the title
/// (`… on a.example:443`); `None` port = the default one.
fn site(f: &Finding) -> Option<(String, Option<u16>)> {
    let h = f.host.trim();
    if h.is_empty() || h == "-" {
        return None;
    }
    if let Some((b, p)) = split_port(h) {
        return Some((b.to_ascii_lowercase(), Some(p)));
    }
    let marker = format!("{h}:");
    let port = f.title.match_indices(&marker).find_map(|(i, m)| {
        let rest = &f.title[i + m.len()..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<u16>().ok()
    });
    Some((h.to_ascii_lowercase(), port))
}

/// Replaces `host:port` with `host` in a text.
fn strip_port(text: &str, host: &str, port: Option<u16>) -> String {
    match port {
        Some(p) => text.replace(&format!("{host}:{p}"), host),
        None => text.to_string(),
    }
}

/// Rule, host without the port, title without the port.
type GroupKey = (String, String, String);

fn group_key(f: &Finding, host: &str, port: Option<u16>) -> GroupKey {
    let rule = f.provenance.rule.clone();
    let title = if PER_SITE.contains(&rule.as_str()) {
        String::new()
    } else {
        strip_port(&f.title, host, port)
    };
    (rule, host.to_string(), title)
}

/// Ports line of a merged finding (`Порты: 443, 2083`); the report translates it.
pub fn ports_line(ports: &[u16]) -> String {
    let list: Vec<String> = ports.iter().map(u16::to_string).collect();
    format!("Порты: {}", list.join(", "))
}

fn merge(id: u64, host: &str, mut group: Vec<(Finding, Option<u16>)>) -> Finding {
    // Default port first, then by number; the most severe copy leads.
    group.sort_by_key(|(f, p)| (std::cmp::Reverse(f.sev.rank()), p.unwrap_or(0)));
    let ports: Vec<u16> = group
        .iter()
        .map(|(_, p)| p.unwrap_or(0))
        .filter(|p| *p != 0)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let (lead, lead_port) = &group[0];
    let mut m = lead.clone();
    m.id = id;
    m.host = host.to_string();
    m.title = strip_port(&lead.title, host, *lead_port);
    let descs: Vec<String> = group
        .iter()
        .map(|(f, p)| strip_port(&f.description, host, *p))
        .collect();
    let same = descs.iter().all(|d| *d == descs[0]);
    let mut desc = Vec::new();
    if same {
        if !descs[0].is_empty() {
            desc.push(descs[0].clone());
        }
    } else {
        // Different details per port: keep each port's text (it names host:port itself).
        let mut seen = BTreeSet::new();
        for (f, _) in &group {
            if seen.insert(f.description.clone()) && !f.description.is_empty() {
                desc.push(f.description.clone());
            }
        }
    }
    if !ports.is_empty() {
        desc.push(ports_line(&ports));
    }
    m.description = desc.join("\n");
    let mut ev = Vec::new();
    let mut seen = BTreeSet::new();
    for (f, p) in &group {
        if f.evidence.is_empty() || !seen.insert(f.evidence.clone()) {
            continue;
        }
        ev.push(match p {
            Some(p) if group.len() > 1 => format!("[{host}:{p}]\n{}", f.evidence),
            _ => f.evidence.clone(),
        });
    }
    m.evidence = ev.join("\n\n");
    for (f, _) in &group[1..] {
        for t in &f.tags {
            if !m.tags.contains(t) {
                m.tags.push(t.clone());
            }
        }
        for c in &f.cve {
            if !m.cve.contains(c) {
                m.cve.push(c.clone());
            }
        }
        for d in &f.rel.docs {
            if !m.rel.docs.contains(d) {
                m.rel.docs.push(*d);
            }
        }
        if f.time < m.time && !f.time.is_empty() {
            m.time = f.time.clone();
        }
        if m.url.is_none() {
            m.url = f.url.clone();
        }
        m.active |= f.active;
    }
    m.first_scan = group.iter().filter_map(|(f, _)| f.first_scan.clone()).min();
    m
}

/// Moves triage of earlier findings (`from`, first match wins) onto `f`.
fn carry(f: &mut Finding, from: &[u64], prev: &BTreeMap<u64, PrevFinding>) {
    let olds: Vec<&PrevFinding> = from.iter().filter_map(|id| prev.get(id)).collect();
    let Some(lead) = olds
        .iter()
        .find(|p| p.status != FindingStatus::New)
        .or(olds.first())
    else {
        return;
    };
    f.status = match lead.status {
        FindingStatus::Fixed => FindingStatus::New,
        s => s,
    };
    if let Some(s) = lead.sev {
        f.sev = s;
    }
    for p in &olds {
        for n in &p.notes {
            if !f.notes.contains(n) {
                f.notes.push(n.clone());
            }
        }
        for ph in &p.photos {
            if !f.photos.contains(ph) {
                f.photos.push(ph.clone());
            }
        }
        for t in &p.tags {
            if !f.tags.contains(t) {
                f.tags.push(t.clone());
            }
        }
    }
    if let Some(fs) = olds.iter().filter_map(|p| p.first_scan.clone()).min() {
        f.first_scan = Some(fs);
    }
    if let Some(t) = olds.iter().filter_map(|p| p.time.clone()).min() {
        f.time = t;
    }
}

/// Merges per-port copies of a finding into one per rule and host (see the module docs).
/// Returns the ids of earlier findings absorbed by a finding with another id.
pub fn merge_ports(fs: &mut Vec<Finding>, prev: &BTreeMap<u64, PrevFinding>) -> Vec<u64> {
    let mut groups: BTreeMap<GroupKey, Vec<(usize, Option<u16>)>> = BTreeMap::new();
    let present: BTreeSet<u64> = fs.iter().map(|f| f.id).collect();
    for (i, f) in fs.iter().enumerate() {
        if !mergeable(&f.provenance.rule) {
            continue;
        }
        if let Some((host, port)) = site(f) {
            groups
                .entry(group_key(f, &host, port))
                .or_default()
                .push((i, port));
        }
    }
    let mut drop: BTreeSet<usize> = BTreeSet::new();
    let mut add = Vec::new();
    let mut absorbed = BTreeSet::new();
    // Several titles of one rule on one host (rare) keep apart: the title joins the id key.
    let mut per_host: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (rule, host, _) in groups.keys() {
        *per_host.entry((rule.clone(), host.clone())).or_default() += 1;
    }
    for ((rule, host, title), members) in groups {
        let merged_id = if per_host[&(rule.clone(), host.clone())] > 1 {
            finding_id(&rule, &format!("{host}|{title}"))
        } else {
            finding_id(&rule, &host)
        };
        let member_ids: Vec<u64> = members.iter().map(|(i, _)| fs[*i].id).collect();
        if members.iter().any(|(_, p)| p.is_some()) {
            let group: Vec<(Finding, Option<u16>)> =
                members.iter().map(|(i, p)| (fs[*i].clone(), *p)).collect();
            let mut m = merge(merged_id, &host, group);
            if !prev.contains_key(&m.id) {
                carry(&mut m, &member_ids, prev);
            }
            absorbed.extend(member_ids.iter().filter(|id| **id != m.id));
            drop.extend(members.iter().map(|(i, _)| *i));
            add.push(m);
        } else if members.len() == 1
            && prev.contains_key(&merged_id)
            && !present.contains(&merged_id)
        {
            // The other ports went away: the single finding takes the merged one's triage.
            let f = &mut fs[members[0].0];
            if f.id != merged_id {
                if !prev.contains_key(&f.id) {
                    carry(f, &[merged_id], prev);
                }
                absorbed.insert(merged_id);
            }
        }
    }
    let mut i = 0;
    fs.retain(|_| {
        let keep = !drop.contains(&i);
        i += 1;
        keep
    });
    for m in add {
        absorbed.remove(&m.id);
        if !fs.iter().any(|x| x.id == m.id) {
            fs.push(m);
        }
    }
    absorbed
        .into_iter()
        .filter(|id| prev.contains_key(id) && !fs.iter().any(|f| f.id == *id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_core::api::Note;
    use foca_core::Severity;

    fn tls(port: u16, detail: &str) -> Finding {
        crate::infra::finding(crate::infra::InfraFinding {
            code: "tls_legacy_version",
            sev: Severity::Medium,
            host: "edge.example",
            object: &format!("edge.example:{port}"),
            detail,
            evidence: format!("port {port}"),
            module: "tls",
            active: true,
            time: "2026-11-20T10:00:00",
            scan: Some("s1"),
            url: None,
            tags: vec![],
        })
    }

    fn recon(host: &str, rule: &str, title: &str) -> Finding {
        let mut f = tls(443, "x");
        f.id = crate::util::stable_id(&[rule, host]);
        f.host = host.into();
        f.title = title.into();
        f.provenance.rule = rule.into();
        f.description = "Карты исходников раскрывают исходный код фронтенда.".into();
        f
    }

    #[test]
    fn ports_of_one_host_merge_into_one_finding() {
        let mut fs = vec![
            tls(8443, "TLS 1.0"),
            tls(443, "TLS 1.0"),
            tls(2083, "TLS 1.0"),
            tls(2087, "TLS 1.0"),
        ];
        let absorbed = merge_ports(&mut fs, &BTreeMap::new());
        assert!(absorbed.is_empty(), "nothing stored before");
        assert_eq!(fs.len(), 1, "{fs:#?}");
        let f = &fs[0];
        assert_eq!(f.id, finding_id("infra.tls_legacy_version", "edge.example"));
        assert_eq!(f.title, "Устаревшие версии TLS на edge.example");
        assert_eq!(
            f.description,
            "Обнаружено при проверке edge.example: TLS 1.0\nПорты: 443, 2083, 2087, 8443"
        );
        assert!(f.evidence.contains("[edge.example:2083]\nport 2083"));
    }

    #[test]
    fn different_details_keep_each_port_text() {
        let mut fs = vec![tls(443, "TLS 1.0"), tls(8443, "TLS 1.0, TLS 1.1")];
        merge_ports(&mut fs, &BTreeMap::new());
        assert_eq!(fs.len(), 1);
        assert_eq!(
            fs[0].description,
            "Обнаружено при проверке edge.example:443: TLS 1.0\n\
             Обнаружено при проверке edge.example:8443: TLS 1.0, TLS 1.1\nПорты: 443, 8443"
        );
    }

    #[test]
    fn per_site_rule_merges_default_and_extra_port() {
        let mut fs = vec![
            recon(
                "app.example",
                "recon.sourcemap",
                "Опубликованы source map JS: 3",
            ),
            recon(
                "app.example:8080",
                "recon.sourcemap",
                "Опубликованы source map JS: 1",
            ),
            recon(
                "other.example",
                "recon.sourcemap",
                "Опубликованы source map JS: 2",
            ),
        ];
        merge_ports(&mut fs, &BTreeMap::new());
        assert_eq!(fs.len(), 2, "{fs:#?}");
        let m = fs.iter().find(|f| f.host == "app.example").unwrap();
        assert_eq!(m.title, "Опубликованы source map JS: 3");
        assert!(
            m.description.ends_with("\nПорты: 8080"),
            "{}",
            m.description
        );
        // A host seen on one port only keeps its finding as is.
        assert!(fs.iter().any(|f| f.host == "other.example"
            && f.id == crate::util::stable_id(&["recon.sourcemap", "other.example"])));
    }

    #[test]
    fn triage_of_per_port_findings_moves_to_the_merged_one() {
        let old = tls(2083, "TLS 1.0");
        let note = Note {
            text: "edge setting".into(),
            ..Default::default()
        };
        let prev = BTreeMap::from([
            (
                old.id,
                PrevFinding {
                    status: FindingStatus::Confirmed,
                    sev: Some(Severity::Low),
                    notes: vec![note.clone()],
                    tags: vec![],
                    photos: vec![],
                    first_scan: Some("s0".into()),
                    fixed_scan: None,
                    time: Some("2026-10-01T00:00:00".into()),
                },
            ),
            (tls(443, "TLS 1.0").id, PrevFinding::default()),
        ]);
        let mut fs = vec![tls(443, "TLS 1.0"), tls(2083, "TLS 1.0")];
        let absorbed = merge_ports(&mut fs, &prev);
        assert_eq!(fs.len(), 1);
        let f = &fs[0];
        assert_eq!(f.status, FindingStatus::Confirmed);
        assert_eq!(f.sev, Severity::Low);
        assert_eq!(f.notes, vec![note]);
        assert_eq!(f.first_scan.as_deref(), Some("s0"));
        let mut want = vec![old.id, tls(443, "TLS 1.0").id];
        want.sort();
        let mut got = absorbed.clone();
        got.sort();
        assert_eq!(got, want);

        // Next scan: the merged id is stored, so the store keeps its triage; nothing absorbed.
        let prev2 = BTreeMap::from([(f.id, PrevFinding::default())]);
        let mut fs2 = vec![tls(443, "TLS 1.0"), tls(8443, "TLS 1.0")];
        assert!(merge_ports(&mut fs2, &prev2).is_empty());
        assert_eq!(fs2[0].id, f.id, "stable id across rescans");
    }
}
