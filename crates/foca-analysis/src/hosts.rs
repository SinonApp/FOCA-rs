//! Hosts and computers, collected from document URLs, UNC and local paths, printers,
//! RDP/ICA files, servers in metadata, links and internal addresses found in text.
//!
//! * FQDNs and IPs become [`Host`]s (internal: private IP or a `.local`/`.corp`/… suffix).
//!   The scope status is `in_scope` / `excluded` / `out_of_scope` according to [`Scope`];
//!   exclusions win over targets.
//! * Short NetBIOS names (`BUH-PC07`, `SRV-FILE01`) become [`Pc`]s, classified as `ws` or
//!   `server` by name and source; servers are also added to `hosts` as internal.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::{Host, Pc};
use foca_core::target::parse_ip_literal;
use foca_core::Scope;

use crate::util::{is_internal_fqdn, is_private_ip, strip_port};

/// Where a name was learned from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostSource {
    DocUrl,
    Link,
    Path,
    Printer,
    Rdp,
    Ica,
    HostComputer,
    Server,
    Secret,
    Lnk,
}

impl HostSource {
    pub fn label(self) -> &'static str {
        match self {
            HostSource::DocUrl => "URL документа",
            HostSource::Link => "Ссылки в документах",
            HostSource::Path => "Пути в метаданных",
            HostSource::Printer => "Принтеры в метаданных",
            HostSource::Rdp => ".rdp-файл",
            HostSource::Ica => ".ica-файл",
            HostSource::HostComputer => "EXIF HostComputer",
            HostSource::Server => "Серверы в метаданных",
            HostSource::Secret => "Секреты в документах",
            HostSource::Lnk => ".lnk-ярлык",
        }
    }
}

/// A host mentioned in a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mention {
    pub name: String,
    pub source: HostSource,
    pub doc: u64,
    /// Logins of the document's people (for `Pc.users`).
    pub users: Vec<String>,
    /// Port taken from the address (`:3389`).
    pub port: Option<u16>,
    pub first_scan: Option<String>,
}

/// Kind of name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameKind {
    Ip { private: bool },
    Fqdn { internal: bool },
    NetBios,
    Invalid,
}

pub fn classify(name: &str) -> NameKind {
    let n = name.trim();
    if n.is_empty() || n.len() > 253 || n.contains(['/', '\\', ' ', '*', '?', '@']) {
        return NameKind::Invalid;
    }
    if let Some(ip) = parse_ip_literal(n) {
        return NameKind::Ip {
            private: is_private_ip(ip),
        };
    }
    if n.contains('.') {
        let tld = n.rsplit('.').next().unwrap_or("");
        if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
            return NameKind::Invalid;
        }
        return NameKind::Fqdn {
            internal: is_internal_fqdn(n),
        };
    }
    if n.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && n.chars().any(|c| c.is_ascii_alphabetic())
        && n.len() <= 15 + 10
    {
        NameKind::NetBios
    } else {
        NameKind::Invalid
    }
}

const SERVER_MARKS: &[&str] = &[
    "SRV", "SERVER", "SVR", "DC", "AD", "FS", "FILE", "NAS", "SAN", "SQL", "DB", "TS", "RDS",
    "RDGW", "PRN", "PRINT", "MAIL", "EXCH", "MX", "APP", "WEB", "IIS", "BACKUP", "BKP", "VEEAM",
    "HV", "ESX", "VM", "CTX", "CITRIX", "1C", "PROXY", "GW", "MFP", "STORAGE", "SHARE",
];
const WS_MARKS: &[&str] = &[
    "PC", "WS", "NB", "LT", "NOTEBOOK", "LAPTOP", "DESKTOP", "WKS", "ARM", "USER", "COMP",
];

/// Splits a name into segments: `BUH-PC07` → `BUH`, `PC`; `SRVFILE01` → `SRVFILE`.
fn segments(name: &str) -> Vec<String> {
    name.to_ascii_uppercase()
        .split(['-', '_', '.'])
        .map(|s| s.trim_end_matches(|c: char| c.is_ascii_digit()).to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Classifies a computer as server or workstation by its name and sources.
pub fn pc_kind(name: &str, sources: &BTreeSet<HostSource>) -> &'static str {
    let seg = segments(name);
    let has = |marks: &[&str]| {
        seg.iter().any(|s| {
            marks
                .iter()
                .any(|m| s == m || (m.len() >= 3 && s.starts_with(m)))
        })
    };
    if has(SERVER_MARKS) {
        return "server";
    }
    if has(WS_MARKS) {
        return "ws";
    }
    if sources.contains(&HostSource::HostComputer) || sources.contains(&HostSource::Lnk) {
        return "ws";
    }
    if sources.iter().any(|s| {
        matches!(
            s,
            HostSource::Path | HostSource::Printer | HostSource::Rdp | HostSource::Ica
        )
    }) {
        return "server";
    }
    "ws"
}

fn role_of(name: &str, sources: &BTreeSet<HostSource>, internal: bool) -> String {
    let seg = segments(name);
    let s = |m: &str| seg.iter().any(|x| x.starts_with(m));
    let r = if sources.contains(&HostSource::Rdp) || s("TS") && !s("TEST") || s("RDS") {
        "Терминальный"
    } else if sources.contains(&HostSource::Ica) || s("CTX") {
        "Citrix"
    } else if s("SQL") || seg.iter().any(|x| x == "DB") {
        "СУБД"
    } else if s("NAS") || s("STORAGE") {
        "Хранилище"
    } else if s("PRN") || s("PRINT") || sources.contains(&HostSource::Printer) {
        "Принт-сервер"
    } else if s("MAIL") || s("EXCH") || seg.iter().any(|x| x == "MX") {
        "Почта"
    } else if seg.iter().any(|x| x == "DC" || x == "AD") {
        "Контроллер домена"
    } else if s("MFP") {
        "МФУ"
    } else if sources.contains(&HostSource::DocUrl) {
        "Веб-сервер"
    } else if sources.contains(&HostSource::Path) {
        "Файловый (внутр.)"
    } else if internal {
        "Внутренний"
    } else {
        "-"
    };
    r.to_string()
}

/// Returns the host's status relative to the scope.
pub fn scope_status(scope: &Scope, name: &str) -> &'static str {
    let n = name.trim().to_ascii_lowercase();
    if let Some(ip) = parse_ip_literal(&n) {
        if scope.excludes.iter().any(|t| t.contains_ip(ip)) {
            return "excluded";
        }
        return if scope.targets.iter().any(|t| t.contains_ip(ip)) {
            "in_scope"
        } else {
            "out_of_scope"
        };
    }
    if scope.excludes.iter().any(|t| t.covers_host(&n)) {
        return "excluded";
    }
    if scope.targets.iter().any(|t| t.covers_host(&n)) {
        "in_scope"
    } else {
        "out_of_scope"
    }
}

/// Normalizes a mention: strips the port, lowercases FQDNs and IPs, uppercases NetBIOS names.
pub fn normalize(raw: &str) -> Option<(String, Option<u16>, NameKind)> {
    let raw = raw.trim().trim_matches('"');
    let port = raw
        .rsplit_once(':')
        .filter(|(h, p)| !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()))
        .and_then(|(_, p)| p.parse().ok());
    let name = strip_port(raw).trim_end_matches('.');
    let kind = classify(name);
    let name = match kind {
        NameKind::Invalid => return None,
        NameKind::NetBios => name.to_ascii_uppercase(),
        _ => name.to_ascii_lowercase(),
    };
    Some((name, port, kind))
}

#[derive(Debug, Default)]
struct Agg {
    sources: BTreeSet<HostSource>,
    docs: BTreeSet<u64>,
    users: BTreeSet<String>,
    ports: BTreeSet<(u16, HostSource)>,
    first_scan: Option<String>,
}

/// Hosts, computers and people's workstations (login → workstation name).
#[derive(Debug, Clone, Default)]
pub struct HostsResult {
    pub hosts: Vec<Host>,
    pub pcs: Vec<Pc>,
    pub person_pc: BTreeMap<String, String>,
}

/// Builds hosts and computers. Links that are neither in scope nor internal are dropped as
/// noise.
pub fn build(mentions: &[Mention], scope: &Scope, default_scan: Option<&str>) -> HostsResult {
    let mut agg: BTreeMap<String, (NameKind, Agg)> = BTreeMap::new();
    let mut ws_users: BTreeMap<String, BTreeMap<String, u32>> = BTreeMap::new();
    for m in mentions {
        let Some((name, port, kind)) = normalize(&m.name) else {
            continue;
        };
        if m.source == HostSource::Link {
            let internal = matches!(
                kind,
                NameKind::Ip { private: true } | NameKind::Fqdn { internal: true }
            );
            if !internal && scope_status(scope, &name) == "out_of_scope" {
                continue;
            }
        }
        let port = port.or(match m.source {
            HostSource::Rdp => Some(3389),
            HostSource::Ica => Some(1494),
            _ => None,
        });
        let e = agg.entry(name.clone()).or_insert((kind, Agg::default()));
        e.1.sources.insert(m.source);
        e.1.docs.insert(m.doc);
        if let Some(p) = port {
            e.1.ports.insert((p, m.source));
        }
        if matches!(
            m.source,
            HostSource::HostComputer | HostSource::Lnk | HostSource::Rdp | HostSource::Ica
        ) {
            e.1.users.extend(m.users.iter().cloned());
            if matches!(m.source, HostSource::HostComputer | HostSource::Lnk) {
                for u in &m.users {
                    *ws_users
                        .entry(u.clone())
                        .or_default()
                        .entry(name.clone())
                        .or_default() += 1;
                }
            }
        }
        if let Some(fs) = &m.first_scan {
            if e.1.first_scan.as_ref().is_none_or(|x| fs < x) {
                e.1.first_scan = Some(fs.clone());
            }
        }
    }
    // A short server name that has an internal FQDN (`HQOLYMPS05` ↔ `hqolymps05.corp.loc`) is not
    // duplicated in the host list; only the FQDN stays there (the computer list keeps the name).
    let fq_first: BTreeSet<String> = agg
        .iter()
        .filter(|(_, (k, _))| matches!(k, NameKind::Fqdn { internal: true }))
        .filter_map(|(n, _)| n.split('.').next().map(str::to_ascii_uppercase))
        .collect();
    let mut hosts = Vec::new();
    let mut pcs = Vec::new();
    for (name, (kind, a)) in &agg {
        let source = a
            .sources
            .iter()
            .map(|s| s.label())
            .collect::<Vec<_>>()
            .join(", ");
        let services: Vec<(String, String, String)> = a
            .ports
            .iter()
            .map(|(p, s)| {
                let proto = match p {
                    3389 => "rdp",
                    1494 | 2598 => "ica",
                    80 | 8080 => "http",
                    443 | 8443 => "https",
                    1433 => "mssql",
                    _ => "tcp",
                };
                (
                    format!("{p}/tcp"),
                    proto.to_string(),
                    format!("из {}", s.label()),
                )
            })
            .collect();
        let tech = if a.sources.contains(&HostSource::Rdp) {
            "RDP"
        } else if a.sources.contains(&HostSource::Ica) {
            "Citrix ICA"
        } else {
            "-"
        };
        let first_scan = a.first_scan.clone().or(default_scan.map(str::to_string));
        match kind {
            NameKind::NetBios => {
                let k = pc_kind(name, &a.sources);
                pcs.push(Pc {
                    name: name.clone(),
                    kind: k.into(),
                    users: a.users.iter().cloned().collect(),
                    ip: None,
                    source: source.clone(),
                    docs: a.docs.len() as u32,
                });
                if k == "server" && !fq_first.contains(name) {
                    hosts.push(Host {
                        name: name.clone(),
                        ip: "-".into(),
                        role: role_of(name, &a.sources, true),
                        tech: tech.into(),
                        cloud: "-".into(),
                        services,
                        source,
                        internal: true,
                        sev: "info".into(),
                        first_scan,
                        scope: scope_status(scope, name).into(),
                    });
                }
            }
            NameKind::Ip { private } => hosts.push(Host {
                name: name.clone(),
                ip: name.clone(),
                role: role_of(name, &a.sources, *private),
                tech: tech.into(),
                cloud: "-".into(),
                services,
                source,
                internal: *private,
                sev: if *private { "info" } else { "ok" }.into(),
                first_scan,
                scope: scope_status(scope, name).into(),
            }),
            NameKind::Fqdn { internal } => hosts.push(Host {
                name: name.clone(),
                ip: "-".into(),
                role: role_of(name, &a.sources, *internal),
                tech: tech.into(),
                cloud: "-".into(),
                services,
                source,
                internal: *internal,
                sev: if *internal { "info" } else { "ok" }.into(),
                first_scan,
                scope: scope_status(scope, name).into(),
            }),
            NameKind::Invalid => {}
        }
    }
    // External hosts first, then internal; by name within each group.
    hosts.sort_by(|a, b| a.internal.cmp(&b.internal).then(a.name.cmp(&b.name)));
    pcs.sort_by(|a, b| b.docs.cmp(&a.docs).then(a.name.cmp(&b.name)));
    let person_pc = ws_users
        .into_iter()
        .filter_map(|(u, m)| {
            m.into_iter()
                .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
                .map(|(pc, _)| (u, pc))
        })
        .collect();
    HostsResult {
        hosts,
        pcs,
        person_pc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_name_merged_with_internal_fqdn() {
        let ms = [
            m("HQOLYMPS05", HostSource::Printer, 1, &[]),
            m("hqolymps05.wsdot.loc", HostSource::Path, 2, &[]),
        ];
        let r = build(&ms, &Scope::default(), None);
        let names: Vec<&str> = r.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["hqolymps05.wsdot.loc"]);
        assert!(r.hosts[0].internal);
    }

    fn m(name: &str, source: HostSource, doc: u64, users: &[&str]) -> Mention {
        Mention {
            name: name.into(),
            source,
            doc,
            users: users.iter().map(|s| s.to_string()).collect(),
            port: None,
            first_scan: None,
        }
    }

    #[test]
    fn classify_names() {
        assert_eq!(classify("BUH-PC07"), NameKind::NetBios);
        assert_eq!(classify("10.10.1.40"), NameKind::Ip { private: true });
        assert_eq!(classify("203.0.113.10"), NameKind::Ip { private: false });
        assert_eq!(
            classify("SRV-TS01.corp.contoso.example"),
            NameKind::Fqdn { internal: true }
        );
        assert_eq!(
            classify("portal.contoso.example"),
            NameKind::Fqdn { internal: false }
        );
        assert_eq!(classify("a b"), NameKind::Invalid);
        let none = BTreeSet::new();
        assert_eq!(pc_kind("BUH-PC07", &none), "ws");
        assert_eq!(pc_kind("SRV-FILE01", &none), "server");
        assert_eq!(pc_kind("NAS02", &none), "server");
        assert_eq!(pc_kind("ENG-WS11", &none), "ws");
        assert_eq!(pc_kind("KT-FS01", &none), "server");
        let unc: BTreeSet<_> = [HostSource::Path].into_iter().collect();
        assert_eq!(pc_kind("ALPHA", &unc), "server");
    }

    #[test]
    fn build_hosts_and_scope() {
        let (scope, _) = Scope::from_lines(
            "contoso.example\n10.0.0.0/8",
            "mail.contoso.example\n10.10.1.0/24",
        );
        let ms = vec![
            m("files.contoso.example", HostSource::DocUrl, 1, &[]),
            m("mail.contoso.example", HostSource::Link, 1, &[]),
            m("google.com", HostSource::Link, 1, &[]),
            m("SRV-FILE01", HostSource::Path, 1, &[]),
            m("SRV-FILE01", HostSource::Path, 2, &[]),
            m("ENG-WS11", HostSource::HostComputer, 3, &["v.tkachenko"]),
            m("10.10.1.40:1494", HostSource::Ica, 4, &["o.kovalenko"]),
            m("10.20.0.5", HostSource::Secret, 4, &[]),
        ];
        let r = build(&ms, &scope, Some("s1"));
        let names: Vec<&str> = r.hosts.iter().map(|h| h.name.as_str()).collect();
        assert!(!names.contains(&"google.com"));
        let get = |n: &str| r.hosts.iter().find(|h| h.name == n).unwrap();
        assert_eq!(get("files.contoso.example").scope, "in_scope");
        assert_eq!(get("mail.contoso.example").scope, "excluded");
        assert_eq!(get("10.10.1.40").scope, "excluded");
        assert_eq!(get("10.20.0.5").scope, "in_scope");
        assert_eq!(get("10.10.1.40").services[0].0, "1494/tcp");
        assert!(get("SRV-FILE01").internal);
        assert_eq!(get("SRV-FILE01").role, "Файловый (внутр.)");
        let srv = r.pcs.iter().find(|p| p.name == "SRV-FILE01").unwrap();
        assert_eq!((srv.kind.as_str(), srv.docs), ("server", 2));
        assert_eq!(
            r.person_pc.get("v.tkachenko").map(String::as_str),
            Some("ENG-WS11")
        );
        assert!(
            !names.contains(&"ENG-WS11"),
            "workstations belong only in pcs"
        );
    }
}
