//! Keyless Shodan InternetDB (`https://internetdb.shodan.io/<ip>`): open ports, CPEs, CVEs and
//! host names by IP. Passive: the request goes to Shodan, never to the target. Ports feed the
//! host `services`, CPEs feed `tech`, and CVEs produce a known vulnerabilities finding whose
//! severity depends on the CVE count (Shodan provides no CVSS, so it is conservative: 10 or
//! more is High, otherwise Medium).

use foca_core::Severity;
use foca_net::{Access, NetClient, NetError, NetRequest};
use serde::Deserialize;

use crate::analysis::facts::{self, NetFacts};

/// An InternetDB response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct InternetDb {
    pub ip: String,
    pub ports: Vec<u16>,
    pub cpes: Vec<String>,
    pub hostnames: Vec<String>,
    pub tags: Vec<String>,
    pub vulns: Vec<String>,
}

/// Parses a response; `{"detail":"No information available"}` (404) yields `None`.
pub fn parse_internetdb(body: &str) -> Option<InternetDb> {
    let v: InternetDb = serde_json::from_str(body).ok()?;
    if v.ip.is_empty() {
        return None;
    }
    Some(v)
}

fn svc_of(port: u16) -> &'static str {
    match port {
        80 | 8080 | 8000 | 8008 => "http",
        443 | 8443 => "https",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 465 | 587 => "smtp",
        53 => "dns",
        110 | 995 => "pop3",
        143 | 993 => "imap",
        445 => "smb",
        1433 => "mssql",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        5900 => "vnc",
        6379 => "redis",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "tcp",
    }
}

/// Returns a human-readable product name from a CPE (`cpe:/a:php:php:7.4` becomes "PHP 7.4"),
/// dropping the vendor so names like "php php" or "getbootstrap bootstrap" do not appear.
pub fn cpe_product(c: &str) -> String {
    let p: Vec<&str> = c.trim_start_matches("cpe:/").split(':').collect();
    // CPE 2.2 escapes special characters: `joomla%21` / `joomla\!` mean "joomla!"; a trailing "!"
    // in the product name is not significant
    let dec = |x: &str| foca_search::filter::percent_decode(x).replace('\\', "");
    let prod_s = dec(p.get(2).copied().unwrap_or(""));
    let prod = prod_s.trim_end_matches('!');
    let ver_s = dec(p.get(3).copied().unwrap_or(""));
    let ver = ver_s.as_str();
    const NAMES: &[(&str, &str)] = &[
        ("php", "PHP"),
        ("jquery", "jQuery"),
        ("nginx", "nginx"),
        ("bootstrap", "Bootstrap"),
        ("http_server", "Apache HTTP Server"),
        ("openssh", "OpenSSH"),
        ("node.js", "Node.js"),
        ("ubuntu_linux", "Ubuntu Linux"),
        ("debian_linux", "Debian Linux"),
        ("joomla\\!", "Joomla!"),
        ("joomla", "Joomla!"),
        ("wordpress", "WordPress"),
        ("drupal", "Drupal"),
        ("iis", "Microsoft IIS"),
        ("internet_information_services", "Microsoft IIS"),
        ("mysql", "MySQL"),
        ("postgresql", "PostgreSQL"),
        ("tomcat", "Apache Tomcat"),
        ("exim", "Exim"),
        ("postfix", "Postfix"),
        ("dovecot", "Dovecot"),
        ("proftpd", "ProFTPD"),
        ("vsftpd", "vsftpd"),
        ("openssl", "OpenSSL"),
        ("moodle", "Moodle"),
        ("jre", "Java (JRE)"),
        ("jdk", "Java (JDK)"),
        ("dspace", "DSpace"),
    ];
    let low = prod.to_ascii_lowercase();
    let name = NAMES
        .iter()
        .find(|(k, _)| *k == low)
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| {
            let t = prod.replace('_', " ");
            let mut ch = t.chars();
            match ch.next() {
                Some(f) => f.to_uppercase().collect::<String>() + ch.as_str(),
                None => String::new(),
            }
        });
    if ver.is_empty() || ver == "-" || ver == "*" {
        name
    } else {
        format!("{name} {ver}")
    }
}

/// Returns host technologies from CPEs: human-readable names without duplicates (up to 4).
pub fn cpe_tech(cpes: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    for c in cpes {
        let n = cpe_product(c);
        if n.is_empty() {
            continue;
        }
        // "nginx" and "nginx 1.24" are the same technology: keep the variant with a version
        let base = |x: &str| x.split(' ').next().unwrap_or("").to_ascii_lowercase();
        if let Some(i) = out
            .iter()
            .position(|o| base(o) == base(&n) && (o == &n || !n.contains(' ') || !o.contains(' ')))
        {
            if n.len() > out[i].len() {
                out[i] = n;
            }
            continue;
        }
        out.push(n);
    }
    out.truncate(4);
    out.join(", ")
}

/// Returns the finding severity for a CVE count.
pub fn cve_severity(n: usize) -> Severity {
    if n >= 10 {
        Severity::High
    } else {
        Severity::Medium
    }
}

/// Most CVE ids listed in a finding's evidence.
const MAX_LISTED_CVES: usize = 30;

/// Comma-separated CVE ids, capped at [`MAX_LISTED_CVES`] with an explicit remainder count.
fn cve_list(cves: &[String]) -> String {
    let mut s = cves
        .iter()
        .take(MAX_LISTED_CVES)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if cves.len() > MAX_LISTED_CVES {
        s.push_str(&format!(" … и ещё {}", cves.len() - MAX_LISTED_CVES));
    }
    s
}

/// Applies a response to the facts of host `name` (plus a CVE finding). Returns the CVE count.
/// A finding for a host outside the project scope is tagged
/// [`foca_analysis::findings::OUT_OF_SCOPE_TAG`]: it stays visible as environment context but
/// does not count towards the scope risk score.
pub fn apply(
    f: &mut NetFacts,
    name: &str,
    d: &InternetDb,
    now: &str,
    sid: &str,
    out_of_scope: bool,
) -> usize {
    let h = f.host(name);
    for p in &d.ports {
        let k = format!("{p}/tcp");
        if !h.services.iter().any(|s| s.0 == k) {
            h.services
                .push((k, svc_of(*p).into(), "Shodan InternetDB".into()));
        }
    }
    // tech strings like "php php, nginx, nginx" from older data are recomputed with readable names
    let legacy = h.tech.split(", ").any(|t| {
        let w: Vec<&str> = t.split(' ').collect();
        w.len() >= 2 && w[0].eq_ignore_ascii_case(w[1])
    }) || {
        let v: Vec<&str> = h.tech.split(", ").collect();
        v.iter().enumerate().any(|(i, a)| v[..i].contains(a))
    };
    if !d.cpes.is_empty() && (h.tech.is_empty() || h.tech == "-" || legacy) {
        h.tech = cpe_tech(&d.cpes);
    }
    if d.vulns.is_empty() {
        return 0;
    }
    let mut cves = d.vulns.clone();
    cves.sort();
    let nf = facts::net_finding(
        "internetdb-cve",
        &format!("{name}@{}", d.ip),
        format!("Известные уязвимости (по данным Shodan): {name}"),
        cve_severity(cves.len()),
        name,
        "vuln",
        "Shodan InternetDB",
        "internetdb",
        false,
        now,
        Some(sid),
        format!(
            "Shodan InternetDB сопоставил адресу {} ({name}) {} CVE по версиям ПО из баннеров. \
             Это пассивные данные Shodan (без проверки), возможны ложные срабатывания из-за \
             бэкпортов исправлений.",
            d.ip,
            cves.len()
        ),
        "Проверить версии ПО на хосте и установить обновления; закрыть лишние порты.",
        format!(
            "GET https://internetdb.shodan.io/{}\nports: {:?}\ncpes: {}\nvulns: {}",
            d.ip,
            d.ports,
            d.cpes.join(", "),
            cve_list(&cves)
        ),
        Some(format!("https://internetdb.shodan.io/{}", d.ip)),
    );
    let tag = foca_analysis::findings::OUT_OF_SCOPE_TAG;
    let caveat = " Хост вне скоупа проекта: находка приведена как контекст окружения и не \
                  учитывается в оценке риска.";
    let e = f.findings.entry(nf.id).or_insert(nf);
    // Scope may change between scans: refresh the marker on every apply.
    e.tags.retain(|t| t != tag);
    if let Some(i) = e.description.find(caveat) {
        e.description.truncate(i);
    }
    if out_of_scope {
        e.tags.push(tag.into());
        e.description.push_str(caveat);
    }
    cves.len()
}

/// InternetDB stage: unique host IPv4 addresses (up to 40), one request each. Source events for
/// `internetdb` (running, then ok/error) are reported through `ev(id, status, n, error)`.
pub async fn internetdb_stage(
    net: &NetClient,
    base: &str,
    f: &mut NetFacts,
    now: &str,
    sid: &str,
    in_scope: impl Fn(&str) -> bool,
    ev: impl Fn(&str, &str, Option<usize>, Option<&str>),
) -> Result<usize, NetError> {
    let mut by_ip: Vec<(String, String)> = Vec::new();
    for h in f.hosts.values() {
        if h.ip.parse::<std::net::Ipv4Addr>().is_ok() && !by_ip.iter().any(|x| x.1 == h.ip) {
            by_ip.push((h.name.clone(), h.ip.clone()));
        }
    }
    by_ip.truncate(40);
    if by_ip.is_empty() {
        ev("internetdb", "ok", Some(0), None);
        return Ok(0);
    }
    ev("internetdb", "running", None, None);
    let (mut answered, mut errors, mut found) = (0usize, 0usize, 0usize);
    let mut last_err = None;
    for (name, ip) in by_ip {
        let u = format!("{}/{ip}", base.trim_end_matches('/'));
        let req = NetRequest::get(&u, "internetdb", Access::Passive)?
            .timeout(std::time::Duration::from_secs(20))
            .retries(1);
        let r = match net.send(req).await {
            Ok(r) => r,
            Err(NetError::Cancelled) => return Err(NetError::Cancelled),
            Err(e) => {
                errors += 1;
                last_err = Some(e.to_string());
                continue;
            }
        };
        let st = r.status();
        let body = r.text_limited(1024 * 1024).await.unwrap_or_default();
        if st == 404 {
            answered += 1;
            continue;
        }
        if !(200..300).contains(&st) {
            errors += 1;
            last_err = Some(format!("HTTP {st}"));
            continue;
        }
        answered += 1;
        if let Some(d) = parse_internetdb(&body) {
            found += 1;
            let oos = !in_scope(&name);
            apply(f, &name, &d, now, sid, oos);
        }
    }
    if answered == 0 && errors > 0 {
        ev("internetdb", "error", Some(0), last_err.as_deref());
    } else {
        ev("internetdb", "ok", Some(found), None);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_apply() {
        let d = parse_internetdb(
            r#"{"cpes":["cpe:/a:apache:tomcat","cpe:/a:oracle:jre"],"hostnames":["demo.testfire.net"],"ip":"65.61.137.117","ports":[80,443,8080],"tags":["cloud"],"vulns":["CVE-2020-1938","CVE-2019-0232"]}"#,
        )
        .unwrap();
        assert_eq!(d.ports, vec![80, 443, 8080]);
        assert!(parse_internetdb(r#"{"detail":"No information available"}"#).is_none());
        let mut f = NetFacts::default();
        let n = apply(
            &mut f,
            "demo.testfire.net",
            &d,
            "2026-11-20T10:00:00",
            "s1",
            false,
        );
        assert_eq!(n, 2);
        let h = &f.hosts["demo.testfire.net"];
        assert!(h
            .services
            .iter()
            .any(|s| s.0 == "8080/tcp" && s.1 == "http"));
        assert_eq!(h.tech, "Apache Tomcat, Java (JRE)");
        let fd = f.findings.values().next().unwrap();
        assert_eq!(fd.sev, Severity::Medium);
        assert!(fd.title.contains("по данным Shodan"));
        assert_eq!(cve_severity(12), Severity::High);
    }

    #[test]
    fn long_cve_list_reports_the_remainder() {
        let vulns: Vec<String> = (0..45).map(|i| format!("\"CVE-2024-{:04}\"", i)).collect();
        let d = parse_internetdb(&format!(
            r#"{{"cpes":[],"hostnames":[],"ip":"65.61.137.117","ports":[80],"tags":[],"vulns":[{}]}}"#,
            vulns.join(",")
        ))
        .unwrap();
        let mut f = NetFacts::default();
        assert_eq!(
            apply(
                &mut f,
                "demo.testfire.net",
                &d,
                "2026-11-20T10:00:00",
                "s1",
                false
            ),
            45
        );
        let ev = &f.findings.values().next().unwrap().evidence;
        assert!(ev.contains("CVE-2024-0029"), "{ev}");
        assert!(!ev.contains("CVE-2024-0030"), "{ev}");
        assert!(ev.contains("… и ещё 15"), "{ev}");
    }

    #[test]
    fn out_of_scope_host_finding_is_context_only() {
        let d = parse_internetdb(
            r#"{"cpes":[],"hostnames":[],"ip":"65.61.137.117","ports":[80],"tags":[],"vulns":["CVE-2020-1938","CVE-2019-0232"]}"#,
        )
        .unwrap();
        let mut f = NetFacts::default();
        apply(
            &mut f,
            "cdn.example.net",
            &d,
            "2026-11-20T10:00:00",
            "s1",
            true,
        );
        let fd = f.findings.values().next().unwrap().clone();
        assert!(fd
            .tags
            .iter()
            .any(|t| t == foca_analysis::findings::OUT_OF_SCOPE_TAG));
        assert!(fd.description.contains("вне скоупа"));
        assert_eq!(foca_analysis::findings::risk(&[fd], true).score, Some(0));
        // Back in scope on a later scan: the marker and caveat are dropped, no duplicates.
        apply(
            &mut f,
            "cdn.example.net",
            &d,
            "2026-11-20T11:00:00",
            "s2",
            false,
        );
        let fd = f.findings.values().next().unwrap();
        assert!(fd.tags.is_empty(), "{:?}", fd.tags);
        assert!(!fd.description.contains("вне скоупа"));
    }

    /// The out-of-scope caveat is appended to a templated description: every sentence must
    /// still reach the UK/EN report translated.
    #[cfg(feature = "report")]
    #[test]
    fn out_of_scope_caveat_is_translated_in_reports() {
        let d = InternetDb {
            ip: "192.0.2.10".into(),
            ports: vec![443],
            vulns: (1..=95).map(|i| format!("CVE-2024-{i:04}")).collect(),
            ..Default::default()
        };
        let mut f = NetFacts::default();
        apply(
            &mut f,
            "edge.example.test",
            &d,
            "2026-11-20T10:00:00",
            "s1",
            true,
        );
        let snap = foca_core::api::Snapshot {
            findings: f.findings.values().cloned().collect(),
            ..Default::default()
        };
        for lang in [foca_report::Lang::Uk, foca_report::Lang::En] {
            let o = foca_report::ReportOptions {
                fmt: foca_report::ReportFormat::Md,
                lang,
                ..Default::default()
            };
            let now = time::macros::datetime!(2026-11-20 12:00 UTC);
            let md = String::from_utf8(foca_report::build_report(&snap, &o, now).bytes).unwrap();
            for ru in ["сопоставил", "вне скоупа", "находка", "ещё"] {
                assert!(!md.contains(ru), "{lang:?}: «{ru}» left in\n{md}");
            }
        }
    }
}

#[cfg(test)]
mod cpe_name_tests {
    use super::*;

    #[test]
    fn cpe_human_names_without_duplicates() {
        let c: Vec<String> = [
            "cpe:/a:getbootstrap:bootstrap",
            "cpe:/a:php:php",
            "cpe:/a:jquery:jquery:1.8.0",
            "cpe:/a:f5:nginx",
            "cpe:/a:igor_sysoev:nginx",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(cpe_tech(&c), "Bootstrap, PHP, jQuery 1.8.0, nginx");
        assert_eq!(
            cpe_product("cpe:/a:apache:http_server:2.4.66"),
            "Apache HTTP Server 2.4.66"
        );
        assert_eq!(cpe_product("cpe:/o:canonical:ubuntu_linux"), "Ubuntu Linux");
        // the escaped "joomla!" (real InternetDB data) collapses into joomla
        assert_eq!(cpe_product("cpe:/a:joomla:joomla%21"), "Joomla!");
        assert_eq!(cpe_product("cpe:/a:joomla:joomla\\!:3.9"), "Joomla! 3.9");
        let j: Vec<String> = [
            "cpe:/a:joomla:joomla%21",
            "cpe:/a:joomla:joomla",
            "cpe:/a:f5:nginx",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(cpe_tech(&j), "Joomla!, nginx");
    }
}
