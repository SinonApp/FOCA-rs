//! Port table in the hosts (infrastructure) section: the own port scan (`ports` module,
//! active level only) and the Shodan InternetDB cache, taken from `snapshot.ports`. The
//! engine fills it only for reports: `[{ host, ip, ports: [HostPort], ports_scan }]`, see
//! docs/API.md. Strings go through the report redactor (`Ctx::h` / `Ctx::m`).

use std::fmt::Write as _;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::opts::Lang;
use crate::safe::{html as esc, md as mesc};
use crate::Ctx;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Port {
    pub port: u16,
    pub proto: String,
    pub service: String,
    pub banner: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub source: String,
    pub unconfirmed: bool,
    pub outdated: Option<String>,
    pub sensitive: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct HostPorts {
    pub host: String,
    pub ip: Option<String>,
    pub ports: Vec<Port>,
    pub ports_scan: Value,
    /// Host technologies (`Host.tech`, from CPEs / banners); not part of `snapshot.ports`.
    #[serde(skip)]
    pub tech: String,
}

use crate::i18n::PortsT as T;

fn strings(l: Lang) -> &'static T {
    &crate::i18n::bundle(l).ports
}

fn list(c: &Ctx) -> Vec<HostPorts> {
    serde_json::from_value::<Vec<HostPorts>>(c.snap.ports.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|h| !h.ports.is_empty() || unreliable(h))
        .map(|mut h| {
            if let Some(x) = c.snap.hosts.iter().find(|x| x.name == h.host) {
                h.tech = x.tech.clone();
            }
            h
        })
        .collect()
}

/// Host technologies (from CPEs) that belong to the service of a port, e.g. `Apache HTTP
/// Server 2.4.58, PHP 8.1.2` for 80/443 or `OpenSSH 8.9` for 22. Used when the port itself
/// carries no product, version or banner (InternetDB lists CPEs per host, not per port).
fn cpe_version(p: &Port, tech: &str) -> String {
    const WEB: &[&str] = &[
        "apache",
        "nginx",
        "iis",
        "litespeed",
        "openresty",
        "caddy",
        "tomcat",
        "jetty",
        "php",
        "lighttpd",
        "envoy",
        "varnish",
        "node",
    ];
    let svc = p.service.to_ascii_lowercase();
    let web = svc.starts_with("http") || matches!(p.port, 80 | 443 | 8000 | 8080 | 8443 | 8888);
    let keys: &[&str] = match () {
        _ if web => WEB,
        _ if svc == "ssh" || p.port == 22 => &["ssh"],
        _ if svc.starts_with("ftp") || p.port == 21 => &["ftp"],
        _ if svc.contains("mysql") || p.port == 3306 => &["mysql", "mariadb"],
        _ if svc.contains("postgres") || p.port == 5432 => &["postgres"],
        _ if matches!(
            svc.as_str(),
            "smtp" | "smtps" | "submission" | "imap" | "imaps" | "pop3" | "pop3s"
        ) =>
        {
            &["postfix", "exim", "dovecot", "sendmail", "exchange"]
        }
        _ => &[],
    };
    let hits: Vec<&str> = tech
        .split(", ")
        .map(str::trim)
        .filter(|x| x.chars().any(|c| c.is_ascii_digit()))
        .filter(|x| {
            let l = x.to_ascii_lowercase();
            keys.iter().any(|k| l.contains(k))
        })
        .collect();
    if hits.is_empty() {
        String::new()
    } else {
        format!("{} (CPE)", hits.join(", "))
    }
}

fn unreliable(h: &HostPorts) -> bool {
    h.ports_scan["unreliable"].is_string()
}

/// Hosts with an unreliable scan (comma-separated), noted at the top of the subsection.
fn unreliable_hosts(hs: &[HostPorts]) -> Option<String> {
    let v: Vec<&str> = hs
        .iter()
        .filter(|h| unreliable(h))
        .map(|h| h.host.as_str())
        .collect();
    (!v.is_empty()).then(|| v.join(", "))
}

fn ver(p: &Port) -> String {
    let v = [p.product.as_deref(), p.version.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    if v.is_empty() {
        p.banner.clone().unwrap_or_default()
    } else {
        v
    }
}

fn note(t: &T, p: &Port) -> String {
    let mut n = Vec::new();
    if let Some(s) = &p.sensitive {
        n.push(format!("{s}: {}", t.sensitive));
    }
    if p.outdated.is_some() {
        n.push(t.outdated.to_string());
    }
    if p.unconfirmed {
        n.push(t.unconfirmed.to_string());
    }
    n.join("; ")
}

fn rows(t: &T, hs: &[HostPorts]) -> Vec<[String; 6]> {
    let mut out = Vec::new();
    for h in hs {
        for p in &h.ports {
            out.push([
                h.host.clone(),
                format!(
                    "{}/{}",
                    p.port,
                    if p.proto.is_empty() { "tcp" } else { &p.proto }
                ),
                p.service.clone(),
                Some(ver(p))
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| cpe_version(p, &h.tech)),
                if p.source == "scan" { t.scan } else { t.cache }.to_string(),
                note(t, p),
            ]);
        }
    }
    out
}

/// HTML: the open ports subsection after the hosts table.
pub(crate) fn html(c: &Ctx, h: &mut String) {
    let hs = list(c);
    if hs.is_empty() {
        return;
    }
    let t = strings(c.o.lang);
    let _ = write!(
        h,
        "<h3 id=\"ports\">{}</h3><p class=\"muted\">{}</p>",
        esc(t.title),
        esc(t.legend)
    );
    if let Some(u) = unreliable_hosts(&hs) {
        let _ = write!(
            h,
            "<p class=\"warn\"><b>⚠ {}</b> {}</p>",
            esc(t.unreliable),
            c.h(&u)
        );
    }
    let rs = rows(t, &hs);
    if rs.is_empty() {
        return;
    }
    h.push_str("<table><thead><tr>");
    for th in [t.host, t.port, t.service, t.version, t.source, t.note] {
        let _ = write!(h, "<th>{}</th>", esc(th));
    }
    h.push_str("</tr></thead><tbody>\n");
    for r in rs {
        let _ = writeln!(
            h,
            "<tr><td><span class=\"mono\">{}</span></td><td><span class=\"mono\">{}</span></td><td>{}</td><td><span class=\"mono\">{}</span></td><td>{}</td><td>{}</td></tr>",
            c.h(&r[0]), c.h(&r[1]), c.h(&r[2]), c.h(&r[3]), c.h(&r[4]), c.h(&r[5])
        );
    }
    h.push_str("</tbody></table>\n");
}

/// Markdown: the same subsection.
pub(crate) fn md(c: &Ctx, o: &mut String) {
    let hs = list(c);
    if hs.is_empty() {
        return;
    }
    let t = strings(c.o.lang);
    let _ = writeln!(o, "### {}\n\n_{}_\n", mesc(t.title), mesc(t.legend));
    if let Some(u) = unreliable_hosts(&hs) {
        let _ = writeln!(o, "> **⚠ {}** {}\n", mesc(t.unreliable), c.m(&u));
    }
    let rs = rows(t, &hs);
    if rs.is_empty() {
        return;
    }
    let _ = writeln!(
        o,
        "| {} | {} | {} | {} | {} | {} |\n|---|---|---|---|---|---|",
        mesc(t.host),
        mesc(t.port),
        mesc(t.service),
        mesc(t.version),
        mesc(t.source),
        mesc(t.note)
    );
    for r in rs {
        let _ = writeln!(
            o,
            "| {} | {} | {} | {} | {} | {} |",
            c.m(&r[0]),
            c.m(&r[1]),
            c.m(&r[2]),
            c.m(&r[3]),
            c.m(&r[4]),
            c.m(&r[5])
        );
    }
    o.push('\n');
}

/// DOCX: the open ports table (cells redacted, not escaped).
pub(crate) fn doc_tables(c: &Ctx) -> Vec<crate::table::DocTable> {
    let hs = list(c);
    if hs.is_empty() {
        return Vec::new();
    }
    let t = strings(c.o.lang);
    let mut note = t.legend.to_string();
    if let Some(u) = unreliable_hosts(&hs) {
        let _ = write!(note, "\n⚠ {} {}", t.unreliable, c.r(&u));
    }
    let rows = rows(t, &hs)
        .iter()
        .map(|r| r.iter().map(|x| c.r(x)).collect())
        .collect();
    vec![crate::table::DocTable::new(
        t.title,
        Some(note),
        &[t.host, t.port, t.service, t.version, t.source, t.note],
        rows,
    )]
}

/// JSON report: the `ports` block, only when there is data (keeps golden files without ports
/// stable).
pub(crate) fn json(c: &Ctx) -> Value {
    let hs = list(c);
    if hs.is_empty() {
        return Value::Null;
    }
    json!(hs
        .iter()
        .map(|h| json!({ "host": h.host, "ip": h.ip, "scan": h.ports_scan,
            "ports": h.ports.iter().map(|p| json!({ "port": p.port, "proto": if p.proto.is_empty() { "tcp" } else { &p.proto },
                "service": p.service, "product": p.product, "version": p.version, "banner": p.banner,
                "source": p.source, "unconfirmed": p.unconfirmed, "outdated": p.outdated, "sensitive": p.sensitive })).collect::<Vec<_>>() }))
        .collect::<Vec<_>>())
}
