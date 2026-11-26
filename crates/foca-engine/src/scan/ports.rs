//! Port scan stage: a TCP connect scan with `foca_net::ports` over live in-scope hosts.
//!
//! * Active level only (full profile, or custom with the `ports` module); with the passive and
//!   standard profiles the stage does nothing and makes no connection attempts.
//! * Hosts: network facts with an address (no dangling CNAMEs), in scope and not excluded
//!   (`rules::check` here plus `Access::active` in `scan_ports`, a double check). One IP means one
//!   scan (names with the same address share the result); target domains come first; at most
//!   `max_hosts` (20) per scan.
//! * Ports: top 100 by default, `top: 1000`, or a custom `list` (`22,80,8000-8100`).
//!   Parameters: `settings.ports`, then the run parameters `scan_start { ports }` (which survive a resume).
//! * Source `ports` (`source` events: `running` with `host`/`hosts`/`host_index`, final `ok` with `n`
//!   open ports); the per-host timeout is `settings.net.source_timeout` (at least 30 s); skipping uses
//!   `scan_skip_source { id: "ports" }`; after a stop, resuming does not rescan hosts this scan
//!   already covered.
//! * Results go into host facts (`NetHost.ports_scan`) and `services` (banner/version instead of an
//!   empty field or the InternetDB marker). Findings: exposed sensitive services (`ports.exposed`) and
//!   outdated HTTP server versions per the `foca-recon` rules (`ports.outdated`).

use std::collections::BTreeMap;
use std::time::Duration;

use foca_core::api::ScopeDto;
use foca_core::Severity;
use foca_net::ports::{
    device_intercepts_tcp, mass_open, parse_ports, scan_ports, top_ports, PortResult, PortScan,
    PortScanConfig, INTERCEPT_PROBES, UNRELIABLE_INTERCEPT,
};
use foca_net::NetError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{known_hosts, reanalyze_bg, Ctx, Stop, STAGES};
use crate::analysis::facts::{self, NetFacts, NetHost};
use crate::analysis::rules::{self, KnownHost};
use crate::engine::{lock, Core};

/// Source and module id.
pub const SOURCE: &str = "ports";
/// Default number of hosts per scan.
pub const MAX_HOSTS_DEFAULT: usize = 20;
/// InternetDB marker in `services` (see `intel.rs`).
const IDB: &str = "Shodan InternetDB";

pub(crate) fn run_key(scan_id: &str) -> String {
    format!("scan_ports:{scan_id}")
}

/// Default `settings.ports` (see `docs/API.md`).
pub fn default_settings() -> Value {
    json!({ "top": 100, "list": "", "max_hosts": MAX_HOSTS_DEFAULT, "banners": true })
}

/// Returns the effective parameters: defaults, then `settings.ports`, then run parameters.
fn effective(e: &Core, run: &Value) -> Value {
    let mut v = default_settings();
    if let Ok(s) = e.store().settings_get() {
        if s["ports"].is_object() {
            foca_store::settings::merge(&mut v, &s["ports"]);
        }
    }
    if run.is_object() {
        foca_store::settings::merge(&mut v, run);
    }
    v
}

/// Returns the port list and its label (top 100, top 1000, or the custom list).
pub fn ports_of(v: &Value) -> Result<(Vec<u16>, String), String> {
    let list = v["list"].as_str().unwrap_or("").trim();
    let top = v["top"].as_u64().unwrap_or(100);
    if top == 0 || v["top"].as_str() == Some("custom") {
        if list.is_empty() {
            return Err("свой список портов пуст".into());
        }
        let p = parse_ports(list)?;
        return Ok((p, format!("свой: {list}")));
    }
    let n = if top >= 1000 { 1000 } else { 100 };
    Ok((top_ports(n), format!("топ-{n}")))
}

/// Port scan result for a host (facts `NetHost.ports_scan`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PortsScanInfo {
    pub scan: String,
    pub at: String,
    pub ip: Option<String>,
    /// Label: top 100, top 1000 or a custom list.
    pub spec: String,
    pub ports: Vec<u16>,
    pub scanned: usize,
    pub closed: usize,
    pub filtered: usize,
    pub ms: u64,
    pub cancelled: bool,
    pub error: Option<String>,
    pub open: Vec<PortResult>,
    /// Ports known from the Shodan InternetDB cache before the scan.
    pub internetdb: Vec<u16>,
    /// Set when the scan is unreliable (`canary` | `mass_open` | `intercept`): the device network
    /// accepts connections on any port, so no open ports are recorded and no findings are created.
    pub unreliable: Option<String>,
    /// Set when the address belongs to a CDN, a cloud or a shared hosting and the host was added
    /// through `scope_add_hosts`: the port scan does not touch it (reason for the UI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_probe: Option<String>,
}

/// Warning text of the `ports` source for an unreliable scan (see `docs/API.md` and Help).
pub const UNRELIABLE_MSG: &str = "Скан портов недостоверен: сеть устройства (VPN, AdGuard, прокси) \
     принимает соединения на любом порту. Отключите локальный VPN или добавьте FOCA-rs в исключения";

/// Returns `true` if the host's previous scan looked like an accept-everything network (saved before or flagged).
fn prev_unreliable(h: &NetHost) -> bool {
    let Some(i) = h
        .ports_scan
        .clone()
        .and_then(|v| serde_json::from_value::<PortsScanInfo>(v).ok())
    else {
        return false;
    };
    i.unreliable.is_some() || mass_open(i.scanned, &i.open)
}

/// Extracts the port of a `ports` finding for `host` (from a title like "...: host:port" or "(host:port)").
fn finding_port(f: &foca_core::api::Finding, host: &str) -> Option<u16> {
    if f.module != SOURCE || f.host != host {
        return None;
    }
    let pat = format!("{host}:");
    let i = f.title.rfind(&pat)? + pat.len();
    let d: String = f.title[i..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    d.parse().ok()
}

/// Reconciles a host's port findings after its scan. An unreliable scan deletes all of the host's port
/// findings (from the database too, rather than marking them fixed) and drops ports recorded by the
/// previous scan (the InternetDB cache stays). A reliable scan handles findings for ports that are no
/// longer open: if the previous scan was unreliable they are deleted, otherwise they leave the facts
/// (the port was closed, so the analysis marks them fixed).
/// Returns (number removed from facts, ids to delete from the database).
pub fn reconcile(
    f: &mut NetFacts,
    name: &str,
    r: &PortScan,
    unreliable: bool,
) -> (usize, Vec<u64>) {
    let prev_bad = f.hosts.get(name).is_some_and(prev_unreliable);
    let open: Vec<u16> = r.open.iter().map(|p| p.port).collect();
    let mut gone = Vec::new();
    let mut delete = Vec::new();
    for (id, x) in &f.findings {
        let Some(port) = finding_port(x, name) else {
            continue;
        };
        if unreliable || !open.contains(&port) {
            gone.push(*id);
            if unreliable || prev_bad {
                delete.push(*id);
            }
        }
    }
    for id in &gone {
        f.findings.remove(id);
    }
    if unreliable || prev_bad {
        if let Some(h) = f.hosts.get_mut(name) {
            let old: Vec<u16> = h
                .ports_scan
                .clone()
                .and_then(|v| serde_json::from_value::<PortsScanInfo>(v).ok())
                .map(|i| i.open.iter().map(|p| p.port).collect())
                .unwrap_or_default();
            h.services.retain(|s| {
                s.2 == IDB
                    || s.0
                        .split('/')
                        .next()
                        .and_then(|p| p.parse::<u16>().ok())
                        .is_none_or(|p| !old.contains(&p) || open.contains(&p) && !unreliable)
            });
        }
    }
    (gone.len(), delete)
}

/// Records an unreliable scan: only the summary (no open ports); host services are left alone.
pub fn apply_unreliable(h: &mut NetHost, info: PortsScanInfo) {
    let mut info = info;
    info.internetdb = h
        .services
        .iter()
        .filter(|s| s.2 == IDB)
        .filter_map(|s| s.0.split('/').next()?.parse().ok())
        .collect();
    info.open = Vec::new();
    h.ports_scan = Some(serde_json::to_value(info).unwrap_or(Value::Null));
}

/// A sensitive service: port, name, `foca_net` service, severity, risk and recommendation.
struct Sensitive {
    port: u16,
    name: &'static str,
    svc: &'static str,
    sev: Severity,
    risk: &'static str,
    rec: &'static str,
}

const SENSITIVE: &[Sensitive] = &[
    Sensitive { port: 23, name: "Telnet", svc: "telnet", sev: Severity::High,
        risk: "Telnet передаёт логин и пароль открытым текстом; доступ из интернета: частая цель перебора паролей.",
        rec: "Отключите Telnet, используйте SSH с ключами; если нужен, только из VPN/доверенных адресов." },
    Sensitive { port: 21, name: "FTP", svc: "ftp", sev: Severity::Medium,
        risk: "FTP передаёт учётные данные и файлы без шифрования; анонимный вход нередко открыт по ошибке.",
        rec: "Замените на SFTP/FTPS, отключите анонимный вход, ограничьте доступ по адресам." },
    Sensitive { port: 3389, name: "RDP", svc: "rdp", sev: Severity::High,
        risk: "Удалённый рабочий стол Windows в интернете: главная точка входа шифровальщиков (перебор паролей, уязвимости RDP).",
        rec: "Закройте порт снаружи; доступ: через VPN или RD Gateway с MFA, включите NLA и блокировку при переборе." },
    Sensitive { port: 445, name: "SMB", svc: "smb", sev: Severity::High,
        risk: "Общие папки Windows (SMB) из интернета: риск утечки файлов и червей (EternalBlue/WannaCry).",
        rec: "Заблокируйте 139/445 на периметре; общий доступ к файлам: только внутри сети или через VPN." },
    Sensitive { port: 3306, name: "MySQL", svc: "mysql", sev: Severity::High,
        risk: "СУБД доступна из интернета: перебор паролей, эксплуатация уязвимостей, утечка базы.",
        rec: "Слушайте только локальный/внутренний адрес, закройте порт межсетевым экраном, доступ: через VPN/SSH-туннель." },
    Sensitive { port: 5432, name: "PostgreSQL", svc: "postgresql", sev: Severity::High,
        risk: "СУБД доступна из интернета: перебор паролей, эксплуатация уязвимостей, утечка базы.",
        rec: "Ограничьте listen_addresses и pg_hba.conf внутренними адресами, закройте порт снаружи." },
    Sensitive { port: 6379, name: "Redis", svc: "redis", sev: Severity::High,
        risk: "Redis из интернета часто работает без пароля: чтение/запись данных и выполнение команд на сервере.",
        rec: "Привяжите Redis к 127.0.0.1/внутренней сети, включите protected-mode и ACL/пароль, закройте порт." },
    Sensitive { port: 27017, name: "MongoDB", svc: "mongodb", sev: Severity::High,
        risk: "MongoDB из интернета: частая причина утечек баз (в том числе без авторизации).",
        rec: "bindIp: только внутренние адреса, включите авторизацию, закройте порт межсетевым экраном." },
    Sensitive { port: 9200, name: "Elasticsearch", svc: "elasticsearch", sev: Severity::High,
        risk: "HTTP API Elasticsearch из интернета позволяет читать и удалять индексы, если не включена защита.",
        rec: "Включите xpack security (TLS и пароли), закройте 9200 снаружи, доступ: через обратный прокси с авторизацией." },
    Sensitive { port: 2376, name: "Docker API (TLS)", svc: "docker-tls", sev: Severity::Critical,
        risk: "Docker API на TLS-порту 2376 принял запрос без клиентского сертификата, а значит даёт полный контроль над хостом (запуск контейнеров с root-доступом).",
        rec: "Включите взаимную TLS-аутентификацию (tlsverify, свой CA для клиентов) или закройте порт; удалённое управление: через SSH." },
    Sensitive { port: 2375, name: "Docker API", svc: "docker", sev: Severity::Critical,
        risk: "Docker API без TLS на 2375 даёт полный контроль над хостом (запуск контейнеров с root-доступом).",
        rec: "Немедленно закройте 2375; если удалённый доступ нужен, только 2376 с взаимной TLS-аутентификацией или SSH." },
];

fn sensitive_of(p: &PortResult) -> Option<&'static Sensitive> {
    SENSITIVE
        .iter()
        .find(|s| s.port == p.port)
        .or_else(|| SENSITIVE.iter().find(|s| s.svc == p.service))
}

/// Returns the port label for `services` (`OpenSSH 6.6.1p1`, else the banner, else empty).
pub fn port_label(p: &PortResult) -> String {
    match (&p.product, &p.version) {
        (Some(pr), Some(v)) => format!("{pr} {v}"),
        (Some(pr), None) => pr.clone(),
        _ => p.banner.clone().unwrap_or_default(),
    }
}

/// Detects an outdated HTTP server version (`foca-recon` technology rules, as in site reconnaissance).
pub fn outdated_of(p: &PortResult) -> Option<(String, String)> {
    let b = p.banner.as_deref()?;
    let server = b
        .strip_prefix("Server:")
        .or_else(|| b.strip_prefix("server:"))
        .map(str::trim)?;
    let page = foca_recon::tech::PageInput {
        url: String::new(),
        headers: vec![("Server".into(), server.into())],
        html: String::new(),
    };
    foca_recon::tech::detect(&page)
        .into_iter()
        .find_map(|t| Some((format!("{} {}", t.name, t.version?), t.outdated?)))
}

/// Builds findings from a host scan result.
#[cfg(test)]
pub fn port_findings(
    host: &str,
    r: &PortScan,
    now: &str,
    sid: &str,
) -> Vec<foca_core::api::Finding> {
    port_findings_also(host, &[], r, now, sid)
}

/// Admin panels by banner or `Server` header: lowercase token to name and severity.
const ADMIN_PANELS: &[(&str, &str, Severity)] = &[
    ("pve-api-daemon", "Proxmox VE API", Severity::High),
    ("miniserv", "Webmin", Severity::High),
    ("mikrotik", "MikroTik RouterOS", Severity::High),
    ("routeros", "MikroTik RouterOS", Severity::High),
    ("vmware", "VMware ESXi / vCenter", Severity::High),
    ("ilo", "HPE iLO", Severity::High),
    ("idrac", "Dell iDRAC", Severity::High),
    ("cpanel", "cPanel / WHM", Severity::Medium),
    ("plesk", "Plesk", Severity::Medium),
    ("portainer", "Portainer", Severity::High),
];

fn admin_panel_of(p: &PortResult) -> Option<(&'static str, Severity)> {
    let t = format!(
        "{} {}",
        p.banner.as_deref().unwrap_or(""),
        p.product.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();
    ADMIN_PANELS.iter().find_map(|(tok, name, sev)| {
        let hit = if tok.len() <= 4 {
            // short tokens must match a whole word (iLO, not "silo")
            t.split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| w == *tok)
        } else {
            t.contains(tok)
        };
        hit.then_some((*name, *sev))
    })
}

/// Builds port findings for an address: `host` is the primary name and `also` lists other names of the
/// same IP (one finding per IP:port, with the names in the description). A sensitive service gets its
/// severity only with a confirmed protocol (`PortResult.confirmed`), otherwise it is unconfirmed info.
pub fn port_findings_also(
    host: &str,
    also: &[String],
    r: &PortScan,
    now: &str,
    sid: &str,
) -> Vec<foca_core::api::Finding> {
    let mut out = Vec::new();
    let ip = r.ip.clone().unwrap_or_else(|| "-".into());
    let names = if also.is_empty() {
        String::new()
    } else {
        format!(" Тот же адрес у имён: {}.", also.join(", "))
    };
    for p in &r.open {
        let label = port_label(p);
        if let Some(s) = sensitive_of(p) {
            if !p.confirmed {
                let why = match p.detail.as_deref() {
                    Some("client-cert") => " TLS требует клиентский сертификат, без него доступа нет.",
                    _ => " Сервис не ответил своим протоколом: возможно, порт принимает соединения фильтр, балансировщик или VPN.",
                };
                out.push(facts::net_finding(
                    "ports-unconfirmed",
                    &format!("{host}:{}", p.port),
                    format!("Открыт порт {}/tcp ({}), сервис не подтверждён: {host}:{}", p.port, s.name, p.port),
                    Severity::Info,
                    host,
                    "network",
                    "Скан портов",
                    SOURCE,
                    true,
                    now,
                    Some(sid),
                    format!("Порт {}/tcp на {host} ({ip}) принимает TCP-соединения, но протокол {} не подтверждён.{why}{names}", p.port, s.name),
                    "Проверьте вручную, что за сервис слушает порт; лишние порты закройте на периметре.",
                    format!("{host}:{} открыт ({}), протокол не подтверждён", p.port, p.service),
                    None,
                ));
            } else {
                let mut sev = s.sev;
                let mut extra = String::new();
                match (s.svc, p.detail.as_deref()) {
                    // Redis answered PONG to PING without a password: unauthenticated access
                    ("redis", Some("no-auth")) => {
                        sev = Severity::Critical;
                        extra =
                            " Redis ответил на PING без пароля: авторизация не требуется.".into();
                    }
                    ("elasticsearch", Some("no-auth")) => {
                        sev = Severity::Critical;
                        extra = " Elasticsearch отдал сведения о кластере без авторизации.".into();
                    }
                    (_, Some("auth")) => {
                        sev = Severity::Medium;
                        extra = " Сервис требует авторизацию: риск перебора паролей и уязвимостей."
                            .into();
                    }
                    _ => {}
                }
                out.push(facts::net_finding(
                    "ports-exposed",
                    &format!("{host}:{}", p.port),
                    format!("Открытый сервис {} из интернета: {host}:{}", s.name, p.port),
                    sev,
                    host,
                    "network",
                    "Скан портов",
                    SOURCE,
                    true,
                    now,
                    Some(sid),
                    format!(
                        "Порт {}/tcp ({}) на {host} ({ip}) принимает соединения из интернета, протокол подтверждён ответом сервиса. {}{extra}{names}",
                        p.port, s.name, s.risk
                    ),
                    s.rec,
                    if label.is_empty() {
                        format!("{host}:{} открыт ({})", p.port, p.service)
                    } else {
                        format!("{host}:{} открыт ({}): {label}", p.port, p.service)
                    },
                    None,
                ));
            }
        } else if let Some((name, sev)) = admin_panel_of(p) {
            out.push(facts::net_finding(
                "ports-admin",
                &format!("{host}:{}", p.port),
                format!("Панель администрирования {name} из интернета: {host}:{}", p.port),
                sev,
                host,
                "network",
                "Скан портов",
                SOURCE,
                true,
                now,
                Some(sid),
                format!(
                    "На {host}:{} ({ip}) отвечает {name}, интерфейс управления инфраструктурой доступен из интернета: перебор паролей, уязвимости панели, полный контроль при компрометации.{names}",
                    p.port
                ),
                "Уберите панель из интернета: доступ только из VPN/сети управления, MFA, актуальные обновления.",
                format!("{host}:{}: {label}", p.port),
                None,
            ));
        }
        if let Some((what, why)) = outdated_of(p) {
            out.push(facts::net_finding(
                "ports-outdated",
                &format!("{host}:{}:{what}", p.port),
                format!("Устаревшая версия сервиса: {what} ({host}:{})", p.port),
                Severity::Medium,
                host,
                "vuln",
                "Скан портов",
                SOURCE,
                true,
                now,
                Some(sid),
                format!("Сервис на {host}:{} сообщает версию {what}: {why}.", p.port),
                "Обновите ПО до поддерживаемой версии и скройте версию в баннере (ServerTokens Prod / server_tokens off).",
                p.banner.clone().unwrap_or_default(),
                None,
            ));
        }
    }
    out
}

/// Returns hosts to scan as (IP, names): in scope, not excluded, with an address; target domains first.
pub fn targets(
    f: &NetFacts,
    scope: &ScopeDto,
    known: &[KnownHost],
    domains: &[String],
) -> Vec<(String, Vec<String>)> {
    let mut hosts: Vec<&NetHost> = f
        .hosts
        .values()
        .filter(|h| h.dangling.is_none())
        .filter(|h| first_ip(&h.ip).is_some())
        .collect();
    hosts.sort_by_key(|h| (!domains.contains(&h.name), h.name.clone()));
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for h in hosts {
        if !rules::check(scope, &h.name, known).ok {
            continue;
        }
        let ip = first_ip(&h.ip).unwrap_or_default();
        // the address itself must not be excluded either
        if rules::check(scope, &ip, known).code == "excluded" {
            continue;
        }
        match out.iter_mut().find(|x| x.0 == ip) {
            Some(x) => x.1.push(h.name.clone()),
            None => out.push((ip, vec![h.name.clone()])),
        }
    }
    out
}

/// Host names that must not be touched by any active TCP/TLS probe (liveness, TLS inspection,
/// extra-port recon): names on a "no probe" address (CDN / cloud / shared hosting, see
/// [`crate::analysis::scope_bulk::skip_reason`]): the same partition the port scan uses. A name added in
/// bulk whose address is unknown cannot be classified and is held as well.
pub(crate) fn no_probe_names(
    np: &crate::analysis::scope_bulk::NoProbe,
    scope: &ScopeDto,
    f: &NetFacts,
) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    if np.hosts.is_empty() && np.ips.is_empty() {
        return out;
    }
    let mut by_ip: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for h in f.hosts.values() {
        match first_ip(&h.ip) {
            Some(ip) => by_ip.entry(ip).or_default().push(h.name.clone()),
            None if np.hosts.contains(&rules::norm_host(&h.name)) => {
                out.insert(h.name.clone());
            }
            None => {}
        }
    }
    for (ip, names) in by_ip {
        if crate::analysis::scope_bulk::skip_reason(np, scope, &ip, &names).is_some() {
            out.extend(names);
        }
    }
    out
}

/// Prefix of the finding tag for results measured on a CDN edge (`cdn_edge:cloudflare`).
pub const CDN_EDGE_TAG: &str = "cdn_edge:";

/// Tag `cdn_edge:<provider id>` when `ip` belongs to a CDN / reverse-proxy edge range.
///
/// Policy: addresses of names added in bulk on a CDN/cloud/shared range are never probed
/// ([`no_probe_names`]). Explicit scope targets are probed even when they resolve to a CDN edge:
/// the client asked for them, but what answers there is the CDN, not the origin: ports, TLS
/// versions, ALPN and OCSP are CDN settings. Such findings carry this tag so the report can word
/// the fix as a CDN setting.
pub(crate) fn cdn_edge_tag(ip: &str) -> Option<String> {
    let c = foca_net::cdn::classify_ip(first_ip(ip)?.parse().ok()?)?;
    (c.kind == foca_net::cdn::RangeKind::Cdn).then(|| format!("{CDN_EDGE_TAG}{}", c.provider))
}

/// [`no_probe_names`] for the running scan (reads the project's "no probe" record).
pub(super) fn held_names(c: &Ctx, f: &NetFacts) -> std::collections::BTreeSet<String> {
    let np: crate::analysis::scope_bulk::NoProbe =
        facts::get(&lock(&c.db), crate::analysis::scope_bulk::K_NO_PROBE);
    no_probe_names(&np, &c.scope, f)
}

fn first_ip(s: &str) -> Option<String> {
    s.split([',', ' '])
        .map(str::trim)
        .find(|x| x.parse::<std::net::IpAddr>().is_ok())
        .map(String::from)
}

/// Applies a scan result to the host: `ports_scan` and `services`.
pub fn apply(h: &mut NetHost, r: &PortScan, info: PortsScanInfo) {
    let mut info = info;
    info.internetdb = h
        .services
        .iter()
        .filter(|s| s.2 == IDB)
        .filter_map(|s| s.0.split('/').next()?.parse().ok())
        .collect();
    for p in &r.open {
        let k = format!("{}/tcp", p.port);
        let label = port_label(p);
        match h.services.iter_mut().find(|s| s.0 == k) {
            Some(s) => {
                if s.2.is_empty() || s.2 == IDB || !label.is_empty() {
                    s.1 = p.service.clone();
                    s.2 = label;
                }
            }
            None => h.services.push((k, p.service.clone(), label)),
        }
    }
    if h.tech.is_empty() || h.tech == "-" {
        let t: Vec<String> = r
            .open
            .iter()
            .filter(|p| p.product.is_some())
            .map(port_label)
            .take(4)
            .collect();
        if !t.is_empty() {
            h.tech = t.join(", ");
        }
    }
    info.open = r.open.clone();
    h.ports_scan = Some(serde_json::to_value(info).unwrap_or(Value::Null));
}

/// Returns the host's port view for the snapshot (`Host.ports`, `Host.ports_scan`).
pub fn host_view(h: &NetHost) -> (Value, Value) {
    let info: Option<PortsScanInfo> = h
        .ports_scan
        .clone()
        .and_then(|v| serde_json::from_value(v).ok());
    let mut list: BTreeMap<u16, Value> = BTreeMap::new();
    if let Some(i) = &info {
        for p in &i.open {
            let outdated = outdated_of(p).map(|x| x.1);
            list.insert(p.port, json!({ "port": p.port, "proto": "tcp", "service": p.service,
                "banner": p.banner, "product": p.product, "version": p.version, "tls": p.tls,
                "cert_names": p.cert_names, "source": "scan", "cached": i.internetdb.contains(&p.port),
                "unconfirmed": false, "outdated": outdated,
                "confirmed": p.confirmed, "detail": p.detail,
                "sensitive": sensitive_of(p).filter(|_| p.confirmed).map(|s| s.name) }));
        }
    }
    for s in h.services.iter().filter(|s| s.2 == IDB) {
        let Some(port) = s.0.split('/').next().and_then(|x| x.parse::<u16>().ok()) else {
            continue;
        };
        if list.contains_key(&port) {
            continue;
        }
        // in the InternetDB cache, but our own scan checked this port and did not find it open
        let unconfirmed = info
            .as_ref()
            .is_some_and(|i| !i.cancelled && i.unreliable.is_none() && i.ports.contains(&port));
        list.insert(
            port,
            json!({ "port": port, "proto": "tcp", "service": s.1,
            "banner": null, "product": null, "version": null, "tls": false, "cert_names": [],
            "source": "internetdb", "cached": true, "unconfirmed": unconfirmed, "outdated": null,
            "sensitive": null }),
        );
    }
    let summary = match info {
        Some(i) => json!({ "scan": i.scan, "at": i.at, "ip": i.ip, "spec": i.spec,
            "scanned": i.scanned, "open": i.open.len(), "closed": i.closed, "filtered": i.filtered,
            "ms": i.ms, "cancelled": i.cancelled, "error": i.error, "unreliable": i.unreliable,
            "no_probe": i.no_probe }),
        None => Value::Null,
    };
    (json!(list.into_values().collect::<Vec<_>>()), summary)
}

/// Returns ports of all project hosts for reports (`Snapshot.ports`), only hosts with ports.
pub(crate) fn report_view(db: &foca_store::ProjectDb) -> Value {
    let f: NetFacts = facts::get(db, facts::K_NET);
    let v: Vec<Value> = f
        .hosts
        .values()
        .filter_map(|h| {
            let (list, scan) = host_view(h);
            if list.as_array().is_none_or(|a| a.is_empty()) && scan["unreliable"].is_null() {
                return None;
            }
            let ip = first_ip(&h.ip);
            Some(json!({ "host": h.name, "ip": ip, "ports": list, "ports_scan": scan }))
        })
        .collect();
    if v.is_empty() {
        Value::Null
    } else {
        json!(v)
    }
}

/// Records hosts whose address is held out of the port scan (CDN/cloud/shared hosting) and returns
/// the note for the source event.
fn mark_no_probe(
    c: &Ctx,
    held: &[(String, Vec<String>, String)],
    sid: &str,
    now: &str,
    spec: &str,
    ports: &[u16],
) -> Result<Option<String>, Stop> {
    if held.is_empty() {
        return Ok(None);
    }
    let db = lock(&c.db);
    let mut f: NetFacts = facts::get(&db, facts::K_NET);
    for (ip, names, why) in held {
        for n in names {
            f.host(n).ports_scan = Some(
                serde_json::to_value(PortsScanInfo {
                    scan: sid.to_string(),
                    at: now.to_string(),
                    ip: Some(ip.clone()),
                    spec: spec.to_string(),
                    ports: ports.to_vec(),
                    no_probe: Some(why.clone()),
                    ..Default::default()
                })
                .unwrap_or(Value::Null),
            );
        }
    }
    facts::put(&db, facts::K_NET, &f)?;
    let list: Vec<String> = held
        .iter()
        .take(5)
        .map(|(ip, _, why)| format!("{ip}: {why}"))
        .collect();
    let more = held.len().saturating_sub(list.len());
    Ok(Some(format!(
        "без скана портов (CDN/облако/общий хостинг): {}{}",
        list.join("; "),
        if more > 0 {
            format!(" … ещё {more}")
        } else {
            String::new()
        }
    )))
}

/// Stores a host scan result in the facts: ports and findings (reliable) or just the flag (unreliable);
/// removed port findings are deleted from the database. Returns `true` if anything was removed (re-analysis needed).
fn store_host(
    c: &Ctx,
    names: &[String],
    r: &PortScan,
    info: PortsScanInfo,
    now: &str,
    sid: &str,
    new_findings: &mut usize,
) -> Result<bool, Stop> {
    let db = lock(&c.db);
    let mut f: NetFacts = facts::get(&db, facts::K_NET);
    let bad = r.unreliable.is_some();
    let mut removed = Vec::new();
    let mut gone = 0;
    for (k, name) in names.iter().enumerate() {
        if !r.cancelled {
            let (g, d) = reconcile(&mut f, name, r, bad);
            gone += g;
            removed.extend(d);
        }
        if k > 0 {
            // One finding per IP:port (under the primary name); copies under other names of the same
            // address from earlier scans are deleted rather than marked fixed.
            let dup: Vec<u64> = f
                .findings
                .iter()
                .filter(|(_, x)| finding_port(x, name).is_some())
                .map(|(id, _)| *id)
                .collect();
            for id in &dup {
                f.findings.remove(id);
            }
            removed.extend(dup);
        }
        if bad {
            apply_unreliable(f.host(name), info.clone());
            continue;
        }
        apply(f.host(name), r, info.clone());
        if k > 0 {
            continue;
        }
        let mut fresh = port_findings_also(name, &names[1..], r, now, sid);
        if let Some(tag) = r.ip.as_deref().and_then(cdn_edge_tag) {
            for x in &mut fresh {
                x.tags.push(tag.clone());
            }
        }
        if !r.cancelled {
            // A finding for the same port under a different rule (stored by an earlier scan as High without protocol confirmation,
            // now unconfirmed info): the old one is deleted rather than marked fixed.
            let open: Vec<u16> = r.open.iter().map(|p| p.port).collect();
            let stale: Vec<u64> = f
                .findings
                .iter()
                .filter(|(id, x)| {
                    finding_port(x, name).is_some_and(|p| open.contains(&p))
                        && !fresh.iter().any(|n| n.id == **id)
                        && x.title.contains(':')
                })
                .map(|(id, _)| *id)
                .collect();
            for id in &stale {
                f.findings.remove(id);
            }
            removed.extend(stale);
        }
        for x in fresh {
            if !f.findings.contains_key(&x.id) {
                *new_findings += 1;
            }
            f.findings.entry(x.id).or_insert(x);
        }
    }
    let changed = gone > 0;
    facts::put(&db, facts::K_NET, &f)?;
    if !removed.is_empty() {
        let n = db.findings_delete(&removed)?;
        tracing::info!(target: "foca::scan", "{sid}: порты, снято находок недостоверного скана: {n}");
    }
    Ok(changed)
}

pub(super) async fn stage_ports(c: &mut Ctx) -> Result<(), Stop> {
    let idx = STAGES.iter().position(|s| s.0 == "ports").unwrap_or(5);
    if c.level != "active" || !c.module(SOURCE) {
        return Ok(());
    }
    let ss = c.e.store().settings_get().unwrap_or_default()["sources"].clone();
    if !super::source_enabled(&ss, SOURCE) {
        c.source_event(SOURCE, "off", None);
        return Ok(());
    }
    if lock(&c.skip).contains(SOURCE) {
        c.source_event(SOURCE, "skipped", None);
        return Ok(());
    }
    let run: Value = facts::get(&lock(&c.db), &run_key(&c.scan_id));
    let v = effective(&c.e, &run);
    let (ports, spec) = match ports_of(&v) {
        Ok(x) => x,
        Err(e) => {
            c.source_event_full(SOURCE, "error", None, Some(&e));
            return Ok(());
        }
    };
    let max_hosts = v["max_hosts"]
        .as_u64()
        .map(|x| x as usize)
        .filter(|x| *x > 0)
        .unwrap_or(MAX_HOSTS_DEFAULT);
    let mut cfg = PortScanConfig {
        ports: ports.clone(),
        banners: v["banners"].as_bool() != Some(false),
        // hidden setting for test benches: custom canary ports (`[]` disables the check)
        canaries: v["canaries"].as_array().map(|a| {
            a.iter()
                .filter_map(|x| x.as_u64().and_then(|p| u16::try_from(p).ok()))
                .collect()
        }),
        ..Default::default()
    };
    if let Some(r) = c.e.store().settings_get().unwrap_or_default()["net"]["rps"].as_f64() {
        if r <= 0.0 {
            cfg.rps = None;
        }
    }
    let (list, held, sid, now) = {
        let db = lock(&c.db);
        let f: NetFacts = facts::get(&db, facts::K_NET);
        let known: Vec<KnownHost> = f
            .hosts
            .values()
            .map(|h| KnownHost {
                name: h.name.clone(),
                ip: h.ip.clone(),
            })
            .chain(known_hosts(&db))
            .collect();
        let all = targets(&f, &c.scope, &known, &c.domains);
        let sid = c.scan_id.clone();
        // on resume, skip hosts this scan has already fully covered
        let done = |names: &[String]| {
            names.iter().any(|n| {
                f.hosts
                    .get(n)
                    .and_then(|h| h.ports_scan.as_ref())
                    .is_some_and(|p| p["scan"] == sid.as_str() && p["cancelled"] != true)
            })
        };
        // CDN / cloud / shared-hosting addresses of names added in bulk are never probed
        let np: crate::analysis::scope_bulk::NoProbe =
            facts::get(&db, crate::analysis::scope_bulk::K_NO_PROBE);
        let (all, held): (Vec<_>, Vec<_>) = all
            .into_iter()
            .map(|(ip, names)| {
                let why = crate::analysis::scope_bulk::skip_reason(&np, &c.scope, &ip, &names);
                (ip, names, why)
            })
            .partition(|x| x.2.is_none());
        let list: Vec<(String, Vec<String>)> = all
            .into_iter()
            .map(|(ip, names, _)| (ip, names))
            .take(max_hosts)
            .filter(|(_, n)| !done(n))
            .collect();
        let held: Vec<(String, Vec<String>, String)> = held
            .into_iter()
            .map(|(ip, names, why)| (ip, names, why.unwrap_or_default()))
            .collect();
        (list, held, sid, c.e.now_iso())
    };
    let held_note = mark_no_probe(c, &held, &sid, &now, &spec, &ports)?;
    if list.is_empty() {
        let msg = held_note.unwrap_or_else(|| "нет живых хостов в скоупе".into());
        c.source_event_full(SOURCE, "ok", Some(0), Some(&msg));
        return Ok(());
    }
    let n = list.len();
    let per_host = c.e.source_timeout().max(Duration::from_secs(30));
    tracing::info!(target: "foca::scan", "{}: порты {n} хост(ов), {spec}", c.scan_id);
    let mut open_total = 0usize;
    let mut new_findings = 0usize;
    let mut status = "ok";
    let mut err: Option<String> = None;
    let mut unreliable_hosts = 0usize;
    let mut changed = false;
    // The device network intercepts TCP (local VPN/AdGuard/proxy): a connection to a non-routable
    // TEST-NET address "succeeded", so a port scan is meaningless and the hosts are not touched.
    let custom_probes = v["intercept_probe"].as_array().map(|a| {
        a.iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect::<Vec<_>>()
    });
    let cached_intercept = lock(&c.st).canary.as_ref().map(|r| r.tcp_intercept);
    let intercepted = match custom_probes {
        Some(probes) => {
            !probes.is_empty()
                && device_intercepts_tcp(&c.net, &probes, Duration::from_millis(1500)).await
        }
        None => match cached_intercept {
            Some(true) => true,
            Some(false) => false,
            None => {
                let probes: Vec<String> = INTERCEPT_PROBES.iter().map(|s| s.to_string()).collect();
                !probes.is_empty()
                    && device_intercepts_tcp(&c.net, &probes, Duration::from_millis(1500)).await
            }
        },
    };
    if intercepted {
        tracing::warn!(target: "foca::scan", "{}: порты, сеть устройства перехватывает TCP", c.scan_id);
    }
    for (i, (ip, names)) in list.iter().enumerate() {
        c.gate().await?;
        if lock(&c.skip).contains(SOURCE) {
            status = "skipped";
            break;
        }
        let host = names[0].clone();
        c.source_event_x(
            SOURCE,
            "running",
            Some(open_total),
            None,
            json!({ "host": host, "ip": ip, "hosts": n, "host_index": i, "spec": spec,
                    "timeout_s": per_host.as_secs() }),
        );
        if intercepted {
            let r = PortScan {
                host: host.clone(),
                ip: Some(ip.clone()),
                open: Vec::new(),
                scanned: 0,
                closed: 0,
                filtered: 0,
                ms: 0,
                batch: 0,
                cancelled: false,
                unreliable: Some(UNRELIABLE_INTERCEPT.into()),
                canaries: 0,
                canaries_open: 0,
            };
            let info = PortsScanInfo {
                scan: sid.clone(),
                at: now.clone(),
                ip: r.ip.clone(),
                spec: spec.clone(),
                ports: ports.clone(),
                unreliable: r.unreliable.clone(),
                ..Default::default()
            };
            unreliable_hosts += 1;
            changed |= store_host(c, names, &r, info, &now, &sid, &mut new_findings)?;
            c.progress(idx, (i as f64 + 1.0) / n as f64);
            continue;
        }
        let child = c.cancel.child_token();
        let net = c.group_net("target")?.with_cancel(child.clone());
        let fut = scan_ports(&net, &host, &cfg);
        tokio::pin!(fut);
        let deadline = tokio::time::sleep(per_host);
        tokio::pin!(deadline);
        let mut tick = tokio::time::interval(Duration::from_millis(300));
        let mut timed_out = false;
        let mut skipped = false;
        let res = loop {
            tokio::select! {
                r = &mut fut => break r,
                _ = &mut deadline, if !timed_out => { timed_out = true; child.cancel(); }
                _ = c.cancel.cancelled() => { child.cancel(); }
                _ = tick.tick() => {
                    if !skipped && lock(&c.skip).contains(SOURCE) { skipped = true; child.cancel(); }
                }
            }
        };
        if c.cancel.is_cancelled() {
            return Err(Stop::Cancelled);
        }
        let r = match res {
            Ok(r) => r,
            Err(NetError::Cancelled) => {
                status = if skipped { "skipped" } else { "timeout" };
                if timed_out {
                    err = Some(format!("{host}: нет ответа за отведённое время"));
                }
                break;
            }
            Err(e) => {
                tracing::warn!(target: "foca::scan", "{}: порты {host}: {e}", c.scan_id);
                err = Some(format!("{host}: {e}"));
                continue;
            }
        };
        if r.unreliable.is_some() {
            unreliable_hosts += 1;
        } else {
            open_total += r.open.len();
        }
        let info = PortsScanInfo {
            scan: sid.clone(),
            at: now.clone(),
            ip: r.ip.clone(),
            spec: spec.clone(),
            ports: ports.clone(),
            scanned: r.scanned,
            closed: r.closed,
            filtered: r.filtered,
            ms: r.ms,
            cancelled: r.cancelled,
            error: timed_out.then(|| "таймаут хоста".to_string()),
            unreliable: r.unreliable.clone(),
            ..Default::default()
        };
        changed |= store_host(c, names, &r, info, &now, &sid, &mut new_findings)?;
        c.progress(idx, (i as f64 + 1.0) / n as f64);
        if r.cancelled {
            status = if skipped { "skipped" } else { "timeout" };
            break;
        }
    }
    if status == "ok" && err.is_some() && open_total == 0 {
        status = "error";
    }
    if unreliable_hosts > 0 && matches!(status, "ok" | "error") {
        // the warning takes precedence over "ok": open ports of such hosts are not recorded and no findings are created
        status = "unreliable";
        err = Some(UNRELIABLE_MSG.into());
    }
    if err.is_none() {
        err = held_note;
    }
    c.source_event_x(
        SOURCE,
        status,
        Some(open_total),
        err.as_deref(),
        if unreliable_hosts > 0 {
            json!({ "unreliable": { "hosts": unreliable_hosts, "intercept": intercepted } })
        } else {
            Value::Null
        },
    );
    if new_findings > 0 || changed {
        let ids = reanalyze_bg(c).await?;
        c.findings_events(&ids);
    }
    tracing::info!(target: "foca::scan", "{}: порты, открыто {open_total}, новых находок {new_findings}", c.scan_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pr(port: u16, service: &str, banner: Option<&str>) -> PortResult {
        PortResult {
            port,
            service: service.into(),
            banner: banner.map(String::from),
            product: None,
            version: None,
            tls: false,
            cert_names: vec![],
            confirmed: true,
            detail: banner
                .is_some_and(|b| b.contains("PONG"))
                .then(|| "no-auth".to_string()),
        }
    }

    /// Without protocol confirmation a finding is info only, as is 2376 with a client certificate; a
    /// Proxmox panel detected by banner is a finding; one finding per IP lists all names.
    #[test]
    fn severity_needs_confirmation() {
        let mut rdp = pr(3389, "rdp", None);
        rdp.confirmed = false;
        let mut d2376 = pr(2376, "docker", Some("TLS: client certificate required"));
        d2376.confirmed = false;
        d2376.detail = Some("client-cert".into());
        let pve = pr(
            8006,
            "https",
            Some("HTTP/1.1 501 · Server: pve-api-daemon/3.0"),
        );
        let ftps = pr(990, "ftps", Some("220 FTPS ready"));
        let r = PortScan {
            open: vec![rdp, d2376, pve, ftps],
            ..scan(vec![], 100, None)
        };
        let also = vec!["www.h".to_string()];
        let f = port_findings_also("h", &also, &r, "t", "s1");
        let t: Vec<(&str, Severity)> = f.iter().map(|x| (x.title.as_str(), x.sev)).collect();
        assert_eq!(f.len(), 3, "{t:?}");
        assert!(f
            .iter()
            .filter(|x| x.title.contains("не подтверждён"))
            .all(|x| x.sev == Severity::Info));
        assert!(f
            .iter()
            .any(|x| x.title.contains("2376") && x.description.contains("клиентский сертификат")));
        assert!(f
            .iter()
            .any(|x| x.title.contains("Proxmox VE API") && x.sev == Severity::High));
        assert!(
            !f.iter().any(|x| x.title.contains("990")),
            "FTPS is not 'unencrypted FTP'"
        );
        assert!(f.iter().all(|x| x.description.contains("www.h")));
        // a confirmed 2376 without a certificate has its own text, not a copy of the 2375 one
        let mut ok2376 = pr(2376, "docker", Some("Docker API 24.0.7"));
        ok2376.detail = Some("no-auth".into());
        let f = port_findings(
            "h",
            &PortScan {
                open: vec![ok2376],
                ..scan(vec![], 100, None)
            },
            "t",
            "s1",
        );
        assert!(f[0].description.contains("TLS-порту 2376") && f[0].sev == Severity::Critical);
    }

    #[test]
    fn targets_skip_excluded_and_dedupe_by_ip() {
        let scope = ScopeDto {
            targets: vec![foca_core::api::ScopeTarget {
                v: "example.test".into(),
                kind: "domain".into(),
            }],
            excl: vec!["mail.example.test".into(), "10.0.0.9".into()],
            ..Default::default()
        };
        let mut f = NetFacts::default();
        for (n, ip) in [
            ("example.test", "127.0.0.1"),
            ("www.example.test", "127.0.0.1"),
            ("mail.example.test", "127.0.0.2"),
            ("db.example.test", "10.0.0.9"),
            ("other.test", "127.0.0.3"),
            ("old.example.test", "CNAME → x.azurewebsites.net"),
        ] {
            f.host(n).ip = ip.into();
        }
        let t = targets(&f, &scope, &[], &["example.test".into()]);
        assert_eq!(
            t,
            vec![(
                "127.0.0.1".to_string(),
                vec!["example.test".to_string(), "www.example.test".to_string()]
            )]
        );
    }

    #[test]
    fn cdn_edge_results_are_tagged_with_the_provider() {
        // Cloudflare edge (104.16.0.0/13), as in the scope_bulk tests
        assert_eq!(
            cdn_edge_tag("104.16.1.1").as_deref(),
            Some("cdn_edge:cloudflare")
        );
        assert_eq!(
            cdn_edge_tag("104.16.1.1, 104.16.1.2").as_deref(),
            Some("cdn_edge:cloudflare")
        );
        assert_eq!(cdn_edge_tag("192.0.2.10"), None);
        assert_eq!(cdn_edge_tag("CNAME → x.example.net"), None);
    }

    #[test]
    fn ports_spec() {
        assert_eq!(ports_of(&json!({"top": 100})).unwrap().0.len(), 100);
        assert_eq!(ports_of(&json!({"top": 1000})).unwrap().1, "топ-1000");
        let (p, s) = ports_of(&json!({"top": 0, "list": "22,80"})).unwrap();
        assert_eq!(p, vec![22, 80]);
        assert!(s.starts_with("свой"));
        assert!(ports_of(&json!({"top": 0, "list": ""})).is_err());
    }

    #[test]
    fn sensitive_and_outdated() {
        let r = PortScan {
            host: "h".into(),
            ip: Some("1.2.3.4".into()),
            open: vec![
                pr(22, "ssh", None),
                pr(6379, "redis", Some("+PONG")),
                pr(3389, "rdp", None),
                pr(80, "http", Some("Server: Apache/2.2.15 (CentOS)")),
            ],
            scanned: 100,
            closed: 96,
            filtered: 0,
            ms: 5,
            batch: 50,
            cancelled: false,
            unreliable: None,
            canaries: 3,
            canaries_open: 0,
        };
        let f = port_findings("h", &r, "2026-11-20T10:00:00", "s1");
        let t: Vec<&str> = f.iter().map(|x| x.title.as_str()).collect();
        assert_eq!(f.len(), 3, "{t:?}");
        assert!(f
            .iter()
            .any(|x| x.title.contains("Redis") && x.sev == Severity::Critical));
        assert!(f
            .iter()
            .any(|x| x.title.contains("RDP") && x.sev == Severity::High));
        assert!(f.iter().any(|x| x.title.contains("Устаревшая") && x.active));
        let mut h = NetHost {
            name: "h".into(),
            services: vec![("443/tcp".into(), "https".into(), IDB.into())],
            ..Default::default()
        };
        apply(
            &mut h,
            &r,
            PortsScanInfo {
                ports: vec![22, 80, 443, 3389, 6379],
                ..Default::default()
            },
        );
        let (list, sum) = host_view(&h);
        let a = list.as_array().unwrap();
        assert_eq!(a.len(), 5);
        let p443 = a.iter().find(|x| x["port"] == 443).unwrap();
        assert_eq!(p443["source"], "internetdb");
        assert_eq!(p443["unconfirmed"], true);
        assert_eq!(sum["open"], 4);
    }

    fn scan(open: Vec<PortResult>, scanned: usize, unreliable: Option<&str>) -> PortScan {
        PortScan {
            host: "h".into(),
            ip: Some("1.2.3.4".into()),
            open,
            scanned,
            closed: 0,
            filtered: 0,
            ms: 5,
            batch: 50,
            cancelled: false,
            unreliable: unreliable.map(String::from),
            canaries: 3,
            canaries_open: 0,
        }
    }

    /// Fake ports through a local VPN: an unreliable scan removes the findings (deleted, not marked
    /// fixed) and drops ports from earlier scans, while the InternetDB cache stays.
    #[test]
    fn unreliable_scan_drops_port_findings() {
        // an earlier scan (before port canaries existed): 60 of 100 "open", all silent
        let fake: Vec<PortResult> = [21, 22, 445, 2375, 3389, 6379]
            .iter()
            .map(|p| pr(*p, "unknown", None))
            .chain((7000..7054).map(|p| pr(p, "unknown", None)))
            .collect();
        let old = scan(fake, 100, None);
        let mut f = NetFacts::default();
        let mut h = NetHost {
            name: "h".into(),
            services: vec![("443/tcp".into(), "https".into(), IDB.into())],
            ..Default::default()
        };
        apply(&mut h, &old, PortsScanInfo::default());
        f.hosts.insert("h".into(), h);
        for x in port_findings("h", &old, "t", "s1") {
            f.findings.insert(x.id, x);
        }
        // another host is left alone
        let other = scan(vec![pr(3389, "rdp", None)], 100, None);
        for x in port_findings("o", &other, "t", "s1") {
            f.findings.insert(x.id, x);
        }
        let n0 = f.findings.len();
        assert!(n0 > 5);
        let bad = scan(vec![], 0, Some("canary"));
        let (gone, del) = reconcile(&mut f, "h", &bad, true);
        assert_eq!(gone, n0 - 1);
        assert_eq!(del.len(), gone, "deleted rather than marked fixed");
        assert_eq!(f.findings.len(), 1);
        apply_unreliable(
            f.host("h"),
            PortsScanInfo {
                unreliable: Some("canary".into()),
                ports: vec![22, 443],
                ..Default::default()
            },
        );
        let h = &f.hosts["h"];
        assert_eq!(
            h.services.len(),
            1,
            "only the InternetDB cache remains: {:?}",
            h.services
        );
        let (list, sum) = host_view(h);
        assert_eq!(sum["unreliable"], "canary");
        let a = list.as_array().unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(
            a[0]["unconfirmed"], false,
            "an unreliable scan does not refute the cache"
        );
    }

    /// A reliable rescan: a closed port's finding leaves the facts (the analysis marks it fixed); if
    /// the previous scan was a mass "open", the finding is deleted.
    #[test]
    fn reliable_rescan_reconciles() {
        let mut f = NetFacts::default();
        let old = scan(
            vec![pr(3389, "rdp", None), pr(6379, "redis", None)],
            100,
            None,
        );
        apply(f.host("h"), &old, PortsScanInfo::default());
        for x in port_findings("h", &old, "t", "s1") {
            f.findings.insert(x.id, x);
        }
        let now = scan(vec![pr(6379, "redis", None)], 100, None);
        let (gone, del) = reconcile(&mut f, "h", &now, false);
        assert_eq!((gone, del.len()), (1, 0));
        assert_eq!(f.findings.len(), 1);
        // the previous scan was a mass "open"
        let fake: Vec<PortResult> = (7000..7060).map(|p| pr(p, "unknown", None)).collect();
        let mut g = NetFacts::default();
        let mut with_rdp = fake.clone();
        with_rdp.push(pr(3389, "rdp", None));
        let old = scan(with_rdp.clone(), 100, None);
        apply(
            g.host("h"),
            &old,
            PortsScanInfo {
                scanned: 100,
                open: with_rdp,
                ..Default::default()
            },
        );
        for x in port_findings("h", &old, "t", "s1") {
            g.findings.insert(x.id, x);
        }
        let (gone, del) = reconcile(&mut g, "h", &scan(vec![], 100, None), false);
        assert_eq!((gone, del.len()), (1, 1));
        assert!(g.hosts["h"].services.iter().all(|s| s.0 != "3389/tcp"));
    }
}
