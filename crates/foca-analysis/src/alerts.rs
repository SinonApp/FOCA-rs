//! Event alerts for scheduled monitoring (mini-ASM) and the risk trend between scans.
//!
//! * [`evaluate`] compares two [`AlertSnapshot`]s (the previous and the current scan of a
//!   project) under [`AlertSettings`] and returns [`Alert`]s plus the deduplication state to
//!   persist until the next scan.
//! * [`risk_trend`] aggregates the scan history of a project into a [`RiskTrend`] series.
//!
//! An [`AlertSnapshot`] never carries secret or PII values: documents report only counters
//! (`secrets`, `pii`) and a GPS flag, so alerts can only contain host names, ports, document
//! names, dates and counts. [`Alert::params`] is the only free-form payload and is built here
//! from those safe fields.
//!
//! Deduplication: diff rules (new host, port, document, CT certificate) fire only for items absent
//! from the previous snapshot. State rules (TLS expiry, dangling CNAME, risk above threshold) fire
//! once per key and stay silent while the key remains in [`AlertBatch::state`]; when the
//! condition clears, the key is dropped and the alert can fire again later. An incomplete scan
//! never clears keys (a source that did not answer is not a fix).

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::Scan;
use foca_core::Severity;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Alert rule identifiers (`settings.alerts.<rule>` and `Alert.rule`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertRule {
    NewHost,
    NewPort,
    DocSecret,
    DocPii,
    DocGps,
    TlsExpiry,
    DanglingCname,
    CtNewCert,
    RiskRise,
}

impl AlertRule {
    pub const ALL: [AlertRule; 9] = [
        AlertRule::NewHost,
        AlertRule::NewPort,
        AlertRule::DocSecret,
        AlertRule::DocPii,
        AlertRule::DocGps,
        AlertRule::TlsExpiry,
        AlertRule::DanglingCname,
        AlertRule::CtNewCert,
        AlertRule::RiskRise,
    ];

    /// Stable snake_case id (same as the serde form).
    pub fn id(self) -> &'static str {
        match self {
            AlertRule::NewHost => "new_host",
            AlertRule::NewPort => "new_port",
            AlertRule::DocSecret => "doc_secret",
            AlertRule::DocPii => "doc_pii",
            AlertRule::DocGps => "doc_gps",
            AlertRule::TlsExpiry => "tls_expiry",
            AlertRule::DanglingCname => "dangling_cname",
            AlertRule::CtNewCert => "ct_new_cert",
            AlertRule::RiskRise => "risk_rise",
        }
    }

    /// Diff rules compare against the previous snapshot and stay silent on the baseline scan.
    pub fn is_diff(self) -> bool {
        !matches!(
            self,
            AlertRule::TlsExpiry | AlertRule::DanglingCname | AlertRule::RiskRise
        )
    }
}

/// Alert settings (`settings.alerts`). Missing fields take the defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertSettings {
    /// Master switch.
    pub enabled: bool,
    /// Per-rule switches; a missing rule is enabled.
    pub rules: BTreeMap<AlertRule, bool>,
    /// Alerts below this severity are dropped.
    pub min_severity: Severity,
    /// TLS: warn when a certificate expires within this many days.
    pub tls_warn_days: u32,
    /// TLS: high severity within this many days (expired certificates are critical).
    pub tls_crit_days: u32,
    /// Risk: fire when the score reaches this value (crossing from below).
    pub risk_threshold: u8,
    /// Risk: fire when the score grows by at least this many points between two scans (0 = off).
    pub risk_delta: u8,
    /// Ports considered dangerous when exposed (high severity instead of medium).
    pub risky_ports: Vec<u16>,
    /// Upper bound of alerts per batch; the rest is summarized in [`AlertBatch::dropped`].
    pub max_alerts: usize,
}

impl Default for AlertSettings {
    fn default() -> Self {
        AlertSettings {
            enabled: true,
            rules: BTreeMap::new(),
            min_severity: Severity::Info,
            tls_warn_days: 30,
            tls_crit_days: 14,
            risk_threshold: 70,
            risk_delta: 15,
            risky_ports: vec![
                21, 23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017,
            ],
            max_alerts: 50,
        }
    }
}

impl AlertSettings {
    /// Reads `settings.alerts` leniently: an invalid section falls back to the defaults, but an
    /// explicit master switch is still honoured.
    pub fn from_json(v: &Value) -> AlertSettings {
        let mut cfg: AlertSettings = serde_json::from_value(v.clone()).unwrap_or_default();
        if let Some(enabled) = v["enabled"].as_bool() {
            cfg.enabled = enabled;
        }
        cfg
    }

    pub fn rule_on(&self, r: AlertRule) -> bool {
        self.enabled && self.rules.get(&r).copied().unwrap_or(true)
    }

    /// Returns `true` if an alert of this severity passes the `min_severity` threshold.
    pub fn keeps(&self, sev: Severity) -> bool {
        sev.rank() >= self.min_severity.rank()
    }

    /// Severity of a newly exposed port: high for the configured risky ports, medium otherwise.
    pub fn new_port_severity(&self, port: u16) -> Severity {
        if self.risky_ports.contains(&port) {
            Severity::High
        } else {
            Severity::Medium
        }
    }
}

/// An open port seen by the scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(default)]
pub struct PortRef {
    pub host: String,
    pub port: u16,
    /// Detected service (`ssh`, `http`, ...), empty if unknown.
    pub service: String,
}

/// A document with counters only (never values).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DocRef {
    pub id: u64,
    pub name: String,
    pub host: String,
    /// Number of secrets found in the document.
    pub secrets: u32,
    /// Number of PII matches (IDs, phone numbers, e-mails in text, ...).
    pub pii: u32,
    /// The document carries GPS coordinates.
    pub gps: bool,
}

/// A TLS certificate served by a host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CertRef {
    pub host: String,
    /// SHA-256 fingerprint (hex); a renewed certificate gets a new dedup key.
    pub fingerprint: String,
    /// `notAfter`, RFC 3339 (`2026-12-01T00:00:00Z`) or a date (`2026-12-01`).
    pub not_after: String,
}

/// A certificate from CT logs (`foca_net::ct::CtCert` mirror).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CtRef {
    /// `crtsh` | `certspotter`.
    pub source: String,
    pub id: String,
    pub names: Vec<String>,
    /// Issuer organization or CA name.
    pub issuer: String,
    /// `notBefore`, RFC 3339 or date (informational).
    pub not_before: String,
}

/// A dangling CNAME (`foca_net::takeover::Dangling` mirror).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DanglingRef {
    pub host: String,
    pub chain: Vec<String>,
    pub provider: Option<String>,
    /// `crit` (claimable at a known provider) or `warn`.
    pub sev: String,
}

/// Counts of active findings by severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SevCounts {
    pub crit: u32,
    pub high: u32,
    pub warn: u32,
    pub low: u32,
    pub info: u32,
}

impl SevCounts {
    pub fn add(&mut self, s: Severity) {
        match s {
            Severity::Critical => self.crit += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.warn += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }

    pub fn total(&self) -> u32 {
        self.crit + self.high + self.warn + self.low + self.info
    }

    /// Risk score with the weights of [`crate::findings::risk`] (crit .25, high .12, warn .05,
    /// low .02, info 0).
    pub fn risk(&self) -> u8 {
        let p = 0.75f64.powi(self.crit as i32)
            * 0.88f64.powi(self.high as i32)
            * 0.95f64.powi(self.warn as i32)
            * 0.98f64.powi(self.low as i32);
        (100.0 * (1.0 - p)).round().clamp(0.0, 100.0) as u8
    }
}

/// What a scan saw, in the shape the alert rules need. Filled by the engine from the project
/// database after a scan; every field defaults to empty.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertSnapshot {
    pub scan_id: String,
    /// Scan finish time, RFC 3339.
    pub scan_time: String,
    /// False when sources failed, the network was intercepted or the scan was stopped.
    pub complete: bool,
    pub hosts: BTreeSet<String>,
    pub ports: Vec<PortRef>,
    pub docs: Vec<DocRef>,
    pub certs: Vec<CertRef>,
    pub ct: Vec<CtRef>,
    pub dangling: Vec<DanglingRef>,
    /// Risk score 0..=100 (`None` = no data).
    pub risk: Option<u8>,
    pub counts: SevCounts,
}

/// A reference to an entity the alert is about (for navigation in the UI).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRef {
    /// `host` | `port` | `doc` | `cert` | `ct` | `project`.
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

/// A triggered alert. `title_key` is an i18n key (`alert.<rule>`); `params` fill its
/// placeholders and contain only names, numbers and dates (never secret or PII values).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    /// Dedup key: `<rule>:<entity>[:<band>]`.
    pub key: String,
    pub rule: AlertRule,
    #[serde(rename = "severity")]
    pub sev: Severity,
    pub title_key: String,
    pub params: BTreeMap<String, Value>,
    pub refs: Vec<EntityRef>,
}

/// Result of [`evaluate`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AlertBatch {
    /// Alerts to deliver, most severe first.
    pub alerts: Vec<Alert>,
    /// Alerts cut by `max_alerts`.
    pub dropped: usize,
    /// True when diff rules were skipped (no previous snapshot).
    pub baseline: bool,
    /// Dedup keys of active state alerts to store and pass as `fired` next time.
    pub state: BTreeSet<String>,
}

fn parse_time(s: &str) -> Option<OffsetDateTime> {
    let s = s.trim();
    if let Ok(t) = OffsetDateTime::parse(s, &Rfc3339) {
        return Some(t);
    }
    let d = time::Date::parse(
        s.get(..10)?,
        time::macros::format_description!("[year]-[month]-[day]"),
    )
    .ok()?;
    Some(d.midnight().assume_utc())
}

fn date_only(t: OffsetDateTime) -> String {
    format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day())
}

fn eref(kind: &str, id: impl Into<String>) -> EntityRef {
    EntityRef {
        kind: kind.into(),
        id: id.into(),
    }
}

struct Acc<'a> {
    cfg: &'a AlertSettings,
    out: Vec<Alert>,
}

impl Acc<'_> {
    fn push(
        &mut self,
        rule: AlertRule,
        key: String,
        sev: Severity,
        params: Value,
        refs: Vec<EntityRef>,
    ) {
        if !self.cfg.keeps(sev) {
            return;
        }
        let params = match params {
            Value::Object(m) => m.into_iter().collect(),
            _ => BTreeMap::new(),
        };
        self.out.push(Alert {
            key,
            rule,
            sev,
            title_key: format!("alert.{}", rule.id()),
            params,
            refs,
        });
    }
}

/// Evaluates the alert rules for `cur` against `prev` (`None` on the first scan).
///
/// `fired` is the [`AlertBatch::state`] stored after the previous evaluation; `now` is used for
/// TLS expiry (pass the scan finish time for reproducible results).
pub fn evaluate(
    prev: Option<&AlertSnapshot>,
    cur: &AlertSnapshot,
    cfg: &AlertSettings,
    fired: &BTreeSet<String>,
    now: OffsetDateTime,
) -> AlertBatch {
    let mut acc = Acc {
        cfg,
        out: Vec::new(),
    };
    let mut state: BTreeSet<String> = BTreeSet::new();
    if !cfg.enabled {
        return AlertBatch {
            state: fired.clone(),
            ..Default::default()
        };
    }
    let on = |r| cfg.rule_on(r);

    if let Some(prev) = prev {
        diff_rules(prev, cur, &mut acc, &on);
    }

    // TLS expiry: one alert per certificate and band (warn → crit → expired escalates).
    if on(AlertRule::TlsExpiry) {
        for c in &cur.certs {
            let Some(na) = parse_time(&c.not_after) else {
                continue;
            };
            let days = (na - now).whole_days();
            let (band, sev) = if na <= now {
                ("expired", Severity::Critical)
            } else if days < i64::from(cfg.tls_crit_days) {
                ("crit", Severity::High)
            } else if days < i64::from(cfg.tls_warn_days) {
                ("warn", Severity::Medium)
            } else {
                continue;
            };
            let fp = if c.fingerprint.is_empty() {
                &c.not_after
            } else {
                &c.fingerprint
            };
            let key = format!("tls_expiry:{}:{fp}:{band}", c.host.to_ascii_lowercase());
            state.insert(key.clone());
            if !fired.contains(&key) {
                acc.push(
                    AlertRule::TlsExpiry,
                    key,
                    sev,
                    json!({ "host": c.host, "days": days.max(0), "date": date_only(na), "expired": na <= now }),
                    vec![eref("host", &c.host), eref("cert", fp.clone())],
                );
            }
        }
    }

    if on(AlertRule::DanglingCname) {
        for d in &cur.dangling {
            let key = format!("dangling_cname:{}", d.host.to_ascii_lowercase());
            state.insert(key.clone());
            if fired.contains(&key) {
                continue;
            }
            let sev = if d.sev == "crit" {
                Severity::Critical
            } else {
                Severity::High
            };
            acc.push(
                AlertRule::DanglingCname,
                key,
                sev,
                json!({
                    "host": d.host,
                    "cname": d.chain.last().cloned().unwrap_or_default(),
                    "provider": d.provider.clone().unwrap_or_default(),
                }),
                vec![eref("host", &d.host)],
            );
        }
    }

    if on(AlertRule::RiskRise) {
        if let Some(r) = cur.risk {
            let p = prev.and_then(|p| p.risk);
            let key = "risk_rise:threshold".to_string();
            if r >= cfg.risk_threshold && cfg.risk_threshold > 0 {
                state.insert(key.clone());
            }
            let crossed =
                r >= cfg.risk_threshold && cfg.risk_threshold > 0 && !fired.contains(&key);
            let jumped = cfg.risk_delta > 0 && p.is_some_and(|p| r >= p && r - p >= cfg.risk_delta);
            if crossed || jumped {
                let k = if crossed {
                    key
                } else {
                    format!("risk_rise:delta:{}", cur.scan_id)
                };
                acc.push(
                    AlertRule::RiskRise,
                    k,
                    if r >= 90 {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    json!({
                        "risk": r,
                        "prev": p,
                        "delta": p.map(|p| i16::from(r) - i16::from(p)),
                        "threshold": cfg.risk_threshold,
                        "crit": cur.counts.crit,
                        "high": cur.counts.high,
                    }),
                    vec![eref("project", "risk")],
                );
            }
        }
    }

    // An incomplete scan does not prove that a condition cleared: keep the old keys.
    if !cur.complete {
        state.extend(fired.iter().cloned());
    }

    let mut alerts = acc.out;
    alerts.sort_by(|a, b| b.sev.rank().cmp(&a.sev.rank()).then(a.key.cmp(&b.key)));
    alerts.dedup_by(|a, b| a.key == b.key);
    let dropped = alerts.len().saturating_sub(cfg.max_alerts.max(1));
    alerts.truncate(cfg.max_alerts.max(1));
    AlertBatch {
        alerts,
        dropped,
        baseline: prev.is_none(),
        state,
    }
}

fn diff_rules(
    prev: &AlertSnapshot,
    cur: &AlertSnapshot,
    acc: &mut Acc<'_>,
    on: &dyn Fn(AlertRule) -> bool,
) {
    let cfg = acc.cfg;
    if on(AlertRule::NewHost) {
        let old: BTreeSet<String> = prev.hosts.iter().map(|h| h.to_ascii_lowercase()).collect();
        for h in &cur.hosts {
            if !old.contains(&h.to_ascii_lowercase()) {
                acc.push(
                    AlertRule::NewHost,
                    format!("new_host:{}", h.to_ascii_lowercase()),
                    Severity::Low,
                    json!({ "host": h }),
                    vec![eref("host", h)],
                );
            }
        }
    }
    if on(AlertRule::NewPort) {
        let old: BTreeSet<(String, u16)> = prev
            .ports
            .iter()
            .map(|p| (p.host.to_ascii_lowercase(), p.port))
            .collect();
        for p in &cur.ports {
            if old.contains(&(p.host.to_ascii_lowercase(), p.port)) {
                continue;
            }
            let sev = cfg.new_port_severity(p.port);
            acc.push(
                AlertRule::NewPort,
                format!("new_port:{}:{}", p.host.to_ascii_lowercase(), p.port),
                sev,
                json!({ "host": p.host, "port": p.port, "service": p.service }),
                vec![
                    eref("host", &p.host),
                    eref("port", format!("{}:{}", p.host, p.port)),
                ],
            );
        }
    }
    let old_docs: BTreeSet<u64> = prev.docs.iter().map(|d| d.id).collect();
    for d in cur.docs.iter().filter(|d| !old_docs.contains(&d.id)) {
        let refs = || vec![eref("doc", d.id.to_string())];
        if d.secrets > 0 && on(AlertRule::DocSecret) {
            acc.push(
                AlertRule::DocSecret,
                format!("doc_secret:{}", d.id),
                Severity::Critical,
                json!({ "doc": d.name, "host": d.host, "count": d.secrets }),
                refs(),
            );
        }
        if d.pii > 0 && on(AlertRule::DocPii) {
            acc.push(
                AlertRule::DocPii,
                format!("doc_pii:{}", d.id),
                Severity::High,
                json!({ "doc": d.name, "host": d.host, "count": d.pii }),
                refs(),
            );
        }
        if d.gps && on(AlertRule::DocGps) {
            acc.push(
                AlertRule::DocGps,
                format!("doc_gps:{}", d.id),
                Severity::Medium,
                json!({ "doc": d.name, "host": d.host }),
                refs(),
            );
        }
    }
    if on(AlertRule::CtNewCert) {
        let old: BTreeSet<(&str, &str)> = prev
            .ct
            .iter()
            .map(|c| (c.source.as_str(), c.id.as_str()))
            .collect();
        let known: BTreeSet<String> = prev
            .ct
            .iter()
            .flat_map(|c| c.names.iter())
            .chain(prev.hosts.iter())
            .map(|n| n.to_ascii_lowercase())
            .collect();
        for c in &cur.ct {
            if old.contains(&(c.source.as_str(), c.id.as_str())) {
                continue;
            }
            let new_names: Vec<&String> = c
                .names
                .iter()
                .filter(|n| !known.contains(&n.to_ascii_lowercase()))
                .collect();
            let names: Vec<&String> = c.names.iter().take(5).collect();
            acc.push(
                AlertRule::CtNewCert,
                format!("ct_new_cert:{}:{}", c.source, c.id),
                if new_names.is_empty() {
                    Severity::Info
                } else {
                    Severity::Low
                },
                json!({
                    "names": names,
                    "count": c.names.len(),
                    "new_names": new_names.len(),
                    "issuer": c.issuer,
                }),
                vec![eref("ct", format!("{}:{}", c.source, c.id))],
            );
        }
    }
}

/// One point of the risk trend.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TrendPoint {
    pub scan_id: String,
    /// Scan finish (or start) time, RFC 3339.
    pub time: String,
    pub risk: u8,
    pub counts: SevCounts,
    pub total: u32,
    /// False for stopped or incomplete scans (the UI draws these points hollow).
    pub complete: bool,
}

/// Risk trend over the scans of a project, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RiskTrend {
    pub points: Vec<TrendPoint>,
    /// Last minus first risk score (`None` with fewer than two points).
    pub delta: Option<i16>,
    /// `up` | `down` | `flat` | `none`.
    pub direction: String,
    pub peak: Option<u8>,
}

/// Builds the risk trend from the scan history (`Scan.snapshot.findings` holds the active
/// findings of each scan). Scans without a finish time are skipped; `limit` keeps the latest N
/// points (0 = all).
pub fn risk_trend(scans: &[Scan], limit: usize) -> RiskTrend {
    let points = scans
        .iter()
        .filter(|s| s.finished_at.is_some() && matches!(s.status.as_str(), "done" | "stopped"))
        .map(|s| {
            let mut counts = SevCounts::default();
            for sev in s.snapshot.findings.values() {
                counts.add(*sev);
            }
            TrendPoint {
                scan_id: s.id.clone(),
                time: s
                    .finished_at
                    .clone()
                    .unwrap_or_else(|| s.started_at.clone()),
                risk: counts.risk(),
                total: counts.total(),
                counts,
                complete: s.status == "done" && !s.env.as_ref().is_some_and(|e| e.incomplete),
            }
        })
        .collect();
    trend_from_points(points, limit)
}

/// Sorts points by time, keeps the latest `limit` (0 = all) and computes delta/direction/peak.
pub fn trend_from_points(mut points: Vec<TrendPoint>, limit: usize) -> RiskTrend {
    points.sort_by_key(|p| parse_time(&p.time).map(|t| t.unix_timestamp()).unwrap_or(0));
    if limit > 0 && points.len() > limit {
        points.drain(..points.len() - limit);
    }
    let delta = match (points.first(), points.last()) {
        (Some(a), Some(b)) if points.len() > 1 => Some(i16::from(b.risk) - i16::from(a.risk)),
        _ => None,
    };
    let direction = match delta {
        None => "none",
        Some(d) if d > 0 => "up",
        Some(d) if d < 0 => "down",
        _ => "flat",
    }
    .to_string();
    let peak = points.iter().map(|p| p.risk).max();
    RiskTrend {
        points,
        delta,
        direction,
        peak,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-01 12:00 UTC);

    fn base() -> AlertSnapshot {
        AlertSnapshot {
            scan_id: "s1".into(),
            scan_time: "2026-10-25T12:00:00Z".into(),
            complete: true,
            hosts: ["www.example.com".to_string()].into(),
            ports: vec![PortRef {
                host: "www.example.com".into(),
                port: 443,
                service: "https".into(),
            }],
            docs: vec![DocRef {
                id: 1,
                name: "old.pdf".into(),
                host: "www.example.com".into(),
                ..Default::default()
            }],
            ct: vec![CtRef {
                source: "crtsh".into(),
                id: "100".into(),
                names: vec!["www.example.com".into()],
                issuer: "Example CA".into(),
                ..Default::default()
            }],
            risk: Some(30),
            ..Default::default()
        }
    }

    fn after() -> AlertSnapshot {
        let mut s = base();
        s.scan_id = "s2".into();
        s.hosts.insert("vpn.example.com".into());
        s.ports.push(PortRef {
            host: "vpn.example.com".into(),
            port: 3389,
            service: "rdp".into(),
        });
        s.ports.push(PortRef {
            host: "www.example.com".into(),
            port: 8080,
            service: String::new(),
        });
        s.docs.push(DocRef {
            id: 2,
            name: "passwords.xlsx".into(),
            host: "www.example.com".into(),
            secrets: 3,
            pii: 2,
            gps: true,
        });
        s.certs.push(CertRef {
            host: "www.example.com".into(),
            fingerprint: "ab12".into(),
            not_after: "2026-11-10T00:00:00Z".into(),
        });
        s.ct.push(CtRef {
            source: "crtsh".into(),
            id: "101".into(),
            names: vec!["dev.example.com".into(), "www.example.com".into()],
            issuer: "Example CA".into(),
            ..Default::default()
        });
        s.dangling.push(DanglingRef {
            host: "old.example.com".into(),
            chain: vec!["gone.provider.test".into()],
            provider: Some("Provider".into()),
            sev: "crit".into(),
        });
        s.risk = Some(75);
        s
    }

    fn rules(b: &AlertBatch) -> Vec<AlertRule> {
        let mut r: Vec<_> = b.alerts.iter().map(|a| a.rule).collect();
        r.sort();
        r.dedup();
        r
    }

    #[test]
    fn diff_triggers_every_rule() {
        let cfg = AlertSettings::default();
        let b = evaluate(Some(&base()), &after(), &cfg, &BTreeSet::new(), NOW);
        assert_eq!(rules(&b), AlertRule::ALL.to_vec());
        assert_eq!(b.alerts[0].sev, Severity::Critical);
        let rdp = b
            .alerts
            .iter()
            .find(|a| a.key == "new_port:vpn.example.com:3389");
        assert_eq!(rdp.unwrap().sev, Severity::High);
        let p8080 = b
            .alerts
            .iter()
            .find(|a| a.key == "new_port:www.example.com:8080");
        assert_eq!(p8080.unwrap().sev, Severity::Medium);
        let tls = b
            .alerts
            .iter()
            .find(|a| a.rule == AlertRule::TlsExpiry)
            .unwrap();
        assert_eq!(tls.sev, Severity::High);
        assert_eq!(tls.params["days"], 8);
        let ct = b
            .alerts
            .iter()
            .find(|a| a.rule == AlertRule::CtNewCert)
            .unwrap();
        assert_eq!(ct.params["new_names"], 1);
        assert_eq!(ct.sev, Severity::Low);
        let sec = b
            .alerts
            .iter()
            .find(|a| a.rule == AlertRule::DocSecret)
            .unwrap();
        assert_eq!(sec.params["count"], 3);
        assert_eq!(sec.title_key, "alert.doc_secret");
        assert!(!b.baseline);
    }

    #[test]
    fn dedup_across_scans() {
        let cfg = AlertSettings::default();
        let b1 = evaluate(Some(&base()), &after(), &cfg, &BTreeSet::new(), NOW);
        let mut third = after();
        third.scan_id = "s3".into();
        let b2 = evaluate(Some(&after()), &third, &cfg, &b1.state, NOW);
        assert!(b2.alerts.is_empty(), "{:?}", b2.alerts);
        assert_eq!(b2.state, b1.state);
        // escalation to a new band fires again
        let b3 = evaluate(
            Some(&third),
            &third,
            &cfg,
            &b2.state,
            datetime!(2026-11-11 00:00 UTC),
        );
        assert_eq!(rules(&b3), vec![AlertRule::TlsExpiry]);
        assert_eq!(b3.alerts[0].sev, Severity::Critical);
    }

    #[test]
    fn cleared_condition_can_fire_again_but_not_after_incomplete_scan() {
        let cfg = AlertSettings::default();
        let b1 = evaluate(Some(&base()), &after(), &cfg, &BTreeSet::new(), NOW);
        let mut gone = after();
        gone.dangling.clear();
        gone.complete = false;
        let b2 = evaluate(Some(&after()), &gone, &cfg, &b1.state, NOW);
        assert!(b2.state.contains("dangling_cname:old.example.com"));
        gone.complete = true;
        let b3 = evaluate(Some(&after()), &gone, &cfg, &b2.state, NOW);
        assert!(!b3.state.contains("dangling_cname:old.example.com"));
        let b4 = evaluate(Some(&gone), &after(), &cfg, &b3.state, NOW);
        assert_eq!(rules(&b4), vec![AlertRule::DanglingCname]);
    }

    #[test]
    fn baseline_skips_diff_rules_and_settings_filter() {
        let cfg = AlertSettings::default();
        let b = evaluate(None, &after(), &cfg, &BTreeSet::new(), NOW);
        assert!(b.baseline);
        assert!(b.alerts.iter().all(|a| !a.rule.is_diff()));
        assert!(!b.alerts.is_empty());

        let mut cfg = AlertSettings::default();
        cfg.rules.insert(AlertRule::NewHost, false);
        cfg.min_severity = Severity::High;
        cfg.tls_crit_days = 5;
        let b = evaluate(Some(&base()), &after(), &cfg, &BTreeSet::new(), NOW);
        assert!(b.alerts.iter().all(|a| a.sev.rank() >= 3));
        assert!(!b.alerts.iter().any(|a| a.rule == AlertRule::NewHost));
        assert!(!b.alerts.iter().any(|a| a.rule == AlertRule::TlsExpiry));

        let off = AlertSettings {
            enabled: false,
            ..Default::default()
        };
        assert!(
            evaluate(Some(&base()), &after(), &off, &BTreeSet::new(), NOW)
                .alerts
                .is_empty()
        );

        let cap = AlertSettings {
            max_alerts: 2,
            ..Default::default()
        };
        let b = evaluate(Some(&base()), &after(), &cap, &BTreeSet::new(), NOW);
        assert_eq!(b.alerts.len(), 2);
        assert!(b.dropped > 0);
    }

    #[test]
    fn risk_delta_without_threshold_crossing() {
        let cfg = AlertSettings {
            risk_threshold: 95,
            risk_delta: 10,
            ..Default::default()
        };
        let mut a = base();
        a.risk = Some(40);
        let mut b = base();
        b.risk = Some(55);
        let r = evaluate(Some(&a), &b, &cfg, &BTreeSet::new(), NOW);
        assert_eq!(rules(&r), vec![AlertRule::RiskRise]);
        assert_eq!(r.alerts[0].params["delta"], 15);
        b.risk = Some(45);
        assert!(evaluate(Some(&a), &b, &cfg, &BTreeSet::new(), NOW)
            .alerts
            .is_empty());
    }

    #[test]
    fn params_contain_no_values_only_counts() {
        let b = evaluate(
            Some(&base()),
            &after(),
            &AlertSettings::default(),
            &BTreeSet::new(),
            NOW,
        );
        for a in &b.alerts {
            for k in a.params.keys() {
                assert!(
                    [
                        "host",
                        "port",
                        "service",
                        "doc",
                        "count",
                        "days",
                        "date",
                        "expired",
                        "cname",
                        "provider",
                        "names",
                        "new_names",
                        "issuer",
                        "risk",
                        "prev",
                        "delta",
                        "threshold",
                        "crit",
                        "high"
                    ]
                    .contains(&k.as_str()),
                    "unexpected param {k}"
                );
            }
        }
        let json = serde_json::to_value(&b.alerts[0]).unwrap();
        assert!(json.get("severity").is_some() && json.get("title_key").is_some());
    }

    #[test]
    fn trend_series() {
        let mk = |id: &str, t: &str, sevs: &[Severity], status: &str| Scan {
            id: id.into(),
            status: status.into(),
            started_at: t.into(),
            finished_at: Some(t.into()),
            snapshot: foca_core::api::ScanSnapshot {
                findings: sevs
                    .iter()
                    .enumerate()
                    .map(|(i, s)| (i.to_string(), *s))
                    .collect(),
                ..Default::default()
            },
            ..Default::default()
        };
        let scans = vec![
            mk(
                "b",
                "2026-10-08T10:00:00Z",
                &[Severity::Critical],
                "stopped",
            ),
            mk(
                "a",
                "2026-10-01T10:00:00Z",
                &[Severity::Critical, Severity::High],
                "done",
            ),
            mk("c", "2026-10-15T10:00:00Z", &[Severity::Low], "done"),
            Scan {
                finished_at: None,
                ..mk("d", "2026-10-20T10:00:00Z", &[], "running")
            },
        ];
        let t = risk_trend(&scans, 0);
        let ids: Vec<_> = t.points.iter().map(|p| p.scan_id.as_str()).collect();
        assert_eq!(ids, ["a", "b", "c"]);
        assert_eq!(t.points[0].risk, 34);
        assert_eq!(t.points[1].risk, 25);
        assert!(!t.points[1].complete);
        assert_eq!(t.points[2].risk, 2);
        assert_eq!(t.points[0].counts.high, 1);
        assert_eq!(t.delta, Some(-32));
        assert_eq!(t.direction, "down");
        assert_eq!(t.peak, Some(34));
        assert_eq!(risk_trend(&scans, 2).points.len(), 2);
        assert_eq!(risk_trend(&[], 0).direction, "none");
    }
}
