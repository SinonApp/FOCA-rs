//! Network stage step: user-installed sandboxed plugins (`plugins` source).
//!
//! Every enabled custom plugin (WASM or declarative) runs once per in-scope target domain with the
//! scan's `NetClient`. Builtin declarative manifests are skipped: they mirror core sources
//! (CertSpotter, robots/sitemap) that the scan already queries.
//!
//! Safety: plugin URLs go through [`crate::services::plugins::authorize_plugin_url`] with the full project
//! scope and `passive = level != "active"`, so passive and standard scans never let a plugin touch
//! a target host, and `net:scoped` plugins never leave the scope. The client's passive guard is the
//! second line of defence. Each plugin has a fuel budget and a wall-clock limit; a failing or
//! blocked plugin never fails the scan: the source ends as `error` with the failed plugin ids.

use std::sync::Arc;
use std::time::Duration;

use foca_net::dns::DnsLookup;

use super::{sev_of, Ctx, Stop};
use crate::analysis::facts::{self, NetFacts};
use crate::analysis::rules::{self, KnownHost};
use crate::engine::lock;
use crate::services::plugins::{
    run_plugin, PluginManifest, PluginRunResult, PluginStore, DEFAULT_FUEL_LIMIT,
};

/// Scan source id of the plugin step.
pub const SOURCE: &str = "plugins";
/// Wall-clock limit of a single plugin run (one domain).
pub const PLUGIN_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound of hosts a single plugin may add per domain.
const MAX_HOSTS_PER_RUN: usize = 200;

/// Plugins that take part in a real scan: enabled custom manifests.
pub(crate) fn scan_plugins(all: Vec<PluginManifest>) -> Vec<PluginManifest> {
    all.into_iter()
        .filter(|m| m.enabled && !m.builtin)
        .collect()
}

/// Outcome of one plugin over all domains, for the source status.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    pub found: usize,
    pub failed: Vec<String>,
    /// Plugins not run by policy: a target-touching plugin in a passive scan (ADR-0009).
    pub blocked_passive: Vec<String>,
    /// At least one plugin run completed without a policy block.
    pub ran: bool,
}

/// Prefix of the ADR-0009 policy block reason (see `plugins::authorize_plugin_url`).
const BLOCKED_PASSIVE: &str = "blocked_passive";

impl Tally {
    pub fn error_text(&self) -> Option<String> {
        let mut parts = Vec::new();
        if !self.failed.is_empty() {
            parts.push(format!("плагины с ошибкой: {}", self.failed.join("; ")));
        }
        if !self.blocked_passive.is_empty() {
            parts.push(format!(
                "не запущены в пассивном режиме (обращаются к цели): {}",
                self.blocked_passive.join(", ")
            ));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        }
    }

    /// Final source status: `error` only for real failures (timeouts, runtime errors, blocked
    /// requests outside the passive policy); `skipped` when every plugin was held back by the
    /// passive-mode policy: an intentional skip that does not make the scan incomplete.
    pub fn status(&self) -> &'static str {
        if !self.failed.is_empty() {
            "error"
        } else if !self.blocked_passive.is_empty() && !self.ran {
            "skipped"
        } else {
            "ok"
        }
    }
}

/// Merges one plugin result into the network facts. Returns the number of hosts and findings kept.
#[allow(clippy::too_many_arguments)]
pub(crate) fn merge_result(
    f: &mut NetFacts,
    r: &PluginRunResult,
    domain: &str,
    passive: bool,
    touches: bool,
    allowed: &dyn Fn(&str) -> bool,
    resolved: &std::collections::BTreeMap<String, Vec<String>>,
    now: &str,
    sid: &str,
) -> usize {
    let src = format!("plugin:{}", r.id);
    let mut n = 0;
    for h in r.hosts.iter().take(MAX_HOSTS_PER_RUN) {
        let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty() || !allowed(&h) {
            continue;
        }
        let Some(ips) = resolved.get(&h) else {
            continue;
        };
        let x = f.host(&h);
        if x.source.is_empty() {
            x.source = src.clone();
        }
        if x.first_scan.is_none() {
            x.first_scan = Some(sid.to_string());
        }
        if let Some(ip) = ips.first() {
            if x.ip.is_empty() || x.ip == "-" {
                x.ip = ip.clone();
            }
        }
        n += 1;
    }
    for p in &r.findings {
        let rule = format!("plugin-{}", r.id);
        let key = format!("{domain}|{}|{}", p.title, p.detail);
        let nf = facts::net_finding(
            &rule,
            &key,
            p.title.clone(),
            sev_of(&p.severity),
            domain,
            "plugin",
            &src,
            "plugin",
            !passive && touches,
            now,
            Some(sid),
            p.detail.clone(),
            "",
            p.detail.clone(),
            r.http_url.clone(),
        );
        f.findings.entry(nf.id).or_insert(nf);
        n += 1;
    }
    n
}

/// Runs the plugin step of the network stage.
pub(super) async fn run(
    c: &mut Ctx,
    dns: &Arc<dyn DnsLookup>,
    f: &mut NetFacts,
    hosts_known: &[KnownHost],
    now: &str,
    sid: &str,
) -> Result<(), Stop> {
    if !c.module("crt") && !c.module("dns") {
        return Ok(());
    }
    if !lock(&c.st).source_ids.iter().any(|x| x == SOURCE) {
        return Ok(());
    }
    let plugins = scan_plugins(PluginStore::new(&c.e.cfg.data_dir).load_all());
    if plugins.is_empty() {
        c.source_event_full(SOURCE, "off", Some(0), None);
        return Ok(());
    }
    c.source_event_full(SOURCE, "running", None, None);
    let scope = foca_core::Scope::from(&c.scope);
    let passive = c.level != "active";
    let net = c.group_net("recon")?;
    let scope_dto = c.scope.clone();
    let known: Vec<KnownHost> = hosts_known.to_vec();
    let allowed = move |h: &str| {
        let r = rules::check(&scope_dto, h, &known);
        r.ok && r.code != "excluded"
    };
    let domains = c.domains.clone();
    let mut tally = Tally::default();
    for m in &plugins {
        let touches = m.declarative.as_ref().is_some_and(|d| d.touches_target)
            || m.permissions.iter().any(|p| p == "net:scoped");
        let mut errors = Vec::new();
        let mut held = false;
        for d in &domains {
            c.gate().await?;
            let fut = run_plugin(m, d, passive, &scope, Some(&net), None, DEFAULT_FUEL_LIMIT);
            let r = match tokio::time::timeout(PLUGIN_TIMEOUT, fut).await {
                Err(_) => {
                    errors.push(format!("таймаут {}", PLUGIN_TIMEOUT.as_secs()));
                    continue;
                }
                Ok(Err(e)) => {
                    if c.cancel.is_cancelled() {
                        return Err(Stop::Cancelled);
                    }
                    errors.push(e.message.clone());
                    continue;
                }
                Ok(Ok(r)) => r,
            };
            match &r.blocked_reason {
                Some(why) if why.starts_with(BLOCKED_PASSIVE) => held = true,
                Some(why) => errors.push(why.clone()),
                None => tally.ran = true,
            }
            let names: Vec<String> = r
                .hosts
                .iter()
                .take(MAX_HOSTS_PER_RUN)
                .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|h| !h.is_empty() && allowed(h))
                .collect();
            let resolved: std::collections::BTreeMap<String, Vec<String>> =
                foca_net::dns::resolve_alive(dns.clone(), &names, 4)
                    .await
                    .into_iter()
                    .collect();
            tally.found += merge_result(f, &r, d, passive, touches, &allowed, &resolved, now, sid);
        }
        if !errors.is_empty() {
            errors.dedup();
            tally
                .failed
                .push(format!("{}: {}", m.id, errors.join(", ")));
        }
        if held && !tally.blocked_passive.contains(&m.id) {
            tally.blocked_passive.push(m.id.clone());
        }
    }
    let status = tally.status();
    c.source_event_full(
        SOURCE,
        status,
        Some(tally.found),
        tally.error_text().as_deref(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::plugins::{builtin_manifests, PluginFinding};
    use std::collections::BTreeMap;

    fn result(id: &str) -> PluginRunResult {
        PluginRunResult {
            ok: true,
            id: id.into(),
            runtime: "wasm".into(),
            fuel_used: 10,
            hosts: vec![
                "dev.example.com".into(),
                "evil.org".into(),
                "gone.example.com".into(),
            ],
            urls: vec![],
            findings: vec![PluginFinding {
                title: "Test".into(),
                severity: "high".into(),
                detail: "x".into(),
            }],
            blocked_reason: None,
            http_url: Some("https://api.example.net/x".into()),
        }
    }

    #[test]
    fn only_enabled_custom_plugins_run_in_scans() {
        let mut all = builtin_manifests();
        assert!(scan_plugins(all.clone()).is_empty());
        let mut custom = all[0].clone();
        custom.id = "my-wasm".into();
        custom.builtin = false;
        custom.enabled = true;
        let mut off = custom.clone();
        off.id = "my-off".into();
        off.enabled = false;
        all.push(custom);
        all.push(off);
        let ids: Vec<String> = scan_plugins(all).into_iter().map(|m| m.id).collect();
        assert_eq!(ids, vec!["my-wasm".to_string()]);
    }

    #[test]
    fn merge_keeps_only_resolved_in_scope_hosts_and_labels_source() {
        let mut f = NetFacts::default();
        let resolved: BTreeMap<String, Vec<String>> = [
            ("dev.example.com".to_string(), vec!["192.0.2.7".to_string()]),
            ("evil.org".to_string(), vec!["192.0.2.8".to_string()]),
        ]
        .into_iter()
        .collect();
        let allowed = |h: &str| h.ends_with("example.com");
        let n = merge_result(
            &mut f,
            &result("p1"),
            "example.com",
            true,
            true,
            &allowed,
            &resolved,
            "2026-01-01T00:00:00",
            "s1",
        );
        assert_eq!(n, 2);
        assert_eq!(f.hosts.len(), 1);
        let h = &f.hosts["dev.example.com"];
        assert_eq!(h.source, "plugin:p1");
        assert_eq!(h.ip, "192.0.2.7");
        let fd = f.findings.values().next().unwrap();
        assert_eq!(fd.source, "plugin:p1");
        assert_eq!(fd.sev, foca_core::Severity::High);
        assert!(!fd.active, "passive run never marks plugin findings active");
        assert_eq!(fd.provenance.rule, "plugin-p1");
    }

    #[test]
    fn failed_plugins_are_listed_in_the_source_error() {
        let mut t = Tally::default();
        assert_eq!(t.error_text(), None);
        t.failed.push("a: таймаут 30".into());
        assert!(t.error_text().unwrap().contains("a: таймаут 30"));
    }
}
