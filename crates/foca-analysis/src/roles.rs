//! Role classification of host names: `dev-api.staging.example.com` → development/staging and
//! API. The roles drive tags in the host list and raise the priority of exposed
//! development, administration, CI and database hosts.
//!
//! Pure functions over names: labels left of the zone are split on `-`/`_`, trailing digits are
//! dropped (`dev01` → `dev`), and the tokens are looked up in a small table.

use std::collections::BTreeSet;

use foca_core::Severity;
use serde::{Deserialize, Serialize};

/// Role of a host derived from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Development, test, staging, UAT, demo and legacy environments.
    DevStage,
    /// Remote access: VPN, RDP gateways, Citrix, Outlook Web Access, bastions.
    RemoteAccess,
    /// Administration panels, device management interfaces, hypervisor consoles.
    Admin,
    /// APIs: REST, GraphQL, gRPC, WebSocket, API docs.
    Api,
    /// Source control, CI/CD, artifact registries, issue trackers.
    VcsCi,
    /// Mail: MX, SMTP/IMAP/POP, webmail, autodiscover.
    Mail,
    /// Monitoring and logging dashboards.
    Monitoring,
    /// Databases and caches.
    Database,
    /// File transfer, shares, object storage, backups.
    Storage,
    /// Single sign-on and identity providers.
    Auth,
    /// Intranet and internal business systems.
    Internal,
}

impl Role {
    /// Stable key, used as the tag id and the i18n key suffix (`role.dev_stage`).
    pub fn as_str(self) -> &'static str {
        match self {
            Role::DevStage => "dev_stage",
            Role::RemoteAccess => "remote_access",
            Role::Admin => "admin",
            Role::Api => "api",
            Role::VcsCi => "vcs_ci",
            Role::Mail => "mail",
            Role::Monitoring => "monitoring",
            Role::Database => "database",
            Role::Storage => "storage",
            Role::Auth => "auth",
            Role::Internal => "internal",
        }
    }

    /// Base priority of the role (0-100) when the host is reachable.
    pub fn weight(self) -> u8 {
        match self {
            Role::Admin | Role::Database => 40,
            Role::RemoteAccess | Role::VcsCi => 35,
            Role::DevStage | Role::Monitoring | Role::Storage | Role::Internal => 30,
            Role::Auth => 25,
            Role::Api => 20,
            Role::Mail => 10,
        }
    }
}

/// Token table: `(token, role)`. Tokens are whole labels or `-`/`_` parts without trailing digits.
const TOKENS: &[(&str, Role)] = &[
    // development / staging
    ("dev", Role::DevStage),
    ("devel", Role::DevStage),
    ("develop", Role::DevStage),
    ("development", Role::DevStage),
    ("stage", Role::DevStage),
    ("staging", Role::DevStage),
    ("stg", Role::DevStage),
    ("test", Role::DevStage),
    ("testing", Role::DevStage),
    ("tst", Role::DevStage),
    ("qa", Role::DevStage),
    ("uat", Role::DevStage),
    ("preprod", Role::DevStage),
    ("pre", Role::DevStage),
    ("sandbox", Role::DevStage),
    ("sbx", Role::DevStage),
    ("demo", Role::DevStage),
    ("beta", Role::DevStage),
    ("alpha", Role::DevStage),
    ("canary", Role::DevStage),
    ("lab", Role::DevStage),
    ("poc", Role::DevStage),
    ("pilot", Role::DevStage),
    ("tmp", Role::DevStage),
    ("temp", Role::DevStage),
    ("old", Role::DevStage),
    ("legacy", Role::DevStage),
    // remote access
    ("vpn", Role::RemoteAccess),
    ("sslvpn", Role::RemoteAccess),
    ("remote", Role::RemoteAccess),
    ("rdp", Role::RemoteAccess),
    ("rds", Role::RemoteAccess),
    ("rdweb", Role::RemoteAccess),
    ("rdg", Role::RemoteAccess),
    ("rdgw", Role::RemoteAccess),
    ("citrix", Role::RemoteAccess),
    ("netscaler", Role::RemoteAccess),
    ("owa", Role::RemoteAccess),
    ("exchange", Role::RemoteAccess),
    ("anyconnect", Role::RemoteAccess),
    ("globalprotect", Role::RemoteAccess),
    ("fortigate", Role::RemoteAccess),
    ("pulse", Role::RemoteAccess),
    ("vdi", Role::RemoteAccess),
    ("horizon", Role::RemoteAccess),
    ("bastion", Role::RemoteAccess),
    ("jump", Role::RemoteAccess),
    ("ssh", Role::RemoteAccess),
    ("gateway", Role::RemoteAccess),
    // administration
    ("admin", Role::Admin),
    ("administrator", Role::Admin),
    ("adm", Role::Admin),
    ("panel", Role::Admin),
    ("cpanel", Role::Admin),
    ("whm", Role::Admin),
    ("plesk", Role::Admin),
    ("manage", Role::Admin),
    ("manager", Role::Admin),
    ("management", Role::Admin),
    ("mgmt", Role::Admin),
    ("console", Role::Admin),
    ("dashboard", Role::Admin),
    ("backoffice", Role::Admin),
    ("cms", Role::Admin),
    ("webmin", Role::Admin),
    ("phpmyadmin", Role::Admin),
    ("pma", Role::Admin),
    ("ilo", Role::Admin),
    ("idrac", Role::Admin),
    ("ipmi", Role::Admin),
    ("bmc", Role::Admin),
    ("kvm", Role::Admin),
    ("firewall", Role::Admin),
    ("pfsense", Role::Admin),
    ("vcenter", Role::Admin),
    ("esxi", Role::Admin),
    ("proxmox", Role::Admin),
    ("unifi", Role::Admin),
    // APIs
    ("api", Role::Api),
    ("apis", Role::Api),
    ("graphql", Role::Api),
    ("gql", Role::Api),
    ("rest", Role::Api),
    ("ws", Role::Api),
    ("wss", Role::Api),
    ("soap", Role::Api),
    ("rpc", Role::Api),
    ("grpc", Role::Api),
    ("swagger", Role::Api),
    ("openapi", Role::Api),
    ("backend", Role::Api),
    // source control / CI
    ("git", Role::VcsCi),
    ("gitlab", Role::VcsCi),
    ("github", Role::VcsCi),
    ("gitea", Role::VcsCi),
    ("gogs", Role::VcsCi),
    ("bitbucket", Role::VcsCi),
    ("svn", Role::VcsCi),
    ("jenkins", Role::VcsCi),
    ("ci", Role::VcsCi),
    ("cicd", Role::VcsCi),
    ("build", Role::VcsCi),
    ("builds", Role::VcsCi),
    ("drone", Role::VcsCi),
    ("teamcity", Role::VcsCi),
    ("bamboo", Role::VcsCi),
    ("argo", Role::VcsCi),
    ("argocd", Role::VcsCi),
    ("sonar", Role::VcsCi),
    ("sonarqube", Role::VcsCi),
    ("nexus", Role::VcsCi),
    ("artifactory", Role::VcsCi),
    ("registry", Role::VcsCi),
    ("harbor", Role::VcsCi),
    ("docker", Role::VcsCi),
    ("repo", Role::VcsCi),
    ("repos", Role::VcsCi),
    ("jira", Role::VcsCi),
    ("confluence", Role::VcsCi),
    // mail
    ("mail", Role::Mail),
    ("email", Role::Mail),
    ("smtp", Role::Mail),
    ("imap", Role::Mail),
    ("pop", Role::Mail),
    ("mx", Role::Mail),
    ("webmail", Role::Mail),
    ("autodiscover", Role::Mail),
    ("autoconfig", Role::Mail),
    ("relay", Role::Mail),
    ("roundcube", Role::Mail),
    ("zimbra", Role::Mail),
    // monitoring
    ("grafana", Role::Monitoring),
    ("kibana", Role::Monitoring),
    ("prometheus", Role::Monitoring),
    ("zabbix", Role::Monitoring),
    ("nagios", Role::Monitoring),
    ("monitor", Role::Monitoring),
    ("monitoring", Role::Monitoring),
    ("metrics", Role::Monitoring),
    ("elk", Role::Monitoring),
    ("splunk", Role::Monitoring),
    ("sentry", Role::Monitoring),
    ("graylog", Role::Monitoring),
    ("logs", Role::Monitoring),
    ("alertmanager", Role::Monitoring),
    // databases
    ("db", Role::Database),
    ("database", Role::Database),
    ("mysql", Role::Database),
    ("postgres", Role::Database),
    ("pg", Role::Database),
    ("sql", Role::Database),
    ("mssql", Role::Database),
    ("mongo", Role::Database),
    ("mongodb", Role::Database),
    ("redis", Role::Database),
    ("elasticsearch", Role::Database),
    ("couchdb", Role::Database),
    ("clickhouse", Role::Database),
    ("influx", Role::Database),
    // storage
    ("ftp", Role::Storage),
    ("sftp", Role::Storage),
    ("files", Role::Storage),
    ("share", Role::Storage),
    ("storage", Role::Storage),
    ("minio", Role::Storage),
    ("backup", Role::Storage),
    ("backups", Role::Storage),
    ("bak", Role::Storage),
    ("nas", Role::Storage),
    ("nextcloud", Role::Storage),
    ("owncloud", Role::Storage),
    ("webdav", Role::Storage),
    // identity
    ("sso", Role::Auth),
    ("auth", Role::Auth),
    ("login", Role::Auth),
    ("idp", Role::Auth),
    ("adfs", Role::Auth),
    ("sts", Role::Auth),
    ("oauth", Role::Auth),
    ("saml", Role::Auth),
    ("keycloak", Role::Auth),
    ("okta", Role::Auth),
    ("cas", Role::Auth),
    ("identity", Role::Auth),
    ("accounts", Role::Auth),
    // internal systems
    ("intranet", Role::Internal),
    ("internal", Role::Internal),
    ("intra", Role::Internal),
    ("corp", Role::Internal),
    ("private", Role::Internal),
    ("lan", Role::Internal),
    ("erp", Role::Internal),
    ("crm", Role::Internal),
    ("sap", Role::Internal),
    ("1c", Role::Internal),
    ("hr", Role::Internal),
    ("wiki", Role::Internal),
    ("helpdesk", Role::Internal),
];

/// A role found in a host name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleTag {
    pub role: Role,
    /// The token that matched (`staging`).
    pub token: String,
}

/// Roles of one host with the resulting priority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRoles {
    pub host: String,
    /// One tag per role, in label order.
    pub tags: Vec<RoleTag>,
    /// 0-100: the highest role weight plus 10 for every further distinct role.
    pub priority: u8,
}

impl HostRoles {
    pub fn roles(&self) -> BTreeSet<Role> {
        self.tags.iter().map(|t| t.role).collect()
    }

    pub fn has(&self, r: Role) -> bool {
        self.tags.iter().any(|t| t.role == r)
    }

    /// Severity of the host being reachable from the internet (resolves publicly or has an open
    /// port). Unreachable hosts are `Info`.
    ///
    /// * `High`: databases; development/staging together with admin, CI or database roles.
    /// * `Medium`: admin panels, development/staging, CI/source control, monitoring, storage,
    ///   internal systems.
    /// * `Low`: remote access gateways, identity providers, APIs.
    /// * `Info`: mail and untagged hosts.
    pub fn exposure_severity(&self, reachable: bool) -> Severity {
        if !reachable || self.tags.is_empty() {
            return Severity::Info;
        }
        let dev = self.has(Role::DevStage);
        if self.has(Role::Database) || (dev && (self.has(Role::Admin) || self.has(Role::VcsCi))) {
            return Severity::High;
        }
        if dev
            || [
                Role::Admin,
                Role::VcsCi,
                Role::Monitoring,
                Role::Storage,
                Role::Internal,
            ]
            .iter()
            .any(|r| self.has(*r))
        {
            return Severity::Medium;
        }
        if [Role::RemoteAccess, Role::Auth, Role::Api]
            .iter()
            .any(|r| self.has(*r))
        {
            return Severity::Low;
        }
        Severity::Info
    }
}

fn lookup(token: &str) -> Option<Role> {
    TOKENS.iter().find(|(t, _)| *t == token).map(|(_, r)| *r)
}

/// Labels of `host` that carry meaning: those left of `zone` when the host is inside it,
/// otherwise all labels but the registrable-looking last two.
fn meaningful_labels<'a>(host: &'a str, zone: Option<&str>) -> Vec<&'a str> {
    if let Some(z) = zone {
        let z = z.trim().trim_end_matches('.');
        if let Some(rest) = host.strip_suffix(z).and_then(|r| r.strip_suffix('.')) {
            return rest.split('.').filter(|l| !l.is_empty()).collect();
        }
        if host.eq_ignore_ascii_case(z) {
            return Vec::new();
        }
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    labels[..labels.len().saturating_sub(2)].to_vec()
}

fn tokens(label: &str) -> Vec<String> {
    let mut out = vec![label.to_string()];
    for part in label.split(['-', '_']) {
        let stripped = part.trim_end_matches(|c: char| c.is_ascii_digit());
        for t in [part, stripped] {
            if !t.is_empty() && !out.iter().any(|x| x == t) {
                out.push(t.to_string());
            }
        }
    }
    out
}

/// Classifies one host name. `zone` is the scope domain (`example.com`); without it the last two
/// labels are treated as the zone.
pub fn classify_host(host: &str, zone: Option<&str>) -> HostRoles {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let zone = zone.map(str::to_ascii_lowercase);
    let mut tags: Vec<RoleTag> = Vec::new();
    for label in meaningful_labels(&h, zone.as_deref()) {
        for t in tokens(label) {
            if let Some(role) = lookup(&t) {
                if !tags.iter().any(|x| x.role == role) {
                    tags.push(RoleTag { role, token: t });
                }
            }
        }
    }
    let max = tags.iter().map(|t| t.role.weight()).max().unwrap_or(0) as u32;
    let extra = 10 * tags.len().saturating_sub(1) as u32;
    HostRoles {
        host: h,
        priority: (max + extra).min(100) as u8,
        tags,
    }
}

/// Classifies hosts and returns those with at least one role, highest priority first (ties by
/// name).
pub fn classify_hosts<'a>(
    hosts: impl IntoIterator<Item = &'a str>,
    zone: Option<&str>,
) -> Vec<HostRoles> {
    let mut v: Vec<HostRoles> = hosts
        .into_iter()
        .map(|h| classify_host(h, zone))
        .filter(|r| !r.tags.is_empty())
        .collect();
    v.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.host.cmp(&b.host)));
    v.dedup_by(|a, b| a.host == b.host);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(h: &str) -> Vec<&'static str> {
        classify_host(h, Some("example.com"))
            .tags
            .iter()
            .map(|t| t.role.as_str())
            .collect()
    }

    #[test]
    fn basic_roles() {
        assert_eq!(roles("dev-api.example.com"), vec!["dev_stage", "api"]);
        assert_eq!(roles("staging2.example.com"), vec!["dev_stage"]);
        assert_eq!(roles("vpn01.example.com"), vec!["remote_access"]);
        assert_eq!(roles("owa.example.com"), vec!["remote_access"]);
        assert_eq!(roles("admin.panel.example.com"), vec!["admin"]);
        assert_eq!(roles("graphql.example.com"), vec!["api"]);
        assert_eq!(roles("gitlab-ci.example.com"), vec!["vcs_ci"]);
        assert_eq!(roles("mail.example.com"), vec!["mail"]);
        assert_eq!(roles("www.example.com"), Vec::<&str>::new());
        assert_eq!(roles("example.com"), Vec::<&str>::new());
        // the zone itself never contributes tokens
        assert!(classify_host("api.dev.com", Some("dev.com")).tags[0].role == Role::Api);
        assert_eq!(classify_host("api.dev.com", Some("dev.com")).tags.len(), 1);
        // no false positives on substrings
        assert_eq!(roles("developer-portal.example.com"), Vec::<&str>::new());
        assert_eq!(roles("adminton.example.com"), Vec::<&str>::new());
    }

    #[test]
    fn zone_fallback_and_normalization() {
        let r = classify_host("Jenkins.Build.Corp.example.org.", None);
        assert_eq!(r.host, "jenkins.build.corp.example.org");
        let got: Vec<_> = r.tags.iter().map(|t| (t.role, t.token.as_str())).collect();
        assert_eq!(
            got,
            vec![(Role::VcsCi, "jenkins"), (Role::Internal, "corp")]
        );
        // outside the given zone: falls back to the last-two-labels rule
        assert_eq!(
            classify_host("db.other.net", Some("example.com")).tags[0].role,
            Role::Database
        );
    }

    #[test]
    fn priority_and_severity() {
        let a = classify_host("dev-admin.example.com", Some("example.com"));
        assert_eq!(a.priority, 50);
        assert_eq!(a.exposure_severity(true), Severity::High);
        assert_eq!(a.exposure_severity(false), Severity::Info);
        let s = classify_host("staging.example.com", Some("example.com"));
        assert_eq!(s.exposure_severity(true), Severity::Medium);
        let v = classify_host("vpn.example.com", Some("example.com"));
        assert_eq!(v.exposure_severity(true), Severity::Low);
        let m = classify_host("smtp.example.com", Some("example.com"));
        assert_eq!(m.exposure_severity(true), Severity::Info);
        let d = classify_host("mysql.example.com", Some("example.com"));
        assert_eq!(d.exposure_severity(true), Severity::High);
        let w = classify_host("www.example.com", Some("example.com"));
        assert_eq!((w.priority, w.exposure_severity(true)), (0, Severity::Info));
    }

    #[test]
    fn batch_order() {
        let v = classify_hosts(
            [
                "mail.example.com",
                "www.example.com",
                "dev-admin.example.com",
                "api.example.com",
                "mail.example.com",
            ],
            Some("example.com"),
        );
        let hosts: Vec<_> = v.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(
            hosts,
            vec![
                "dev-admin.example.com",
                "api.example.com",
                "mail.example.com"
            ]
        );
    }
}
