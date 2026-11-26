//! Finding rules of the infrastructure modules: TLS/X.509 audit, subdomain enumeration
//! (wildcards, NSEC walking, PTR), SaaS / Microsoft 365, CDN origin, CT history and host roles.
//!
//! The network crates report machine-readable issue codes; this module turns a code into a
//! [`Finding`] with a stable id (`rule` + object key), a Russian title/description/recommendation
//! (the core language; `foca-report` translates them by rule `infra.<code>`) and a category.
//! Severity comes from the caller (the network crate decides it), except for the role boost.

use foca_core::api::{self, FindingProvenance, FindingRel};
use foca_core::{FindingStatus, Severity};

use crate::roles::{HostRoles, Role};

/// One rule: code, category, title template (`{}` = object), recommendation.
pub struct InfraRule {
    pub code: &'static str,
    pub category: &'static str,
    pub title: &'static str,
    pub recommendation: &'static str,
}

const REC_REISSUE: &str = "Заменить сертификатом доверенного УЦ (публичного или корпоративного с распространённым корнем).";
const REC_RENEW: &str =
    "Продлить сертификат до истечения срока и настроить автоматическое продление (ACME).";

#[rustfmt::skip]
pub const RULES: &[InfraRule] = &[
    InfraRule { code: "cert_expired", category: "tls", title: "Просроченный TLS-сертификат на {}", recommendation: REC_RENEW },
    InfraRule { code: "cert_expires_soon", category: "tls", title: "TLS-сертификат на {} скоро истекает", recommendation: REC_RENEW },
    InfraRule { code: "cert_not_yet_valid", category: "tls", title: "TLS-сертификат на {} ещё не действителен", recommendation: "Проверить системное время сервера и дату начала действия сертификата." },
    InfraRule { code: "cert_self_signed", category: "tls", title: "Самоподписанный TLS-сертификат на {}", recommendation: REC_REISSUE },
    InfraRule { code: "cert_unknown_ca", category: "tls", title: "TLS-сертификат на {} выдан неизвестным УЦ", recommendation: REC_REISSUE },
    InfraRule { code: "cert_invalid_chain", category: "tls", title: "Некорректная цепочка TLS-сертификата на {}", recommendation: "Исправить цепочку: отдавать лист и промежуточные сертификаты выдавшего УЦ в правильном порядке." },
    InfraRule { code: "cert_incomplete_chain", category: "tls", title: "Неполная цепочка TLS-сертификата на {}", recommendation: "Добавить промежуточные сертификаты в конфигурацию сервера." },
    InfraRule { code: "cert_hostname_mismatch", category: "tls", title: "Имя хоста не совпадает с TLS-сертификатом на {}", recommendation: "Выпустить сертификат с нужным именем в SAN или исправить привязку виртуального хоста." },
    InfraRule { code: "cert_weak_signature", category: "tls", title: "Слабая подпись TLS-сертификата на {}", recommendation: "Перевыпустить сертификат с подписью SHA-256 или новее." },
    InfraRule { code: "cert_weak_key", category: "tls", title: "Слабый ключ TLS-сертификата на {}", recommendation: "Перевыпустить сертификат с ключом RSA не короче 2048 бит или ECDSA P-256." },
    InfraRule { code: "cert_caa_mismatch", category: "tls", title: "TLS-сертификат на {} выдан УЦ вне политики CAA", recommendation: "Проверить, кто выпустил сертификат; обновить CAA или отозвать сертификат." },
    InfraRule { code: "cert_internal_pki", category: "tls", title: "TLS-сертификат на {} раскрывает внутреннюю PKI", recommendation: "Не публиковать внутренние адреса CRL/AIA и LDAP-пути AD во внешних сертификатах." },
    InfraRule { code: "tls_no_ocsp_stapling", category: "tls", title: "Нет OCSP stapling на {}", recommendation: "Включить OCSP stapling на сервере." },
    InfraRule { code: "tls_no_alpn", category: "tls", title: "Нет ALPN на {}", recommendation: "Включить ALPN (HTTP/2) в конфигурации TLS." },
    InfraRule { code: "tls_legacy_version", category: "tls", title: "Устаревшие версии TLS на {}", recommendation: "Отключить SSLv3, TLS 1.0 и TLS 1.1; оставить TLS 1.2 и 1.3." },
    InfraRule { code: "tls_weak_cipher", category: "tls", title: "Слабые шифры TLS на {}", recommendation: "Отключить наборы NULL/anon/EXPORT/RC4/DES/3DES; оставить AEAD-наборы." },
    InfraRule { code: "tls_origin_confirmed", category: "tls", title: "Подтверждён исходный IP за CDN: {}", recommendation: "Разрешить входящие соединения на исходный сервер только с адресов CDN." },
    InfraRule { code: "tls_default_cert", category: "tls", title: "Сертификат по умолчанию без SNI на {}", recommendation: "Проверить, что сертификат по умолчанию не раскрывает внутренние имена." },
    InfraRule { code: "dns_wildcard", category: "dns", title: "Wildcard DNS в зоне {}", recommendation: "Убедиться, что wildcard-запись нужна: она маскирует несуществующие имена и усложняет учёт хостов." },
    InfraRule { code: "dns_resolver_hijack", category: "dns", title: "Резолвер подменяет несуществующие имена ({})", recommendation: "Использовать доверенный резолвер (DoH): без подтверждения результаты перебора недостоверны." },
    InfraRule { code: "nsec_walkable", category: "dns", title: "Зона {} перечисляется через NSEC", recommendation: "Перейти на NSEC3 или онлайн-подпись с минимальными NSEC-ответами." },
    InfraRule { code: "ptr_shared_hosting", category: "dns", title: "Общий хостинг на {}", recommendation: "Не проводить активные проверки по IP-адресу: они затронут сайты других владельцев." },
    InfraRule { code: "ptr_fcrdns_mismatch", category: "dns", title: "PTR и прямая запись не совпадают на {}", recommendation: "Согласовать PTR и A-записи (FCrDNS)." },
    InfraRule { code: "saas_inventory", category: "cloud", title: "Сервисы организации по DNS ({})", recommendation: "Проверить, что верификационные TXT-записи нужны; удалить записи неиспользуемых сервисов." },
    InfraRule { code: "m365_tenant", category: "cloud", title: "Найден арендатор Microsoft 365 / Entra ID ({})", recommendation: "Учесть арендатора в модели угроз: MFA, условный доступ, мониторинг входов." },
    InfraRule { code: "m365_federated_adfs", category: "cloud", title: "Вход в Microsoft 365 через AD FS ({})", recommendation: "AD FS, цель подбора паролей: включить блокировку extranet lockout и MFA, следить за входами." },
    InfraRule { code: "origin_exposed", category: "cloud", title: "Возможный исходный IP за CDN: {}", recommendation: "Разрешить доступ к исходному серверу только с адресов CDN; сменить IP, если он раскрыт." },
    InfraRule { code: "ct_abandoned_subdomain", category: "dns", title: "Заброшенный поддомен по CT: {}", recommendation: "Удалить DNS-записи неиспользуемого поддомена и проверить возможность захвата (takeover)." },
    InfraRule { code: "host_role_exposed", category: "hosts", title: "Доступен служебный хост: {}", recommendation: "Ограничить доступ к служебному хосту (VPN, фильтр по IP, аутентификация) или убрать его из публичного DNS." },
];

/// Rule of a code, if known.
pub fn rule(code: &str) -> Option<&'static InfraRule> {
    RULES.iter().find(|r| r.code == code)
}

/// Finding rule id (`provenance.rule`) of an infrastructure code.
pub fn rule_id(code: &str) -> String {
    format!("infra.{code}")
}

/// Input of [`finding`].
pub struct InfraFinding<'a> {
    pub code: &'a str,
    pub sev: Severity,
    /// Host the finding belongs to (hosts screen, filters).
    pub host: &'a str,
    /// Object in the title and the id key (`host:port`, zone, IP).
    pub object: &'a str,
    /// Technical detail (as reported by the network crate).
    pub detail: &'a str,
    pub evidence: String,
    /// Module of the request log (`tls`, `tls-legacy`, `bruteforce`, `m365`, ...).
    pub module: &'a str,
    pub active: bool,
    pub time: &'a str,
    pub scan: Option<&'a str>,
    pub url: Option<String>,
    pub tags: Vec<String>,
}

/// Builds the finding; an unknown code gets a generic title so no issue is lost.
pub fn finding(x: InfraFinding<'_>) -> api::Finding {
    let r = rule(x.code);
    let rid = rule_id(x.code);
    let title = match r {
        Some(r) => r.title.replacen("{}", x.object, 1),
        None => format!("{} ({})", x.code, x.object),
    };
    api::Finding {
        id: crate::findings::finding_id(&rid, x.object),
        title,
        sev: x.sev,
        status: FindingStatus::New,
        host: x.host.to_string(),
        category: r.map(|r| r.category).unwrap_or("infra").into(),
        source: source_label(x.module).into(),
        module: x.module.into(),
        active: x.active,
        time: x.time.to_string(),
        first_scan: x.scan.map(str::to_string),
        fixed_scan: None,
        tags: x.tags,
        cve: vec![],
        cvss: None,
        mitre: String::new(),
        description: format!("Обнаружено при проверке {}: {}", x.object, x.detail),
        recommendation: r.map(|r| r.recommendation).unwrap_or("").into(),
        evidence: x.evidence,
        request: String::new(),
        url: x.url,
        doc: None,
        notes: vec![],
        photos: vec![],
        rel: FindingRel::default(),
        provenance: FindingProvenance {
            rule: rid,
            fields: vec![],
            docs: vec![],
        },
    }
}

fn source_label(module: &str) -> &'static str {
    match module {
        "tls" => "TLS/X.509",
        "tls-legacy" => "TLS (legacy)",
        "starttls" => "STARTTLS",
        "tls-no-sni" => "TLS (без SNI)",
        "bruteforce" | "permute" => "DNS (перебор)",
        "nsec" => "DNS (NSEC)",
        "ptr" => "DNS (PTR)",
        "saas" => "DNS (SaaS)",
        "m365" => "Microsoft 365",
        "cdn" => "CDN / origin",
        "crt" => "CT (crt.sh)",
        "roles" => "Роли хостов",
        _ => "Инфраструктура",
    }
}

/// CDN providers whose edge terminates TLS for the customer's names: TLS versions, ciphers,
/// ALPN and OCSP stapling there are settings of the provider's dashboard, not of the server.
const CDN_EDGES: &[&str] = &[
    "cloudflare",
    "fastly",
    "akamai",
    "imperva",
    "incapsula",
    "sucuri",
    "ddos-guard",
    "stackpath",
    "edgio",
    "bunny",
    "gcore",
    "cloudfront",
];

/// Finding tag of a probe answered by a CDN edge (`cdn_edge:<provider>`).
pub const CDN_EDGE_TAG: &str = "cdn_edge:";

/// Recommendations for TLS findings on a CDN edge (by rule code).
const REC_CDN_TLS: &str = "Это настройка CDN-узла: повысьте минимальную версию TLS (Minimum TLS Version) в панели CDN (например, Cloudflare → SSL/TLS → Edge Certificates).";
const REC_CDN_CIPHER: &str = "Это настройка CDN-узла: отключите слабые наборы шифров в панели CDN (например, Cloudflare → SSL/TLS → Edge Certificates → Cipher suites).";

/// CDN provider of the edge that answered a finding's probe: the probe's `cdn_edge:` tag, else
/// the CDN detected for the host (cloud or technologies).
pub fn cdn_edge_of(f: &api::Finding, hosts: &[api::Host]) -> Option<String> {
    if let Some(p) = f.tags.iter().find_map(|t| t.strip_prefix(CDN_EDGE_TAG)) {
        return Some(p.to_string());
    }
    let name = f.host.rsplit_once(':').map_or(f.host.as_str(), |(h, p)| {
        if p.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            f.host.as_str()
        }
    });
    let h = hosts.iter().find(|h| h.name.eq_ignore_ascii_case(name))?;
    let seen = format!("{} {}", h.cloud, h.tech).to_ascii_lowercase();
    CDN_EDGES
        .iter()
        .find(|p| seen.contains(*p))
        .map(|p| p.to_string())
}

/// TLS findings on CDN edges: ALPN and OCSP stapling are managed by the provider, so those
/// findings are dropped; legacy versions and weak ciphers get the dashboard recommendation and
/// the `cdn_edge:` tag. Returns the ids of dropped findings stored by earlier scans.
pub fn adjust_cdn_edges(
    fs: &mut Vec<api::Finding>,
    hosts: &[api::Host],
    prev: &std::collections::BTreeMap<u64, crate::PrevFinding>,
) -> Vec<u64> {
    let mut dropped = Vec::new();
    fs.retain_mut(|f| {
        let code = f.provenance.rule.strip_prefix("infra.").unwrap_or("");
        if !matches!(
            code,
            "tls_no_alpn" | "tls_no_ocsp_stapling" | "tls_legacy_version" | "tls_weak_cipher"
        ) {
            return true;
        }
        let Some(provider) = cdn_edge_of(f, hosts) else {
            return true;
        };
        match code {
            "tls_no_alpn" | "tls_no_ocsp_stapling" => {
                if prev.contains_key(&f.id) {
                    dropped.push(f.id);
                }
                false
            }
            _ => {
                f.recommendation = if code == "tls_weak_cipher" {
                    REC_CDN_CIPHER
                } else {
                    REC_CDN_TLS
                }
                .into();
                let tag = format!("{CDN_EDGE_TAG}{provider}");
                if !f.tags.contains(&tag) {
                    f.tags.push(tag);
                }
                true
            }
        }
    });
    dropped
}

/// Raises severity one step for hosts whose role makes exposure riskier (open dev/staging,
/// admin panels, CI): the plan's "role raises the risk priority" rule.
pub fn role_boost(sev: Severity, roles: Option<&HostRoles>) -> Severity {
    let Some(r) = roles else { return sev };
    if !(r.has(Role::DevStage) || r.has(Role::Admin) || r.has(Role::VcsCi)) {
        return sev;
    }
    match sev {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        s => s,
    }
}

/// Tags `role:<id>` of a host (finding tags and host tags).
pub fn role_tags(roles: Option<&HostRoles>) -> Vec<String> {
    roles
        .map(|r| {
            r.roles()
                .into_iter()
                .map(|x| format!("role:{}", x.as_str()))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roles::classify_host;

    fn tls(code: &str, host: &str, port: u16) -> api::Finding {
        finding(InfraFinding {
            code,
            sev: Severity::Low,
            host,
            object: &format!("{host}:{port}"),
            detail: "x",
            evidence: String::new(),
            module: "tls",
            active: true,
            time: "2026-11-20T10:00:00",
            scan: Some("s1"),
            url: None,
            tags: vec![],
        })
    }

    #[test]
    fn cdn_edge_tls_findings_get_dashboard_advice_and_no_alpn_ocsp() {
        let hosts = vec![
            api::Host {
                name: "edge.example".into(),
                cloud: "Cloudflare".into(),
                ..Default::default()
            },
            api::Host {
                name: "origin.example".into(),
                cloud: "-".into(),
                ..Default::default()
            },
        ];
        let alpn = tls("tls_no_alpn", "edge.example", 443);
        let prev = std::collections::BTreeMap::from([(alpn.id, crate::PrevFinding::default())]);
        let mut fs = vec![
            tls("tls_legacy_version", "edge.example", 8443),
            alpn.clone(),
            tls("tls_no_ocsp_stapling", "edge.example", 2083),
            tls("tls_legacy_version", "origin.example", 443),
            tls("tls_no_alpn", "origin.example", 443),
        ];
        let dropped = adjust_cdn_edges(&mut fs, &hosts, &prev);
        assert_eq!(dropped, vec![alpn.id], "stored ALPN finding is removed");
        let rules: Vec<(&str, &str)> = fs
            .iter()
            .map(|f| (f.host.as_str(), f.provenance.rule.as_str()))
            .collect();
        assert_eq!(
            rules,
            [
                ("edge.example", "infra.tls_legacy_version"),
                ("origin.example", "infra.tls_legacy_version"),
                ("origin.example", "infra.tls_no_alpn"),
            ]
        );
        assert_eq!(fs[0].recommendation, REC_CDN_TLS);
        assert!(fs[0].tags.contains(&"cdn_edge:cloudflare".to_string()));
        assert_ne!(
            fs[1].recommendation, REC_CDN_TLS,
            "origin keeps server advice"
        );
        // The probe's own tag wins even without host data.
        let mut tagged = tls("tls_weak_cipher", "other.example", 443);
        tagged.tags.push("cdn_edge:fastly".into());
        let mut fs = vec![tagged];
        adjust_cdn_edges(&mut fs, &[], &Default::default());
        assert_eq!(fs[0].recommendation, REC_CDN_CIPHER);
    }

    #[test]
    fn finding_has_stable_id_title_and_rule() {
        let mk = |sev| {
            finding(InfraFinding {
                code: "cert_expired",
                sev,
                host: "a.test",
                object: "a.test:443",
                detail: "expired 3 days ago",
                evidence: "CN=a.test".into(),
                module: "tls",
                active: false,
                time: "2026-11-20T10:00:00",
                scan: Some("s1"),
                url: None,
                tags: vec![],
            })
        };
        let a = mk(Severity::High);
        let b = mk(Severity::Low);
        assert_eq!(a.id, b.id, "id ignores severity");
        assert_eq!(a.title, "Просроченный TLS-сертификат на a.test:443");
        assert_eq!(a.provenance.rule, "infra.cert_expired");
        assert_eq!(a.category, "tls");
        assert!(a.recommendation.contains("ACME"));
    }

    #[test]
    fn every_rule_has_one_placeholder_and_unique_code() {
        for r in RULES {
            assert_eq!(r.title.matches("{}").count(), 1, "{}", r.code);
            assert_eq!(RULES.iter().filter(|x| x.code == r.code).count(), 1);
            assert!(!r.recommendation.is_empty());
        }
    }

    #[test]
    fn roles_boost_dev_and_admin_only() {
        let dev = classify_host("dev.example.test", Some("example.test"));
        let www = classify_host("www.example.test", Some("example.test"));
        assert_eq!(role_boost(Severity::Low, Some(&dev)), Severity::Medium);
        assert_eq!(role_boost(Severity::Low, Some(&www)), Severity::Low);
        assert_eq!(role_boost(Severity::High, Some(&dev)), Severity::High);
        assert!(role_tags(Some(&dev)).contains(&"role:dev_stage".to_string()));
    }
}
