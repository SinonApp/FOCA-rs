//! Parsing of project target strings.
//!
//! One input line yields one [`Target`]. Supported forms: domain, wildcard `*.x`, URL,
//! IPv4/IPv6, CIDR, IP range `a-b` (including the short form `10.0.0.1-50`), ASN (`AS15169`),
//! e-mail, and organization or free text (the `org:` prefix forces an organization).
//!
//! Domains are normalized: lowercased, without a trailing dot, IDN converted to punycode
//! (`xn--...`); the original Unicode spelling is kept in `unicode` when it differs.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Target parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    #[error("пустая строка")]
    Empty,
    #[error("некорректный домен: {0}")]
    InvalidDomain(String),
    #[error("некорректный IP-адрес: {0}")]
    InvalidIp(String),
    #[error("некорректная сеть CIDR: {0}")]
    InvalidCidr(String),
    #[error("некорректный диапазон IP: {0}")]
    InvalidRange(String),
    #[error("некорректный URL: {0}")]
    InvalidUrl(String),
    #[error("некорректный e-mail: {0}")]
    InvalidEmail(String),
    #[error("некорректный номер ASN: {0}")]
    InvalidAsn(String),
}

/// A project target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    /// A domain; its subdomains are in scope.
    Domain {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unicode: Option<String>,
    },
    /// `*.base`: subdomains of `base` only, not `base` itself.
    Wildcard {
        base: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unicode: Option<String>,
    },
    /// A URL; only its exact host is in scope.
    Url {
        url: String,
        host: String,
    },
    Ip {
        addr: IpAddr,
    },
    Cidr {
        net: IpNet,
    },
    /// Inclusive range, `start <= end`, within one address family.
    IpRange {
        start: IpAddr,
        end: IpAddr,
    },
    Asn {
        number: u32,
    },
    Email {
        address: String,
        domain: String,
    },
    /// Organization or free text (used for search; never puts hosts in scope).
    Org {
        name: String,
    },
}

impl Target {
    /// Parses a target string. See the module documentation for the accepted forms.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError`] if the string is empty or a recognized form is malformed.
    pub fn parse(input: &str) -> Result<Target, TargetError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(TargetError::Empty);
        }
        if let Some(rest) = strip_prefix_ci(s, "org:") {
            let name = rest.trim();
            if name.is_empty() {
                return Err(TargetError::Empty);
            }
            return Ok(Target::Org {
                name: name.to_string(),
            });
        }
        if let Some(num) = strip_prefix_ci(s, "as") {
            if !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) {
                return num
                    .parse::<u32>()
                    .map(|number| Target::Asn { number })
                    .map_err(|_| TargetError::InvalidAsn(s.to_string()));
            }
        }
        // URL with a scheme
        if s.contains("://") {
            return parse_url(s);
        }
        let has_ws = s.chars().any(char::is_whitespace);
        if !has_ws && s.contains('@') {
            return parse_email(s);
        }
        // IP literal, including [v6]
        if let Some(ip) = parse_ip_literal(s) {
            return Ok(Target::Ip {
                addr: normalize_ip(ip),
            });
        }
        // CIDR, or a URL without a scheme
        if !has_ws && s.contains('/') {
            let (head, _) = s.split_once('/').unwrap_or((s, ""));
            if parse_ip_literal(head).is_some() {
                return parse_cidr(s);
            }
            return parse_url(&format!("https://{s}"));
        }
        // range a-b
        if let Some(t) = try_parse_range(s)? {
            return Ok(t);
        }
        if let Some(base) = s.strip_prefix("*.") {
            let (name, unicode) = normalize_domain(base)?;
            return Ok(Target::Wildcard {
                base: name,
                unicode,
            });
        }
        if s.contains('*') {
            return Err(TargetError::InvalidDomain(s.to_string()));
        }
        if has_ws {
            return Ok(Target::Org {
                name: s.to_string(),
            });
        }
        if s.contains('.') {
            if looks_numeric_dotted(s) {
                return Err(TargetError::InvalidIp(s.to_string()));
            }
            let (name, unicode) = normalize_domain(s)?;
            return Ok(Target::Domain { name, unicode });
        }
        if s.chars().all(|c| c.is_ascii_digit()) {
            return Err(TargetError::InvalidIp(s.to_string()));
        }
        Ok(Target::Org {
            name: s.to_string(),
        })
    }

    /// Returns the short type name (same as the `kind` tag in JSON).
    pub fn kind(&self) -> &'static str {
        match self {
            Target::Domain { .. } => "domain",
            Target::Wildcard { .. } => "wildcard",
            Target::Url { .. } => "url",
            Target::Ip { .. } => "ip",
            Target::Cidr { .. } => "cidr",
            Target::IpRange { .. } => "ip_range",
            Target::Asn { .. } => "asn",
            Target::Email { .. } => "email",
            Target::Org { .. } => "org",
        }
    }

    /// Returns `true` if the target contains the IP (IP, CIDR, range, or URL with an IP host).
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        match self {
            Target::Ip { addr } => *addr == ip,
            Target::Cidr { net } => net.contains(&ip),
            Target::IpRange { start, end } => ip_in_range(ip, *start, *end),
            Target::Url { host, .. } => parse_ip_literal(host).map(normalize_ip) == Some(ip),
            _ => false,
        }
    }

    /// Returns `true` if the target covers the host (already normalized with [`normalize_domain`]).
    ///
    /// `Domain(d)` covers `d` and all of its subdomains, `Wildcard(*.d)` covers subdomains only,
    /// `Url` covers only its exact host; `Email`, `Org`, `Asn` and IP targets cover no host names.
    pub fn covers_host(&self, host: &str) -> bool {
        match self {
            Target::Domain { name, .. } => host == name || is_subdomain_of(host, name),
            Target::Wildcard { base, .. } => is_subdomain_of(host, base),
            Target::Url { host: h, .. } => h == host,
            _ => false,
        }
    }
}

impl FromStr for Target {
    type Err = TargetError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Target::parse(s)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Domain { name, .. } => write!(f, "{name}"),
            Target::Wildcard { base, .. } => write!(f, "*.{base}"),
            Target::Url { url, .. } => write!(f, "{url}"),
            Target::Ip { addr } => write!(f, "{addr}"),
            Target::Cidr { net } => write!(f, "{net}"),
            Target::IpRange { start, end } => write!(f, "{start}-{end}"),
            Target::Asn { number } => write!(f, "AS{number}"),
            Target::Email { address, .. } => write!(f, "{address}"),
            Target::Org { name } => write!(f, "org:{name}"),
        }
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len()
        && s.is_char_boundary(prefix.len())
        && s[..prefix.len()].eq_ignore_ascii_case(prefix)
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn looks_numeric_dotted(s: &str) -> bool {
    s.split('.')
        .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
}

/// Returns `true` if `host` is a strict subdomain of `parent` (dot-delimited: `evilcontoso.ua` is not under `contoso.ua`).
pub fn is_subdomain_of(host: &str, parent: &str) -> bool {
    host.len() > parent.len() + 1
        && host.ends_with(parent)
        && host.as_bytes()[host.len() - parent.len() - 1] == b'.'
}

/// Maps IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4 and leaves other addresses unchanged.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Parses an IP literal; brackets (`[::1]`) are allowed.
pub fn parse_ip_literal(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(s);
    inner.parse::<IpAddr>().ok()
}

fn ip_in_range(ip: IpAddr, start: IpAddr, end: IpAddr) -> bool {
    match (ip, start, end) {
        (IpAddr::V4(i), IpAddr::V4(a), IpAddr::V4(b)) => {
            u32::from(a) <= u32::from(i) && u32::from(i) <= u32::from(b)
        }
        (IpAddr::V6(i), IpAddr::V6(a), IpAddr::V6(b)) => {
            u128::from(a) <= u128::from(i) && u128::from(i) <= u128::from(b)
        }
        _ => false,
    }
}

fn try_parse_range(s: &str) -> Result<Option<Target>, TargetError> {
    let Some((a, b)) = s.split_once('-') else {
        return Ok(None);
    };
    let (a, b) = (a.trim(), b.trim());
    let Some(start) = parse_ip_literal(a).map(normalize_ip) else {
        return Ok(None); // left side is not an IP, so this is probably a hyphenated domain
    };
    let end = if let Some(ip) = parse_ip_literal(b) {
        normalize_ip(ip)
    } else if let (IpAddr::V4(v4), Ok(last)) = (start, b.parse::<u8>()) {
        let o = v4.octets();
        IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], last))
    } else {
        return Err(TargetError::InvalidRange(s.to_string()));
    };
    let ok = match (start, end) {
        (IpAddr::V4(x), IpAddr::V4(y)) => u32::from(x) <= u32::from(y),
        (IpAddr::V6(x), IpAddr::V6(y)) => u128::from(x) <= u128::from(y),
        _ => false,
    };
    if !ok {
        return Err(TargetError::InvalidRange(s.to_string()));
    }
    Ok(Some(Target::IpRange { start, end }))
}

fn parse_cidr(s: &str) -> Result<Target, TargetError> {
    let cleaned: String = s.chars().filter(|c| *c != '[' && *c != ']').collect();
    let net: IpNet = cleaned
        .parse()
        .map_err(|_| TargetError::InvalidCidr(s.to_string()))?;
    let net = match net {
        IpNet::V6(v6) => match v6.addr().to_ipv4_mapped() {
            Some(v4) if v6.prefix_len() >= 96 => ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96)
                .map(IpNet::V4)
                .map_err(|_| TargetError::InvalidCidr(s.to_string()))?,
            _ => IpNet::V6(v6),
        },
        n => n,
    };
    Ok(Target::Cidr { net: net.trunc() })
}

fn parse_url(s: &str) -> Result<Target, TargetError> {
    let u = url::Url::parse(s).map_err(|e| TargetError::InvalidUrl(format!("{s}: {e}")))?;
    let host = match u.host() {
        Some(url::Host::Domain(d)) => {
            normalize_domain(d)
                .map_err(|_| TargetError::InvalidUrl(s.to_string()))?
                .0
        }
        Some(url::Host::Ipv4(v4)) => v4.to_string(),
        Some(url::Host::Ipv6(v6)) => normalize_ip(IpAddr::V6(v6)).to_string(),
        None => return Err(TargetError::InvalidUrl(s.to_string())),
    };
    Ok(Target::Url {
        url: u.to_string(),
        host,
    })
}

fn parse_email(s: &str) -> Result<Target, TargetError> {
    let s = s.strip_prefix("mailto:").unwrap_or(s);
    let (local, domain) = s
        .rsplit_once('@')
        .ok_or_else(|| TargetError::InvalidEmail(s.to_string()))?;
    if local.is_empty() || local.contains('@') || local.len() > 64 {
        return Err(TargetError::InvalidEmail(s.to_string()));
    }
    let (domain, _) =
        normalize_domain(domain).map_err(|_| TargetError::InvalidEmail(s.to_string()))?;
    Ok(Target::Email {
        address: format!("{local}@{domain}"),
        domain,
    })
}

/// Normalizes a domain name: case, trailing dot, IDN to punycode, label validation.
/// Returns the ASCII name and the Unicode spelling if it differs.
///
/// # Errors
///
/// Returns [`TargetError::InvalidDomain`] if the name is empty, cannot be converted to
/// ASCII or has an invalid label.
pub fn normalize_domain(input: &str) -> Result<(String, Option<String>), TargetError> {
    let s = input.trim();
    let s = s.strip_suffix('.').unwrap_or(s);
    let err = || TargetError::InvalidDomain(input.trim().to_string());
    if s.is_empty() || s.len() > 253 * 4 {
        return Err(err());
    }
    let ascii = idna::domain_to_ascii(s).map_err(|_| err())?;
    if ascii.is_empty() || ascii.len() > 253 {
        return Err(err());
    }
    let labels: Vec<&str> = ascii.split('.').collect();
    if labels.len() < 2 {
        return Err(err());
    }
    for l in &labels {
        if l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-') {
            return Err(err());
        }
        if !l
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(err());
        }
    }
    if labels
        .last()
        .is_some_and(|t| t.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(err());
    }
    let (uni, _) = idna::domain_to_unicode(&ascii);
    let unicode = (uni != ascii).then_some(uni);
    Ok((ascii, unicode))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Target {
        Target::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn domains() {
        assert_eq!(
            p("Contoso.EXAMPLE."),
            Target::Domain {
                name: "contoso.example".into(),
                unicode: None
            }
        );
        match p("приклад.укр") {
            Target::Domain { name, unicode } => {
                assert!(name.starts_with("xn--"), "{name}");
                assert_eq!(unicode.as_deref(), Some("приклад.укр"));
            }
            t => panic!("{t:?}"),
        }
        assert_eq!(
            p("*.contoso.ua"),
            Target::Wildcard {
                base: "contoso.ua".into(),
                unicode: None
            }
        );
        assert!(matches!(
            Target::parse("-bad.ua"),
            Err(TargetError::InvalidDomain(_))
        ));
        assert!(matches!(
            Target::parse("a..b"),
            Err(TargetError::InvalidDomain(_))
        ));
        assert!(matches!(
            Target::parse("foo.*.ua"),
            Err(TargetError::InvalidDomain(_))
        ));
        assert!(matches!(
            Target::parse(&format!("{}.ua", "a".repeat(64))),
            Err(TargetError::InvalidDomain(_))
        ));
        assert!(matches!(
            Target::parse("300.1.1.1"),
            Err(TargetError::InvalidIp(_))
        ));
        assert!(matches!(
            Target::parse("1.2.3"),
            Err(TargetError::InvalidIp(_))
        ));
        assert_eq!(Target::parse("   "), Err(TargetError::Empty));
    }

    #[test]
    fn ips_and_nets() {
        assert_eq!(
            p("10.0.0.1"),
            Target::Ip {
                addr: "10.0.0.1".parse().unwrap()
            }
        );
        assert_eq!(
            p("[2001:db8::1]"),
            Target::Ip {
                addr: "2001:db8::1".parse().unwrap()
            }
        );
        assert_eq!(
            p("::ffff:192.0.2.5"),
            Target::Ip {
                addr: "192.0.2.5".parse().unwrap()
            }
        );
        assert_eq!(
            p("192.168.1.77/24"),
            Target::Cidr {
                net: "192.168.1.0/24".parse().unwrap()
            }
        );
        assert_eq!(
            p("2001:db8::/32"),
            Target::Cidr {
                net: "2001:db8::/32".parse().unwrap()
            }
        );
        assert!(matches!(
            Target::parse("10.0.0.0/33"),
            Err(TargetError::InvalidCidr(_))
        ));
        assert_eq!(
            p("10.0.0.1 - 10.0.0.9"),
            Target::IpRange {
                start: "10.0.0.1".parse().unwrap(),
                end: "10.0.0.9".parse().unwrap()
            }
        );
        assert_eq!(
            p("10.0.0.1-50"),
            Target::IpRange {
                start: "10.0.0.1".parse().unwrap(),
                end: "10.0.0.50".parse().unwrap()
            }
        );
        assert!(matches!(
            Target::parse("10.0.0.9-10.0.0.1"),
            Err(TargetError::InvalidRange(_))
        ));
        assert!(matches!(
            Target::parse("10.0.0.1-::1"),
            Err(TargetError::InvalidRange(_))
        ));
    }

    #[test]
    fn misc() {
        assert_eq!(p("AS15169"), Target::Asn { number: 15169 });
        assert_eq!(p("as1"), Target::Asn { number: 1 });
        assert!(matches!(
            Target::parse("AS99999999999"),
            Err(TargetError::InvalidAsn(_))
        ));
        assert_eq!(
            p("I.Petrenko@Contoso.example"),
            Target::Email {
                address: "I.Petrenko@contoso.example".into(),
                domain: "contoso.example".into()
            }
        );
        assert!(matches!(
            Target::parse("@x.ua"),
            Err(TargetError::InvalidEmail(_))
        ));
        assert_eq!(
            p("Contoso Energy LLC."),
            Target::Org {
                name: "Contoso Energy LLC.".into()
            }
        );
        assert_eq!(
            p("org:contoso.ua"),
            Target::Org {
                name: "contoso.ua".into()
            }
        );
        assert_eq!(
            p("Contoso"),
            Target::Org {
                name: "Contoso".into()
            }
        );
        assert!(matches!(
            Target::parse("12345"),
            Err(TargetError::InvalidIp(_))
        ));
    }

    #[test]
    fn urls() {
        match p("https://Files.Contoso.example/media/x.docx") {
            Target::Url { host, url } => {
                assert_eq!(host, "files.contoso.example");
                assert_eq!(url, "https://files.contoso.example/media/x.docx");
            }
            t => panic!("{t:?}"),
        }
        assert!(matches!(p("portal.contoso.ua/login"), Target::Url { .. }));
        assert!(
            matches!(p("http://[2001:db8::1]:8080/"), Target::Url { ref host, .. } if host == "2001:db8::1")
        );
        assert!(matches!(
            Target::parse("http://"),
            Err(TargetError::InvalidUrl(_))
        ));
    }

    #[test]
    fn display_roundtrip() {
        for s in [
            "contoso.ua",
            "*.contoso.ua",
            "10.0.0.0/8",
            "10.0.0.1-10.0.0.5",
            "AS1",
            "a@b.ua",
            "org:Contoso",
            "::1",
        ] {
            let t = p(s);
            assert_eq!(p(&t.to_string()), t, "{s}");
            let j = serde_json::to_string(&t).unwrap();
            assert_eq!(serde_json::from_str::<Target>(&j).unwrap(), t);
        }
    }

    #[test]
    fn subdomain_boundary() {
        assert!(is_subdomain_of("a.contoso.example", "contoso.example"));
        assert!(!is_subdomain_of("evilcontoso.example", "contoso.example"));
        assert!(!is_subdomain_of("contoso.example", "contoso.example"));
    }
}
