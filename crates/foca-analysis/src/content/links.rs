//! External links inside documents (`foca-analysis::links`).
//!
//! Extracts URLs from text, classifies links to cloud workspaces (Google Drive/Docs, Notion,
//! Trello, SharePoint/OneDrive, Figma, Jira/Confluence, GitHub/GitLab/Bitbucket, Dropbox, Miro,
//! meeting links) and finds credentials embedded in URLs: generic `?token=`/`?key=`/`?sig=`
//! parameters, Azure SAS, AWS/GCS presigned URLs, Slack/Discord/Teams webhooks and Telegram bot
//! tokens. Token values are wrapped in [`SecretValue`] and replaced by their mask in
//! [`LinkHit::url`]; the original URL is kept only in [`LinkHit::raw`].

use std::sync::OnceLock;

use foca_core::{api::SecretValue, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::util::{is_internal_fqdn, is_private_ip, parse_ip};

/// Cloud service / workspace a link points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    GoogleDocs,
    GoogleDrive,
    Notion,
    Trello,
    SharePoint,
    OneDrive,
    Figma,
    Jira,
    Confluence,
    GitHub,
    GitLab,
    Bitbucket,
    Dropbox,
    Miro,
    Meeting,
    AzureStorage,
    AwsS3,
    GoogleStorage,
    Slack,
    Discord,
    Teams,
    Telegram,
}

impl Service {
    pub fn label(self) -> &'static str {
        match self {
            Service::GoogleDocs => "Google Docs",
            Service::GoogleDrive => "Google Drive",
            Service::Notion => "Notion",
            Service::Trello => "Trello",
            Service::SharePoint => "SharePoint",
            Service::OneDrive => "OneDrive",
            Service::Figma => "Figma",
            Service::Jira => "Jira",
            Service::Confluence => "Confluence",
            Service::GitHub => "GitHub",
            Service::GitLab => "GitLab",
            Service::Bitbucket => "Bitbucket",
            Service::Dropbox => "Dropbox",
            Service::Miro => "Miro",
            Service::Meeting => "Онлайн-встреча",
            Service::AzureStorage => "Azure Storage",
            Service::AwsS3 => "Amazon S3",
            Service::GoogleStorage => "Google Cloud Storage",
            Service::Slack => "Slack",
            Service::Discord => "Discord",
            Service::Teams => "Microsoft Teams",
            Service::Telegram => "Telegram",
        }
    }
}

/// A credential embedded in a URL.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LinkToken {
    /// Query parameter name or `path` for tokens in the path (webhooks, bot tokens).
    pub name: String,
    /// `azure_sas` | `aws_presigned` | `gcs_signed` | `webhook` | `bot_token` | `query` |
    /// `userinfo`
    pub kind: String,
    pub value: SecretValue,
}

/// A classified link.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LinkHit {
    /// Display URL with every token value replaced by its mask.
    pub url: String,
    /// Original URL (persistence and explicit reveal only; masked in `Debug`).
    pub raw: SecretValue,
    pub host: String,
    pub service: Option<Service>,
    /// `document`, `spreadsheet`, `folder`, `board`, `repo`, `issue`, `page`, …
    pub resource: Option<String>,
    /// The link is a "share by link" URL (anyone with the link can open it).
    pub shared: bool,
    /// The host is internal (private IP, AD suffix, self-hosted Jira/GitLab without a public TLD).
    pub internal: bool,
    pub tokens: Vec<LinkToken>,
    /// Expiry of a presigned URL / SAS, as found (`se=`, `X-Amz-Date`+`X-Amz-Expires`).
    pub expires: Option<String>,
    /// Proposed finding severity.
    pub sev: Severity,
}

/// Maximum links returned per text.
pub const MAX_LINKS: usize = 1000;

fn re_url() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:https?://|www\.)[^\s<>"'`{}|\\^\[\]]{3,2048}"#).expect("url regex")
    })
}

/// Extracts and classifies all URLs of `text` (deduplicated by the original URL).
pub fn extract(text: &str) -> Vec<LinkHit> {
    let mut out: Vec<LinkHit> = Vec::new();
    for m in re_url().find_iter(text) {
        let u = m
            .as_str()
            .trim_end_matches(['.', ',', ';', ':', '!', '?', ')', '»', '”', '\'', '>']);
        if out.iter().any(|h| h.raw.expose() == u) {
            continue;
        }
        if let Some(h) = classify(u) {
            out.push(h);
            if out.len() >= MAX_LINKS {
                break;
            }
        }
    }
    out
}

/// Only links worth reporting: a known service, an embedded token or an internal host.
pub fn interesting(text: &str) -> Vec<LinkHit> {
    extract(text)
        .into_iter()
        .filter(|h| h.service.is_some() || !h.tokens.is_empty() || h.internal)
        .collect()
}

struct Parts<'a> {
    host: String,
    userinfo: Option<&'a str>,
    path: &'a str,
    query: &'a str,
}

fn split(url: &str) -> Option<Parts<'_>> {
    let rest = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..auth_end];
    let tail = &rest[auth_end..];
    let (userinfo, hostport) = match auth.rfind('@') {
        Some(i) => (Some(&auth[..i]), &auth[i + 1..]),
        None => (None, auth),
    };
    let host = if let Some(h) = hostport.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host
            .chars()
            .any(|c| !(c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':')))
    {
        return None;
    }
    let tail = tail.split('#').next().unwrap_or("");
    let (path, query) = match tail.find('?') {
        Some(i) => (&tail[..i], &tail[i + 1..]),
        None => (tail, ""),
    };
    Some(Parts {
        host,
        userinfo,
        path,
        query,
    })
}

fn ends(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

const TOKEN_PARAMS: &[&str] = &[
    "token",
    "access_token",
    "auth",
    "auth_token",
    "key",
    "api_key",
    "apikey",
    "sig",
    "signature",
    "secret",
    "client_secret",
    "password",
    "pwd",
    "pass",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
    "x-goog-signature",
    "x-goog-credential",
    "awsaccesskeyid",
    "rlkey",
    "share_token",
    "private_token",
    "jwt",
];

fn placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    v.len() < 6
        || l.contains("xxx")
        || l.contains("example")
        || l.contains("your")
        || l.starts_with('{')
        || l.starts_with('<')
        || l.starts_with('$')
        || l.starts_with("%7b")
        || v.chars().all(|c| c == v.chars().next().unwrap_or('x'))
}

/// Classifies one URL. Returns `None` for strings that are not URLs with a host.
pub fn classify(url: &str) -> Option<LinkHit> {
    let url = url.trim();
    let full = if url.to_ascii_lowercase().starts_with("www.") {
        format!("http://{url}")
    } else {
        url.to_string()
    };
    let p = split(&full)?;
    let host = p.host.clone();
    let path_l = p.path.to_ascii_lowercase();
    let mut tokens: Vec<(String, String, String)> = Vec::new(); // (name, kind, value)
    let params: Vec<(&str, &str)> = p
        .query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .collect();
    let has = |n: &str| params.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    let get = |n: &str| {
        params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| *v)
    };

    let (mut service, mut resource): (Option<Service>, Option<String>) = (None, None);
    let mut shared = false;
    let mut expires = None;
    let seg = |i: usize| p.path.split('/').filter(|s| !s.is_empty()).nth(i);

    if ends(&host, "docs.google.com") {
        service = Some(Service::GoogleDocs);
        resource = seg(0).map(|s| s.to_string());
        shared = path_l.contains("/d/") && (has("usp") || path_l.ends_with("/edit"));
    } else if ends(&host, "drive.google.com") {
        service = Some(Service::GoogleDrive);
        resource = Some(
            if path_l.contains("/folders/") {
                "folder"
            } else {
                "file"
            }
            .into(),
        );
        shared = has("usp") || has("id") || path_l.contains("/file/d/");
    } else if ends(&host, "notion.so") || ends(&host, "notion.site") || ends(&host, "notion.com") {
        service = Some(Service::Notion);
        resource = Some("page".into());
        shared = host.ends_with("notion.site");
    } else if ends(&host, "trello.com") {
        service = Some(Service::Trello);
        resource = match seg(0) {
            Some("b") => Some("board".into()),
            Some("c") => Some("card".into()),
            _ => None,
        };
        shared = resource.is_some();
    } else if host.ends_with("-my.sharepoint.com")
        || ends(&host, "onedrive.live.com")
        || ends(&host, "1drv.ms")
    {
        service = Some(Service::OneDrive);
        shared = path_l.starts_with("/:") || host == "1drv.ms" || has("resid");
    } else if ends(&host, "sharepoint.com") {
        service = Some(Service::SharePoint);
        resource = if path_l.starts_with("/sites/") || path_l.starts_with("/teams/") {
            seg(1).map(|s| format!("site:{s}"))
        } else {
            None
        };
        shared = path_l.starts_with("/:");
    } else if ends(&host, "figma.com") {
        service = Some(Service::Figma);
        resource = seg(0).map(|s| s.to_string());
    } else if ends(&host, "atlassian.net")
        || host.starts_with("jira.")
        || host.starts_with("confluence.")
        || host.starts_with("wiki.")
    {
        let conf = path_l.starts_with("/wiki")
            || host.starts_with("confluence.")
            || host.starts_with("wiki.")
            || path_l.contains("/display/")
            || path_l.contains("/pages/");
        service = Some(if conf {
            Service::Confluence
        } else {
            Service::Jira
        });
        resource = if path_l.starts_with("/browse/") {
            Some("issue".into())
        } else if conf {
            Some("page".into())
        } else {
            None
        };
    } else if ends(&host, "github.com") || ends(&host, "githubusercontent.com") {
        service = Some(Service::GitHub);
        resource = (seg(1).is_some()).then(|| "repo".to_string());
    } else if ends(&host, "gitlab.com") || host.starts_with("gitlab.") || host.starts_with("git.") {
        service = Some(Service::GitLab);
        resource = (seg(1).is_some()).then(|| "repo".to_string());
    } else if ends(&host, "bitbucket.org") || host.starts_with("bitbucket.") {
        service = Some(Service::Bitbucket);
        resource = (seg(1).is_some()).then(|| "repo".to_string());
    } else if ends(&host, "dropbox.com") || ends(&host, "dropboxusercontent.com") || host == "db.tt"
    {
        service = Some(Service::Dropbox);
        shared =
            path_l.starts_with("/s/") || path_l.starts_with("/scl/") || path_l.starts_with("/sh/");
    } else if ends(&host, "miro.com") {
        service = Some(Service::Miro);
        resource = path_l.contains("/board/").then(|| "board".to_string());
        shared = has("share_link_id");
    } else if ends(&host, "zoom.us") && (path_l.starts_with("/j/") || path_l.starts_with("/my/")) {
        service = Some(Service::Meeting);
        resource = Some("zoom".into());
        if let Some(pw) = get("pwd") {
            tokens.push(("pwd".into(), "query".into(), pw.into()));
        }
    } else if ends(&host, "teams.microsoft.com") && path_l.contains("meetup-join") {
        service = Some(Service::Meeting);
        resource = Some("teams".into());
    } else if ends(&host, "meet.google.com") {
        service = Some(Service::Meeting);
        resource = Some("google_meet".into());
    }

    // Storage presigned URLs.
    if host.contains(".blob.core.windows.net")
        || host.contains(".file.core.windows.net")
        || host.contains(".queue.core.windows.net")
        || host.contains(".table.core.windows.net")
        || host.contains(".dfs.core.windows.net")
    {
        service = Some(Service::AzureStorage);
        if let (Some(sig), true) = (get("sig"), has("sv") || has("se") || has("sp")) {
            tokens.push(("sig".into(), "azure_sas".into(), sig.into()));
            expires = get("se").map(pct_decode);
        }
    }
    if host.contains("amazonaws.com") && (host.contains("s3") || has("x-amz-signature")) {
        service = service.or(Some(Service::AwsS3));
    }
    if let Some(sig) = get("x-amz-signature") {
        tokens.push(("X-Amz-Signature".into(), "aws_presigned".into(), sig.into()));
        if let Some(c) = get("x-amz-credential") {
            tokens.push(("X-Amz-Credential".into(), "aws_presigned".into(), c.into()));
        }
        if let Some(t) = get("x-amz-security-token") {
            tokens.push((
                "X-Amz-Security-Token".into(),
                "aws_presigned".into(),
                t.into(),
            ));
        }
        expires = match (get("x-amz-date"), get("x-amz-expires")) {
            (Some(d), Some(e)) => Some(format!("{d}+{e}s")),
            (Some(d), None) => Some(d.to_string()),
            _ => None,
        };
    } else if let (Some(sig), Some(id)) = (get("signature"), get("awsaccesskeyid")) {
        tokens.push(("Signature".into(), "aws_presigned".into(), sig.into()));
        tokens.push(("AWSAccessKeyId".into(), "aws_presigned".into(), id.into()));
        expires = get("expires").map(str::to_string);
    }
    if let Some(sig) = get("x-goog-signature") {
        service = service.or(Some(Service::GoogleStorage));
        tokens.push(("X-Goog-Signature".into(), "gcs_signed".into(), sig.into()));
    }

    // Webhooks and bot tokens in the path.
    if host == "hooks.slack.com" && path_l.starts_with("/services/") {
        service = Some(Service::Slack);
        resource = Some("webhook".into());
        if let Some(t) = p.path.strip_prefix("/services/") {
            tokens.push(("path".into(), "webhook".into(), t.into()));
        }
    } else if (ends(&host, "discord.com") || ends(&host, "discordapp.com"))
        && path_l.starts_with("/api/webhooks/")
    {
        service = Some(Service::Discord);
        resource = Some("webhook".into());
        if let Some(t) = p.path.rsplit('/').find(|s| !s.is_empty()) {
            tokens.push(("path".into(), "webhook".into(), t.into()));
        }
    } else if host.ends_with(".webhook.office.com")
        || (ends(&host, "outlook.office.com") && path_l.starts_with("/webhook"))
    {
        service = Some(Service::Teams);
        resource = Some("webhook".into());
        let t = p
            .path
            .split('/')
            .filter(|s| !s.is_empty())
            .skip(1)
            .collect::<Vec<_>>()
            .join("/");
        if !t.is_empty() {
            tokens.push(("path".into(), "webhook".into(), t));
        }
    } else if host == "api.telegram.org" && path_l.starts_with("/bot") {
        service = Some(Service::Telegram);
        resource = Some("bot".into());
        if let Some(t) = p.path[4..].split('/').next() {
            tokens.push(("path".into(), "bot_token".into(), t.into()));
        }
    }

    // Generic token-like query parameters.
    for (k, v) in &params {
        let kl = k.to_ascii_lowercase();
        if !TOKEN_PARAMS.contains(&kl.as_str()) {
            continue;
        }
        if tokens.iter().any(|(n, _, _)| n.eq_ignore_ascii_case(k)) {
            continue;
        }
        if kl == "key" && service == Some(Service::GoogleDocs) {
            continue;
        }
        tokens.push((k.to_string(), "query".into(), v.to_string()));
    }
    if let Some(ui) = p.userinfo {
        if let Some((_, pw)) = ui.split_once(':') {
            tokens.push(("userinfo".into(), "userinfo".into(), pw.to_string()));
        }
    }
    tokens.retain(|(_, _, v)| !placeholder(v));

    let internal = match parse_ip(&host) {
        Some(ip) => is_private_ip(ip),
        None => {
            is_internal_fqdn(&host)
                || !host.contains('.')
                || host
                    .split('.')
                    .next_back()
                    .is_some_and(|tld| tld.len() > 6 && !tld.starts_with("xn--"))
        }
    };

    // Display URL: token values replaced by masks.
    let mut shown = full.clone();
    for (_, _, v) in &tokens {
        shown = shown.replace(v.as_str(), &foca_core::api::mask(v));
    }
    let sev = if tokens.iter().any(|(_, k, _)| k != "query")
        || tokens.iter().any(|(n, _, _)| {
            n.to_ascii_lowercase().contains("pass")
                || n == "pwd"
                || n == "secret"
                || n == "client_secret"
        }) {
        Severity::High
    } else if !tokens.is_empty() {
        Severity::Medium
    } else if internal || (shared && service.is_some()) {
        Severity::Low
    } else {
        Severity::Info
    };
    let sev = if matches!(
        service,
        Some(Service::Slack | Service::Discord | Service::Teams | Service::Telegram)
    ) && !tokens.is_empty()
        || tokens
            .iter()
            .any(|(_, k, _)| k == "azure_sas" || k == "aws_presigned" || k == "userinfo")
            && expires.is_none()
    {
        Severity::Critical.max_sev(sev)
    } else {
        sev
    };
    Some(LinkHit {
        url: shown,
        raw: SecretValue::new(url),
        host,
        service,
        resource,
        shared,
        internal,
        tokens: tokens
            .into_iter()
            .map(|(name, kind, v)| LinkToken {
                name,
                kind,
                value: SecretValue::new(v),
            })
            .collect(),
        expires,
        sev,
    })
}

trait MaxSev {
    fn max_sev(self, other: Severity) -> Severity;
}

impl MaxSev for Severity {
    /// The more severe of the two (`Critical` is the smallest variant).
    fn max_sev(self, other: Severity) -> Severity {
        let rank = |s: Severity| match s {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        if rank(self) <= rank(other) {
            self
        } else {
            other
        }
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(u: &str) -> LinkHit {
        classify(u).unwrap()
    }

    #[test]
    fn workspaces() {
        let cases = [
            (
                "https://docs.google.com/document/d/1AbCdEfGhIjKlMnOp/edit?usp=sharing",
                Service::GoogleDocs,
            ),
            (
                "https://drive.google.com/drive/folders/1AbCdEfGh",
                Service::GoogleDrive,
            ),
            (
                "https://example-team.notion.site/Plan-0123456789abcdef",
                Service::Notion,
            ),
            ("https://trello.com/b/AbCd1234/sprint", Service::Trello),
            (
                "https://contoso.sharepoint.com/sites/HR/Shared%20Documents/x.docx",
                Service::SharePoint,
            ),
            (
                "https://contoso-my.sharepoint.com/:w:/g/personal/user_contoso_com/EabC",
                Service::OneDrive,
            ),
            ("https://www.figma.com/file/AbCdEf/Design", Service::Figma),
            ("https://contoso.atlassian.net/browse/OPS-12", Service::Jira),
            (
                "https://contoso.atlassian.net/wiki/spaces/IT/pages/1",
                Service::Confluence,
            ),
            ("https://github.com/example-org/repo", Service::GitHub),
            ("https://gitlab.example.corp/team/app", Service::GitLab),
            (
                "https://www.dropbox.com/s/abc123/file.pdf?dl=0",
                Service::Dropbox,
            ),
            ("https://miro.com/app/board/uXjVAbC=/", Service::Miro),
        ];
        for (u, s) in cases {
            assert_eq!(one(u).service, Some(s), "{u}");
        }
        let d = one("https://docs.google.com/document/d/1AbCdEfGhIjKlMnOp/edit?usp=sharing");
        assert!(d.shared);
        assert_eq!(d.resource.as_deref(), Some("document"));
        let sp = one("https://contoso.sharepoint.com/sites/HR/x");
        assert_eq!(sp.resource.as_deref(), Some("site:HR"));
        assert!(one("https://gitlab.example.corp/team/app").internal);
        assert!(one("http://10.0.0.5/wiki").internal);
        assert!(!one("https://github.com/x/y").internal);
    }

    #[test]
    fn tokens_are_masked() {
        let sas = "https://acct.blob.core.windows.net/c/f.pdf?sv=2022-11-02&se=2030-01-01T00%3A00%3A00Z&sp=r&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789%2Babc%3D";
        let h = one(sas);
        assert_eq!(h.service, Some(Service::AzureStorage));
        assert_eq!(h.tokens[0].kind, "azure_sas");
        assert_eq!(h.expires.as_deref(), Some("2030-01-01T00:00:00Z"));
        assert!(!h.url.contains("AbCdEfGhIjKlMnOp"), "{}", h.url);
        assert!(!format!("{h:?}").contains("AbCdEfGhIjKlMnOp"));

        let aws = "https://bucket.s3.eu-central-1.amazonaws.com/a.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLETESTKEY12%2F20260101%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260101T000000Z&X-Amz-Expires=3600&X-Amz-Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let h = one(aws);
        assert_eq!(h.service, Some(Service::AwsS3));
        assert!(h.tokens.iter().any(|t| t.name == "X-Amz-Signature"));
        assert_eq!(h.expires.as_deref(), Some("20260101T000000Z+3600s"));
        assert!(!h.url.contains("0123456789abcdef0123"));

        let slack =
            one("https://hooks.slack.com/services/T00000000/B00000000/AbCdEfGhIjKlMnOpQrStUvWx");
        assert_eq!(slack.service, Some(Service::Slack));
        assert_eq!(slack.sev, Severity::Critical);
        assert!(!slack.url.contains("AbCdEfGhIjKlMnOpQrStUvWx"));
        let disc = one("https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz_-0123456789");
        assert_eq!(disc.tokens[0].kind, "webhook");
        let q = one("https://api.example.org/v1/data?format=json&api_key=Zx81kLm2Qp93Rt");
        assert_eq!(q.tokens.len(), 1);
        assert_eq!(q.tokens[0].name, "api_key");
        assert_eq!(q.sev, Severity::Medium);
        // Placeholders are not tokens.
        assert!(one("https://api.example.org/?token=YOUR_TOKEN")
            .tokens
            .is_empty());
        assert!(one("https://api.example.org/?key={key}").tokens.is_empty());
    }

    #[test]
    fn extract_from_text() {
        let t = "Див. https://trello.com/b/AbCd1234/sprint), а також www.figma.com/file/X1/Y. \
                 Звичайне посилання https://example.org/page.";
        let all = extract(t);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].raw.expose(), "https://trello.com/b/AbCd1234/sprint");
        assert_eq!(interesting(t).len(), 2);
        assert!(extract("http://").is_empty());
        let big = "https://a.b/".repeat(5000);
        assert!(extract(&big).len() <= MAX_LINKS);
    }
}
