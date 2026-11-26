//! Cloud storage: finds bucket references in text and URLs (S3, GCS, Azure Blob,
//! DigitalOcean Spaces, Yandex Object Storage), normalizes names and optionally checks for a
//! public listing through `foca_net::NetClient`.
//!
//! [`find_buckets`] only parses the text it is given. The check ([`check_buckets`]) is off by
//! default (`BucketCheckOptions::enabled = false`) and sends a single GET per bucket found in
//! documents or pages; bucket names are never brute-forced.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use foca_net::{Access, NetClient, NetRequest};
use regex::Regex;
use serde::{Deserialize, Serialize};

pub const MODULE: &str = "buckets";

/// Storage provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    AwsS3,
    Gcs,
    AzureBlob,
    DoSpaces,
    YandexStorage,
}

impl Provider {
    pub fn label(self) -> &'static str {
        match self {
            Provider::AwsS3 => "Amazon S3",
            Provider::Gcs => "Google Cloud Storage",
            Provider::AzureBlob => "Azure Blob Storage",
            Provider::DoSpaces => "DigitalOcean Spaces",
            Provider::YandexStorage => "Yandex Object Storage",
        }
    }
}

/// Result of an access check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BucketStatus {
    /// Not checked (checking is disabled).
    Unchecked,
    /// Listing is public: number of keys on the first page and up to 10 samples.
    PublicListing { keys: usize, sample: Vec<String> },
    /// The bucket exists but listing is denied (403/AccessDenied).
    Closed,
    /// The bucket does not exist (404/NoSuchBucket), so its name may be claimable.
    NotFound,
    /// Could not be determined (network error, unexpected response).
    Unknown { reason: String },
}

/// A discovered bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bucket {
    pub provider: Provider,
    /// Normalized name (lowercase; `account/container` or `account` for Azure).
    pub name: String,
    pub region: Option<String>,
    /// Links it appeared in (up to 5).
    pub evidence: Vec<String>,
    /// Where it was found (page or document URLs, up to 5).
    pub sources: Vec<String>,
    pub status: BucketStatus,
}

impl Bucket {
    /// Deduplication key.
    pub fn key(&self) -> String {
        format!("{:?}:{}", self.provider, self.name)
    }

    /// Listing URL to check; `None` if the bucket cannot be checked (e.g. Azure without a
    /// container).
    pub fn listing_url(&self) -> Option<String> {
        Some(match self.provider {
            Provider::AwsS3 => {
                if self.name.contains('.') {
                    // Dotted names break TLS with virtual-host addressing, so use path style.
                    match &self.region {
                        Some(r) => {
                            format!("https://s3.{r}.amazonaws.com/{}/?max-keys=50", self.name)
                        }
                        None => format!("https://s3.amazonaws.com/{}/?max-keys=50", self.name),
                    }
                } else {
                    format!("https://{}.s3.amazonaws.com/?max-keys=50", self.name)
                }
            }
            Provider::Gcs => format!("https://storage.googleapis.com/{}/?max-keys=50", self.name),
            Provider::AzureBlob => {
                let (acct, cont) = self.name.split_once('/')?;
                format!("https://{acct}.blob.core.windows.net/{cont}?restype=container&comp=list&maxresults=50")
            }
            Provider::DoSpaces => format!(
                "https://{}.{}.digitaloceanspaces.com/?max-keys=50",
                self.name,
                self.region.as_deref()?
            ),
            Provider::YandexStorage => {
                format!("https://storage.yandexcloud.net/{}/?max-keys=50", self.name)
            }
        })
    }
}

struct Pat {
    provider: Provider,
    re: Regex,
    /// Capture group indices: name, region, extra name part (Azure container).
    name: usize,
    region: Option<usize>,
    extra: Option<usize>,
}

/// (provider, regex, name group, region group, extra name part group).
type PatSpec = (Provider, String, usize, Option<usize>, Option<usize>);

fn pats() -> &'static [Pat] {
    static P: OnceLock<Vec<Pat>> = OnceLock::new();
    P.get_or_init(|| {
        let b = r"([a-z0-9][a-z0-9.\-_]{1,61}[a-z0-9])";
        let pre = r#"(?:^|[\s"'(=,;<>`]|//)"#;
        let v: Vec<PatSpec> = vec![
            // bucket.s3.amazonaws.com, bucket.s3.eu-west-1.amazonaws.com, bucket.s3-website-us-east-1…
            (Provider::AwsS3, format!(r"{b}\.s3(?:-website)?(?:[.-](?:dualstack\.)?([a-z]{{2}}-[a-z]+-\d))?\.amazonaws\.com"), 1, Some(2), None),
            // s3.amazonaws.com/bucket, s3.eu-west-1.amazonaws.com/bucket, s3-eu-west-1.amazonaws.com/bucket
            (Provider::AwsS3, format!(r"{pre}s3(?:[.-](?:dualstack\.)?([a-z]{{2}}-[a-z]+-\d))?\.amazonaws\.com/{b}"), 2, Some(1), None),
            (Provider::AwsS3, format!(r"\bs3://{b}"), 1, None, None),
            (Provider::Gcs, format!(r"{pre}(?:storage\.googleapis\.com|storage\.cloud\.google\.com|commondatastorage\.googleapis\.com)/{b}"), 1, None, None),
            (Provider::Gcs, format!(r"{b}\.storage\.googleapis\.com"), 1, None, None),
            (Provider::Gcs, format!(r"\bgs://{b}"), 1, None, None),
            (Provider::AzureBlob, r"\b([a-z0-9]{3,24})\.blob\.core\.windows\.net(?:/([a-z0-9$][a-z0-9-]{2,62}))?".to_string(), 1, None, Some(2)),
            (Provider::DoSpaces, format!(r"{b}\.([a-z]{{3}}\d)\.(?:cdn\.)?digitaloceanspaces\.com"), 1, Some(2), None),
            (Provider::DoSpaces, format!(r"{pre}([a-z]{{3}}\d)\.digitaloceanspaces\.com/{b}"), 2, Some(1), None),
            (Provider::YandexStorage, format!(r"{pre}storage\.yandexcloud\.net/{b}"), 1, None, None),
            (Provider::YandexStorage, format!(r"{b}\.storage\.yandexcloud\.net"), 1, None, None),
        ];
        v.into_iter()
            .map(|(provider, p, name, region, extra)| Pat {
                provider,
                re: Regex::new(&format!("(?i){p}")).expect("bucket re"),
                name,
                region,
                extra,
            })
            .collect()
    })
}

fn valid_name(n: &str) -> bool {
    const BAD: &[&str] = &[
        "s3", "www", "storage", "static", "assets", "docs", "console", "aws",
    ];
    n.len() >= 3
        && !BAD.contains(&n)
        && !n.contains("..")
        && !n.starts_with("xn--")
        && n.chars().any(|c| c.is_ascii_alphabetic())
        && !n.split('.').all(|p| p.chars().all(|c| c.is_ascii_digit()))
}

/// Finds bucket references in text. `source` is where the text came from (page or document
/// URL).
pub fn find_buckets(text: &str, source: &str) -> Vec<Bucket> {
    let mut map: BTreeMap<String, Bucket> = BTreeMap::new();
    for p in pats() {
        for c in p.re.captures_iter(text) {
            let Some(n) = c.get(p.name) else { continue };
            let mut name = n
                .as_str()
                .to_ascii_lowercase()
                .trim_matches('.')
                .to_string();
            if !valid_name(&name) {
                continue;
            }
            if let Some(e) = p.extra.and_then(|i| c.get(i)) {
                name = format!("{name}/{}", e.as_str().to_ascii_lowercase());
            }
            let region = p
                .region
                .and_then(|i| c.get(i))
                .map(|m| m.as_str().to_ascii_lowercase());
            let m = c.get(0).map(|m| m.as_str()).unwrap_or_default();
            let ev = m
                .trim_start_matches(|ch: char| !ch.is_ascii_alphanumeric())
                .to_string();
            let b = Bucket {
                provider: p.provider,
                name,
                region,
                evidence: vec![],
                sources: vec![],
                status: BucketStatus::Unchecked,
            };
            let e = map.entry(b.key()).or_insert(b);
            if e.region.is_none() {
                e.region = p
                    .region
                    .and_then(|i| c.get(i))
                    .map(|m| m.as_str().to_ascii_lowercase());
            }
            if e.evidence.len() < 5 && !e.evidence.contains(&ev) {
                e.evidence.push(ev);
            }
            if !source.is_empty() && e.sources.len() < 5 && !e.sources.iter().any(|s| s == source) {
                e.sources.push(source.to_string());
            }
        }
    }
    // Azure: a bare `account` is absorbed by `account/container`.
    let keys: Vec<String> = map.keys().cloned().collect();
    for k in &keys {
        if let Some(acct) = k.strip_prefix("AzureBlob:") {
            if !acct.contains('/')
                && keys
                    .iter()
                    .any(|o| o.starts_with(&format!("AzureBlob:{acct}/")))
            {
                map.remove(k);
            }
        }
    }
    map.into_values().collect()
}

/// Merges bucket lists from several sources, deduplicating and combining evidence and
/// sources.
pub fn merge_buckets(lists: impl IntoIterator<Item = Vec<Bucket>>) -> Vec<Bucket> {
    let mut map: BTreeMap<String, Bucket> = BTreeMap::new();
    for l in lists {
        for b in l {
            match map.get_mut(&b.key()) {
                None => {
                    map.insert(b.key(), b);
                }
                Some(e) => {
                    for x in b.evidence {
                        if e.evidence.len() < 5 && !e.evidence.contains(&x) {
                            e.evidence.push(x);
                        }
                    }
                    for x in b.sources {
                        if e.sources.len() < 5 && !e.sources.contains(&x) {
                            e.sources.push(x);
                        }
                    }
                    if e.region.is_none() {
                        e.region = b.region;
                    }
                }
            }
        }
    }
    map.into_values().collect()
}

/// Classifies the response to a listing request.
pub fn classify_listing(status: u16, body: &str) -> BucketStatus {
    static KEY: OnceLock<Regex> = OnceLock::new();
    let key =
        KEY.get_or_init(|| Regex::new(r"<(?:Key|Name)>([^<]{1,300})</(?:Key|Name)>").expect("re"));
    let listing = body.contains("<ListBucketResult") || body.contains("<EnumerationResults");
    if (200..300).contains(&status) && listing {
        let mut keys: Vec<String> = key.captures_iter(body).map(|c| c[1].to_string()).collect();
        // In S3 the first <Name> is the bucket name, not a key.
        if body.contains("<ListBucketResult") && !keys.is_empty() && body.contains("<Name>") {
            keys.remove(0);
        }
        let n = keys.len();
        keys.truncate(10);
        return BucketStatus::PublicListing {
            keys: n,
            sample: keys,
        };
    }
    if body.contains("NoSuchBucket")
        || body.contains("ContainerNotFound")
        || body.contains("ResourceNotFound")
        || status == 404
    {
        return BucketStatus::NotFound;
    }
    if status == 403
        || status == 401
        || body.contains("AccessDenied")
        || body.contains("AuthenticationFailed")
        || body.contains("PublicAccessNotPermitted")
    {
        return BucketStatus::Closed;
    }
    if (200..300).contains(&status) {
        // A website bucket (index.html) exists but does not expose its listing.
        return BucketStatus::Closed;
    }
    BucketStatus::Unknown {
        reason: format!("HTTP {status}"),
    }
}

/// Check options.
#[derive(Debug, Clone)]
pub struct BucketCheckOptions {
    /// Whether to send any requests at all (off by default).
    pub enabled: bool,
    /// Access type for the foca-net log and scope. Defaults to `Passive` because the host is a
    /// cloud provider, not the target; the engine may set `Access::active("bucket-listing")`.
    pub access: Access,
    /// Maximum number of buckets checked per run.
    pub max_checks: usize,
}

impl Default for BucketCheckOptions {
    fn default() -> Self {
        BucketCheckOptions {
            enabled: false,
            access: Access::Passive,
            max_checks: 50,
        }
    }
}

/// Checks a bucket at a specific listing URL (one GET, body capped at 256 KiB).
pub async fn check_bucket_at(client: &NetClient, url: &str, access: Access) -> BucketStatus {
    let req = match NetRequest::get(url, MODULE, access) {
        Ok(r) => r.retries(0).no_redirects(),
        Err(e) => {
            return BucketStatus::Unknown {
                reason: e.to_string(),
            }
        }
    };
    match client.send(req).await {
        Ok(r) => {
            let st = r.status();
            let body = r.text_limited(256 << 10).await.unwrap_or_default();
            classify_listing(st, &body)
        }
        Err(foca_net::NetError::Status(s)) => classify_listing(s, ""),
        Err(e) => BucketStatus::Unknown {
            reason: e.to_string(),
        },
    }
}

/// Checks the buckets and fills in `status` when `opts.enabled` is set; otherwise does
/// nothing.
pub async fn check_buckets(client: &NetClient, buckets: &mut [Bucket], opts: &BucketCheckOptions) {
    if !opts.enabled {
        return;
    }
    for b in buckets.iter_mut().take(opts.max_checks) {
        if client.is_cancelled() {
            break;
        }
        b.status = match b.listing_url() {
            Some(u) => check_bucket_at(client, &u, opts.access.clone()).await,
            None => BucketStatus::Unknown {
                reason: "нет URL листинга (Azure без контейнера / нет региона)".into(),
            },
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXT: &str = r#"
<img src="https://acme-files.s3.eu-west-1.amazonaws.com/img/logo.png">
<a href="https://s3.amazonaws.com/acme.backups/db.sql.gz">dump</a>
<a href='//s3-us-west-2.amazonaws.com/acme-media/v.mp4'>
s3://Acme-Logs/2020/  gs://acme-gcs-data/file
https://storage.googleapis.com/acme-public/report.pdf
https://acmestore01.blob.core.windows.net/invoices/2021.pdf https://acmestore01.blob.core.windows.net/
https://acme-space.fra1.digitaloceanspaces.com/a.png https://ams3.digitaloceanspaces.com/acme-two/x
https://storage.yandexcloud.net/acme-ya/doc.docx https://acme-ya2.storage.yandexcloud.net/x
https://www.s3.amazonaws.com/ http://127.0.0.1.s3.amazonaws.com/
"#;

    #[test]
    fn finds_all_providers() {
        let b = find_buckets(TXT, "https://ex.com/");
        let names: Vec<String> = b
            .iter()
            .map(|x| format!("{:?}:{}", x.provider, x.name))
            .collect();
        for want in [
            "AwsS3:acme-files",
            "AwsS3:acme.backups",
            "AwsS3:acme-media",
            "AwsS3:acme-logs",
            "Gcs:acme-gcs-data",
            "Gcs:acme-public",
            "AzureBlob:acmestore01/invoices",
            "DoSpaces:acme-space",
            "DoSpaces:acme-two",
            "YandexStorage:acme-ya",
            "YandexStorage:acme-ya2",
        ] {
            assert!(names.contains(&want.to_string()), "{want}: {names:?}");
        }
        assert_eq!(names.len(), 11, "{names:?}");
        let f = b.iter().find(|x| x.name == "acme-files").unwrap();
        assert_eq!(f.region.as_deref(), Some("eu-west-1"));
        assert_eq!(f.sources, vec!["https://ex.com/".to_string()]);
        assert_eq!(
            b.iter()
                .find(|x| x.name == "acme-media")
                .unwrap()
                .region
                .as_deref(),
            Some("us-west-2")
        );
        assert_eq!(
            f.listing_url().unwrap(),
            "https://acme-files.s3.amazonaws.com/?max-keys=50"
        );
        let dotted = b.iter().find(|x| x.name == "acme.backups").unwrap();
        assert_eq!(
            dotted.listing_url().unwrap(),
            "https://s3.amazonaws.com/acme.backups/?max-keys=50"
        );
        let az = b
            .iter()
            .find(|x| x.provider == Provider::AzureBlob)
            .unwrap();
        assert!(az
            .listing_url()
            .unwrap()
            .contains("restype=container&comp=list"));
    }

    #[test]
    fn listing_classification() {
        let s3 = "<ListBucketResult><Name>acme</Name><Contents><Key>a.txt</Key></Contents><Contents><Key>b/c.pdf</Key></Contents></ListBucketResult>";
        assert_eq!(
            classify_listing(200, s3),
            BucketStatus::PublicListing {
                keys: 2,
                sample: vec!["a.txt".into(), "b/c.pdf".into()]
            }
        );
        assert_eq!(
            classify_listing(403, "<Error><Code>AccessDenied</Code></Error>"),
            BucketStatus::Closed
        );
        assert_eq!(
            classify_listing(404, "<Code>NoSuchBucket</Code>"),
            BucketStatus::NotFound
        );
        let az = "<EnumerationResults><Blobs><Blob><Name>x.pdf</Name></Blob></Blobs></EnumerationResults>";
        assert!(matches!(
            classify_listing(200, az),
            BucketStatus::PublicListing { keys: 1, .. }
        ));
        assert!(matches!(
            classify_listing(500, ""),
            BucketStatus::Unknown { .. }
        ));
    }

    #[test]
    fn merge_dedupes() {
        let a = find_buckets("https://xbk1.s3.amazonaws.com/a", "p1");
        let b = find_buckets("s3://xbk1", "p2");
        let m = merge_buckets([a, b]);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].sources, vec!["p1".to_string(), "p2".to_string()]);
    }
}
