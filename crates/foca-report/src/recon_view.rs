//! Website recon view of `snapshot.recon` (docs/API.md): the input of the website section and
//! of the per-host software summary.

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Tech {
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    pub outdated: Option<String>,
    pub host: String,
    /// Offline NVD CVE summary of the technology version.
    pub cve: Option<foca_core::api::CveSummary>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Query {
    pub engine: String,
    pub q: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Favicon {
    pub url: String,
    pub mmh3: i64,
    pub md5: String,
    pub queries: Vec<Query>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Site {
    pub host: String,
    pub via: String,
    pub favicon: Option<Favicon>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Item {
    pub kind: String,
    pub id: String,
    pub path: String,
    pub reason: String,
    pub loc: String,
    pub url: String,
    pub method: Option<String>,
    pub title: String,
    pub mask: String,
    pub source: String,
    pub host: String,
    pub contacts: Vec<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Bucket {
    pub label: String,
    pub name: String,
    pub status: String,
    pub keys: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Hit {
    pub repo: String,
    pub path: String,
    pub url: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Code {
    pub query: String,
    pub total: u64,
    pub hits: Vec<Hit>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ReconView {
    pub at: Option<String>,
    pub level: Option<String>,
    pub sites: Vec<Site>,
    pub tech: Vec<Tech>,
    pub analytics: Vec<Item>,
    pub hidden_paths: Vec<Item>,
    pub sitemap: Vec<Item>,
    pub sitemap_total: usize,
    pub security: Vec<Item>,
    pub endpoints: Vec<Item>,
    pub endpoints_total: usize,
    pub secrets: Vec<Item>,
    pub buckets: Vec<Bucket>,
    pub code: Option<Code>,
}

impl ReconView {
    pub fn from_snapshot(v: &Value) -> ReconView {
        serde_json::from_value(v.clone()).unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.tech.is_empty()
            && self.sites.iter().all(|s| s.favicon.is_none())
            && self.analytics.is_empty()
            && self.hidden_paths.is_empty()
            && self.sitemap.is_empty()
            && self.security.is_empty()
            && self.endpoints.is_empty()
            && self.secrets.is_empty()
            && self.buckets.is_empty()
            && self.code.as_ref().is_none_or(|c| c.hits.is_empty())
    }
}
