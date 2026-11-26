//! Project data model: projects, documents, entities, findings and scan events.
//!
//! Field names and enum values match the UI (`ui/screens/findings.js`, `ui/js/demo-data.js`):
//! severity serializes as `crit|high|warn|low|info` and status as
//! `new|confirmed|false|accepted|fixed`. Synonyms (`critical`, `medium`, `false_positive`) are
//! accepted on input for readability.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::metadata::Metadata;
use crate::scope::Scope;
pub use crate::severity::Severity;

/// A project.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated: OffsetDateTime,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_dir: Option<String>,
}

impl Project {
    pub fn new(id: impl Into<String>, name: impl Into<String>, now: OffsetDateTime) -> Self {
        Project {
            id: id.into(),
            name: name.into(),
            created: now,
            updated: now,
            scope: Scope::default(),
            notes: String::new(),
            download_dir: None,
        }
    }
}

/// Document state in the processing pipeline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocStatus {
    #[default]
    Queued,
    Downloading,
    Downloaded,
    Analyzed,
    Error,
    Skipped,
}

/// A project document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Document {
    pub id: u64,
    pub name: String,
    pub ext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Source that produced the URL (`wayback`, `crawler`, `local`, ...).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    pub size: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    pub status: DocStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub found_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}

/// An entity aggregated from documents and network data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entity {
    Person {
        name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        logins: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        emails: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        aliases: Vec<String>,
    },
    Email {
        address: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    Host {
        name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ips: Vec<IpAddr>,
        /// Internal host (from paths or metadata; does not resolve externally).
        #[serde(default)]
        internal: bool,
    },
    Pc {
        name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        users: Vec<String>,
    },
    Software {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
    Path {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    Printer {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<String>,
    },
    Secret {
        /// Rule type (`password`, `aws_key`, `connection_string`, ...).
        rule: String,
        /// Masked value for display.
        masked: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entropy: Option<f64>,
    },
}

/// An entity with an identifier and links to documents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityRecord {
    pub id: u64,
    #[serde(flatten)]
    pub entity: Entity,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub doc_ids: Vec<u64>,
}

/// Finding triage status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingStatus {
    #[default]
    #[serde(rename = "new")]
    New,
    #[serde(rename = "confirmed")]
    Confirmed,
    #[serde(rename = "false", alias = "false_positive")]
    FalsePositive,
    /// Risk accepted by the client.
    #[serde(rename = "accepted")]
    Accepted,
    #[serde(rename = "fixed")]
    Fixed,
}

/// Parses the contract string of a status (`new|confirmed|false|accepted|fixed`); the error
/// carries the rejected input.
impl std::str::FromStr for FindingStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "new" => Ok(FindingStatus::New),
            "confirmed" => Ok(FindingStatus::Confirmed),
            "false" | "false_positive" => Ok(FindingStatus::FalsePositive),
            "accepted" => Ok(FindingStatus::Accepted),
            "fixed" => Ok(FindingStatus::Fixed),
            _ => Err(s.to_string()),
        }
    }
}

/// Finding category (UI tabs).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    #[default]
    Docs,
    Sw,
    Dns,
    Web,
    Mail,
    People,
}

/// Finding provenance: where and when the evidence was obtained.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Provenance {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub time: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    /// Raw outgoing request (for the request log).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub request: String,
    #[serde(alias = "doc", skip_serializing_if = "Option::is_none")]
    pub doc_id: Option<u64>,
}

/// Links of a finding.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FindingRel {
    pub people: Vec<String>,
    pub pcs: Vec<String>,
    pub docs: Vec<u64>,
}

/// A finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: u64,
    pub title: String,
    #[serde(rename = "sev", alias = "severity")]
    pub severity: Severity,
    #[serde(default)]
    pub status: FindingStatus,
    #[serde(default)]
    pub category: FindingCategory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default)]
    pub source: String,
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default)]
    pub provenance: Provenance,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub recommendation: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cve: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mitre: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(default)]
    pub rel: FindingRel,
}

/// Scan stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStage {
    Discovery,
    Download,
    Metadata,
    Network,
    Analysis,
    Report,
}

/// Source state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Waiting,
    Running,
    Done,
    Error,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Scan event for the UI (`app.emit`) and the CLI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanEvent {
    Stage {
        stage: ScanStage,
    },
    Progress {
        stage: ScanStage,
        done: u64,
        total: u64,
    },
    Source {
        source: String,
        state: SourceState,
        #[serde(default)]
        found: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    DocumentFound {
        url: String,
        source: String,
    },
    DocumentDownloaded {
        doc_id: u64,
        size: u64,
        sha256: String,
    },
    DocumentAnalyzed {
        doc_id: u64,
    },
    Finding {
        finding: Box<Finding>,
    },
    Log {
        level: LogLevel,
        message: String,
    },
    Finished {
        cancelled: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn severity_and_status_wire_names() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"crit\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Medium).unwrap(),
            "\"warn\""
        );
        assert_eq!(
            serde_json::from_str::<Severity>("\"critical\"").unwrap(),
            Severity::Critical
        );
        assert_eq!(
            serde_json::from_str::<Severity>("\"medium\"").unwrap(),
            Severity::Medium
        );
        assert_eq!(
            serde_json::to_string(&FindingStatus::FalsePositive).unwrap(),
            "\"false\""
        );
        assert_eq!(
            serde_json::from_str::<FindingStatus>("\"false_positive\"").unwrap(),
            FindingStatus::FalsePositive
        );
        assert!(Severity::Critical < Severity::Info);
        assert_eq!(Severity::Critical.rank(), 4);
    }

    #[test]
    fn finding_json_shape() {
        let f = Finding {
            id: 4,
            title: "Пароль в тексте документа".into(),
            severity: Severity::Critical,
            status: FindingStatus::New,
            category: FindingCategory::Docs,
            host: Some("files.contoso.example".into()),
            source: "Секреты в документах".into(),
            time: datetime!(2026-11-19 21:12 UTC),
            tags: vec![],
            provenance: Provenance {
                source: "Секреты в документах".into(),
                url: Some("https://files.contoso.example/x.docx".into()),
                time: Some(datetime!(2026-11-19 21:12 UTC)),
                sha256: "ab".repeat(32),
                request: String::new(),
                doc_id: Some(1),
            },
            description: String::new(),
            recommendation: String::new(),
            cve: vec![],
            cvss: Some(9.1),
            mitre: "T1552.001".into(),
            evidence: String::new(),
            notes: vec![],
            rel: FindingRel {
                people: vec!["a.bondar".into()],
                pcs: vec![],
                docs: vec![1],
            },
        };
        let v: serde_json::Value = serde_json::to_value(&f).unwrap();
        assert_eq!(v["sev"], "crit");
        assert_eq!(v["status"], "new");
        assert_eq!(v["category"], "docs");
        assert_eq!(v["provenance"]["doc_id"], 1);
        assert_eq!(v["time"], "2026-11-19T21:12:00Z");
        let back: Finding = serde_json::from_value(v).unwrap();
        assert_eq!(back, f);
        // UI form: provenance.doc
        let p: Provenance = serde_json::from_str(r#"{"source":"x","doc":7}"#).unwrap();
        assert_eq!(p.doc_id, Some(7));
    }

    #[test]
    fn event_and_entity_tags() {
        let e = ScanEvent::Progress {
            stage: ScanStage::Download,
            done: 3,
            total: 10,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "progress");
        assert_eq!(v["stage"], "download");
        let r = EntityRecord {
            id: 1,
            entity: Entity::Pc {
                name: "BUH-PC07".into(),
                users: vec![],
            },
            doc_ids: vec![3],
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["kind"], "pc");
        assert_eq!(v["name"], "BUH-PC07");
        assert_eq!(serde_json::from_value::<EntityRecord>(v).unwrap(), r);
    }
}
