//! Finding severity: the leaf type shared by findings, forensics records and API views.
//!
//! Wire names are `crit|high|warn|low|info`; `critical` and `medium` are accepted on input.

use serde::{Deserialize, Serialize};

/// Finding severity.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum Severity {
    #[serde(rename = "crit", alias = "critical")]
    Critical,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "warn", alias = "medium")]
    Medium,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "info")]
    #[default]
    Info,
}

impl Severity {
    /// Returns the rank used in risk scoring: Critical = 4 down to Info = 0.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }
}
