//! X.509 and TLS inspector.
//!
//! The module is split by access class, mirroring the scan profiles (ADR-0009):
//!
//! * [`x509`]: pure certificate parsing (subject/issuer fields, SAN, fingerprints, CDP/AIA and
//!   the internal PKI/AD hints they leak). No network.
//! * [`audit`]: certificate and chain audit (expiry, self-signed, unknown CA, incomplete chain,
//!   hostname mismatch, weak signature or key, CAA) and the [`Issue`] list derived from it. No
//!   network.
//! * [`handshake`]: a full rustls handshake that records the presented chain, the negotiated
//!   version, cipher suite, ALPN and OCSP stapling. The standard probe ([`inspect_standard`]) is a
//!   `TouchesTarget` request; the no-SNI probe and STARTTLS ([`starttls`]) are active operations.
//! * [`legacy`]: raw `ClientHello` probes for TLS 1.0/1.1 (and SSL 3.0 on request) and weak
//!   cipher suites, which rustls cannot negotiate. Active only.
//!
//! Every connection goes through [`crate::tcp::connect`]: scope check, exclusions by resolved IP,
//! rate limit, proxy and the request log. `Access::Passive` is refused before any network call.
//! The passive part of the inspector (CT history, timeline, abandoned hosts, organization pivot)
//! lives in [`crate::ct`].

pub mod audit;
pub mod ct;
pub mod handshake;
pub mod legacy;
pub mod starttls;
pub mod x509;

use foca_core::Severity;
use serde::{Deserialize, Serialize};

use crate::client::Access;
use crate::NetError;

pub use audit::{audit_chain, check_caa, AuditConfig, CaaCheck, CertAudit, TrustStatus};
pub use handshake::{
    inspect, inspect_no_sni, inspect_standard, starttls_inspect, InspectOptions, TlsInspection,
    MODULE,
};
pub use legacy::{probe_legacy, LegacyConfig, LegacyReport, TlsVersion};
pub use starttls::StartTls;
pub use x509::{parse_cert, pki_hints, CertInfo, DnInfo, PkiHint};

/// A finding candidate produced by the inspector. `code` is stable and machine-readable; the
/// engine maps it to a localized finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    pub code: String,
    pub severity: Severity,
    pub detail: String,
}

impl Issue {
    pub fn new(code: &str, severity: Severity, detail: impl Into<String>) -> Self {
        Issue {
            code: code.to_string(),
            severity,
            detail: detail.into(),
        }
    }
}

/// Refuses passive access: the passive profile never connects to a target (ADR-0009).
pub(crate) fn refuse_passive(host: &str, access: &Access) -> Result<(), NetError> {
    if matches!(access, Access::Passive) {
        return Err(NetError::OutOfScope {
            host: host.to_string(),
            reason: "TLS inspection connects to the target; not allowed in passive mode".into(),
        });
    }
    Ok(())
}

/// Lowercase hex encoding.
pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_is_refused() {
        assert!(refuse_passive("a.test", &Access::Passive)
            .unwrap_err()
            .is_scope_denial());
        assert!(refuse_passive("a.test", &Access::TouchesTarget).is_ok());
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
    }
}
