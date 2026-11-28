//! Ukrainian qualified electronic signature (КЕП) certificate fields.
//!
//! Qualified certificates issued by Ukrainian trust service providers (КНЕДП, formerly АЦСК)
//! carry the organization and personal tax codes in two known layouts:
//!
//! * current profile (ETSI EN 319 412-1 semantics identifiers): subject `serialNumber`
//!   (2.5.4.5) `TINUA-<10 digits>` for the personal tax number (РНОКПП) and
//!   `organizationIdentifier` (2.5.4.97) `NTRUA-<8 digits>` for the legal entity code (ЄДРПОУ);
//! * legacy profile: the `SubjectDirectoryAttributes` extension (2.5.29.9) with
//!   1.2.804.2.1.1.1.11.1.4.1.1 (РНОКПП/ДРФО) and 1.2.804.2.1.1.1.11.1.4.2.1 (ЄДРПОУ).
//!
//! The personal tax number is validated here and kept as written (the user sees the full
//! value; logs and masked reports mask it downstream).

use foca_core::CertInfo;

/// Legacy UA attribute: personal tax number (РНОКПП, formerly ДРФО).
pub const OID_UA_DRFO: &str = "1.2.804.2.1.1.1.11.1.4.1.1";
/// Legacy UA attribute: legal entity code (ЄДРПОУ).
pub const OID_UA_EDRPOU: &str = "1.2.804.2.1.1.1.11.1.4.2.1";
/// Prefix of the legacy UA subject directory attributes.
const OID_UA_ATTR_PREFIX: &str = "1.2.804.2.1.1.1.11.1.4.";
/// X.520 `serialNumber`.
pub const OID_SERIAL_NUMBER: &str = "2.5.4.5";
/// X.520 `organizationIdentifier`.
pub const OID_ORG_IDENTIFIER: &str = "2.5.4.97";

/// Returns `true` if `s` is a 10-digit РНОКПП with a valid check digit.
pub fn rnokpp_valid(s: &str) -> bool {
    let d: Vec<i64> = s
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|c| i64::from(c - b'0'))
        .collect();
    if d.len() != 10 || s.len() != 10 {
        return false;
    }
    const W: [i64; 9] = [-1, 5, 7, 9, 4, 6, 10, 5, 7];
    let sum: i64 = d.iter().zip(W).map(|(a, w)| a * w).sum();
    sum.rem_euclid(11) % 10 == d[9]
}

fn digits(s: &str, n: usize) -> Option<&str> {
    let s = s.trim();
    (s.len() == n && s.bytes().all(|c| c.is_ascii_digit())).then_some(s)
}

/// Strips a semantics identifier prefix (`TINUA-`, `NTRUA:`), case-insensitive.
fn strip_semantics<'a>(v: &'a str, prefix: &str) -> Option<&'a str> {
    let v = v.trim();
    let head = v.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    v.get(prefix.len()..)
        .map(|r| r.trim_start_matches(['-', ':', ' ']))
}

fn set_rnokpp(info: &mut CertInfo, raw: &str) {
    if info.rnokpp.is_none() {
        info.rnokpp = Some(raw.to_string());
        info.rnokpp_valid = Some(rnokpp_valid(raw));
    }
}

/// Applies a subject attribute. Returns the value as it is shown.
pub fn subject_attr(info: &mut CertInfo, oid: &str, value: &str) -> String {
    match oid {
        OID_SERIAL_NUMBER => {
            if let Some(n) = strip_semantics(value, "TINUA").and_then(|r| digits(r, 10)) {
                set_rnokpp(info, n);
                return value.to_string();
            }
            if let Some(n) = strip_semantics(value, "NTRUA").and_then(|r| digits(r, 8)) {
                info.edrpou.get_or_insert_with(|| n.to_string());
            }
            value.to_string()
        }
        OID_ORG_IDENTIFIER => {
            if let Some(n) = strip_semantics(value, "NTRUA").and_then(|r| digits(r, 8)) {
                info.edrpou.get_or_insert_with(|| n.to_string());
            }
            value.to_string()
        }
        _ => value.to_string(),
    }
}

/// Applies a `SubjectDirectoryAttributes` attribute (legacy UA profile).
pub fn directory_attr(info: &mut CertInfo, oid: &str, value: &str) {
    if !oid.starts_with(OID_UA_ATTR_PREFIX) {
        return;
    }
    let v = value.trim();
    if oid == OID_UA_DRFO || oid.starts_with("1.2.804.2.1.1.1.11.1.4.1.") {
        if let Some(n) = digits(v, 10) {
            set_rnokpp(info, n);
        }
    } else if oid == OID_UA_EDRPOU || oid.starts_with("1.2.804.2.1.1.1.11.1.4.2.") {
        if let Some(n) = digits(v, 8) {
            info.edrpou.get_or_insert_with(|| n.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rnokpp_checksum() {
        // synthetic numbers with a valid check digit
        assert!(rnokpp_valid("1234567899"));
        assert!(!rnokpp_valid("1234567890"));
        assert!(!rnokpp_valid("12345"));
    }

    #[test]
    fn attributes() {
        let mut c = CertInfo::default();
        let shown = subject_attr(&mut c, OID_SERIAL_NUMBER, "TINUA-1234567899");
        assert_eq!(shown, "TINUA-1234567899");
        assert_eq!(c.rnokpp.as_deref(), Some("1234567899"));
        assert_eq!(c.rnokpp_valid, Some(true));
        subject_attr(&mut c, OID_ORG_IDENTIFIER, "NTRUA-12345678");
        assert_eq!(c.edrpou.as_deref(), Some("12345678"));

        let mut l = CertInfo::default();
        directory_attr(&mut l, OID_UA_DRFO, "1234567899");
        directory_attr(&mut l, OID_UA_EDRPOU, "87654321");
        directory_attr(&mut l, "2.5.4.3", "1111111111");
        assert_eq!(l.rnokpp.as_deref(), Some("1234567899"));
        assert_eq!(l.edrpou.as_deref(), Some("87654321"));
    }
}
