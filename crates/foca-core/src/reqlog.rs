//! Request log errors. The network layer stores an error as `code: detail`, where `code` is
//! `NetError::code` and `detail` is the error text as the core wrote it (Russian in every
//! version so far). [`LogError::parse`] splits that text into a stable kind and the detail;
//! the in-app journal and the report exports both read errors through it, and each edge
//! renders the detail in its own language.

/// Codes that prefix request log errors (`code: detail`): `NetError::code` plus `limit`, which
/// the client writes when a service already answered 429 in the scan.
const ERROR_CODES: &[&str] = &[
    "out_of_scope",
    "not_active_phase",
    "cancelled",
    "timeout",
    "http_status",
    "too_large",
    "too_many_redirects",
    "bad_url",
    "dns",
    "network",
    "proxy",
    "parse",
    "io",
    "nokey",
    "limit",
];

/// A request log error split into a stable kind and the stored detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogError {
    /// Stable kind: one of the stored codes, a network failure narrowed by its cause
    /// (`refused`, `tls`, `dns`, `timeout`, `unreachable`), `redirect`, or `other` for text
    /// without a known code.
    pub kind: &'static str,
    /// Text after the code as stored (the whole text for `other`), `None` when there is none.
    pub detail: Option<String>,
}

impl LogError {
    /// Classifies a stored error; `None` for an empty one. Works for rows of every version
    /// because the code prefix and the cause markers it reads never changed.
    pub fn parse(err: Option<&str>) -> Option<LogError> {
        let e = err.map(str::trim).filter(|e| !e.is_empty())?;
        let fixed = |kind, detail: Option<&str>| {
            Some(LogError {
                kind,
                detail: detail.map(str::to_string),
            })
        };
        if e == "cancelled" {
            return fixed("cancelled", None);
        }
        if let Some(st) = e.strip_prefix("retry: ") {
            return fixed("http_status", Some(st));
        }
        if let Some(to) = e.strip_prefix("redirect → ") {
            return fixed("redirect", Some(to));
        }
        let (code, detail) = e
            .split_once(": ")
            .and_then(|(c, d)| ERROR_CODES.iter().find(|k| **k == c).map(|k| (*k, d)))
            .unwrap_or(("other", e));
        let kind = if matches!(code, "network" | "io" | "other") {
            narrow(&detail.to_lowercase()).unwrap_or(code)
        } else {
            code
        };
        fixed(kind, Some(detail))
    }
}

/// Narrows a generic network failure by the cause named in its (lowercase) text.
fn narrow(low: &str) -> Option<&'static str> {
    let has = |keys: &[&str]| keys.iter().any(|k| low.contains(k));
    if has(&["connection refused", "os error 111"]) {
        Some("refused")
    } else if has(&["tls", "ssl", "certificate", "handshake", "close_notify"]) {
        Some("tls")
    } else if has(&["dns error", "failed to lookup"]) {
        Some("dns")
    } else if has(&["timed out", "таймаут"]) {
        Some("timeout")
    } else if has(&["unreachable"]) {
        Some("unreachable")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::LogError;

    fn k(e: &str) -> (&'static str, Option<String>) {
        let l = LogError::parse(Some(e)).expect("classified");
        (l.kind, l.detail)
    }

    #[test]
    fn stored_errors_get_stable_kinds() {
        assert_eq!(k("timeout: таймаут").0, "timeout");
        assert_eq!(
            k("out_of_scope: вне скоупа: a.example (в исключениях скоупа)"),
            (
                "out_of_scope",
                Some("вне скоупа: a.example (в исключениях скоупа)".into())
            )
        );
        assert_eq!(k("http_status: HTTP 503").0, "http_status");
        assert_eq!(
            k("retry: HTTP 429"),
            ("http_status", Some("HTTP 429".into()))
        );
        assert_eq!(
            k("network: сеть: error sending request: tcp connect error: Connection refused (os error 111)").0,
            "refused"
        );
        assert_eq!(
            k("network: сеть: invalid peer certificate: UnknownIssuer").0,
            "tls"
        );
        assert_eq!(k("dns: DNS: no record").0, "dns");
        assert_eq!(k("cancelled"), ("cancelled", None));
        assert_eq!(k("something odd"), ("other", Some("something odd".into())));
        assert_eq!(LogError::parse(None), None);
        assert_eq!(LogError::parse(Some("  ")), None);
    }

    /// Russian texts written by older cores, exactly as found in a phone export.
    #[test]
    fn old_russian_rows_keep_their_codes() {
        for (e, kind, detail) in [
            (
                "too_large: превышен лимит размера 256 байт",
                "too_large",
                "превышен лимит размера 256 байт",
            ),
            ("timeout: таймаут", "timeout", "таймаут"),
            (
                "limit: сервис уже ответил 429 в этом скане, запрос не отправлен",
                "limit",
                "сервис уже ответил 429 в этом скане, запрос не отправлен",
            ),
            (
                "network: сеть: трансфер отклонён: Query Refused",
                "network",
                "сеть: трансфер отклонён: Query Refused",
            ),
            (
                "network: сеть: error sending request for url (https://a.example/)",
                "network",
                "сеть: error sending request for url (https://a.example/)",
            ),
            (
                "out_of_scope: вне скоупа: mta-sts.example.com (нет в целях или в исключениях)",
                "out_of_scope",
                "вне скоупа: mta-sts.example.com (нет в целях или в исключениях)",
            ),
        ] {
            assert_eq!(k(e), (kind, Some(detail.to_string())), "{e}");
        }
    }
}
