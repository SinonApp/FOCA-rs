//! HTTP method checks for the active profile: `OPTIONS` (the `Allow`/`Public`/`DAV` headers),
//! `TRACE` reflection (cross-site tracing) and WebDAV `PROPFIND` with `Depth: 0`, plus the CORS
//! check with a forged `Origin`.
//!
//! Access class `active` (`Access::Active`): these requests run only in the active stage of a
//! scan, on in-scope hosts. `PUT`, `DELETE` and other state-changing methods are never sent:
//! they are reported only when the server itself advertises them in `Allow`. The method
//! allow-list [`PROBE_METHODS`] is enforced in [`send_probe`] for every request of this module.

use serde::{Deserialize, Serialize};

use foca_net::{Access, Method, NetClient, NetError, NetRequest};

use crate::webaudit::fetch::read_capped;

/// Request log module.
pub const MODULE: &str = "recon.methods";
/// The only methods this module may send. Anything else is refused before reaching the network.
pub const PROBE_METHODS: &[&str] = &["OPTIONS", "TRACE", "PROPFIND", "GET"];
/// Methods that change server state; reported from `Allow` only, never sent.
pub const UNSAFE_METHODS: &[&str] = &[
    "PUT",
    "DELETE",
    "PATCH",
    "MOVE",
    "COPY",
    "MKCOL",
    "PROPPATCH",
    "LOCK",
    "UNLOCK",
    "CONNECT",
];
/// The forged origin used by the CORS check (reserved TLD, never resolves).
pub const PROBE_ORIGIN: &str = "https://foca-cors-check.invalid";

const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>"#;

/// Results for one URL.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodsReport {
    pub url: String,
    pub options_status: Option<u16>,
    /// Methods from `Allow` and `Public` (uppercased, deduplicated).
    pub allow: Vec<String>,
    /// `DAV` header (WebDAV compliance classes).
    pub dav: Option<String>,
    /// State-changing methods the server advertises (not verified by sending them).
    pub unsafe_advertised: Vec<String>,
    pub trace_status: Option<u16>,
    /// `TRACE` echoed our marker header back.
    pub trace_reflected: bool,
    pub propfind_status: Option<u16>,
    /// `PROPFIND` answered `207 Multi-Status` with a DAV body.
    pub webdav: bool,
    pub errors: Vec<String>,
}

/// Result of the forged-Origin CORS check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorsProbe {
    pub url: String,
    pub status: Option<u16>,
    /// `Access-Control-Allow-Origin` returned for our forged origin.
    pub allow_origin: Option<String>,
    pub allow_credentials: bool,
    /// The forged origin was echoed back.
    pub reflected: bool,
    pub error: Option<String>,
    /// The request was refused by scope or the active-stage policy (nothing was sent).
    #[serde(default)]
    pub denied: bool,
}

/// Options for [`probe_methods`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodsOptions {
    pub trace: bool,
    pub propfind: bool,
}

impl Default for MethodsOptions {
    fn default() -> Self {
        MethodsOptions {
            trace: true,
            propfind: true,
        }
    }
}

/// Sends one probe. Refuses any method outside [`PROBE_METHODS`].
///
/// # Errors
///
/// `BadUrl` for a forbidden method, otherwise network/scope errors from `NetClient`.
pub async fn send_probe(
    client: &NetClient,
    method: &str,
    url: &str,
    operation: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), NetError> {
    let m = method.to_ascii_uppercase();
    if !PROBE_METHODS.contains(&m.as_str()) {
        return Err(NetError::BadUrl(format!(
            "метод {m} запрещён для проверок (не изменяем данные цели)"
        )));
    }
    let method = Method::from_bytes(m.as_bytes()).map_err(|e| NetError::BadUrl(e.to_string()))?;
    let mut req = NetRequest::new(method, url, MODULE, Access::active(operation))?
        .no_redirects()
        .retries(0);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    if let Some(b) = body {
        req = req.body(b.as_bytes().to_vec());
    }
    let r = client.send(req).await?;
    let st = r.status();
    let hs: Vec<(String, String)> = r
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            Some((
                k.as_str().to_ascii_lowercase(),
                v.to_str().ok()?.to_string(),
            ))
        })
        .collect();
    let (b, _) = read_capped(r, 64 << 10).await?;
    Ok((st, hs, b))
}

fn hv<'a>(h: &'a [(String, String)], n: &str) -> Vec<&'a str> {
    h.iter()
        .filter(|(k, _)| k == n)
        .map(|(_, v)| v.as_str())
        .collect()
}

/// Parses `Allow` / `Public` values into uppercased unique methods.
pub fn parse_allow(values: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in values {
        for m in v.split(',') {
            let m = m.trim().to_ascii_uppercase();
            if !m.is_empty()
                && m.chars().all(|c| c.is_ascii_alphabetic() || c == '-')
                && !out.contains(&m)
            {
                out.push(m);
            }
        }
    }
    out
}

fn marker() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("foca-trace-{:x}", t & 0xffff_ffff_ffff)
}

/// Active profile: `OPTIONS`, then optionally `TRACE` and `PROPFIND` (`Depth: 0`) on `url`.
pub async fn probe_methods(client: &NetClient, url: &str, opts: MethodsOptions) -> MethodsReport {
    let mut r = MethodsReport {
        url: url.into(),
        ..Default::default()
    };
    match send_probe(client, "OPTIONS", url, "http_options", &[], None).await {
        Ok((st, h, _)) => {
            r.options_status = Some(st);
            let mut v = hv(&h, "allow");
            v.extend(hv(&h, "public"));
            v.extend(hv(&h, "access-control-allow-methods"));
            r.allow = parse_allow(&v);
            r.dav = hv(&h, "dav").first().map(|s| s.to_string());
            r.unsafe_advertised = r
                .allow
                .iter()
                .filter(|m| UNSAFE_METHODS.contains(&m.as_str()))
                .cloned()
                .collect();
        }
        Err(e) => {
            let stop = crate::webaudit::fetch::host_denied(&e);
            r.errors.push(format!("OPTIONS: {e}"));
            if stop {
                return r;
            }
        }
    }
    if opts.trace && !client.is_cancelled() {
        let mk = marker();
        match send_probe(
            client,
            "TRACE",
            url,
            "http_trace",
            &[("X-Foca-Trace", &mk)],
            None,
        )
        .await
        {
            Ok((st, _, b)) => {
                r.trace_status = Some(st);
                r.trace_reflected =
                    (200..300).contains(&st) && String::from_utf8_lossy(&b).contains(&mk);
            }
            Err(e) => r.errors.push(format!("TRACE: {e}")),
        }
    }
    if opts.propfind && !client.is_cancelled() {
        match send_probe(
            client,
            "PROPFIND",
            url,
            "webdav_propfind",
            &[
                ("Depth", "0"),
                ("Content-Type", "application/xml; charset=utf-8"),
            ],
            Some(PROPFIND_BODY),
        )
        .await
        {
            Ok((st, _, b)) => {
                r.propfind_status = Some(st);
                let t = String::from_utf8_lossy(&b).to_ascii_lowercase();
                r.webdav = st == 207 && t.contains("multistatus");
            }
            Err(e) => r.errors.push(format!("PROPFIND: {e}")),
        }
    }
    r
}

/// Active profile: a GET with `Origin: PROBE_ORIGIN` to see whether CORS reflects any origin.
pub async fn probe_cors(client: &NetClient, url: &str) -> CorsProbe {
    let mut c = CorsProbe {
        url: url.into(),
        ..Default::default()
    };
    match send_probe(
        client,
        "GET",
        url,
        "cors_origin",
        &[("Origin", PROBE_ORIGIN)],
        None,
    )
    .await
    {
        Ok((st, h, _)) => {
            c.status = Some(st);
            c.allow_origin = hv(&h, "access-control-allow-origin")
                .first()
                .map(|s| s.to_string());
            c.allow_credentials = hv(&h, "access-control-allow-credentials")
                .first()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
            c.reflected = c
                .allow_origin
                .as_deref()
                .is_some_and(|o| o.trim().eq_ignore_ascii_case(PROBE_ORIGIN));
        }
        Err(e) => {
            c.denied = crate::webaudit::fetch::host_denied(&e);
            c.error = Some(e.to_string());
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_parsing() {
        assert_eq!(
            parse_allow(&["GET, HEAD,post", "PUT,DELETE", "get"]),
            ["GET", "HEAD", "POST", "PUT", "DELETE"]
        );
        assert!(!PROBE_METHODS.iter().any(|m| UNSAFE_METHODS.contains(m)));
    }
}
