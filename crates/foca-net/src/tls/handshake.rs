//! TLS handshake inspection with rustls: records the presented chain, version, cipher suite,
//! ALPN and OCSP stapling. The certificate is never trusted here; [`super::audit`] judges it.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foca_core::Severity;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

use super::audit::{audit_chain, handshake_issues, AuditConfig, CertAudit, TrustStatus};
use super::starttls::{self, StartTls};
use super::x509::{parse_cert, pki_hints, CertInfo};
use super::{refuse_passive, Issue};
use crate::client::{Access, NetClient};
use crate::NetError;

/// Request log module of the standard handshake probe.
pub const MODULE: &str = "tls";

/// Handshake options.
#[derive(Debug, Clone)]
pub struct InspectOptions {
    /// Send SNI (the host name). `false` asks for the server's default certificate.
    pub sni: bool,
    /// ALPN protocols to offer.
    pub alpn: Vec<String>,
    /// Connect + handshake timeout (each).
    pub timeout: Duration,
    /// Negotiate STARTTLS (or the protocol-specific TLS upgrade) before the handshake.
    pub starttls: Option<StartTls>,
}

impl Default for InspectOptions {
    fn default() -> Self {
        InspectOptions {
            sni: true,
            alpn: vec!["h2".into(), "http/1.1".into()],
            timeout: Duration::from_secs(8),
            starttls: None,
        }
    }
}

/// What one handshake revealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInspection {
    pub host: String,
    pub port: u16,
    /// Peer IP for direct connections (`None` through a proxy).
    pub ip: Option<String>,
    /// SNI sent, if any.
    pub sni: Option<String>,
    pub starttls: Option<StartTls>,
    /// `TLSv1_3`, `TLSv1_2`.
    pub version: Option<String>,
    /// IANA-style suite name (`TLS13_AES_128_GCM_SHA256`).
    pub cipher: Option<String>,
    pub alpn: Option<String>,
    pub ocsp_stapled: bool,
    /// The ClientHello offered ALPN (`h2`, `http/1.1`) and `status_request`: only then do a
    /// missing ALPN answer and a missing OCSP staple say anything about the server. Legacy
    /// raw-hello probes and STARTTLS handshakes offer neither.
    #[serde(default)]
    pub alpn_offered: bool,
    /// Parsed chain, leaf first (unparseable certificates are skipped).
    pub chain: Vec<CertInfo>,
    /// Raw DER chain as presented, leaf first.
    #[serde(skip)]
    pub chain_der: Vec<Vec<u8>>,
    /// Handshake error after the chain was already received (client certificate required, ...).
    pub error: Option<String>,
}

impl TlsInspection {
    pub fn leaf(&self) -> Option<&CertInfo> {
        self.chain.first()
    }

    /// Audits the chain against the host that was asked for (SNI or the IP).
    pub fn audit(&self, cfg: &AuditConfig) -> Result<CertAudit, NetError> {
        let host = self.sni.clone().unwrap_or_else(|| self.host.clone());
        audit_chain(&self.chain_der, Some(&host), cfg)
    }

    /// `true` when this was a completed rustls handshake that offered `h2`/`http/1.1` ALPN and
    /// `status_request` (rustls always sends it), so ALPN and OCSP results are meaningful.
    pub fn modern_handshake(&self) -> bool {
        self.alpn_offered
            && self.starttls.is_none()
            && self.error.is_none()
            && self.version.is_some()
    }

    /// All finding candidates: certificate audit, handshake (ALPN/OCSP) and internal PKI hints.
    /// Without SNI the hostname check is skipped (the default certificate is expected to differ).
    /// ALPN/OCSP issues come only from a [`Self::modern_handshake`].
    pub fn issues(&self, cfg: &AuditConfig) -> Vec<Issue> {
        let mut v = Vec::new();
        let trusted = match audit_chain(&self.chain_der, self.sni.as_deref(), cfg) {
            Ok(a) => {
                let t = a.trust == TrustStatus::Trusted;
                v.extend(a.issues);
                t
            }
            Err(_) => false,
        };
        if self.modern_handshake() {
            v.extend(handshake_issues(
                self.alpn.as_deref(),
                self.ocsp_stapled,
                trusted,
            ));
        }
        if let Some(leaf) = self.leaf() {
            let internal: Vec<String> = pki_hints(leaf)
                .into_iter()
                .filter(|h| h.internal)
                .map(|h| h.ad_domain.unwrap_or(h.url))
                .collect();
            if !internal.is_empty() {
                v.push(Issue::new(
                    "cert_internal_pki",
                    Severity::Info,
                    internal.join(", "),
                ));
            }
        }
        v
    }
}

/// Records the presented chain and stapled OCSP response; accepts any certificate and any
/// handshake signature (inspection, not trust: nothing is sent over the session).
#[derive(Debug)]
struct Capture {
    provider: Arc<CryptoProvider>,
    chain: Mutex<Vec<Vec<u8>>>,
    ocsp: Mutex<bool>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        inter: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        ocsp: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let mut c = self.chain.lock().unwrap_or_else(|p| p.into_inner());
        *c = std::iter::once(end)
            .chain(inter.iter())
            .map(|d| d.as_ref().to_vec())
            .collect();
        *self.ocsp.lock().unwrap_or_else(|p| p.into_inner()) = !ocsp.is_empty();
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let mut v = self
            .provider
            .signature_verification_algorithms
            .supported_schemes();
        // legacy servers (SHA-1 handshake signatures)
        for s in [
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
        ] {
            if !v.contains(&s) {
                v.push(s);
            }
        }
        v
    }
}

fn server_name(host: &str) -> Result<ServerName<'static>, NetError> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(h.to_string()).map_err(|e| NetError::BadUrl(format!("{host}: {e}")))
}

/// Connects to `host:port` with the given access class and inspects the TLS handshake.
/// `Access::Passive` is refused before any network call. Use the wrappers below for the
/// profile-appropriate access class.
pub async fn inspect(
    net: &NetClient,
    module: &str,
    host: &str,
    port: u16,
    access: Access,
    opts: &InspectOptions,
) -> Result<TlsInspection, NetError> {
    refuse_passive(host, &access)?;
    let name = server_name(host)?;
    let (mut tcp, ip) = crate::tcp::connect(net, module, host, port, &access, opts.timeout).await?;
    if let Some(p) = opts.starttls {
        net.cancellable(starttls::upgrade(&mut tcp, p, opts.timeout))
            .await??;
    }
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let cap = Arc::new(Capture {
        provider: provider.clone(),
        chain: Mutex::new(Vec::new()),
        ocsp: Mutex::new(false),
    });
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| NetError::Request(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(cap.clone())
        .with_no_client_auth();
    cfg.alpn_protocols = opts.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    cfg.enable_sni = opts.sni;
    let conn = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let sni = (opts.sni && matches!(name, ServerName::DnsName(_))).then(|| host.to_string());
    let hs = tokio::time::timeout(opts.timeout, conn.connect(name, tcp));
    let res = net.cancellable(hs).await?;
    let chain_der = cap.chain.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let mut out = TlsInspection {
        host: host.to_string(),
        port,
        ip: ip.map(|i| i.to_string()),
        sni,
        starttls: opts.starttls,
        version: None,
        cipher: None,
        alpn: None,
        ocsp_stapled: *cap.ocsp.lock().unwrap_or_else(|p| p.into_inner()),
        alpn_offered: ["h2", "http/1.1"]
            .iter()
            .all(|p| opts.alpn.iter().any(|a| a == p)),
        chain: chain_der
            .iter()
            .filter_map(|d| parse_cert(d).ok())
            .collect(),
        chain_der,
        error: None,
    };
    match res {
        Ok(Ok(s)) => {
            let c = s.get_ref().1;
            out.version = c.protocol_version().map(|v| format!("{v:?}"));
            out.cipher = c
                .negotiated_cipher_suite()
                .map(|s| format!("{:?}", s.suite()));
            out.alpn = c
                .alpn_protocol()
                .map(|a| String::from_utf8_lossy(a).into_owned());
        }
        Ok(Err(e)) => out.error = Some(e.to_string()),
        Err(_) => out.error = Some("handshake timeout".into()),
    }
    if out.chain_der.is_empty() {
        return Err(match out.error {
            Some(e) if e == "handshake timeout" => NetError::Timeout,
            Some(e) => NetError::Request(format!("tls: {e}")),
            None => NetError::Request("tls: no certificate".into()),
        });
    }
    Ok(out)
}

/// Standard-profile probe: handshake on a web/TLS port of an in-scope host (`TouchesTarget`).
pub async fn inspect_standard(
    net: &NetClient,
    host: &str,
    port: u16,
    opts: &InspectOptions,
) -> Result<TlsInspection, NetError> {
    inspect(net, MODULE, host, port, Access::TouchesTarget, opts).await
}

/// Active probe: handshake without SNI (typically to an IP) to get the default certificate of
/// an appliance or confirm an origin IP behind a CDN.
pub async fn inspect_no_sni(
    net: &NetClient,
    host: &str,
    port: u16,
    opts: &InspectOptions,
) -> Result<TlsInspection, NetError> {
    let o = InspectOptions {
        sni: false,
        ..opts.clone()
    };
    inspect(
        net,
        "tls-no-sni",
        host,
        port,
        Access::active("tls-no-sni"),
        &o,
    )
    .await
}

/// Compares a no-SNI inspection with the SNI one: a different default certificate is worth
/// showing (appliance identity, other tenants), and a default certificate that names the target
/// on a bare IP confirms an origin server behind a CDN.
pub fn no_sni_issue(no_sni: &TlsInspection, target: &str) -> Option<Issue> {
    let leaf = no_sni.leaf()?;
    if leaf.matches_host(target) {
        return Some(Issue::new(
            "tls_origin_confirmed",
            Severity::Low,
            format!(
                "{}:{} serves a certificate for {target} without SNI",
                no_sni.host, no_sni.port
            ),
        ));
    }
    Some(Issue::new(
        "tls_default_cert",
        Severity::Info,
        format!(
            "{}:{} default certificate: {}",
            no_sni.host,
            no_sni.port,
            leaf.names().join(", ")
        ),
    ))
}

/// Active probe: STARTTLS upgrade + handshake. `proto` defaults to [`StartTls::for_port`].
pub async fn starttls_inspect(
    net: &NetClient,
    host: &str,
    port: u16,
    proto: Option<StartTls>,
    opts: &InspectOptions,
) -> Result<TlsInspection, NetError> {
    let p = proto
        .or_else(|| StartTls::for_port(port))
        .ok_or_else(|| NetError::BadUrl(format!("no STARTTLS protocol for port {port}")))?;
    let o = InspectOptions {
        starttls: Some(p),
        alpn: Vec::new(),
        ..opts.clone()
    };
    inspect(
        net,
        starttls::MODULE,
        host,
        port,
        Access::active("starttls"),
        &o,
    )
    .await
}
