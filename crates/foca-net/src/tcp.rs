//! TCP liveness checks and TCP connections for active modules.
//!
//! A connection is made only after the scope check (`TouchesTarget`/`Active`), to already
//! verified IPs (no second resolution), and through the proxy when one is configured (SOCKS5 or
//! HTTP CONNECT). The proxy is never bypassed (OPSEC, kill switch).

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::client::{Access, NetClient};
use crate::NetError;

/// Default ports for liveness checks.
pub const DEFAULT_PORTS: &[u16] = &[80, 443];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortState {
    pub port: u16,
    pub open: bool,
    #[serde(default)]
    pub verified: bool,
    pub ip: Option<String>,
    pub ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostAlive {
    pub host: String,
    pub alive: bool,
    #[serde(default)]
    pub unreliable: bool,
    pub ports: Vec<PortState>,
}

async fn socks5_connect(
    s: &mut TcpStream,
    proxy: &url::Url,
    host: &str,
    ip: Option<IpAddr>,
    port: u16,
) -> Result<(), NetError> {
    let user = proxy.username();
    let pass = proxy.password().unwrap_or("");
    if user.len() > 255 || pass.len() > 255 || host.len() > 255 {
        return Err(NetError::Proxy(
            "SOCKS5: длина хоста/логина/пароля превышает 255 байт".into(),
        ));
    }
    let auth = !user.is_empty();
    if auth {
        s.write_all(&[5, 2, 0, 2]).await?;
    } else {
        s.write_all(&[5, 1, 0]).await?;
    }
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    if r[0] != 5 {
        return Err(NetError::Proxy("не SOCKS5".into()));
    }
    match r[1] {
        0 => {}
        2 if auth => {
            let mut m = vec![1, user.len() as u8];
            m.extend_from_slice(user.as_bytes());
            m.push(pass.len() as u8);
            m.extend_from_slice(pass.as_bytes());
            s.write_all(&m).await?;
            s.read_exact(&mut r).await?;
            if r[1] != 0 {
                return Err(NetError::Proxy("SOCKS5: неверный логин/пароль".into()));
            }
        }
        _ => {
            return Err(NetError::Proxy(
                "SOCKS5: метод аутентификации не принят".into(),
            ))
        }
    }
    let mut m = vec![5, 1, 0];
    match (proxy.scheme() == "socks5h", ip) {
        (false, Some(IpAddr::V4(v))) => {
            m.push(1);
            m.extend_from_slice(&v.octets());
        }
        (false, Some(IpAddr::V6(v))) => {
            m.push(4);
            m.extend_from_slice(&v.octets());
        }
        _ => {
            m.push(3);
            m.push(host.len() as u8);
            m.extend_from_slice(host.as_bytes());
        }
    }
    m.extend_from_slice(&port.to_be_bytes());
    s.write_all(&m).await?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    if h[1] != 0 {
        return Err(NetError::Proxy(format!(
            "SOCKS5: отказ соединения (код {})",
            h[1]
        )));
    }
    let skip = match h[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        _ => return Err(NetError::Proxy("SOCKS5: неверный ответ".into())),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await?;
    Ok(())
}

fn has_crlf(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r' || b == b'\n')
}

async fn http_connect(
    s: &mut TcpStream,
    proxy: &url::Url,
    host: &str,
    port: u16,
) -> Result<(), NetError> {
    let user = proxy.username();
    let pass = proxy.password().unwrap_or("");
    if has_crlf(host) || has_crlf(user) || has_crlf(pass) {
        return Err(NetError::Proxy(
            "HTTP CONNECT: недопустимые символы CR/LF".into(),
        ));
    }
    let auth_hdr = if !user.is_empty() || proxy.password().is_some() {
        let creds = foca_core::b64::encode(format!("{user}:{pass}").as_bytes());
        format!("Proxy-Authorization: Basic {creds}\r\n")
    } else {
        String::new()
    };
    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth_hdr}\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await? == 0 || buf.len() > 8192 {
            return Err(NetError::Proxy("HTTP CONNECT: обрыв".into()));
        }
        buf.push(b[0]);
    }
    let line = String::from_utf8_lossy(&buf);
    let code = line.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(NetError::Proxy(format!("HTTP CONNECT: {code}")));
    }
    Ok(())
}

/// Opens a TCP connection to `host:port` with scope check, rate limit, logging and proxy support.
/// Returns the stream and the IP (for direct connections).
pub async fn connect(
    net: &NetClient,
    module: &str,
    host: &str,
    port: u16,
    access: &Access,
    timeout: Duration,
) -> Result<(TcpStream, Option<IpAddr>), NetError> {
    let url = format!("tcp://{host}:{port}");
    let ips = net
        .authorize_logged(module, "TCP", &url, host, access)
        .await?;
    let _permit = net.permit().await?;
    net.rate_limit(module).await?;
    let mut rec = net.draft(module, "TCP", &url, host, access);
    let res = dial(net, host, &ips, port, timeout);
    let r = net.cancellable(res).await.and_then(|x| x);
    match &r {
        Ok((_, ip)) => {
            rec.status = Some(0);
            if let Some(ip) = ip {
                rec.error = None;
                rec.url = format!("tcp://{host}:{port} ({ip})");
            }
        }
        Err(e) => rec.error = Some(format!("{}: {e}", e.code())),
    }
    net.record(rec);
    r
}

/// Connects to already verified `ips`, or through the configured proxy (never bypassing it).
/// Performs no scope check, rate limiting or logging; that is the caller's job.
pub(crate) async fn dial(
    net: &NetClient,
    host: &str,
    ips: &[IpAddr],
    port: u16,
    timeout: Duration,
) -> Result<(TcpStream, Option<IpAddr>), NetError> {
    if let Some(p) = net
        .config()
        .proxy
        .as_deref()
        .filter(|p| !p.trim().is_empty())
    {
        let pu = url::Url::parse(p.trim()).map_err(|e| NetError::Proxy(e.to_string()))?;
        let addr = format!(
            "{}:{}",
            pu.host_str().unwrap_or(""),
            pu.port_or_known_default().unwrap_or(1080)
        );
        let mut s = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| NetError::Timeout)??;
        let ip = ips.first().copied();
        let hs = async {
            match pu.scheme() {
                "socks5" | "socks5h" => socks5_connect(&mut s, &pu, host, ip, port).await,
                "http" => http_connect(&mut s, &pu, host, port).await,
                other => Err(NetError::Proxy(format!(
                    "схема {other} не поддерживается для TCP: прямой выход запрещён"
                ))),
            }
        };
        tokio::time::timeout(timeout, hs)
            .await
            .map_err(|_| NetError::Timeout)??;
        return Ok((s, None));
    }
    let mut last = NetError::Dns(format!("{host}: нет адресов"));
    for ip in ips {
        match tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(*ip, port))).await {
            Ok(Ok(s)) => return Ok((s, Some(*ip))),
            Ok(Err(e)) => last = NetError::Request(e.to_string()),
            Err(_) => last = NetError::Timeout,
        }
    }
    Err(last)
}

async fn http_probe(s: &mut TcpStream, host: &str, timeout: Duration) -> bool {
    let req = format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if tokio::time::timeout(timeout, s.write_all(req.as_bytes()))
        .await
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 64];
    matches!(
        tokio::time::timeout(timeout, s.read(&mut buf)).await,
        Ok(Ok(n)) if n >= 5 && buf[..n].starts_with(b"HTTP/")
    )
}

async fn verify_peer_protocol(mut s: TcpStream, host: &str, port: u16, timeout: Duration) -> bool {
    match port {
        443 | 8443 | 465 | 993 | 995 | 990 => {
            let Some(conn) = tls_connector() else {
                return false;
            };
            let sni = match host.parse::<IpAddr>() {
                Ok(ip) => ServerName::IpAddress(ip.into()),
                Err(_) => {
                    let Ok(dn) = ServerName::try_from(host.to_string()) else {
                        return false;
                    };
                    dn
                }
            };
            matches!(
                tokio::time::timeout(timeout, conn.connect(sni, s)).await,
                Ok(Ok(_))
            )
        }
        80 | 8080 | 8000 | 8888 => http_probe(&mut s, host, timeout).await,
        _ => {
            let half = (timeout / 2).max(Duration::from_millis(80));
            let mut buf = [0u8; 64];
            match tokio::time::timeout(half, s.read(&mut buf)).await {
                Ok(Ok(n)) => n > 0,
                Ok(Err(_)) => false,
                Err(_) => http_probe(&mut s, host, timeout.saturating_sub(half).max(half)).await,
            }
        }
    }
}

/// Checks host liveness with TCP connects to `ports` (`TouchesTarget`).
/// When `verify_proto` is `true`, each accepted TCP socket must also produce a valid TLS,
/// HTTP, or banner response so fake local VPN/AdGuard accept-all sockets are rejected.
pub async fn tcp_alive_checked(
    net: &NetClient,
    host: &str,
    ports: &[u16],
    timeout: Duration,
    verify_proto: bool,
) -> Result<HostAlive, NetError> {
    let mut out = Vec::new();
    let mut any_unverified = false;
    let proto_timeout = timeout.min(Duration::from_millis(1500));
    for &port in ports {
        let t = Instant::now();
        match connect(net, "ping", host, port, &Access::TouchesTarget, timeout).await {
            Ok((s, ip)) => {
                if verify_proto {
                    let ok = verify_peer_protocol(s, host, port, proto_timeout).await;
                    if ok {
                        out.push(PortState {
                            port,
                            open: true,
                            verified: true,
                            ip: ip.map(|i| i.to_string()),
                            ms: t.elapsed().as_millis() as u64,
                            error: None,
                        });
                    } else {
                        any_unverified = true;
                        out.push(PortState {
                            port,
                            open: false,
                            verified: false,
                            ip: ip.map(|i| i.to_string()),
                            ms: t.elapsed().as_millis() as u64,
                            error: Some("unverified_tcp_intercept".into()),
                        });
                    }
                } else {
                    drop(s);
                    out.push(PortState {
                        port,
                        open: true,
                        verified: true,
                        ip: ip.map(|i| i.to_string()),
                        ms: t.elapsed().as_millis() as u64,
                        error: None,
                    });
                }
            }
            Err(e) if e.is_scope_denial() || e == NetError::Cancelled => return Err(e),
            Err(e) => out.push(PortState {
                port,
                open: false,
                verified: false,
                ip: None,
                ms: t.elapsed().as_millis() as u64,
                error: Some(e.to_string()),
            }),
        }
    }
    let alive = out.iter().any(|p| p.open);
    Ok(HostAlive {
        host: host.to_string(),
        alive,
        unreliable: verify_proto && any_unverified && !alive,
        ports: out,
    })
}

/// Checks host liveness with TCP connects to the given ports (`TouchesTarget`).
pub async fn tcp_alive(
    net: &NetClient,
    host: &str,
    ports: &[u16],
    timeout: Duration,
) -> Result<HostAlive, NetError> {
    tcp_alive_checked(net, host, ports, timeout, false).await
}

#[derive(Debug)]
struct AcceptAny(Arc<tokio_rustls::rustls::crypto::CryptoProvider>);

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        d: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        tokio_rustls::rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        d: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        tokio_rustls::rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS connector that accepts any certificate: used to read banners and certificates, never
/// to trust them.
pub(crate) fn tls_connector() -> Option<tokio_rustls::TlsConnector> {
    static C: OnceLock<Option<tokio_rustls::TlsConnector>> = OnceLock::new();
    C.get_or_init(|| {
        let prov = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let cfg = tokio_rustls::rustls::ClientConfig::builder_with_provider(prov.clone())
            .with_safe_default_protocol_versions()
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(prov)))
            .with_no_client_auth();
        Some(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
    })
    .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::MemorySink;
    use crate::NetConfig;
    use foca_core::{Scope, Target};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    fn local_client() -> NetClient {
        let mut sc = Scope::default();
        sc.targets.push(Target::parse("127.0.0.1").unwrap());
        NetClient::new(NetConfig::default(), sc, Arc::new(MemorySink::new())).unwrap()
    }

    #[tokio::test]
    async fn silent_accept_all_listener_fails_proto_verification() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let _srv = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = l.accept().await {
                held.push(s);
            }
        });
        let net = local_client();
        let res = tcp_alive_checked(&net, "127.0.0.1", &[port], Duration::from_millis(250), true)
            .await
            .unwrap();
        assert!(!res.alive, "{res:?}");
        assert!(res.unreliable, "{res:?}");
        assert!(!res.ports[0].open);
        assert!(!res.ports[0].verified);
    }

    #[tokio::test]
    async fn real_http_and_passive_banner_pass_proto_verification() {
        let http_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http_l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = http_l.accept().await {
                let mut req = [0u8; 256];
                let _ = s.read(&mut req).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });

        let ssh_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_port = ssh_l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = ssh_l.accept().await {
                let _ = s.write_all(b"SSH-2.0-OpenSSH_9.0\r\n").await;
            }
        });

        let net = local_client();
        let res = tcp_alive_checked(
            &net,
            "127.0.0.1",
            &[http_port, ssh_port],
            Duration::from_millis(600),
            true,
        )
        .await
        .unwrap();
        assert!(res.alive, "{res:?}");
        assert!(!res.unreliable, "{res:?}");
        assert!(res.ports[0].open && res.ports[0].verified);
        assert!(res.ports[1].open && res.ports[1].verified);
    }

    #[tokio::test]
    async fn socks5_rejects_overlong_fields_and_http_connect_rejects_crlf() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { while l.accept().await.is_ok() {} });

        let mut s = TcpStream::connect(addr).await.unwrap();
        let long_user = "a".repeat(260);
        let pu = url::Url::parse(&format!(
            "socks5h://{long_user}:pw@127.0.0.1:{}",
            addr.port()
        ))
        .unwrap();
        let err = socks5_connect(&mut s, &pu, "example.test", None, 443)
            .await
            .unwrap_err();
        assert!(matches!(err, NetError::Proxy(_)), "{err:?}");

        let mut s2 = TcpStream::connect(addr).await.unwrap();
        let pu2 = url::Url::parse(&format!("http://127.0.0.1:{}", addr.port())).unwrap();
        let err2 = http_connect(&mut s2, &pu2, "bad.host\r\nX-Injected: 1", 80)
            .await
            .unwrap_err();
        assert!(matches!(err2, NetError::Proxy(_)), "{err2:?}");
    }
}
