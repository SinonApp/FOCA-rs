//! Protocol upgrades to TLS on plaintext ports: SMTP/IMAP/POP3/FTP STARTTLS, PostgreSQL
//! `SSLRequest` and RDP X.224 negotiation (`PROTOCOL_SSL`). Active only.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::NetError;

/// Request log module of STARTTLS probes.
pub const MODULE: &str = "starttls";

/// Max bytes read from a plaintext greeting/reply.
const MAX_REPLY: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StartTls {
    Smtp,
    Imap,
    Pop3,
    Ftp,
    Postgres,
    Rdp,
}

impl StartTls {
    /// Upgrade protocol of a well-known plaintext port.
    pub fn for_port(port: u16) -> Option<StartTls> {
        Some(match port {
            25 | 587 => StartTls::Smtp,
            143 => StartTls::Imap,
            110 => StartTls::Pop3,
            21 => StartTls::Ftp,
            5432 => StartTls::Postgres,
            3389 => StartTls::Rdp,
            _ => return None,
        })
    }

    /// Default ports probed for STARTTLS certificates.
    pub const PORTS: [u16; 7] = [25, 587, 143, 110, 21, 5432, 3389];

    pub fn as_str(self) -> &'static str {
        match self {
            StartTls::Smtp => "smtp",
            StartTls::Imap => "imap",
            StartTls::Pop3 => "pop3",
            StartTls::Ftp => "ftp",
            StartTls::Postgres => "postgres",
            StartTls::Rdp => "rdp",
        }
    }
}

fn refused(p: StartTls, what: &str) -> NetError {
    NetError::Parse(format!("{}: {what}", p.as_str()))
}

/// Reads until `done(buf)` holds, the peer closes, or the limit is reached.
async fn read_until<S, F>(s: &mut S, wait: Duration, done: F) -> Result<Vec<u8>, NetError>
where
    S: AsyncRead + Unpin,
    F: Fn(&[u8]) -> bool,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let fut = async {
        loop {
            let n = s.read(&mut chunk).await?;
            if n == 0 {
                return Ok::<_, NetError>(());
            }
            buf.extend_from_slice(&chunk[..n]);
            if done(&buf) || buf.len() >= MAX_REPLY {
                return Ok(());
            }
        }
    };
    tokio::time::timeout(wait, fut)
        .await
        .map_err(|_| NetError::Timeout)??;
    Ok(buf)
}

/// Last complete line of a reply.
fn last_line(buf: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(buf).ok()?;
    if !s.ends_with('\n') {
        return None;
    }
    s.trim_end_matches(['\r', '\n']).rsplit('\n').next()
}

/// A complete multi-line SMTP/FTP reply: the last line is `NNN ` (code + space).
fn reply_done(buf: &[u8]) -> bool {
    last_line(buf).is_some_and(|l| {
        let b = l.as_bytes();
        b.len() >= 4 && b[..3].iter().all(u8::is_ascii_digit) && b[3] == b' '
    })
}

fn code(buf: &[u8]) -> Option<&str> {
    last_line(buf).and_then(|l| l.get(..3))
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, b: &[u8]) -> Result<(), NetError> {
    s.write_all(b).await?;
    s.flush().await?;
    Ok(())
}

/// Runs the protocol-specific upgrade on a fresh plaintext connection; on success the next
/// bytes on the stream are the TLS handshake.
pub async fn upgrade<S>(s: &mut S, p: StartTls, wait: Duration) -> Result<(), NetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match p {
        StartTls::Smtp => {
            let g = read_until(s, wait, reply_done).await?;
            if code(&g) != Some("220") {
                return Err(refused(p, "no 220 greeting"));
            }
            send(s, b"EHLO foca.invalid\r\n").await?;
            let ehlo = read_until(s, wait, reply_done).await?;
            if code(&ehlo) != Some("250") {
                return Err(refused(p, "EHLO rejected"));
            }
            if !String::from_utf8_lossy(&ehlo)
                .to_ascii_uppercase()
                .contains("STARTTLS")
            {
                return Err(refused(p, "STARTTLS not offered"));
            }
            send(s, b"STARTTLS\r\n").await?;
            let r = read_until(s, wait, reply_done).await?;
            if code(&r) != Some("220") {
                return Err(refused(p, "STARTTLS rejected"));
            }
        }
        StartTls::Ftp => {
            let g = read_until(s, wait, reply_done).await?;
            if code(&g) != Some("220") {
                return Err(refused(p, "no 220 greeting"));
            }
            send(s, b"AUTH TLS\r\n").await?;
            let r = read_until(s, wait, reply_done).await?;
            if code(&r) != Some("234") {
                return Err(refused(p, "AUTH TLS rejected"));
            }
        }
        StartTls::Imap => {
            let g = read_until(s, wait, |b| last_line(b).is_some()).await?;
            if !g.starts_with(b"* OK") {
                return Err(refused(p, "no * OK greeting"));
            }
            send(s, b"a1 STARTTLS\r\n").await?;
            let r = read_until(s, wait, |b| {
                last_line(b).is_some_and(|l| l.starts_with("a1 "))
            })
            .await?;
            if !last_line(&r).is_some_and(|l| l.starts_with("a1 OK")) {
                return Err(refused(p, "STARTTLS rejected"));
            }
        }
        StartTls::Pop3 => {
            let g = read_until(s, wait, |b| last_line(b).is_some()).await?;
            if !g.starts_with(b"+OK") {
                return Err(refused(p, "no +OK greeting"));
            }
            send(s, b"STLS\r\n").await?;
            let r = read_until(s, wait, |b| last_line(b).is_some()).await?;
            if !r.starts_with(b"+OK") {
                return Err(refused(p, "STLS rejected"));
            }
        }
        StartTls::Postgres => {
            // SSLRequest: length 8, code 80877103
            send(s, &[0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]).await?;
            let mut b = [0u8; 1];
            tokio::time::timeout(wait, s.read_exact(&mut b))
                .await
                .map_err(|_| NetError::Timeout)??;
            if b[0] != b'S' {
                return Err(refused(p, "SSL not supported"));
            }
        }
        StartTls::Rdp => {
            send(s, &rdp_negotiation_request()).await?;
            let mut hdr = [0u8; 4];
            tokio::time::timeout(wait, s.read_exact(&mut hdr))
                .await
                .map_err(|_| NetError::Timeout)??;
            let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
            if hdr[0] != 3 || !(11..=512).contains(&len) {
                return Err(refused(p, "not a TPKT reply"));
            }
            let mut body = vec![0u8; len - 4];
            tokio::time::timeout(wait, s.read_exact(&mut body))
                .await
                .map_err(|_| NetError::Timeout)??;
            parse_rdp_confirm(&body).map_err(|e| refused(p, e))?;
        }
    }
    Ok(())
}

/// TPKT + X.224 Connection Request + RDP_NEG_REQ asking for TLS or CredSSP (MS-RDPBCGR 2.2.1.1).
pub fn rdp_negotiation_request() -> Vec<u8> {
    vec![
        0x03, 0x00, 0x00, 0x13, // TPKT, length 19
        0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR
        0x01, 0x00, 0x08, 0x00, // RDP_NEG_REQ, flags, length 8
        0x03, 0x00, 0x00, 0x00, // PROTOCOL_SSL | PROTOCOL_HYBRID
    ]
}

/// Parses the X.224 Connection Confirm body (after TPKT): TLS follows when the server selected
/// SSL (1), HYBRID (2) or HYBRID_EX (8).
fn parse_rdp_confirm(b: &[u8]) -> Result<u32, &'static str> {
    if b.len() < 6 || b[1] & 0xf0 != 0xd0 {
        return Err("not an X.224 connection confirm");
    }
    let neg = &b[7.min(b.len())..];
    if neg.len() < 8 {
        return Err("standard RDP security only (no TLS)");
    }
    let proto = u32::from_le_bytes([neg[4], neg[5], neg[6], neg[7]]);
    match neg[0] {
        0x02 if proto & 0x0b != 0 => Ok(proto),
        0x02 => Err("standard RDP security only (no TLS)"),
        0x03 => Err("negotiation failure"),
        _ => Err("unexpected negotiation reply"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_parsing() {
        assert!(reply_done(b"250-a\r\n250-STARTTLS\r\n250 OK\r\n"));
        assert!(!reply_done(b"250-a\r\n250-STARTTLS\r\n"));
        assert!(!reply_done(b"250 OK"));
        assert_eq!(code(b"220-x\r\n220 ready\r\n"), Some("220"));
        assert_eq!(StartTls::for_port(587), Some(StartTls::Smtp));
        assert_eq!(StartTls::for_port(443), None);
    }

    #[test]
    fn rdp_confirm() {
        let ok = [
            0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 0x02, 0, 0x08, 0, 1, 0, 0, 0,
        ];
        assert_eq!(parse_rdp_confirm(&ok), Ok(1));
        let fail = [
            0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 0x03, 0, 0x08, 0, 5, 0, 0, 0,
        ];
        assert!(parse_rdp_confirm(&fail).is_err());
        assert!(parse_rdp_confirm(&[0x06, 0xd0, 0, 0, 0, 0, 0]).is_err());
        assert_eq!(rdp_negotiation_request().len(), 19);
    }
}
