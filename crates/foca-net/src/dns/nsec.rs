//! DNSSEC NSEC zone walking.
//!
//! A zone signed with NSEC (not NSEC3) links every owner name to the next one in canonical order,
//! so following the chain from the apex lists the whole zone without guessing a single name. The
//! walk asks an authoritative server for the NSEC record of the current name (and, if that is not
//! answered directly, for the nonexistent name `\000.<current>`, whose denial carries the same
//! record), then moves to the next name until the chain returns to the apex.
//!
//! The walk stops without enumerating when the zone uses NSEC3 (hashed names), when the server
//! synthesizes minimal NSEC records on the fly ("black lies": the next name is `\000.<owner>`),
//! on a loop, a name outside the zone, or the configured limit.
//!
//! This is an active module, like AXFR: it runs only during the active stage for a zone in scope
//! (`Scope::check_active(zone)`), talks only to the zone's authoritative name servers over TCP/53
//! (`Access::ZoneInfra`, through the configured proxy if any), never contacts excluded servers, and
//! logs every query.

use std::collections::HashSet;
use std::time::Duration;

use hickory_resolver::proto::op::{Message, ResponseCode};
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::client::{Access, NetClient};
use crate::dns::{norm_name, DnsLookup, RType};
use crate::NetError;

/// Request log module name.
pub const MODULE: &str = "nsec";

const T_A: u16 = 1;
const T_NSEC: u16 = 47;
const T_NSEC3: u16 = 50;
const T_NSEC3PARAM: u16 = 51;

/// A domain name as raw lowercase labels (NSEC chains may contain binary labels such as `\000`).
pub type Labels = Vec<Vec<u8>>;

/// Splits a presentation name into labels (no escapes; used for zone names from settings).
pub fn labels_of(name: &str) -> Labels {
    norm_name(name)
        .split('.')
        .filter(|l| !l.is_empty())
        .map(|l| l.as_bytes().to_vec())
        .collect()
}

/// Formats labels as a presentation name, escaping bytes outside `[a-z0-9-_*]` as `\DDD`.
pub fn labels_to_string(l: &Labels) -> String {
    let mut s = String::new();
    for (i, lab) in l.iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        for &b in lab {
            if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'*' {
                s.push(b as char);
            } else {
                s.push_str(&format!("\\{b:03}"));
            }
        }
    }
    s
}

fn lower(l: &[u8]) -> Vec<u8> {
    l.to_ascii_lowercase()
}

fn is_under(name: &Labels, zone: &Labels) -> bool {
    name.len() >= zone.len() && name[name.len() - zone.len()..] == zone[..]
}

/// Encodes a query in TCP framing, with an EDNS OPT record (4096-byte payload, DO bit set) and
/// recursion not desired.
pub fn encode_query(name: &Labels, qtype: u16, id: u16) -> Vec<u8> {
    let mut m = Vec::with_capacity(64);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
    for l in name {
        m.push(l.len().min(63) as u8);
        m.extend_from_slice(&l[..l.len().min(63)]);
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    // OPT: root name, type 41, class = payload size, TTL = ext-rcode/version/flags (DO), no options
    m.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0x80, 0, 0, 0]);
    let mut out = (m.len() as u16).to_be_bytes().to_vec();
    out.extend(m);
    out
}

/// Parses NSEC RDATA: the next owner name (uncompressed, RFC 4034 4.1.1) and the type bitmap.
pub fn parse_nsec_rdata(d: &[u8]) -> Option<(Labels, Vec<u16>)> {
    let mut i = 0;
    let mut next = Vec::new();
    loop {
        let len = *d.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        next.push(lower(d.get(i..i + len)?));
        i += len;
    }
    let mut types = Vec::new();
    while i < d.len() {
        let block = *d.get(i)? as u16;
        let len = *d.get(i + 1)? as usize;
        if len == 0 || len > 32 {
            return None;
        }
        let bm = d.get(i + 2..i + 2 + len)?;
        for (j, byte) in bm.iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    types.push(block * 256 + (j * 8 + bit) as u16);
                }
            }
        }
        i += 2 + len;
    }
    Some((next, types))
}

/// Encodes NSEC RDATA (used by test fixtures and documented here for symmetry with the parser).
pub fn encode_nsec_rdata(next: &Labels, types: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    for l in next {
        out.push(l.len() as u8);
        out.extend_from_slice(l);
    }
    out.push(0);
    let mut ts: Vec<u16> = types.to_vec();
    ts.sort_unstable();
    ts.dedup();
    let mut b = 0;
    while b < ts.len() {
        let block = ts[b] >> 8;
        let mut bm = [0u8; 32];
        let mut maxb = 0;
        while b < ts.len() && ts[b] >> 8 == block {
            let lo = (ts[b] & 0xff) as usize;
            bm[lo / 8] |= 0x80 >> (lo % 8);
            maxb = maxb.max(lo / 8 + 1);
            b += 1;
        }
        out.push(block as u8);
        out.push(maxb as u8);
        out.extend_from_slice(&bm[..maxb]);
    }
    out
}

/// Returns the mnemonic of a record type code (`TYPE123` for unknown ones).
pub fn type_name(t: u16) -> String {
    let rt = RecordType::from(t);
    match rt {
        RecordType::Unknown(_) => format!("TYPE{t}"),
        other => other.to_string(),
    }
}

/// Zone signing mode as seen by the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signing {
    /// Plain NSEC chain: walkable.
    Nsec,
    /// NSEC3 (hashed owner names): not walkable, by design of this module.
    Nsec3,
    /// NSEC records synthesized per query ("black lies" / minimal covering): not walkable.
    NsecMinimal,
    /// No NSEC or NSEC3 seen (unsigned zone, or the server does not answer authoritatively).
    None,
    /// The server could not be queried.
    Unknown,
}

/// One link of the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsecLink {
    pub owner: String,
    pub next: String,
    /// Record types present at the owner name.
    pub types: Vec<String>,
}

/// Walk settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsecConfig {
    /// Owner names collected at most.
    pub max_names: usize,
    /// Timeout of the connection and of each answer.
    pub timeout: Duration,
    /// Pause between queries, to stay polite to the authoritative server.
    pub delay: Duration,
    pub port: u16,
}

impl Default for NsecConfig {
    fn default() -> Self {
        NsecConfig {
            max_names: 5000,
            timeout: Duration::from_secs(10),
            delay: Duration::from_millis(50),
            port: 53,
        }
    }
}

/// Result of a walk against one server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsecWalk {
    pub zone: String,
    pub server: String,
    pub signing: Signing,
    pub links: Vec<NsecLink>,
    /// Owner names below the apex (wildcard owners `*.x` included as is).
    pub names: Vec<String>,
    /// The chain returned to the apex.
    pub complete: bool,
    /// Why the walk ended early: `nsec3`, `minimal_nsec`, `no_nsec`, `limit`, `loop`,
    /// `out_of_zone`, `refused`, `error`.
    pub stopped: Option<String>,
    pub error: Option<String>,
    pub queries: usize,
}

struct Conn<'a> {
    net: &'a NetClient,
    zone: String,
    server: String,
    port: u16,
    timeout: Duration,
    stream: Option<TcpStream>,
    id: u16,
    reconnects: u32,
    queries: usize,
}

impl Conn<'_> {
    fn access(&self) -> Access {
        Access::ZoneInfra {
            zone: self.zone.clone(),
            operation: "nsec-walk".into(),
        }
    }

    async fn connect(&mut self) -> Result<(), NetError> {
        let access = self.access();
        let (s, _) = crate::tcp::connect(
            self.net,
            MODULE,
            &self.server,
            self.port,
            &access,
            self.timeout,
        )
        .await?;
        self.stream = Some(s);
        Ok(())
    }

    async fn exchange(&mut self, name: &Labels, qtype: u16) -> Result<Message, NetError> {
        loop {
            if self.stream.is_none() {
                self.connect().await?;
            }
            match self.try_exchange(name, qtype).await {
                Ok(m) => return Ok(m),
                Err(NetError::Io(_) | NetError::Request(_)) if self.reconnects < 3 => {
                    // servers close idle or long-lived TCP sessions; reconnect and repeat once more
                    self.reconnects += 1;
                    self.stream = None;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn try_exchange(&mut self, name: &Labels, qtype: u16) -> Result<Message, NetError> {
        self.net.rate_limit(MODULE).await?;
        self.id = self.id.wrapping_add(1);
        self.queries += 1;
        let access = self.access();
        let qn = labels_to_string(name);
        let mut rec = self.net.draft(
            MODULE,
            &type_name(qtype),
            &format!(
                "dns+tcp://{}:{}/{qn}/{}",
                self.server,
                self.port,
                type_name(qtype)
            ),
            &self.server,
            &access,
        );
        let q = encode_query(name, qtype, self.id);
        let id = self.id;
        let timeout = self.timeout;
        let Some(s) = self.stream.as_mut() else {
            return Err(NetError::Request("not connected".into()));
        };
        let work = async {
            s.write_all(&q).await?;
            loop {
                let mut lb = [0u8; 2];
                s.read_exact(&mut lb).await?;
                let mut buf = vec![0u8; u16::from_be_bytes(lb) as usize];
                s.read_exact(&mut buf).await?;
                let m = Message::from_vec(&buf).map_err(|e| NetError::Parse(e.to_string()))?;
                if m.metadata.id == id {
                    return Ok::<_, NetError>((m, buf.len()));
                }
            }
        };
        let r = self
            .net
            .cancellable(tokio::time::timeout(timeout, work))
            .await
            .and_then(|x| x.map_err(|_| NetError::Timeout))
            .and_then(|x| x);
        match r {
            Ok((m, n)) => {
                rec.status = Some(u16::from(m.metadata.response_code));
                rec.bytes = n as u64 + 2;
                self.net.record(rec);
                Ok(m)
            }
            Err(e) => {
                rec.error = Some(format!("{}: {e}", e.code()));
                self.net.record(rec);
                Err(e)
            }
        }
    }
}

fn owner_labels(r: &Record) -> Labels {
    r.name.iter().map(lower).collect()
}

fn rdata_bytes(r: &Record) -> Option<&[u8]> {
    match &r.data {
        RData::Unknown { rdata, .. } => Some(&rdata.anything),
        _ => None,
    }
}

fn find_nsec(records: &[Record], owner: &Labels) -> Option<(Labels, Vec<u16>)> {
    records
        .iter()
        .filter(|r| u16::from(r.record_type()) == T_NSEC && owner_labels(r) == *owner)
        .find_map(|r| parse_nsec_rdata(rdata_bytes(r)?))
}

fn has_type(m: &Message, t: u16) -> bool {
    m.answers
        .iter()
        .chain(m.authorities.iter())
        .any(|r| u16::from(r.record_type()) == t)
}

/// Walks the zone against one server. Never fails: errors and denials end up in the result.
pub async fn nsec_walk_server(
    net: &NetClient,
    zone: &str,
    server: &str,
    cfg: &NsecConfig,
) -> NsecWalk {
    let zone_s = norm_name(zone);
    let zl = labels_of(&zone_s);
    let mut w = NsecWalk {
        zone: zone_s.clone(),
        server: server.to_string(),
        signing: Signing::Unknown,
        links: Vec::new(),
        names: Vec::new(),
        complete: false,
        stopped: None,
        error: None,
        queries: 0,
    };
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(7) as u16;
    let mut c = Conn {
        net,
        zone: zone_s.clone(),
        server: server.to_string(),
        port: cfg.port,
        timeout: cfg.timeout,
        stream: None,
        id: seed,
        reconnects: 0,
        queries: 0,
    };
    let mut cur = zl.clone();
    let mut seen: HashSet<Labels> = HashSet::new();
    let stop = loop {
        if w.names.len() >= cfg.max_names {
            break "limit";
        }
        if !w.links.is_empty() && !cfg.delay.is_zero() {
            if let Err(e) = net.cancellable(tokio::time::sleep(cfg.delay)).await {
                w.error = Some(e.to_string());
                break "error";
            }
        }
        let m = match c.exchange(&cur, T_NSEC).await {
            Ok(m) => m,
            Err(e) => {
                w.error = Some(format!("{}: {e}", e.code()));
                break "error";
            }
        };
        if matches!(
            m.metadata.response_code,
            ResponseCode::Refused | ResponseCode::NotAuth | ResponseCode::ServFail
        ) {
            break "refused";
        }
        let mut link = find_nsec(&m.answers, &cur);
        if link.is_none() && has_type(&m, T_NSEC3) {
            w.signing = Signing::Nsec3;
            break "nsec3";
        }
        if link.is_none() {
            // the denial for `\000.<cur>` is covered by the NSEC record owned by `cur`
            let mut probe = vec![vec![0u8]];
            probe.extend(cur.iter().cloned());
            match c.exchange(&probe, T_A).await {
                Ok(m2) => {
                    link = find_nsec(&m2.authorities, &cur);
                    if link.is_none() && has_type(&m2, T_NSEC3) {
                        w.signing = Signing::Nsec3;
                        break "nsec3";
                    }
                }
                Err(e) => {
                    w.error = Some(format!("{}: {e}", e.code()));
                    break "error";
                }
            }
        }
        let Some((next, types)) = link else {
            if cur == zl {
                if let Ok(m3) = c.exchange(&zl, T_NSEC3PARAM).await {
                    if has_type(&m3, T_NSEC3PARAM) || has_type(&m3, T_NSEC3) {
                        w.signing = Signing::Nsec3;
                        break "nsec3";
                    }
                }
                w.signing = Signing::None;
            }
            break "no_nsec";
        };
        if next.first().is_some_and(|l| l.as_slice() == [0]) && next[1..] == cur[..] {
            w.signing = Signing::NsecMinimal;
            break "minimal_nsec";
        }
        w.signing = Signing::Nsec;
        seen.insert(cur.clone());
        if cur != zl {
            w.names.push(labels_to_string(&cur));
        }
        w.links.push(NsecLink {
            owner: labels_to_string(&cur),
            next: labels_to_string(&next),
            types: types.iter().map(|t| type_name(*t)).collect(),
        });
        if next == zl {
            w.complete = true;
            break "";
        }
        if !is_under(&next, &zl) {
            break "out_of_zone";
        }
        if seen.contains(&next) {
            break "loop";
        }
        cur = next;
    };
    if !stop.is_empty() {
        w.stopped = Some(stop.to_string());
    }
    w.queries = c.queries;
    w
}

/// Walks an in-scope zone through its authoritative name servers, stopping at the first server
/// that produces a definite answer (a chain, NSEC3 or a minimal NSEC signer).
///
/// # Errors
///
/// Fails before any query if the scope or the active stage does not allow the operation for the
/// zone, and if the zone has no name servers.
pub async fn nsec_walk(
    net: &NetClient,
    dns: &dyn DnsLookup,
    zone: &str,
    cfg: &NsecConfig,
) -> Result<NsecWalk, NetError> {
    let zone = norm_name(zone);
    net.authorize_logged(
        MODULE,
        "NSEC",
        &format!("nsec://{zone}"),
        &zone,
        &Access::active("nsec-walk"),
    )
    .await?;
    let ns = dns.lookup(&zone, RType::NS).await?.values(RType::NS);
    let mut last = None;
    for n in ns {
        if net.is_cancelled() {
            return Err(NetError::Cancelled);
        }
        let w = nsec_walk_server(net, &zone, &n, cfg).await;
        if matches!(
            w.signing,
            Signing::Nsec | Signing::Nsec3 | Signing::NsecMinimal
        ) {
            return Ok(w);
        }
        last = Some(w);
    }
    last.ok_or_else(|| NetError::Dns(format!("{zone}: no NS records")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::MemorySink;
    use crate::NetConfig;
    use foca_core::Scope;
    use hickory_resolver::proto::op::OpCode;
    use hickory_resolver::proto::rr::rdata::NULL;
    use hickory_resolver::proto::rr::Name;
    use std::sync::Arc;

    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Nsec,
        /// NSEC answered only through denials of `\000.<name>`
        Denial,
        Nsec3,
        BlackLies,
    }

    const CHAIN: &[&str] = &[
        "zt.test",
        "*.zt.test",
        "dev.zt.test",
        "mail.zt.test",
        "vpn.zt.test",
    ];

    fn nsec_record(owner: &Name, next: &Labels, types: &[u16]) -> Record {
        Record::from_rdata(
            owner.clone(),
            300,
            RData::Unknown {
                code: RecordType::NSEC,
                rdata: NULL::with(encode_nsec_rdata(next, types)),
            },
        )
    }

    fn respond(req: &Message, mode: Mode) -> Message {
        let mut m = Message::response(req.metadata.id, OpCode::Query);
        let q = &req.queries[0];
        let qn: Labels = q.name().iter().map(lower).collect();
        let qt = u16::from(q.query_type());
        let owner_s = labels_to_string(&qn);
        let pos = CHAIN.iter().position(|n| *n == owner_s);
        match mode {
            Mode::Nsec3 => {
                if qt == T_NSEC3PARAM {
                    m.answers.push(Record::from_rdata(
                        q.name().clone(),
                        0,
                        RData::Unknown {
                            code: RecordType::NSEC3PARAM,
                            rdata: NULL::with(vec![1, 0, 0, 0]),
                        },
                    ));
                }
            }
            Mode::BlackLies => {
                if qt == T_NSEC {
                    let mut next = vec![vec![0u8]];
                    next.extend(qn.clone());
                    m.answers.push(nsec_record(q.name(), &next, &[T_NSEC, 46]));
                }
            }
            Mode::Nsec | Mode::Denial => {
                if qt == T_NSEC && mode == Mode::Nsec {
                    if let Some(i) = pos {
                        let next = labels_of(CHAIN[(i + 1) % CHAIN.len()]);
                        m.answers
                            .push(nsec_record(q.name(), &next, &[1, 46, T_NSEC]));
                    }
                } else if qt == T_A && qn.first().is_some_and(|l| l.as_slice() == [0]) {
                    let base = labels_to_string(&qn[1..].to_vec());
                    if let Some(i) = CHAIN.iter().position(|n| *n == base) {
                        m.metadata.response_code = ResponseCode::NXDomain;
                        let owner = Name::from_ascii(format!("{base}.")).unwrap();
                        let next = labels_of(CHAIN[(i + 1) % CHAIN.len()]);
                        m.authorities
                            .push(nsec_record(&owner, &next, &[1, 15, 46, T_NSEC]));
                    }
                }
            }
        }
        m
    }

    async fn fake_ns(mode: Mode) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    loop {
                        let mut lb = [0u8; 2];
                        if s.read_exact(&mut lb).await.is_err() {
                            return;
                        }
                        let mut q = vec![0u8; u16::from_be_bytes(lb) as usize];
                        if s.read_exact(&mut q).await.is_err() {
                            return;
                        }
                        let req = Message::from_vec(&q).unwrap();
                        assert!(!req.metadata.recursion_desired);
                        let b = respond(&req, mode).to_vec().unwrap();
                        s.write_all(&(b.len() as u16).to_be_bytes()).await.unwrap();
                        s.write_all(&b).await.unwrap();
                    }
                });
            }
        });
        port
    }

    fn client(active: bool) -> (NetClient, Arc<MemorySink>) {
        let (mut scope, _) = Scope::from_lines("zt.test", "");
        scope.active_phase = active;
        let sink = Arc::new(MemorySink::new());
        (
            NetClient::new(NetConfig::default(), scope, sink.clone()).unwrap(),
            sink,
        )
    }

    fn cfg(port: u16) -> NsecConfig {
        NsecConfig {
            port,
            delay: Duration::ZERO,
            timeout: Duration::from_secs(5),
            ..Default::default()
        }
    }

    #[test]
    fn rdata_roundtrip() {
        let next = labels_of("Mail.Example.com");
        let types = [1, 2, 6, 15, 16, 28, 46, 47, 48, 257, 65534];
        let d = encode_nsec_rdata(&next, &types);
        let (n, t) = parse_nsec_rdata(&d).unwrap();
        assert_eq!(labels_to_string(&n), "mail.example.com");
        assert_eq!(t, types.to_vec());
        assert!(parse_nsec_rdata(&[3, b'a']).is_none());
        assert_eq!(labels_to_string(&vec![vec![0], b"x".to_vec()]), "\\000.x");
        assert_eq!(type_name(47), "NSEC");
        let q = encode_query(&labels_of("zt.test"), T_NSEC, 9);
        let m = Message::from_vec(&q[2..]).unwrap();
        assert_eq!(m.queries[0].query_type(), RecordType::NSEC);
        assert!(m.edns.as_ref().unwrap().flags().dnssec_ok);
    }

    #[tokio::test]
    async fn walks_full_chain() {
        for mode in [Mode::Nsec, Mode::Denial] {
            let port = fake_ns(mode).await;
            let (net, sink) = client(true);
            let w = nsec_walk_server(&net, "zt.test", "127.0.0.1", &cfg(port)).await;
            assert_eq!(w.signing, Signing::Nsec, "{:?}", w.error);
            assert!(w.complete, "{:?}", w.stopped);
            assert_eq!(
                w.names,
                vec!["*.zt.test", "dev.zt.test", "mail.zt.test", "vpn.zt.test"]
            );
            let want: &[&str] = if mode == Mode::Nsec {
                &["A", "RRSIG", "NSEC"]
            } else {
                &["A", "MX", "RRSIG", "NSEC"]
            };
            assert_eq!(w.links[0].types, want);
            assert!(
                sink.records()
                    .iter()
                    .filter(|r| r.module == MODULE && r.active)
                    .count()
                    >= w.queries
            );
            let limited = nsec_walk_server(
                &net,
                "zt.test",
                "127.0.0.1",
                &NsecConfig {
                    max_names: 2,
                    ..cfg(port)
                },
            )
            .await;
            assert_eq!(limited.stopped.as_deref(), Some("limit"));
            assert_eq!(limited.names.len(), 2);
        }
    }

    #[tokio::test]
    async fn detects_unwalkable_zones() {
        let (net, _) = client(true);
        let port = fake_ns(Mode::Nsec3).await;
        let w = nsec_walk_server(&net, "zt.test", "127.0.0.1", &cfg(port)).await;
        assert_eq!(
            (w.signing, w.stopped.as_deref()),
            (Signing::Nsec3, Some("nsec3"))
        );
        assert!(w.names.is_empty());
        let port = fake_ns(Mode::BlackLies).await;
        let w = nsec_walk_server(&net, "zt.test", "127.0.0.1", &cfg(port)).await;
        assert_eq!(
            (w.signing, w.stopped.as_deref()),
            (Signing::NsecMinimal, Some("minimal_nsec"))
        );
    }

    #[tokio::test]
    async fn denied_outside_active_phase_or_scope() {
        let port = fake_ns(Mode::Nsec).await;
        let dns = crate::dns::StaticDns::new().add("zt.test", RType::NS, &["127.0.0.1"]);
        // passive or standard profile: no active stage, no query at all
        let (net, sink) = client(false);
        let r = nsec_walk(&net, &dns, "zt.test", &cfg(port)).await;
        assert!(matches!(r, Err(NetError::ActiveDenied(_))), "{r:?}");
        assert!(sink.records().iter().all(|x| x.blocked));
        let w = nsec_walk_server(&net, "zt.test", "127.0.0.1", &cfg(port)).await;
        assert_eq!(w.queries, 0);
        assert!(w.error.unwrap().starts_with("not_active_phase"));
        // a zone outside the scope
        let (net, _) = client(true);
        assert!(nsec_walk(&net, &dns, "other.test", &cfg(port))
            .await
            .is_err());
        // an excluded name server is never contacted
        let (mut scope, _) = Scope::from_lines("zt.test", "127.0.0.1");
        scope.active_phase = true;
        let net = NetClient::new(NetConfig::default(), scope, Arc::new(MemorySink::new())).unwrap();
        let w = nsec_walk_server(&net, "zt.test", "127.0.0.1", &cfg(port)).await;
        assert_eq!(w.queries, 0);
        assert!(w.error.unwrap().starts_with("out_of_scope"));
        // the full path through NS lookup works in the active stage
        let (net, _) = client(true);
        let w = nsec_walk(&net, &dns, "zt.test", &cfg(port)).await.unwrap();
        assert!(w.complete);
    }
}
