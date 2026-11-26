//! DNS zone transfer (AXFR).
//!
//! This is an active module: it runs only during the active stage of a scan and only for a
//! zone in scope (`Scope::check_active(zone)`). It sends nothing but an AXFR query for that
//! zone name, and only to the zone's authoritative name servers. Those are usually hosted by a
//! third-party DNS provider and are treated as service infrastructure of the target
//! (`Access::ZoneInfra`); name servers matching an exclusion (by name or IP) are never contacted.
//! Queries and responses are hickory-proto DNS messages over TCP/53, through the configured
//! proxy if any.

use std::time::Duration;

use hickory_resolver::proto::op::{Message, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RecordType};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::client::{Access, NetClient};
use crate::dns::{norm_name, DnsLookup, DnsRecord, RType};
use crate::NetError;

const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RECORDS: usize = 200_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxfrResult {
    pub zone: String,
    pub server: String,
    pub ok: bool,
    pub records: Vec<DnsRecord>,
    pub error: Option<String>,
}

/// Builds an AXFR query in TCP framing (with the 2-byte length prefix).
pub fn axfr_query(zone: &str, id: u16) -> Result<Vec<u8>, NetError> {
    let name = Name::from_ascii(format!("{}.", norm_name(zone)))
        .map_err(|e| NetError::Parse(e.to_string()))?;
    let mut m = Message::query();
    m.metadata.id = id;
    m.metadata.recursion_desired = false;
    m.add_query(Query::query(name, RecordType::AXFR));
    let body = m.to_vec().map_err(|e| NetError::Parse(e.to_string()))?;
    let mut out = (body.len() as u16).to_be_bytes().to_vec();
    out.extend(body);
    Ok(out)
}

fn to_record(r: &hickory_resolver::proto::rr::Record) -> DnsRecord {
    let value = match &r.data {
        hickory_resolver::proto::rr::RData::TXT(t) => t
            .txt_data
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect::<Vec<_>>()
            .join(""),
        other => other.to_string(),
    };
    DnsRecord {
        name: norm_name(&r.name.to_string()),
        rtype: r.record_type().to_string(),
        ttl: r.ttl,
        value: value.trim_end_matches('.').to_string(),
    }
}

/// Performs a transfer from a single `server:port`; the scope is checked for `server`.
pub async fn axfr_one(
    net: &NetClient,
    zone: &str,
    server: &str,
    port: u16,
    timeout: Duration,
) -> AxfrResult {
    let zone = norm_name(zone);
    let mut res = AxfrResult {
        zone: zone.clone(),
        server: server.to_string(),
        ok: false,
        records: Vec::new(),
        error: None,
    };
    // The zone's name servers are target service infrastructure: allowed if the zone is in scope,
    // the active stage is on and the server itself is not excluded.
    let access = Access::ZoneInfra {
        zone: zone.clone(),
        operation: "axfr".into(),
    };
    let (mut s, _ip) = match crate::tcp::connect(net, "axfr", server, port, &access, timeout).await
    {
        Ok(x) => x,
        Err(e) => {
            res.error = Some(format!("{}: {e}", e.code()));
            return res;
        }
    };
    let mut rec = net.draft(
        "axfr",
        "AXFR",
        &format!("dns+tcp://{server}:{port}/{zone}/AXFR#ns-зоны-цели"),
        server,
        &access,
    );
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(7)
        & 0xffff) as u16;
    let work = async {
        let q = axfr_query(&zone, id)?;
        s.write_all(&q).await?;
        let mut bytes = 0u64;
        let mut soa = 0;
        let mut records = Vec::new();
        loop {
            let mut lb = [0u8; 2];
            if let Err(e) = s.read_exact(&mut lb).await {
                if records.is_empty() {
                    return Err(NetError::Request(format!("соединение закрыто: {e}")));
                }
                break;
            }
            let len = u16::from_be_bytes(lb) as usize;
            let mut buf = vec![0u8; len];
            s.read_exact(&mut buf).await?;
            bytes += len as u64 + 2;
            if bytes > MAX_BYTES {
                return Err(NetError::TooLarge { limit: MAX_BYTES });
            }
            let m = Message::from_vec(&buf).map_err(|e| NetError::Parse(e.to_string()))?;
            if m.metadata.response_code != ResponseCode::NoError {
                return Err(NetError::Request(format!(
                    "трансфер отклонён: {}",
                    m.metadata.response_code
                )));
            }
            if m.answers.is_empty() {
                return Err(NetError::Request("трансфер отклонён: пустой ответ".into()));
            }
            for r in &m.answers {
                if r.record_type() == RecordType::SOA {
                    soa += 1;
                }
                records.push(to_record(r));
            }
            if records.len() > MAX_RECORDS {
                return Err(NetError::TooLarge {
                    limit: MAX_RECORDS as u64,
                });
            }
            if soa >= 2 {
                break;
            }
        }
        Ok::<_, NetError>((records, bytes))
    };
    let r = net
        .cancellable(tokio::time::timeout(timeout, work))
        .await
        .and_then(|x| x.map_err(|_| NetError::Timeout))
        .and_then(|x| x);
    match r {
        Ok((records, bytes)) => {
            rec.status = Some(0);
            rec.bytes = bytes;
            // The last SOA repeats the first one.
            let mut records = records;
            if records.len() > 1 && records.last().is_some_and(|r| r.rtype == "SOA") {
                records.pop();
            }
            res.ok = true;
            res.records = records;
        }
        Err(e) => {
            rec.error = Some(format!("{}: {e}", e.code()));
            res.error = Some(e.to_string());
        }
    }
    net.record(rec);
    res
}

/// Attempts AXFR against every name server of the zone.
///
/// Name servers matching an exclusion are skipped and reported as denied in the log and in
/// the result.
///
/// # Errors
///
/// Fails only if the scope or the active stage does not allow the operation for the zone.
pub async fn axfr(
    net: &NetClient,
    dns: &dyn DnsLookup,
    zone: &str,
    timeout: Duration,
) -> Result<Vec<AxfrResult>, NetError> {
    let zone = norm_name(zone);
    net.authorize_logged(
        "axfr",
        "AXFR",
        &format!("axfr://{zone}"),
        &zone,
        &Access::active("axfr"),
    )
    .await?;
    let ns = dns.lookup(&zone, RType::NS).await?.values(RType::NS);
    let mut out = Vec::new();
    for n in ns {
        if net.is_cancelled() {
            return Err(NetError::Cancelled);
        }
        out.push(axfr_one(net, &zone, &n, 53, timeout).await);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::MemorySink;
    use crate::NetConfig;
    use foca_core::Scope;
    use hickory_resolver::proto::op::OpCode;
    use hickory_resolver::proto::rr::rdata::{A, SOA, TXT};
    use hickory_resolver::proto::rr::{RData, Record};
    use std::sync::Arc;

    fn zone_msgs(id: u16) -> Vec<Vec<u8>> {
        let z = Name::from_ascii("zt.test.").unwrap();
        let soa = Record::from_rdata(
            z.clone(),
            300,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.zt.test.").unwrap(),
                Name::from_ascii("admin.zt.test.").unwrap(),
                1,
                2,
                3,
                4,
                5,
            )),
        );
        let mut m1 = Message::response(id, OpCode::Query);
        m1.answers.push(soa.clone());
        m1.answers.push(Record::from_rdata(
            Name::from_ascii("vpn.zt.test.").unwrap(),
            300,
            RData::A(A("192.0.2.7".parse().unwrap())),
        ));
        let mut m2 = Message::response(id, OpCode::Query);
        m2.answers.push(Record::from_rdata(
            z.clone(),
            300,
            RData::TXT(TXT::new(vec!["v=spf1 -all".into()])),
        ));
        m2.answers.push(soa);
        vec![m1.to_vec().unwrap(), m2.to_vec().unwrap()]
    }

    async fn fake_ns() -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let mut lb = [0u8; 2];
                if s.read_exact(&mut lb).await.is_err() {
                    continue;
                }
                let mut q = vec![0u8; u16::from_be_bytes(lb) as usize];
                s.read_exact(&mut q).await.unwrap();
                let req = Message::from_vec(&q).unwrap();
                assert_eq!(req.queries[0].query_type(), RecordType::AXFR);
                for m in zone_msgs(req.metadata.id) {
                    s.write_all(&(m.len() as u16).to_be_bytes()).await.unwrap();
                    s.write_all(&m).await.unwrap();
                }
            }
        });
        port
    }

    fn client(active: bool) -> (NetClient, Arc<MemorySink>) {
        let (mut scope, _) = Scope::from_lines("zt.test\n127.0.0.1", "");
        scope.active_phase = active;
        let sink = Arc::new(MemorySink::new());
        let net = NetClient::new(NetConfig::default(), scope, sink.clone()).unwrap();
        (net, sink)
    }

    #[test]
    fn query_encoding() {
        let q = axfr_query("Example.COM", 42).unwrap();
        let m = Message::from_vec(&q[2..]).unwrap();
        assert_eq!(m.metadata.id, 42);
        assert_eq!(m.queries[0].name().to_string(), "example.com.");
        assert_eq!(u16::from_be_bytes([q[0], q[1]]) as usize, q.len() - 2);
    }

    #[tokio::test]
    async fn transfer_from_fake_ns() {
        let port = fake_ns().await;
        let (net, sink) = client(true);
        let r = axfr_one(&net, "zt.test", "127.0.0.1", port, Duration::from_secs(5)).await;
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(r.records.len(), 3);
        assert!(r
            .records
            .iter()
            .any(|x| x.name == "vpn.zt.test" && x.value == "192.0.2.7"));
        assert!(r
            .records
            .iter()
            .any(|x| x.rtype == "TXT" && x.value == "v=spf1 -all"));
        let log = sink.records();
        assert!(log
            .iter()
            .any(|x| x.method == "AXFR" && x.active && x.bytes > 0));
    }

    #[tokio::test]
    async fn denied_outside_active_phase_or_scope() {
        let port = fake_ns().await;
        let (net, sink) = client(false);
        let r = axfr_one(&net, "zt.test", "127.0.0.1", port, Duration::from_secs(5)).await;
        assert!(!r.ok);
        assert!(r.error.unwrap().starts_with("not_active_phase"));
        assert!(sink.records().iter().all(|x| x.blocked));
        // a zone name server outside the scope (third-party DNS hosting) is target infrastructure: transfer allowed
        let port = fake_ns().await;
        let (mut scope, _) = Scope::from_lines("zt.test", "ns.bad.example");
        scope.active_phase = true;
        let mut cfg = NetConfig::default();
        for h in ["ns.other.example", "ns.bad.example"] {
            cfg.host_overrides
                .insert(h.into(), vec!["127.0.0.1".parse().unwrap()]);
        }
        let sink = Arc::new(MemorySink::new());
        let net = NetClient::new(cfg, scope, sink.clone()).unwrap();
        let r = axfr_one(
            &net,
            "zt.test",
            "ns.other.example",
            port,
            Duration::from_secs(5),
        )
        .await;
        assert!(r.ok, "{:?}", r.error);
        assert!(sink
            .records()
            .iter()
            .any(|x| x.method == "AXFR" && x.active && x.url.contains("ns-зоны-цели")));
        // exclusions win: an excluded name server is never contacted
        let r = axfr_one(
            &net,
            "zt.test",
            "ns.bad.example",
            port,
            Duration::from_secs(5),
        )
        .await;
        assert!(
            r.error.as_deref().unwrap().starts_with("out_of_scope"),
            "{:?}",
            r.error
        );
        assert!(sink
            .records()
            .iter()
            .any(|x| x.blocked && x.host == "ns.bad.example"));
        // a zone outside the scope is denied even if the name server is in scope
        let r = axfr_one(
            &net,
            "other.test",
            "ns.other.example",
            port,
            Duration::from_secs(5),
        )
        .await;
        assert!(
            r.error.as_deref().unwrap().starts_with("out_of_scope"),
            "{:?}",
            r.error
        );
    }
}
