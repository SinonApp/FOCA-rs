//! Have I Been Pwned (Pwned Passwords) k-anonymity client (opt-in).
//!
//! Computes SHA-1 locally on the device and sends only the 5-character uppercase hex prefix
//! to `GET /range/<5-HEX>` via [`NetClient`] with [`Access::Passive`] and `Add-Padding: true`.
//! Neither the secret itself nor the remaining 35 hex characters of its hash ever leave the
//! device, appear in error messages, or reach request/debug logs.

use std::time::Duration;

use serde::Serialize;

use crate::{Access, NetClient, NetError, NetRequest};

/// Request log module name.
pub const MODULE: &str = "hibp";
/// Default Pwned Passwords API base URL.
pub const DEFAULT_BASE: &str = "https://api.pwnedpasswords.com";
/// Hard upper bound for `/range/<prefix>` response bodies (typically ~30-50 KB with padding).
const MAX_RANGE_BYTES: u64 = 512 * 1024;

/// Result of a k-anonymity Pwned Passwords range check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HibpResult {
    pub pwned: bool,
    pub count: u64,
    /// First 5 uppercase hex chars of the local SHA-1 digest (the only hash data transmitted).
    pub prefix: String,
}

/// Computes uppercase 40-character RFC 3174 SHA-1 hex digest purely in safe Rust.
pub fn sha1_hex_upper(input: &[u8]) -> String {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(input.len() + 72);
    msg.extend_from_slice(input);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in msg.as_chunks::<64>().0 {
        for (i, slot) in w[..16].iter_mut().enumerate() {
            let b = &chunk[i * 4..i * 4 + 4];
            *slot = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    format!("{h0:08X}{h1:08X}{h2:08X}{h3:08X}{h4:08X}")
}

/// Checks `secret` against Pwned Passwords using 5-char SHA-1 k-anonymity.
///
/// Only `/range/<5-HEX>` is ever requested (`Access::Passive`, `Add-Padding: true`, redirects
/// disabled). Empty secrets return `Ok(HibpResult { pwned: false, count: 0, .. })` without any
/// network request.
pub async fn check_pwned_password(
    net: &NetClient,
    secret: &str,
    base_url: Option<&str>,
    timeout: Duration,
) -> Result<HibpResult, NetError> {
    if secret.is_empty() {
        return Ok(HibpResult {
            pwned: false,
            count: 0,
            prefix: String::new(),
        });
    }
    let digest = sha1_hex_upper(secret.as_bytes());
    let (prefix, suffix) = digest.split_at(5);
    let prefix = prefix.to_string();
    let base = base_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_BASE)
        .trim_end_matches('/');
    let url = format!("{base}/range/{prefix}");
    // Never include the secret or hash suffix in BadUrl errors.
    let req = NetRequest::get(&url, MODULE, Access::Passive)
        .map_err(|_| NetError::BadUrl("неверный базовый URL HIBP".into()))?
        .header("Add-Padding", "true")
        .retries(0)
        .timeout(timeout)
        .no_redirects();
    let resp = net.send(req).await?;
    let st = resp.status();
    if !(200..300).contains(&st) {
        return Err(NetError::Status(st));
    }
    let body = resp.text_limited(MAX_RANGE_BYTES).await?;
    let mut count = 0u64;
    for line in body.lines() {
        let Some((cand, raw_count)) = line.trim().split_once(':') else {
            continue;
        };
        if cand.trim().eq_ignore_ascii_case(suffix) {
            if let Ok(n) = raw_count.trim().parse::<u64>() {
                count = count.max(n);
            }
        }
    }
    Ok(HibpResult {
        pwned: count > 0,
        count,
        prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testserver::{TestResponse, TestServer};
    use crate::{MemorySink, NetConfig};
    use foca_core::Scope;
    use std::sync::{Arc, Mutex};

    #[test]
    fn rfc3174_sha1_vectors() {
        assert_eq!(
            sha1_hex_upper(b""),
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        );
        assert_eq!(
            sha1_hex_upper(b"abc"),
            "A9993E364706816ABA3E25717850C26C9CD0D89D"
        );
        assert_eq!(
            sha1_hex_upper(b"password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
        assert_eq!(
            sha1_hex_upper(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn k_anonymity_sends_only_five_hex_prefix_and_ignores_padding() {
        type SeenRanges = Arc<Mutex<Vec<(String, Option<String>)>>>;
        let seen_paths: SeenRanges = Arc::new(Mutex::new(Vec::new()));
        let sp = seen_paths.clone();
        let srv = TestServer::start(move |r| {
            let pad = r.headers.get("add-padding").cloned();
            sp.lock().unwrap().push((r.path().to_string(), pad));
            match r.path() {
                "/range/5BAA6" => TestResponse::ok(
                    // lowercase suffix + padded :0 line for another suffix + matching count
                    b"00000000000000000000000000000000001:0\n1e4c9b93f3f0682250b6cf8331b7ee68fd8:9545824\n"
                        .to_vec(),
                ),
                "/range/84983" => {
                    // match present only as HIBP Add-Padding decoy (:0)
                    TestResponse::ok(
                        b"E441C3BD26EBAAE4AA1F95129E5E54670F1:0\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:12\n"
                            .to_vec(),
                    )
                }
                _ => TestResponse::status(404),
            }
        })
        .await;

        let sink = Arc::new(MemorySink::new());
        let cfg = NetConfig {
            retries: 0,
            global_rps: None,
            ..Default::default()
        };
        let net = NetClient::new(cfg, Scope::default(), sink.clone()).unwrap();

        let hit = check_pwned_password(&net, "password", Some(&srv.url()), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            hit,
            HibpResult {
                pwned: true,
                count: 9_545_824,
                prefix: "5BAA6".into(),
            }
        );

        let decoy = check_pwned_password(
            &net,
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            Some(&srv.url()),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(
            decoy,
            HibpResult {
                pwned: false,
                count: 0,
                prefix: "84983".into(),
            }
        );

        let empty = check_pwned_password(&net, "", Some(&srv.url()), Duration::from_secs(5))
            .await
            .unwrap();
        assert!(!empty.pwned);
        assert_eq!(empty.count, 0);

        // Check every outgoing HTTP request and sink record: only /range/<5HEX>, Add-Padding: true,
        // and never the secret, 35-char suffix, or 40-char digest.
        let paths = seen_paths.lock().unwrap().clone();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], ("/range/5BAA6".into(), Some("true".into())));
        assert_eq!(paths[1], ("/range/84983".into(), Some("true".into())));
        let recs = sink.records();
        assert_eq!(recs.len(), 2);
        for rec in &recs {
            assert_eq!(rec.module, MODULE);
            assert_eq!(rec.access, "passive");
            assert!(!rec.url.contains("password"));
            assert!(!rec.url.contains("1E4C9B93"));
            assert!(!rec.url.contains("1e4c9b93"));
            assert!(!rec.url.contains("E441C3BD"));
        }
    }
}
