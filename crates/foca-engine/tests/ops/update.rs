//! In-app update against a mock GitHub (no real network): releases check with ETag reuse and
//! rate limit backoff, flavor-matched APK download with resume, and refusal on a tampered
//! `SHA256SUMS.txt`, a wrong signature domain or a corrupted APK.

use std::sync::{Arc, Mutex};

use crate::common::*;
use foca_engine::selfupdate as su;
use foca_net::testserver::{TestRequest, TestResponse, TestServer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SEED: [u8; 32] = [0x5a; 32];
const NEW: &str = "99.0.0-beta.1";

fn pubkey() -> [u8; 32] {
    use ring::signature::KeyPair;
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
    kp.public_key().as_ref().try_into().unwrap()
}

/// What the mock serves; tests flip fields between calls.
#[derive(Clone)]
struct Mock {
    base: String,
    apk: Vec<u8>,
    /// Bytes served as the APK (differs from `apk` for the corruption test).
    served_apk: Vec<u8>,
    sums: String,
    sig: String,
    /// `Some(status, headers)` answers the releases list with that status.
    list_fail: Option<(u16, Vec<(&'static str, String)>)>,
}

fn apk_name(flavor: &str) -> String {
    su::apk_asset_name(NEW, flavor)
}

fn releases_json(base: &str) -> String {
    let asset = |name: &str, size: usize| {
        json!({ "name": name, "size": size,
            "browser_download_url": format!("{base}/dl/{name}") })
    };
    json!([
        { "tag_name": "signatures-v3", "prerelease": true, "draft": false, "assets": [] },
        { "tag_name": format!("v{NEW}"), "prerelease": true, "draft": false,
          "published_at": "2026-12-01T10:00:00Z", "html_url": format!("{base}/rel"),
          "body": "## Changes\n- Faster\n<!-- foca:schema 999 -->\n<!-- foca:version-code 99000001 -->",
          "assets": [asset(&apk_name("foss"), 4096), asset(&apk_name("play"), 10),
                     asset(su::SUMS_ASSET, 1), asset(su::SIG_ASSET, 1)] },
        { "tag_name": "v1.0.0", "prerelease": false, "draft": false, "assets": [] }
    ])
    .to_string()
}

fn handle(m: &Mock, r: &TestRequest) -> TestResponse {
    let path = r.path();
    if path == format!("/repos/{}/releases", su::REPO) {
        if let Some((status, hs)) = &m.list_fail {
            let mut t = TestResponse::status(*status);
            for (k, v) in hs {
                t = t.header(k, v);
            }
            return t;
        }
        if r.headers.get("if-none-match").map(String::as_str) == Some("\"v1\"") {
            return TestResponse::status(304);
        }
        return TestResponse::ok(releases_json(&m.base)).header("ETag", "\"v1\"");
    }
    let name = path.trim_start_matches("/dl/");
    if name == su::SUMS_ASSET {
        return TestResponse::ok(m.sums.clone());
    }
    if name == su::SIG_ASSET {
        return TestResponse::ok(m.sig.clone());
    }
    if name == apk_name("foss") {
        if let Some(from) = r
            .headers
            .get("range")
            .and_then(|v| v.strip_prefix("bytes="))
            .and_then(|v| v.trim_end_matches('-').parse::<usize>().ok())
        {
            return TestResponse {
                status: 206,
                body: m.served_apk[from..].to_vec(),
                ..Default::default()
            };
        }
        return TestResponse::ok(m.served_apk.clone());
    }
    TestResponse::status(404)
}

struct Gh {
    _dir: tempfile::TempDir,
    cache: std::path::PathBuf,
    srv: TestServer,
    mock: Arc<Mutex<Mock>>,
    engine: foca_engine::Engine,
}

impl Gh {
    async fn call(&self, cmd: &str, a: Value) -> Value {
        self.engine
            .invoke(cmd, a.clone())
            .await
            .unwrap_or_else(|e| panic!("{cmd} {a}: {e}"))
    }
    fn set(&self, f: impl FnOnce(&mut Mock)) {
        f(&mut self.mock.lock().unwrap());
    }
    fn list_hits(&self) -> usize {
        self.srv.hits(&format!("/repos/{}/releases", su::REPO))
    }
}

async fn gh() -> Gh {
    let apk: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let sums = format!(
        "{}  {}\n{}  {}\n",
        hex(&Sha256::digest(&apk)),
        apk_name("foss"),
        "0".repeat(64),
        apk_name("play")
    );
    let sig = su::sign_sums(sums.as_bytes(), &SEED).unwrap();
    let mock = Arc::new(Mutex::new(Mock {
        base: String::new(),
        served_apk: apk.clone(),
        apk,
        sums,
        sig,
        list_fail: None,
    }));
    let m2 = mock.clone();
    let srv = TestServer::start(move |r| handle(&m2.lock().unwrap(), r)).await;
    mock.lock().unwrap().base = srv.url();
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("app-cache");
    let url = srv.url();
    let api = url.clone();
    let c2 = cache.clone();
    let (engine, _, _) = open_with(
        dir.path(),
        &url,
        Arc::new(foca_engine::MemoryKeys::new()),
        move |cfg| {
            cfg.endpoints.github_api = api;
            cfg.release_pubkey = pubkey();
            cfg.cache_dir = c2;
        },
    );
    Gh {
        _dir: dir,
        cache,
        srv,
        mock,
        engine,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_finds_flavor_update_and_reuses_etag() {
    let g = gh().await;
    let st = g.call("update_status", json!({ "flavor": "foss" })).await;
    assert!(st["update"].is_null(), "nothing checked yet: {st}");
    assert_eq!(st["current"], su::current_version());
    assert_eq!(st["settings"]["prerelease"], true);
    assert_eq!(st["download"]["phase"], "idle");

    let v = g.call("update_check", json!({ "flavor": "foss" })).await;
    assert_eq!(v["outcome"], "available", "{v}");
    let u = &v["update"];
    assert_eq!(u["version"], NEW);
    assert_eq!(u["asset"], apk_name("foss"));
    assert_eq!(u["size"], 4096);
    assert_eq!(u["version_code"], 99000001);
    assert_eq!(u["notes"], "## Changes\n- Faster");
    assert_eq!(u["schema"]["release"], 999);
    assert_eq!(u["schema"]["migrates"], true);
    // The request carried only the plain versioned User-Agent and no cookies or tokens.
    let req = g.srv.requests().pop().unwrap();
    assert_eq!(
        req.headers.get("user-agent").map(String::as_str),
        Some(format!("FOCA-rs/{}", env!("CARGO_PKG_VERSION")).as_str())
    );
    for h in ["cookie", "authorization", "accept-language"] {
        assert!(!req.headers.contains_key(h), "{h} sent: {:?}", req.headers);
    }

    // Second check: conditional request, 304, cached list reused.
    let v = g.call("update_check", json!({ "flavor": "play" })).await;
    assert_eq!(v["outcome"], "available");
    assert_eq!(v["update"]["asset"], apk_name("play"));
    let last = g.srv.requests().pop().unwrap();
    assert_eq!(
        last.headers.get("if-none-match").map(String::as_str),
        Some("\"v1\"")
    );
    // Stable channel only: the pre-release is not offered.
    let v = g
        .call(
            "update_check",
            json!({ "flavor": "foss", "prerelease": false }),
        )
        .await;
    assert_eq!(v["outcome"], "up_to_date", "{v}");
    assert!(v["update"].is_null());
    // Unknown flavor is a bad argument.
    let e = g
        .engine
        .invoke("update_check", json!({ "flavor": "x" }))
        .await
        .unwrap_err();
    assert_eq!(e.code, "bad_args");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limit_backs_off_without_new_requests() {
    let g = gh().await;
    let now = time::macros::datetime!(2026-11-20 10:00 UTC).unix_timestamp();
    g.set(|m| {
        m.list_fail = Some((
            403,
            vec![
                ("x-ratelimit-remaining", "0".into()),
                ("x-ratelimit-reset", (now + 600).to_string()),
            ],
        ))
    });
    let v = g.call("update_check", json!({ "flavor": "foss" })).await;
    assert_eq!(v["outcome"], "error", "{v}");
    assert_eq!(v["error"]["code"], "update_rate_limited");
    assert_eq!(v["error"]["retry_at"], now + 600);
    assert_eq!(v["backoff_until"], now + 600);
    assert_eq!(g.list_hits(), 1);
    // A manual retry inside the window answers from the backoff without asking GitHub.
    g.set(|m| m.list_fail = None);
    let v = g.call("update_check", json!({ "flavor": "foss" })).await;
    assert_eq!(v["error"]["code"], "update_rate_limited");
    assert_eq!(g.list_hits(), 1);
    let st = g.call("update_status", json!({ "flavor": "foss" })).await;
    assert_eq!(st["backoff_until"], now + 600);

    // 429 with Retry-After on a fresh engine; a plain 500 is an HTTP error without backoff.
    let g = gh().await;
    g.set(|m| m.list_fail = Some((429, vec![("retry-after", "30".into())])));
    let v = g.call("update_check", json!({ "flavor": "foss" })).await;
    assert_eq!(v["error"]["retry_at"], now + 30);
    let g = gh().await;
    g.set(|m| m.list_fail = Some((500, vec![])));
    let v = g.call("update_check", json!({ "flavor": "foss" })).await;
    assert_eq!(v["error"]["code"], "update_http");
    assert!(v["backoff_until"].is_null());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automatic_check_respects_settings_and_interval() {
    let g = gh().await;
    g.call(
        "settings_set",
        json!({ "patch": { "update": { "auto": false } } }),
    )
    .await;
    let v = g
        .call("update_check", json!({ "flavor": "foss", "auto": true }))
        .await;
    assert_eq!(v["skipped"], "disabled");
    assert_eq!(g.list_hits(), 0);
    g.call(
        "settings_set",
        json!({ "patch": { "update": { "auto": true } } }),
    )
    .await;
    let v = g
        .call("update_check", json!({ "flavor": "foss", "auto": true }))
        .await;
    assert_eq!(v["outcome"], "available", "{v}");
    let v = g
        .call("update_check", json!({ "flavor": "foss", "auto": true }))
        .await;
    assert_eq!(v["skipped"], "not_due");
    assert_eq!(g.list_hits(), 1);
}

async fn download(g: &Gh) -> Value {
    g.call("update_download", json!({ "flavor": "foss", "wait": true }))
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_verifies_then_resumes() {
    let g = gh().await;
    let e = g
        .engine
        .invoke("update_download", json!({ "flavor": "foss" }))
        .await
        .unwrap_err();
    assert_eq!(e.code, "update_none", "no check yet");
    g.call("update_check", json!({ "flavor": "foss" })).await;

    // A partial file from an interrupted run: the download continues with a Range request.
    let apk = g.mock.lock().unwrap().apk.clone();
    let want = hex(&Sha256::digest(&apk));
    let dir = su::download_dir(&g.cache);
    std::fs::create_dir_all(&dir).unwrap();
    let part = dir.join(format!("{}.part", apk_name("foss")));
    std::fs::write(&part, &apk[..1000]).unwrap();
    std::fs::write(
        dir.join(format!("{}.part.json", apk_name("foss"))),
        json!({ "sha256": want }).to_string(),
    )
    .unwrap();
    let v = download(&g).await;
    assert_eq!(v["phase"], "ready", "{v}");
    let path = std::path::PathBuf::from(v["path"].as_str().unwrap());
    assert!(path.starts_with(&g.cache));
    assert_eq!(std::fs::read(&path).unwrap(), apk);
    assert!(!part.exists());
    let ranged = g
        .srv
        .requests()
        .into_iter()
        .filter(|r| r.path().ends_with(".apk"))
        .collect::<Vec<_>>();
    assert_eq!(ranged.len(), 1);
    assert_eq!(
        ranged[0].headers.get("range").map(String::as_str),
        Some("bytes=1000-")
    );
    let st = g.call("update_status", json!({ "flavor": "foss" })).await;
    assert_eq!(st["download"]["phase"], "ready");

    // Cancel with nothing running clears the downloaded file.
    g.call("update_cancel", json!({})).await;
    assert!(!path.exists());
    let st = g.call("update_status", json!({ "flavor": "foss" })).await;
    assert_eq!(st["download"]["phase"], "idle");
}

fn apk_requests(g: &Gh) -> usize {
    g.srv.hits(&format!("/dl/{}", apk_name("foss")))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_sums_wrong_domain_or_corrupt_apk_are_refused() {
    let g = gh().await;
    g.call("update_check", json!({ "flavor": "foss" })).await;

    // SHA256SUMS.txt changed after signing: refused before the APK is requested.
    let good = g.mock.lock().unwrap().clone();
    g.set(|m| m.sums = m.sums.replacen('0', "1", 1));
    let v = download(&g).await;
    assert_eq!(v["phase"], "failed");
    assert_eq!(v["error"]["code"], "update_sig_mismatch", "{v}");
    assert_eq!(apk_requests(&g), 0);

    // A signature without the release domain prefix (a replayed bundle-style signature).
    g.set(|m| {
        use ring::signature::Ed25519KeyPair;
        let kp = Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap();
        m.sums = good.sums.clone();
        m.sig = hex(kp.sign(good.sums.as_bytes()).as_ref());
    });
    let v = download(&g).await;
    assert_eq!(v["error"]["code"], "update_sig_mismatch");
    assert_eq!(apk_requests(&g), 0);

    // An empty signature file.
    g.set(|m| m.sig = String::new());
    let v = download(&g).await;
    assert_eq!(v["error"]["code"], "update_sig_invalid");

    // Signed sums, but the served APK differs: SHA-256 mismatch, nothing kept in the cache.
    g.set(|m| {
        m.sig = good.sig.clone();
        m.served_apk[10] ^= 0xff;
    });
    let v = download(&g).await;
    assert_eq!(v["error"]["code"], "update_sha_mismatch", "{v}");
    assert_eq!(apk_requests(&g), 1);
    let left: Vec<_> = std::fs::read_dir(su::download_dir(&g.cache))
        .map(|d| d.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "{left:?}");
}
