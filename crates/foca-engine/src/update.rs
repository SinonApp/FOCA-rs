//! In-app update commands: `update_status`, `update_check`, `update_download`, `update_cancel`.
//!
//! Every request goes through the engine's network client (proxy and network settings apply)
//! with the plain `FOCA-rs/<version>` User-Agent and no other identifier. The check reads the
//! GitHub releases list (ETag cached, rate limits back off); the download fetches the APK of
//! this build's flavor into the app cache with resume, after `SHA256SUMS.txt` and its Ed25519
//! signature verified. Installing (APK certificate, package and versionCode checks plus the
//! PackageInstaller session) is the platform's part (`platform_update_install`).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use foca_core::Scope;
use foca_net::{Access, NetClient, NetRequest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::engine::lock;
use crate::services::selfupdate::{self as su, Candidate, State};
use crate::util::arg_str;
use crate::{CmdError, CmdResult, Engine};

/// Largest releases list, `SHA256SUMS.txt` and signature accepted.
const LIST_LIMIT: u64 = 4 << 20;
const SMALL_LIMIT: u64 = 64 << 10;
/// Upper bound of one APK download request (resume continues after it).
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Minimum gap between two progress events.
const PROGRESS_EVERY: Duration = Duration::from_millis(400);

fn err(code: &str, message: impl Into<String>) -> CmdError {
    CmdError::new(code, message)
}

fn flavor_arg(a: &Value) -> Result<String, CmdError> {
    let f = arg_str(a, "flavor").unwrap_or("foss").trim();
    if su::FLAVORS.contains(&f) {
        Ok(f.to_string())
    } else {
        Err(err("bad_args", format!("неизвестный вариант сборки: {f}")))
    }
}

fn error_json(e: &CmdError, retry_at: Option<i64>) -> Value {
    let mut v = json!({ "code": e.code, "message": e.message });
    if let Some(t) = retry_at {
        v["retry_at"] = json!(t);
    }
    v
}

impl Engine {
    fn update_settings(&self) -> Value {
        let s = self.store().settings_get().unwrap_or_default();
        let u = &s["update"];
        json!({
            "auto": u["auto"].as_bool().unwrap_or(true),
            "wifi_only": u["wifi_only"].as_bool().unwrap_or(true),
            "prerelease": u["prerelease"].as_bool().unwrap_or(true),
        })
    }

    fn epoch(&self) -> i64 {
        self.now().unix_timestamp()
    }

    fn cache_dir(&self) -> &Path {
        &self.inner.cfg.cache_dir
    }

    /// Project schema of this build (projects are migrated up to it on open).
    fn schema_current() -> u32 {
        foca_store::schema::PROJECT_MIGRATIONS.len() as u32
    }

    fn candidate_json(c: &Candidate) -> Value {
        let schema = su::schema_marker(&c.release.body);
        let cur = Self::schema_current();
        json!({
            "version": c.release.version,
            "tag": c.release.tag,
            "prerelease": c.release.prerelease,
            "published_at": c.release.published_at,
            "html_url": c.release.html_url,
            "notes": su::notes_text(&c.release.body),
            "asset": c.apk.name,
            "size": c.apk.size,
            "version_code": su::version_code_marker(&c.release.body),
            "schema": { "current": cur, "release": schema, "migrates": schema.is_some_and(|s| s > cur) },
        })
    }

    fn cached_candidate(&self, st: &State, flavor: &str, include_pre: bool) -> Option<Candidate> {
        if st.releases_json.is_empty() {
            return None;
        }
        let rs = su::parse_releases(&st.releases_json).ok()?;
        su::pick_update(&rs, su::current_version(), flavor, include_pre)
    }

    fn update_view(&self, st: &State, flavor: &str, include_pre: bool) -> Value {
        let backoff = (st.backoff_until > self.epoch()).then_some(st.backoff_until);
        let cand = self.cached_candidate(st, flavor, include_pre);
        let progress = lock(&self.inner.update_job).progress.clone();
        json!({
            "current": su::current_version(),
            "flavor": flavor,
            "settings": self.update_settings(),
            "checked_at": st.checked_at,
            "backoff_until": backoff,
            "error": st.last_error,
            "update": cand.as_ref().map(Self::candidate_json),
            "download": if progress.is_null() { json!({ "phase": "idle" }) } else { progress },
        })
    }

    /// `update_status { flavor? }` → last check result from the cache, settings and the download
    /// state; no network.
    pub(crate) fn update_status(&self, a: &Value) -> CmdResult {
        let flavor = flavor_arg(a)?;
        let include_pre = self.update_settings()["prerelease"]
            .as_bool()
            .unwrap_or(true);
        if lock(&self.inner.update_job).cancel.is_none() {
            su::prune_downloads(self.cache_dir(), su::current_version(), None);
        }
        let mut v = self.update_view(&su::read_state(self.data_dir()), &flavor, include_pre);
        v["outcome"] = json!("status");
        Ok(v)
    }

    fn releases_url(&self) -> String {
        format!(
            "{}/repos/{}/releases?per_page=30",
            self.inner.cfg.endpoints.github_api.trim_end_matches('/'),
            su::REPO
        )
    }

    fn update_client(&self) -> Result<NetClient, CmdError> {
        self.net_client_ua(
            Scope::default(),
            Arc::new(foca_net::NullSink),
            Some("honest"),
        )
    }

    /// `update_check { flavor, prerelease?, auto? }` → asks GitHub for releases. `auto: true` is
    /// the daily background check: it is skipped when disabled, on mobile data with Wi-Fi only,
    /// or when the last check is younger than a day. Failures (network, rate limit) come back as
    /// `outcome: "error"` with `error { code, message, retry_at? }`.
    pub(crate) async fn update_check(&self, a: &Value) -> CmdResult {
        let flavor = flavor_arg(a)?;
        let settings = self.update_settings();
        let include_pre = a["prerelease"]
            .as_bool()
            .unwrap_or_else(|| settings["prerelease"].as_bool().unwrap_or(true));
        let auto = a["auto"].as_bool().unwrap_or(false);
        let mut st = su::read_state(self.data_dir());
        let now = self.epoch();
        let skip = if !auto {
            None
        } else if settings["auto"] == false {
            Some("disabled")
        } else if settings["wifi_only"] != false && self.mobile.metered() {
            Some("metered")
        } else if !su::auto_due(&st, now) {
            Some("not_due")
        } else {
            None
        };
        if let Some(reason) = skip {
            let mut v = self.update_view(&st, &flavor, include_pre);
            v["outcome"] = json!("skipped");
            v["skipped"] = json!(reason);
            return Ok(v);
        }
        if st.backoff_until > now {
            let e = err(
                "update_rate_limited",
                "GitHub временно ограничил запросы, повторите позже",
            );
            let mut v = self.update_view(&st, &flavor, include_pre);
            v["outcome"] = json!("error");
            v["error"] = error_json(&e, Some(st.backoff_until));
            return Ok(v);
        }
        let outcome = match self.fetch_releases(&mut st, now).await {
            Ok(()) => {
                st.last_error = None;
                st.backoff_until = 0;
                if self.cached_candidate(&st, &flavor, include_pre).is_some() {
                    "available"
                } else {
                    "up_to_date"
                }
            }
            Err((e, retry)) => {
                if let Some(t) = retry {
                    st.backoff_until = t;
                }
                st.last_error = Some(error_json(&e, retry));
                "error"
            }
        };
        st.checked_at = self.now_iso();
        st.checked_epoch = now;
        su::write_state(self.data_dir(), &st)?;
        tracing::info!(target: "foca::engine", "проверка обновлений: {outcome}");
        let mut v = self.update_view(&st, &flavor, include_pre);
        v["outcome"] = json!(outcome);
        Ok(v)
    }

    /// One conditional GET of the releases list; a 304 keeps the cached list (and does not count
    /// against the GitHub rate limit).
    async fn fetch_releases(
        &self,
        st: &mut State,
        now: i64,
    ) -> Result<(), (CmdError, Option<i64>)> {
        let net = self.update_client().map_err(|e| (e, None))?;
        let mut req = NetRequest::get(&self.releases_url(), "update", Access::Passive)
            .map_err(|e| (err("update_net", e.to_string()), None))?
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .retries(0);
        if !st.etag.is_empty() && !st.releases_json.is_empty() {
            req = req.header("If-None-Match", &st.etag);
        }
        let resp = net
            .send(req)
            .await
            .map_err(|e| (err("update_net", format!("GitHub недоступен: {e}")), None))?;
        let status = resp.status();
        if status == 304 {
            return Ok(());
        }
        let hdr = |k: &str| resp.header(k).map(str::to_string);
        if let Some(wait) = su::rate_limit_wait(status, hdr, now) {
            return Err((
                err(
                    "update_rate_limited",
                    "GitHub временно ограничил запросы, повторите позже",
                ),
                Some(now + wait),
            ));
        }
        if !(200..300).contains(&status) {
            return Err((
                err("update_http", format!("GitHub ответил HTTP {status}")),
                None,
            ));
        }
        let etag = resp.header("etag").unwrap_or_default().to_string();
        let body = resp
            .text_limited(LIST_LIMIT)
            .await
            .map_err(|e| (err("update_net", format!("GitHub недоступен: {e}")), None))?;
        su::parse_releases(&body).map_err(|e| (e, None))?;
        st.etag = etag;
        st.releases_json = body;
        Ok(())
    }

    /// Release asset URLs: HTTPS on github.com, or (test bench) the origin of a loopback API
    /// endpoint.
    fn asset_url_ok(&self, url: &str) -> bool {
        let Ok(u) = url::Url::parse(url) else {
            return false;
        };
        if !u.username().is_empty() || u.password().is_some() {
            return false;
        }
        if u.scheme() == "https" && u.host_str() == Some("github.com") && u.port().is_none() {
            return true;
        }
        let Ok(api) = url::Url::parse(&self.inner.cfg.endpoints.github_api) else {
            return false;
        };
        api.host_str().is_some_and(crate::util::is_loopback_host) && api.origin() == u.origin()
    }

    async fn fetch_small(&self, net: &NetClient, url: &str) -> Result<Vec<u8>, CmdError> {
        if !self.asset_url_ok(url) {
            return Err(err(
                "update_bad_url",
                format!("недопустимый адрес файла релиза: {url}"),
            ));
        }
        let req = NetRequest::get(url, "update", Access::Passive)
            .map_err(|e| err("update_net", e.to_string()))?;
        let resp = net
            .send(req)
            .await
            .map_err(|e| err("update_net", format!("загрузка {url}: {e}")))?;
        if resp.status() == 404 {
            return Err(err("update_not_signed", "в релизе нет файла подписи"));
        }
        let resp = resp
            .ensure_success()
            .map_err(|e| err("update_net", format!("загрузка {url}: {e}")))?;
        resp.bytes_limited(SMALL_LIMIT)
            .await
            .map_err(|e| err("update_net", format!("загрузка {url}: {e}")))
    }

    /// `update_download { flavor, wait? }` → downloads and verifies the APK of the update found
    /// by the last check. Progress comes as `update` events; `wait: true` returns the final state.
    pub(crate) async fn update_download(&self, a: &Value) -> CmdResult {
        let flavor = flavor_arg(a)?;
        let include_pre = self.update_settings()["prerelease"]
            .as_bool()
            .unwrap_or(true);
        let st = su::read_state(self.data_dir());
        let cand = self
            .cached_candidate(&st, &flavor, include_pre)
            .ok_or_else(|| {
                err(
                    "update_none",
                    "нет доступного обновления, проверьте ещё раз",
                )
            })?;
        let cancel = CancellationToken::new();
        {
            let mut job = lock(&self.inner.update_job);
            if job.cancel.is_some() {
                return Err(err("busy", "обновление уже загружается"));
            }
            job.cancel = Some(cancel.clone());
            job.progress = json!({ "phase": "download", "version": cand.release.version,
                "received": 0, "total": cand.apk.size });
        }
        let e = self.clone();
        let fut = async move {
            let version = cand.release.version.clone();
            let r = e.download_run(&cand, cancel.clone()).await;
            let ev = match r {
                Ok(path) => json!({ "type": "update", "phase": "ready", "version": version,
                    "path": path.to_string_lossy(), "received": cand.apk.size, "total": cand.apk.size,
                    "asset": cand.apk.name }),
                Err(_) if cancel.is_cancelled() => {
                    e.discard_download(&cand.apk.name);
                    json!({ "type": "update", "phase": "cancelled", "version": version })
                }
                Err(x) => {
                    tracing::warn!(target: "foca::engine", "обновление {version}: {} {}", x.code, x.message);
                    json!({ "type": "update", "phase": "failed", "version": version,
                        "error": { "code": x.code, "message": x.message } })
                }
            };
            {
                let mut job = lock(&e.inner.update_job);
                job.cancel = None;
                let mut p = ev.clone();
                if let Some(o) = p.as_object_mut() {
                    o.remove("type");
                }
                job.progress = p;
            }
            e.emit(ev.clone());
            ev
        };
        if a["wait"].as_bool().unwrap_or(false) {
            return Ok(fut.await);
        }
        tokio::spawn(fut);
        Ok(json!({ "started": true }))
    }

    /// `update_cancel {}` → stops a running download and removes its files.
    pub(crate) fn update_cancel(&self) -> CmdResult {
        let running = lock(&self.inner.update_job).cancel.clone();
        match running {
            Some(t) => t.cancel(),
            None => {
                let _ = std::fs::remove_dir_all(su::download_dir(self.cache_dir()));
                lock(&self.inner.update_job).progress = Value::Null;
            }
        }
        Ok(json!({ "ok": true, "running": false }))
    }

    fn discard_download(&self, asset: &str) {
        let d = su::download_dir(self.cache_dir());
        for suffix in ["", ".part", ".part.json"] {
            let _ = std::fs::remove_file(d.join(format!("{asset}{suffix}")));
        }
    }

    fn progress(&self, cand: &Candidate, phase: &str, received: u64) {
        let p = json!({ "phase": phase, "version": cand.release.version,
            "received": received, "total": cand.apk.size });
        lock(&self.inner.update_job).progress = p.clone();
        let mut ev = p;
        ev["type"] = json!("update");
        self.emit(ev);
    }

    async fn download_run(
        &self,
        cand: &Candidate,
        cancel: CancellationToken,
    ) -> Result<PathBuf, CmdError> {
        let net = self.update_client()?.with_cancel(cancel.clone());
        let asset = |name: &str| {
            cand.release
                .assets
                .iter()
                .find(|x| x.name == name)
                .ok_or_else(|| err("update_not_signed", format!("в релизе нет {name}")))
        };
        // Signature first: nothing large is downloaded for an unsigned or tampered release.
        let sums = self.fetch_small(&net, &asset(su::SUMS_ASSET)?.url).await?;
        let sig = self.fetch_small(&net, &asset(su::SIG_ASSET)?.url).await?;
        let sig = String::from_utf8_lossy(&sig);
        su::verify_sums_signature(&sums, &sig, &self.inner.cfg.release_pubkey)?;
        let parsed = su::parse_sums(&String::from_utf8_lossy(&sums))?;
        let want = su::expected_sha256(&parsed, &cand.apk.name)?;

        let dir = su::download_dir(self.cache_dir());
        std::fs::create_dir_all(&dir)?;
        su::prune_downloads(
            self.cache_dir(),
            su::current_version(),
            Some(&cand.apk.name),
        );
        let fin = dir.join(&cand.apk.name);
        if fin.exists() {
            if file_sha256(&fin)? == want {
                return Ok(fin);
            }
            let _ = std::fs::remove_file(&fin);
        }
        let part = dir.join(format!("{}.part", cand.apk.name));
        let meta = dir.join(format!("{}.part.json", cand.apk.name));
        let same = std::fs::read(&meta)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .is_some_and(|m| m["sha256"] == want.as_str());
        if !same {
            let _ = std::fs::remove_file(&part);
        }
        std::fs::write(
            &meta,
            json!({ "sha256": want, "url": cand.apk.url }).to_string(),
        )?;
        self.fetch_apk(&net, cand, &part).await?;

        self.progress(cand, "verify", cand.apk.size);
        let got = file_sha256(&part)?;
        if got != want {
            self.discard_download(&cand.apk.name);
            return Err(err(
                "update_sha_mismatch",
                format!("SHA-256 файла не совпадает с SHA256SUMS.txt: {got}"),
            ));
        }
        std::fs::rename(&part, &fin)?;
        let _ = std::fs::remove_file(&meta);
        Ok(fin)
    }

    /// Downloads the APK into `part`, continuing a partial file with a Range request.
    async fn fetch_apk(
        &self,
        net: &NetClient,
        cand: &Candidate,
        part: &Path,
    ) -> Result<(), CmdError> {
        if !self.asset_url_ok(&cand.apk.url) {
            return Err(err(
                "update_bad_url",
                format!("недопустимый адрес файла релиза: {}", cand.apk.url),
            ));
        }
        let mut have = std::fs::metadata(part).map(|m| m.len()).unwrap_or(0);
        if cand.apk.size > 0 && have > cand.apk.size {
            let _ = std::fs::remove_file(part);
            have = 0;
        }
        let mut req = NetRequest::get(&cand.apk.url, "update", Access::Passive)
            .map_err(|e| err("update_net", e.to_string()))?
            .timeout(DOWNLOAD_TIMEOUT)
            .retries(1);
        if have > 0 {
            req = req.header("Range", &format!("bytes={have}-"));
        }
        let net_err = |e: foca_net::NetError| err("update_net", format!("загрузка APK: {e}"));
        let mut resp = net.send(req).await.map_err(net_err)?;
        let status = resp.status();
        let append = match status {
            206 if have > 0 => true,
            200 => false,
            416 if have > 0 && have == cand.apk.size => return Ok(()),
            _ => {
                return Err(err("update_http", format!("загрузка APK: HTTP {status}")));
            }
        };
        if !append {
            have = 0;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(part)?;
        let mut last = std::time::Instant::now();
        self.progress(cand, "download", have);
        while let Some(chunk) = resp.chunk().await.map_err(net_err)? {
            f.write_all(&chunk)?;
            have += chunk.len() as u64;
            if cand.apk.size > 0 && have > cand.apk.size {
                return Err(err("update_size", "APK больше заявленного размера"));
            }
            if last.elapsed() >= PROGRESS_EVERY {
                last = std::time::Instant::now();
                self.progress(cand, "download", have);
            }
        }
        f.flush()?;
        if cand.apk.size > 0 && have != cand.apk.size {
            return Err(err(
                "update_size",
                format!("загружено {have} из {} байт", cand.apk.size),
            ));
        }
        self.progress(cand, "download", have);
        Ok(())
    }
}

fn file_sha256(p: &Path) -> Result<String, CmdError> {
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(su::hex_encode(&h.finalize()))
}
