//! `foca serve --data <dir> [--port 8787] [--ui ui] [--test-net file]`: e2e harness exposing
//! the real engine over HTTP on 127.0.0.1 only (browser UI tests without Android or
//! webkit2gtk).
//!
//! * `POST /invoke {cmd, args}` → `Engine::invoke`: `{result}` or
//!   `{error:{code,message,targets?}}` (HTTP 200; 400 only for an unparsable request);
//!   `platform_*` commands are stubs (like the demo backend, but files for share/save are
//!   resolved for real, strictly inside the data directory);
//! * `GET /events`: Server-Sent Events, `data: {"event":"scan://event"|"net","payload":…}`;
//! * `GET /…`: static files from `ui/` (no escaping the root).
//!
//! `qa/tauri-shim.js` provides `window.__TAURI__` on top of this API. `--test-net` takes the
//! file written by `foca testnet --write-config` (a local "internet": CDX/crt.sh/documents,
//! StaticDns).

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::Args;
use foca_engine::{CmdError, Engine, EngineConfig, FnEvents, MemoryKeys};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

#[derive(Args, Debug)]
pub struct ServeOpts {
    /// Data directory (like app_data_dir on Android): projects.db, project files, exports/, reports/
    #[arg(long)]
    pub data: PathBuf,
    #[arg(long, default_value_t = 8787)]
    pub port: u16,
    /// UI directory (default: the repository's ui/)
    #[arg(long)]
    pub ui: Option<PathBuf>,
    /// Local "internet" configuration (`foca testnet --write-config`)
    #[arg(long)]
    pub test_net: Option<PathBuf>,
    /// Directory of "phone files" for the platform_pick_files / platform_pick_image stubs
    #[arg(long)]
    pub pick_dir: Option<PathBuf>,
    /// Local time offset in minutes (like the device utc_offset in the Android bridge)
    #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
    pub utc_offset_min: i32,
}

struct Ctx {
    engine: Engine,
    ui: PathBuf,
    data: PathBuf,
    pick: Option<PathBuf>,
    tx: broadcast::Sender<String>,
}

pub fn run(o: ServeOpts) -> Result<bool> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    rt.block_on(serve(o))
}

fn find_ui(o: &ServeOpts) -> Result<PathBuf> {
    let mut c: Vec<PathBuf> = vec![];
    if let Some(u) = &o.ui {
        c.push(u.clone());
    }
    c.push("ui".into());
    c.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui"));
    c.into_iter()
        .find(|p| p.join("index.html").is_file())
        .and_then(|p| p.canonicalize().ok())
        .ok_or_else(|| anyhow!("не найдена папка ui/ (index.html): укажите --ui"))
}

/// Applies the test network configuration to the engine.
pub fn apply_test_net(cfg: &mut EngineConfig, t: &Value) -> Result<()> {
    let base = t["base"]
        .as_str()
        .ok_or_else(|| anyhow!("test-net: нет base"))?
        .trim_end_matches('/')
        .to_string();
    cfg.endpoints.wayback = base.clone();
    cfg.endpoints.crtsh = base.clone();
    cfg.endpoints.cc_collinfo = format!("{base}/collinfo.json");
    cfg.endpoints.rdap = foca_net::rdap::RdapEndpoints {
        ripestat: format!("{base}/ripe"),
        rdap: format!("{base}/rdap"),
    };
    cfg.endpoints
        .ai
        .insert("deepseek".into(), format!("{base}/ai"));
    cfg.endpoints
        .ai
        .insert("openai".into(), format!("{base}/ai"));
    cfg.endpoints.ip_echo = format!("{base}/ip");
    cfg.endpoints.sources.insert("grepapp".into(), base.clone());
    cfg.endpoints.ip_geo = format!("{base}/geo/{{ip}}");
    // Every other public source is pointed at the harness too (testnet does not know their
    // paths, so they get a fast 404 / source error): e2e neither depends on nor touches the
    // real internet.
    for id in foca_engine::HOST_SOURCE_IDS
        .iter()
        .chain(foca_engine::DOC_SOURCE_IDS)
        .chain(&["internetdb"])
        .chain(foca_engine::INFRA_SOURCE_IDS)
    {
        cfg.endpoints
            .sources
            .entry((*id).to_string())
            .or_insert_with(|| format!("{base}/src/{id}"));
    }
    // Hard barrier: a host other than localhost / *.test / loopback is never requested; it is
    // written to the request log and to `<data>/test-net-external.log` (qa/real-e2e.sh fails with
    // the host name).
    cfg.net.local_only = Some(cfg.data_dir.join("test-net-external.log"));
    if let Some(z) = t["zone"].as_str() {
        cfg.dns = Some(Arc::new(foca_net::dns::StaticDns::from_zone_text(z)));
    }
    let strs = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    cfg.passive_download_hosts = strs(&t["passive_download_hosts"]);
    if let Some(p) = t["alive_ports"].as_array() {
        cfg.alive_ports = p
            .iter()
            .filter_map(|x| x.as_u64())
            .map(|x| x as u16)
            .collect();
    }
    cfg.site_port = t["site_port"].as_u64().map(|p| p as u16);
    if let Some(m) = t["host_overrides"].as_object() {
        for (h, ips) in m {
            let ips = strs(ips).iter().filter_map(|s| s.parse().ok()).collect();
            cfg.net.host_overrides.insert(h.clone(), ips);
        }
    }
    cfg.net.global_rps = None;
    cfg.net.source_rps.clear();
    cfg.net.retries = 0;
    if let Some(n) = t["download_concurrency"].as_u64() {
        cfg.download_concurrency = n.max(1) as usize;
    }
    if let Some(n) = t["meta_concurrency"].as_u64() {
        cfg.meta_concurrency = n.max(1) as usize;
    }
    if t["fuzz_fast"].as_bool() == Some(true) {
        cfg.fuzz_unthrottled = true;
    }
    // offline StaticDns zone: subdomain brute force needs no adaptive pace
    cfg.dns_unthrottled = true;
    if let Some(n) = t["max_docs"].as_u64() {
        cfg.max_docs = n.max(1) as usize;
    }
    Ok(())
}

async fn serve(o: ServeOpts) -> Result<bool> {
    let ui = find_ui(&o)?;
    std::fs::create_dir_all(&o.data)?;
    let data = o.data.canonicalize()?;
    let (tx, _) = broadcast::channel::<String>(1024);
    let mut cfg = EngineConfig::new(&data);
    // Same as on Android (src-tauri/src/bridge.rs): exports and reports go to the private data
    // directory.
    cfg.export_dir = data.join("exports");
    // Dates use the "device" local time; the offset is explicit (the harness browser runs in
    // the same zone).
    cfg.utc_offset = time::UtcOffset::from_whole_seconds(o.utc_offset_min * 60)
        .map_err(|e| anyhow!("--utc-offset-min: {e}"))?;
    if let Some(f) = &o.test_net {
        let t: Value = serde_json::from_slice(
            &std::fs::read(f).with_context(|| format!("test-net {}", f.display()))?,
        )?;
        apply_test_net(&mut cfg, &t)?;
    }
    let etx = tx.clone();
    let sink = Arc::new(FnEvents(move |e: &Value| {
        let _ = etx.send(json!({ "event": "scan://event", "payload": e }).to_string());
    }));
    let engine =
        Engine::open(cfg, Arc::new(MemoryKeys::new()), sink).map_err(|e| anyhow!("{e}"))?;
    let ctx = Arc::new(Ctx {
        engine,
        ui,
        data,
        pick: o.pick_dir.clone().and_then(|p| p.canonicalize().ok()),
        tx,
    });
    let l = TcpListener::bind(("127.0.0.1", o.port)).await?;
    eprintln!(
        "foca serve: http://127.0.0.1:{}/ (данные {}, ui {})",
        o.port,
        ctx.data.display(),
        ctx.ui.display()
    );
    loop {
        tokio::select! {
            a = l.accept() => {
                let (s, _) = a?;
                let c = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = conn(s, c).await {
                        eprintln!("serve: {e}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                // Like a process kill: a running scan is recorded as stopped/restart on the next start.
                return Ok(true);
            }
        }
    }
}

struct Req {
    method: String,
    path: String,
    body: Vec<u8>,
}

async fn read_req(s: &mut TcpStream) -> std::io::Result<Option<Req>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 64 * 1024 {
            return Ok(None);
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("").to_string();
    let target = first.next().unwrap_or("/").to_string();
    let mut cl = 0usize;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                cl = v.trim().parse().unwrap_or(0);
            }
        }
    }
    if cl > 32 * 1024 * 1024 {
        return Ok(None);
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < cl {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    let path = target.split(['?', '#']).next().unwrap_or("/").to_string();
    Ok(Some(Req { method, path, body }))
}

async fn respond(s: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body).await?;
    s.flush().await
}

async fn conn(mut s: TcpStream, ctx: Arc<Ctx>) -> Result<()> {
    let Some(r) = read_req(&mut s).await? else {
        return Ok(());
    };
    match (r.method.as_str(), r.path.as_str()) {
        ("POST", "/invoke") => {
            let (status, body) = match serde_json::from_slice::<Value>(&r.body) {
                Ok(v) => {
                    let cmd = v["cmd"].as_str().unwrap_or("").to_string();
                    let args = v.get("args").cloned().unwrap_or(Value::Null);
                    // A command error is also HTTP 200 (like a rejected Tauri invoke), so the console shows no
                    // "Failed to load resource".
                    match invoke(&ctx, &cmd, args).await {
                        Ok(v) => (200, json!({ "result": v })),
                        Err(e) => (200, json!({ "error": e })),
                    }
                }
                Err(e) => (
                    400,
                    json!({ "error": { "code": "bad_args", "message": e.to_string() } }),
                ),
            };
            respond(
                &mut s,
                status,
                "application/json; charset=utf-8",
                body.to_string().as_bytes(),
            )
            .await?;
        }
        ("GET", "/events") => {
            let mut rx = ctx.tx.subscribe();
            s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\nretry: 500\n: foca\n\n",
            )
            .await?;
            s.flush().await?;
            loop {
                let msg = tokio::select! {
                    m = rx.recv() => match m {
                        Ok(m) => format!("data: {m}\n\n"),
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => return Ok(()),
                    },
                    _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => ": ping\n\n".to_string(),
                };
                if s.write_all(msg.as_bytes()).await.is_err() || s.flush().await.is_err() {
                    return Ok(());
                }
            }
        }
        ("GET", p) | ("HEAD", p) => match static_file(&ctx.ui, p) {
            Some(f) => {
                let b = tokio::fs::read(&f).await?;
                respond(&mut s, 200, mime(&f), &b).await?
            }
            None => respond(&mut s, 404, "text/plain", b"not found").await?,
        },
        _ => respond(&mut s, 405, "text/plain", b"method").await?,
    }
    Ok(())
}

fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Resolves a static file strictly inside `root`: no `..`, absolute paths or escapes through
/// links.
pub fn static_file(root: &Path, url_path: &str) -> Option<PathBuf> {
    let dec = pct_decode(url_path)?;
    if dec.contains('\0') || dec.contains('\\') {
        return None;
    }
    let rel = dec.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    let rp = Path::new(rel);
    if !rp.components().all(|c| matches!(c, Component::Normal(_))) {
        return None;
    }
    let f = root.join(rp).canonicalize().ok()?;
    (f.starts_with(root) && f.is_file()).then_some(f)
}

fn mime(p: &Path) -> &'static str {
    match p
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        _ => "application/octet-stream",
    }
}

async fn invoke(ctx: &Ctx, cmd: &str, args: Value) -> Result<Value, CmdError> {
    let args = if args.is_null() { json!({}) } else { args };
    if let Some(p) = cmd.strip_prefix("platform_") {
        return platform(ctx, p, &args).await;
    }
    ctx.engine.invoke(cmd, args).await
}

/// Stubs for the platform commands (docs/API.md, platform commands). Files for share and
/// save are resolved as in the Android bridge: only inside the app data directory.
async fn platform(ctx: &Ctx, p: &str, a: &Value) -> Result<Value, CmdError> {
    match p {
        "share" | "save" => {
            let (path, name) = resolve_file(ctx, a).await?;
            if p == "share" {
                return Ok(json!({ "ok": true, "name": name, "stub": true }));
            }
            let dst = ctx.data.join("Download").join("FOCA-rs");
            std::fs::create_dir_all(&dst)?;
            std::fs::copy(&path, dst.join(&name))?;
            Ok(
                json!({ "ok": true, "path": format!("Download/FOCA-rs/{name}"), "uri": null, "stub": true }),
            )
        }
        "biometric" => Ok(json!({ "ok": true, "available": true, "stub": true })),
        "secure" => Ok(json!({ "ok": true, "applied": false, "stub": true })),
        "battery_status" => Ok(json!({
            "ignoring": false, "supported": false, "oem": "pixel", "rom": "Android",
            "manufacturer": "Google", "model": "e2e", "android": "14", "sdk": 34,
            "label": "Стенд e2e · foca serve", "notifications": true, "stub": true })),
        "battery_settings" => Ok(json!({ "opened": null, "stub": true })),
        "notifications" | "request_notifications" => {
            Ok(json!({ "enabled": true, "granted": true, "action": "none", "stub": true }))
        }
        "permissions_status" => Ok(json!({
            "notifications": false, "notifications_runtime": true, "notifications_blocked": false,
            "battery": false, "oem": "pixel", "manufacturer": "Google", "brand": "google", "sdk": 34, "stub": true })),
        "exit" => Ok(json!({ "ok": true, "stub": true })),
        "device_info" => Ok(json!({
            "manufacturer": "Google", "model": "e2e", "release": "14", "sdk": 34, "abi": "x86_64",
            "mem_total_mb": 4096, "mem_avail_mb": 2048, "disk_free_mb": 10240, "service_running": false,
            "battery_ignoring": false, "notifications": true, "net": true, "vpn": false, "stub": true })),
        "pick_files" | "pick_image" => pick(ctx, p == "pick_image", a),
        // Folder picker (SAF tree on Android): every file of the stand's "phone files" directory.
        "pick_folder" => {
            let mut v = pick(ctx, false, &json!({ "multiple": true }))?;
            v["skipped"] = json!(0);
            v["truncated"] = json!(false);
            Ok(v)
        }
        "pick_clear" => {
            let dir = ctx.data.join("picked");
            let removed = std::fs::read_dir(&dir)
                .map(|r| r.filter_map(Result::ok).count())
                .unwrap_or(0);
            let _ = std::fs::remove_dir_all(&dir);
            Ok(json!({ "ok": true, "removed": removed }))
        }
        // Background survival card: a fixed desktop answer, nothing can kill the stand.
        "bg_status" | "bg_set" => Ok(bg_status()),
        // A visible browser for manual search engine verification exists only on Android.
        "verify_search" => Ok(json!({ "ok": false, "unsupported": true, "stub": true,
            "error": "Пройти проверку можно только в приложении на телефоне: встроенного браузера на стенде нет" })),
        // The stand has no native clipboard: the UI falls back to navigator.clipboard.
        "clipboard_read" => Ok(
            json!({ "ok": false, "unsupported": true, "text": "", "available": false, "stub": true }),
        ),
        "clipboard_write" => Ok(json!({ "ok": false, "unsupported": true, "stub": true })),
        "clipboard_clear" => {
            Ok(json!({ "ok": false, "unsupported": true, "cleared": false, "stub": true }))
        }
        _ => Err(CmdError::new("unknown_command", format!("platform_{p}"))),
    }
}

/// `platform_bg_status` / `platform_bg_set` on the stand (settings are not stored).
fn bg_status() -> Value {
    json!({
        "oem": "desktop", "autostart": "unknown", "battery_unrestricted": true,
        "hide_recents": false, "hide_recents_default": false, "hide_recents_chosen": false,
        "stub": true
    })
}

/// File picker (SAF / photo picker on Android): copies into the private `picked/` directory.
fn pick(ctx: &Ctx, image: bool, a: &Value) -> Result<Value, CmdError> {
    let Some(dir) = &ctx.pick else {
        return Ok(json!({ "ok": false, "cancelled": true, "files": [] }));
    };
    let want: Vec<String> = a["names"]
        .as_array()
        .map(|v| {
            v.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let multiple = a["multiple"].as_bool().unwrap_or(!image);
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .filter(|p| {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let ext = n.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
            (want.is_empty() || want.iter().any(|w| w == n))
                && (!image || matches!(ext.as_str(), "jpg" | "jpeg" | "png" | "webp" | "heic"))
        })
        .collect();
    names.sort();
    if !multiple {
        names.truncate(1);
    }
    let out = ctx.data.join("picked");
    std::fs::create_dir_all(&out)?;
    let mut files = vec![];
    for src in names {
        let name = src.file_name().unwrap().to_string_lossy().into_owned();
        let dst = out.join(&name);
        std::fs::copy(&src, &dst)?;
        let size = std::fs::metadata(&dst)?.len();
        files.push(
            json!({ "path": dst.to_string_lossy(), "name": name, "size": size,
            "mime": foca_mime(&name) }),
        );
    }
    Ok(json!({ "ok": !files.is_empty(), "cancelled": files.is_empty(), "files": files }))
}

fn foca_mime(n: &str) -> &'static str {
    match n
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

async fn resolve_file(ctx: &Ctx, a: &Value) -> Result<(PathBuf, String), CmdError> {
    let mut raw = a["path"].as_str().map(str::to_string);
    if raw.is_none() {
        if let Some(rid) = a.get("report").filter(|v| !v.is_null()) {
            let project = a["project"].clone();
            let list = ctx
                .engine
                .invoke("report_list", json!({ "project": project }))
                .await?;
            let rec = list
                .as_array()
                .and_then(|l| l.iter().find(|r| r.get("id") == Some(rid)).cloned())
                .ok_or_else(|| CmdError::not_found("отчёт не найден"))?;
            raw = rec["path"].as_str().map(str::to_string);
        } else if let Some(doc) = a.get("doc").filter(|v| !v.is_null()) {
            let f = ctx
                .engine
                .invoke("doc_file", json!({ "project": a["project"], "id": doc }))
                .await?;
            raw = f["path"].as_str().map(str::to_string);
        }
    }
    let raw = raw.ok_or_else(|| CmdError::new("bad_args", "нужен path, report или doc"))?;
    let root = ctx.data.clone();
    let p = Path::new(&raw);
    let cand = if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    };
    let f = cand
        .canonicalize()
        .ok()
        .filter(|c| c.starts_with(&root) && c.is_file())
        .ok_or_else(|| CmdError::not_found(format!("файл не найден: {raw}")))?;
    let name = a["name"]
        .as_str()
        .map(str::to_string)
        .or_else(|| f.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "foca-export".into());
    Ok((f, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bg_status_is_a_fixed_desktop_answer() {
        let v = bg_status();
        assert_eq!(v["oem"], "desktop");
        assert_eq!(v["autostart"], "unknown");
        assert_eq!(v["battery_unrestricted"], true);
        assert_eq!(v["hide_recents"], false);
    }

    #[test]
    fn static_files_stay_inside_root() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("ui");
        std::fs::create_dir_all(root.join("js")).unwrap();
        std::fs::write(root.join("index.html"), "x").unwrap();
        std::fs::write(root.join("js/a.js"), "x").unwrap();
        std::fs::write(d.path().join("secret.txt"), "x").unwrap();
        let root = root.canonicalize().unwrap();
        assert!(static_file(&root, "/").is_some());
        assert!(static_file(&root, "/js/a.js").is_some());
        assert!(static_file(&root, "/js%2Fa.js").is_some());
        for bad in [
            "/../secret.txt",
            "/js/../../secret.txt",
            "/%2e%2e/secret.txt",
            "/..%2fsecret.txt",
            "//etc/passwd",
            "/js/..\\..\\secret.txt",
            "/nope.js",
            "/%zz",
        ] {
            assert!(static_file(&root, bad).is_none(), "{bad}");
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(d.path().join("secret.txt"), root.join("link.txt")).unwrap();
            assert!(static_file(&root, "/link.txt").is_none());
        }
    }
}
