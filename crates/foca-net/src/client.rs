//! HTTP client with scope enforcement, rate limiting, retries, cancellation and a request log.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::Bytes;
use foca_core::target::{normalize_ip, parse_ip_literal};
use foca_core::{Clock, Scope, ScopeDenied, SystemClock};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use url::Url;

pub use reqwest::Method;

use crate::ratelimit::TokenBucket;
use crate::sink::{redact_url, RequestRecord, RequestSink};
use crate::{BoxFuture, NetError};

/// Access class of a request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Access {
    /// A third-party service (crt.sh, archive.org, Common Crawl, Brave, ...); the scope is not checked.
    Passive,
    /// A target host (crawler, downloads from the target site, TCP liveness): the host must be in
    /// scope and its resolved IPs must not be excluded.
    TouchesTarget,
    /// An active module (AXFR, fuzzer, ...): like `TouchesTarget`, plus the active stage of the scan (`Scope::check_active`).
    Active { operation: String },
    /// An active request to the target's service infrastructure, i.e. an authoritative name server
    /// of an in-scope zone (AXFR). The zone is checked with `check_active(zone)`; the name server
    /// itself (usually third-party DNS hosting) may be out of scope but must not be excluded by
    /// name or resolved IP.
    ZoneInfra { zone: String, operation: String },
}

impl Access {
    pub fn active(op: &str) -> Access {
        Access::Active {
            operation: op.to_string(),
        }
    }

    /// Returns `true` if the request touches the target.
    pub fn touches_target(&self) -> bool {
        !matches!(self, Access::Passive)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Access::Passive => "passive",
            Access::TouchesTarget => "target",
            Access::Active { .. } | Access::ZoneInfra { .. } => "active",
        }
    }
}

/// Returns the honest User-Agent (`FOCA-rs/<version>`, without a URL since the project has no public address).
pub fn honest_ua() -> String {
    format!("FOCA-rs/{}", env!("CARGO_PKG_VERSION"))
}

/// Client settings (mirror `settings.net` in `docs/API.md`).
#[derive(Debug, Clone)]
pub struct NetConfig {
    pub user_agent: String,
    /// Browser profile headers in order, including `user-agent` ([`crate::ua::BrowserProfile`]).
    /// When empty, only `user_agent` is sent. Request headers override headers with the same name.
    pub headers: Vec<(String, String)>,
    /// Sends HTTP/1.1 header names in Title-Case (`User-Agent`), as browsers do.
    pub title_case_headers: bool,
    /// `http://h:p`, `https://h:p`, `socks5://h:p` or `socks5h://h:p` (with `socks5h`, DNS is resolved by the proxy).
    pub proxy: Option<String>,
    pub connect_timeout: Duration,
    /// Read timeout between body chunks.
    pub read_timeout: Duration,
    /// Default overall request timeout (`None` means no overall limit, for large downloads).
    pub timeout: Option<Duration>,
    /// Retries after the first attempt (transient errors, 429/5xx).
    pub retries: u32,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    /// Maximum number of concurrent requests (semaphore).
    pub max_concurrency: usize,
    /// Hosts whose request quota is shared by several sources (OTX: `otx_dns` and `otx_url`). After a
    /// final 429 (with `Retry-After` retries exhausted) this client stops contacting the host for
    /// the rest of its lifetime (the scan) and returns `Status(429)` at once, logging the request as not sent.
    pub shared_limit_hosts: Vec<String>,
    /// Global request rate limit, per second.
    pub global_rps: Option<f64>,
    /// Per-source rate limits (for example `crt` at 0.5).
    pub source_rps: HashMap<String, f64>,
    pub max_redirects: usize,
    /// Static name-to-IP mappings, similar to `/etc/hosts` (used by tests).
    pub host_overrides: HashMap<String, Vec<IpAddr>>,
    /// Default body size limit for `text()`/`json()`.
    pub max_body: u64,
    /// Local network only (the `foca serve --test-net` test bench): requests to anything other than
    /// `localhost`, `*.test`, loopback IPs and `host_overrides` with loopback addresses are rejected
    /// before connecting, logged, and appended as a line to this file if the path is not empty.
    pub local_only: Option<std::path::PathBuf>,
    /// Resolves names for the scope check when a proxy is configured; the system resolver is never
    /// used through a proxy (DNS leak). Without one, a proxied name is treated as unresolved.
    pub proxy_resolver: Option<Arc<dyn ProxyResolver>>,
}

/// Name resolution for scope checks of a proxied client, done through the client itself (for
/// example DNS over HTTPS via the same proxy).
pub trait ProxyResolver: Send + Sync + std::fmt::Debug {
    /// IP addresses of `host`; an empty list when there is no answer.
    fn resolve<'a>(&'a self, net: &'a NetClient, host: &'a str) -> BoxFuture<'a, Vec<IpAddr>>;
}

impl Default for NetConfig {
    fn default() -> Self {
        let mut source_rps = HashMap::new();
        // Go easy on free public APIs.
        source_rps.insert("crt".to_string(), 0.5);
        source_rps.insert("wayback".to_string(), 1.0);
        source_rps.insert("cc".to_string(), 1.0);
        source_rps.insert("certspotter".to_string(), 0.5);
        source_rps.insert("brave".to_string(), 1.0);
        NetConfig {
            user_agent: honest_ua(),
            headers: Vec::new(),
            title_case_headers: false,
            proxy: None,
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(120),
            timeout: None,
            retries: 2,
            backoff_base: Duration::from_millis(500),
            backoff_max: Duration::from_secs(20),
            max_concurrency: 8,
            shared_limit_hosts: vec!["otx.alienvault.com".into()],
            global_rps: Some(10.0),
            source_rps,
            max_redirects: 8,
            host_overrides: HashMap::new(),
            max_body: 32 * 1024 * 1024,
            local_only: None,
            proxy_resolver: None,
        }
    }
}

/// An outgoing request.
#[derive(Debug, Clone)]
pub struct NetRequest {
    pub method: Method,
    pub url: Url,
    pub module: String,
    pub access: Access,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
    pub retries: Option<u32>,
    pub follow_redirects: bool,
    /// For passive requests: allowed hop hosts (archives and similar, including subdomains). `None`
    /// allows any host that is not a target or an exclusion. A hop outside the list fails with `OutOfScope`.
    pub passive_allow: Option<Arc<Vec<String>>>,
}

impl NetRequest {
    pub fn new(method: Method, url: &str, module: &str, access: Access) -> Result<Self, NetError> {
        let url = Url::parse(url).map_err(|e| NetError::BadUrl(format!("{url}: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(NetError::BadUrl(format!("схема {}", url.scheme())));
        }
        Ok(NetRequest {
            method,
            url,
            module: module.to_string(),
            access,
            headers: Vec::new(),
            body: None,
            timeout: None,
            retries: None,
            follow_redirects: true,
            passive_allow: None,
        })
    }

    pub fn get(url: &str, module: &str, access: Access) -> Result<Self, NetError> {
        Self::new(Method::GET, url, module, access)
    }

    pub fn head(url: &str, module: &str, access: Access) -> Result<Self, NetError> {
        Self::new(Method::HEAD, url, module, access)
    }

    /// Restricts the hops of a passive request to a host list (see [`NetRequest::passive_allow`]).
    pub fn passive_allow(mut self, hosts: Arc<Vec<String>>) -> Self {
        self.passive_allow = Some(hosts);
        self
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }

    pub fn body(mut self, b: Vec<u8>) -> Self {
        self.body = Some(b);
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }

    pub fn retries(mut self, n: u32) -> Self {
        self.retries = Some(n);
        self
    }

    pub fn no_redirects(mut self) -> Self {
        self.follow_redirects = false;
        self
    }
}

struct Inner {
    cfg: NetConfig,
    /// Hosts from `shared_limit_hosts` that have already returned a final 429.
    limited: Mutex<std::collections::HashSet<String>>,
    passive: reqwest::Client,
    target: reqwest::Client,
    scope: Arc<RwLock<Scope>>,
    /// The full project scope (targets and exclusions) used to check passive requests. With the
    /// passive profile the network scope is empty, yet passive requests must still stay away from
    /// target hosts and exclusions.
    guard: Arc<RwLock<Scope>>,
    /// Passive requests to target hosts are denied (passive profile); otherwise they are treated as `target`.
    guard_blocks_targets: Arc<std::sync::atomic::AtomicBool>,
    clock: Arc<dyn Clock>,
    sink: Arc<dyn RequestSink>,
    sem: Arc<Semaphore>,
    global: Option<TokenBucket>,
    per_source: Mutex<HashMap<String, Arc<TokenBucket>>>,
}

/// Pause state a client follows: `Some(reason)` while the scan is paused.
pub type PauseState = tokio::sync::watch::Receiver<Option<String>>;

/// Shared HTTP client. Cloning is cheap (`Arc`); a clone may carry its own cancellation token
/// ([`NetClient::with_cancel`]) and follow a scan's pause ([`NetClient::with_pause`]).
#[derive(Clone)]
pub struct NetClient {
    inner: Arc<Inner>,
    cancel: CancellationToken,
    pause: Option<PauseState>,
}

impl std::fmt::Debug for NetClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetClient")
            .field("proxy", &self.inner.cfg.proxy)
            .field("ua", &self.inner.cfg.user_agent)
            .finish()
    }
}

/// Resolver error of the target client: every address is excluded by the scope.
#[derive(Debug)]
struct ExcludedIp(String);

impl std::fmt::Display for ExcludedIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "адреса исключены скоупом: {}", self.0)
    }
}
impl std::error::Error for ExcludedIp {}

/// reqwest resolver: static mappings first, then the system resolver (`getaddrinfo`, which on
/// Android honors Private DNS and VPN settings). For the target client it drops IPs excluded by
/// the scope at connect time, which protects against DNS rebinding between check and connect.
struct ScopedResolver {
    overrides: HashMap<String, Vec<IpAddr>>,
    scope: Option<Arc<RwLock<Scope>>>,
    block_targets: Option<Arc<std::sync::atomic::AtomicBool>>,
    passive_ssrf: bool,
}

fn is_non_loopback_private_ip(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_unspecified()
                || v6.is_multicast()
                || (seg0 & 0xfe00) == 0xfc00
                || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

fn is_loopback_host_name(host: &str) -> bool {
    let h = host
        .trim()
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h.parse::<IpAddr>()
            .is_ok_and(|ip| normalize_ip(ip).is_loopback())
}

fn is_private_or_loopback_host(host: &str) -> bool {
    let h = host
        .trim()
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    is_loopback_host_name(&h)
        || h.ends_with(".local")
        || h.ends_with(".internal")
        || h.parse::<IpAddr>()
            .is_ok_and(|ip| normalize_ip(ip).is_loopback() || is_non_loopback_private_ip(ip))
}

fn is_sensitive_header(name: &str) -> bool {
    let low = name.trim().to_ascii_lowercase();
    matches!(
        low.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "x-api-key"
            | "x-apikey"
            | "x-goog-api-key"
            | "apikey"
            | "api-key"
            | "x-auth-token"
            | "x-token"
    )
}

impl reqwest::dns::Resolve for ScopedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().trim_end_matches('.').to_ascii_lowercase();
        let ov = self.overrides.get(&host).cloned();
        let scope = self.scope.clone();
        let block_targets = self.block_targets.clone();
        let passive_ssrf = self.passive_ssrf;
        Box::pin(async move {
            let has_override = ov.is_some();
            let ips: Vec<IpAddr> = match ov {
                Some(v) => v,
                None => tokio::net::lookup_host((host.as_str(), 0))
                    .await?
                    .map(|a| a.ip())
                    .collect(),
            };
            let check_targets = block_targets
                .as_ref()
                .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed));
            let allow_loopback_literal = is_loopback_host_name(&host);
            let kept: Vec<IpAddr> = ips
                .iter()
                .copied()
                .filter(|ip| {
                    if let Some(s) = &scope {
                        let sg = read_scope(s);
                        if ip_excluded(&sg, *ip) {
                            return false;
                        }
                        if check_targets && sg.allows_ip(*ip) {
                            return false;
                        }
                    }
                    if passive_ssrf && !has_override {
                        if is_non_loopback_private_ip(*ip) {
                            return false;
                        }
                        if !allow_loopback_literal && normalize_ip(*ip).is_loopback() {
                            return false;
                        }
                    }
                    true
                })
                .collect();
            if kept.is_empty() && !ips.is_empty() {
                return Err(Box::new(ExcludedIp(host)) as Box<_>);
            }
            let addrs: reqwest::dns::Addrs =
                Box::new(kept.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

fn read_scope(s: &RwLock<Scope>) -> std::sync::RwLockReadGuard<'_, Scope> {
    match s.read() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Returns `true` if a name or IP literal is covered by a scope exclusion (targets are not checked).
fn scope_excludes(scope: &Scope, host: &str) -> bool {
    match parse_ip_literal(host) {
        Some(ip) => ip_excluded(scope, ip),
        None => scope.excludes.iter().any(|t| t.covers_host(host)),
    }
}

/// Returns `true` if the IP is covered by a scope exclusion.
pub fn ip_excluded(scope: &Scope, ip: IpAddr) -> bool {
    let ip = normalize_ip(ip);
    scope.excludes.iter().any(|t| t.contains_ip(ip))
}

/// Returns `true` for a local test bench host: `localhost`, `*.localhost`, `*.test`, loopback IPs,
/// IPv4 documentation ranges (RFC 5737, not routable; used as port scan canaries), or a name from
/// `host_overrides` whose addresses all fall into these categories.
pub fn is_local_host(host: &str, overrides: &HashMap<String, Vec<IpAddr>>) -> bool {
    let h = host
        .trim()
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h == "test" || h.ends_with(".test") {
        return true;
    }
    let ok = |ip: &IpAddr| match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_documentation(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    if let Ok(ip) = h.parse::<IpAddr>() {
        return ok(&ip);
    }
    overrides
        .get(&h)
        .is_some_and(|v| !v.is_empty() && v.iter().all(ok))
}

fn host_of(url: &Url) -> String {
    match url.host() {
        Some(url::Host::Ipv6(a)) => a.to_string(),
        Some(h) => h.to_string(),
        None => String::new(),
    }
}

fn map_reqwest(e: reqwest::Error) -> NetError {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(&e);
    while let Some(s) = src {
        if let Some(x) = s.downcast_ref::<ExcludedIp>() {
            return NetError::OutOfScope {
                host: x.0.clone(),
                reason: "резолвленный IP в исключениях".into(),
            };
        }
        src = s.source();
    }
    if e.is_timeout() {
        return NetError::Timeout;
    }
    // reqwest puts the full URL into its message; mask credentials (bot tokens, webhook paths)
    let mut msg = match e.url().map(|u| u.as_str().to_string()) {
        Some(u) => e.to_string().replace(&u, &redact_url(&u)),
        None => e.to_string(),
    };
    let mut src = std::error::Error::source(&e);
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    NetError::Request(msg)
}

fn build_client(
    cfg: &NetConfig,
    scope: Option<Arc<RwLock<Scope>>>,
    block_targets: Option<Arc<std::sync::atomic::AtomicBool>>,
    passive_ssrf: bool,
) -> Result<reqwest::Client, NetError> {
    let mut hm = HeaderMap::new();
    for (k, v) in &cfg.headers {
        if let (Ok(k), Ok(v)) = (HeaderName::try_from(k.as_str()), HeaderValue::from_str(v)) {
            hm.insert(k, v);
        }
    }
    if !hm.contains_key(reqwest::header::USER_AGENT) {
        let ua = HeaderValue::from_str(&cfg.user_agent)
            .map_err(|e| NetError::Request(format!("User-Agent: {e}")))?;
        hm.insert(reqwest::header::USER_AGENT, ua);
    }
    let mut b = reqwest::Client::builder()
        .default_headers(hm)
        .connect_timeout(cfg.connect_timeout)
        .read_timeout(cfg.read_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .use_rustls_tls()
        .dns_resolver(Arc::new(ScopedResolver {
            overrides: cfg.host_overrides.clone(),
            scope,
            block_targets,
            passive_ssrf,
        }));
    if cfg.title_case_headers {
        b = b.http1_title_case_headers();
    }
    match &cfg.proxy {
        Some(p) if !p.trim().is_empty() => {
            let proxy =
                reqwest::Proxy::all(p.trim()).map_err(|e| NetError::Proxy(e.to_string()))?;
            b = b.proxy(proxy);
        }
        // Without a proxy, explicitly ignore proxy environment variables for predictable behavior.
        _ => b = b.no_proxy(),
    }
    b.build().map_err(|e| NetError::Request(e.to_string()))
}

impl NetClient {
    /// Creates a client that uses the system clock.
    pub fn new(cfg: NetConfig, scope: Scope, sink: Arc<dyn RequestSink>) -> Result<Self, NetError> {
        Self::with_clock(cfg, scope, sink, Arc::new(SystemClock))
    }

    pub fn with_clock(
        cfg: NetConfig,
        scope: Scope,
        sink: Arc<dyn RequestSink>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, NetError> {
        let guard = Arc::new(RwLock::new(scope.clone()));
        let scope = Arc::new(RwLock::new(scope));
        let guard_blocks_targets = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // the passive client also drops excluded/SSRF/target IPs at connect time
        let passive = build_client(
            &cfg,
            Some(guard.clone()),
            Some(guard_blocks_targets.clone()),
            true,
        )?;
        let target = build_client(&cfg, Some(scope.clone()), None, false)?;
        let global = cfg
            .global_rps
            .filter(|r| r.is_finite() && *r > 0.0)
            .map(|r| TokenBucket::new(r, r.clamp(1.0, 100_000.0)));
        let sem = Arc::new(Semaphore::new(cfg.max_concurrency.max(1)));
        Ok(NetClient {
            inner: Arc::new(Inner {
                limited: Default::default(),
                cfg,
                passive,
                target,
                scope,
                guard,
                guard_blocks_targets,
                clock,
                sink,
                sem,
                global,
                per_source: Mutex::new(HashMap::new()),
            }),
            cancel: CancellationToken::new(),
            pause: None,
        })
    }

    pub fn config(&self) -> &NetConfig {
        &self.inner.cfg
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.inner.clock
    }

    /// Returns a clone with a different cancellation token, sharing limits, log and scope.
    pub fn with_cancel(&self, cancel: CancellationToken) -> NetClient {
        NetClient {
            inner: self.inner.clone(),
            cancel,
            pause: self.pause.clone(),
        }
    }

    /// Returns a clone that holds new requests while `pause` is `Some`: a request waits after
    /// the rate limiter and before it is sent, so a pause stops new traffic at once while the
    /// requests already in flight finish.
    pub fn with_pause(&self, pause: PauseState) -> NetClient {
        NetClient {
            inner: self.inner.clone(),
            cancel: self.cancel.clone(),
            pause: Some(pause),
        }
    }

    /// Waits while the followed scan is paused; fails once the client is cancelled.
    async fn hold(&self) -> Result<(), NetError> {
        let Some(p) = &self.pause else {
            return Ok(());
        };
        let mut p = p.clone();
        loop {
            if self.cancel.is_cancelled() {
                return Err(NetError::Cancelled);
            }
            if p.borrow_and_update().is_none() {
                return Ok(());
            }
            tokio::select! {
                _ = self.cancel.cancelled() => return Err(NetError::Cancelled),
                r = p.changed() => if r.is_err() { return Ok(()); },
            }
        }
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub fn scope(&self) -> Scope {
        read_scope(&self.inner.scope).clone()
    }

    pub fn set_scope(&self, scope: Scope) {
        match self.inner.scope.write() {
            Ok(mut g) => *g = scope,
            Err(p) => *p.into_inner() = scope,
        }
    }

    /// Sets the full project scope for passive requests: exclusions are never contacted, and target
    /// hosts are either denied (`block_targets`, passive profile) or treated as target requests.
    pub fn set_passive_guard(&self, full: Scope, block_targets: bool) {
        match self.inner.guard.write() {
            Ok(mut g) => *g = full,
            Err(p) => *p.into_inner() = full,
        }
        self.inner
            .guard_blocks_targets
            .store(block_targets, std::sync::atomic::Ordering::Relaxed);
    }

    /// Returns the effective access class of a passive request to `host`: exclusions are always
    /// denied; a target host is denied with the passive profile and otherwise becomes `TouchesTarget`
    /// (scope-checked and logged as a target request); any other host is `Passive` if it is in `allow` (when given).
    pub fn passive_access(&self, host: &str, allow: Option<&[String]>) -> Result<Access, NetError> {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty() {
            return Ok(Access::Passive);
        }
        let core = read_scope(&self.inner.scope);
        let guard = read_scope(&self.inner.guard);
        if scope_excludes(&core, &h) || scope_excludes(&guard, &h) {
            return Err(NetError::OutOfScope {
                host: h,
                reason: "в исключениях (пассивный запрос)".into(),
            });
        }
        if core.allows_host(&h) || guard.allows_host(&h) {
            if self
                .inner
                .guard_blocks_targets
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return Err(NetError::OutOfScope {
                    host: h,
                    reason: "хост цели: пассивный профиль к цели не обращается".into(),
                });
            }
            return Ok(Access::TouchesTarget);
        }
        if let Some(allow) = allow {
            let host_ok = allow.iter().any(|p| {
                let p = p.trim().trim_end_matches('.').to_ascii_lowercase();
                h == p || foca_core::target::is_subdomain_of(&h, &p)
            });
            if !host_ok {
                return Err(NetError::OutOfScope {
                    host: h,
                    reason: "редирект пассивного запроса на хост не из пассивных источников".into(),
                });
            }
        }
        Ok(Access::Passive)
    }

    /// Returns `true` if the host is in scope (ignoring the scan stage); used to filter links before requesting them.
    pub fn host_in_scope(&self, host: &str) -> bool {
        read_scope(&self.inner.scope).allows_host(host)
    }

    pub fn has_proxy(&self) -> bool {
        self.inner
            .cfg
            .proxy
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty())
    }

    pub fn is_local_only(&self) -> bool {
        self.inner.cfg.local_only.is_some()
    }

    /// Records an event in the request log.
    pub fn record(&self, rec: RequestRecord) {
        self.inner.sink.record(&rec);
    }

    /// Creates a request log record template.
    pub fn draft(
        &self,
        module: &str,
        method: &str,
        url: &str,
        host: &str,
        access: &Access,
    ) -> RequestRecord {
        RequestRecord {
            time: self.inner.clock.now(),
            module: module.to_string(),
            method: method.to_string(),
            url: redact_url(url),
            host: host.to_string(),
            status: None,
            bytes: 0,
            active: access.touches_target(),
            access: access.label().to_string(),
            blocked: false,
            error: None,
        }
    }

    /// Checks the policy without network access, apart from resolving the name to check exclusions by IP.
    /// Returns the allowed IPs (empty for passive requests and when resolution through a proxy is unavailable).
    pub async fn authorize(&self, host: &str, access: &Access) -> Result<Vec<IpAddr>, NetError> {
        if let Some(log) = &self.inner.cfg.local_only {
            if !is_local_host(host, &self.inner.cfg.host_overrides) {
                if !log.as_os_str().is_empty() {
                    use std::io::Write;
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(log)
                    {
                        let _ = writeln!(f, "{host}");
                    }
                }
                return Err(NetError::OutOfScope {
                    host: host.into(),
                    reason: "стенд test-net: внешний хост запрещён".into(),
                });
            }
        }
        let eff;
        let access = if matches!(access, Access::Passive) {
            eff = self.passive_access(host, None)?;
            if !eff.touches_target() {
                return Ok(Vec::new());
            }
            &eff
        } else {
            access
        };
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.is_empty() {
            return Err(NetError::OutOfScope {
                host: host.into(),
                reason: "пустой хост".into(),
            });
        }
        {
            let scope = read_scope(&self.inner.scope);
            match access {
                Access::Active { .. } => {
                    scope.check_active(&h).map_err(|d| match d {
                        ScopeDenied::OutOfScope(x) => NetError::OutOfScope {
                            host: x,
                            reason: "нет в целях".into(),
                        },
                        ScopeDenied::Excluded(x) => NetError::OutOfScope {
                            host: x,
                            reason: "в исключениях".into(),
                        },
                        other => NetError::ActiveDenied(other),
                    })?;
                }
                Access::ZoneInfra { zone, .. } => {
                    scope.check_active(zone).map_err(|d| match d {
                        ScopeDenied::OutOfScope(x) => NetError::OutOfScope {
                            host: x,
                            reason: "зона не в целях".into(),
                        },
                        ScopeDenied::Excluded(x) => NetError::OutOfScope {
                            host: x,
                            reason: "зона в исключениях".into(),
                        },
                        other => NetError::ActiveDenied(other),
                    })?;
                    if scope_excludes(&scope, &h) {
                        return Err(NetError::OutOfScope {
                            host: h,
                            reason: "NS зоны в исключениях".into(),
                        });
                    }
                }
                _ => {
                    if !scope.allows_host(&h) {
                        return Err(NetError::OutOfScope {
                            host: h,
                            reason: "нет в целях или в исключениях".into(),
                        });
                    }
                }
            }
        }
        if let Some(ip) = parse_ip_literal(&h) {
            return Ok(vec![ip]);
        }
        let ips = match self.inner.cfg.host_overrides.get(&h) {
            Some(v) => v.clone(),
            // Never use the system resolver through a proxy or Tor (DNS leak): exclusion checks use DoH
            // through the same proxy, and no answer is treated as "does not resolve".
            None if self.has_proxy() => match &self.inner.cfg.proxy_resolver {
                Some(r) => r.resolve(self, &h).await,
                None => Vec::new(),
            },
            None => match self
                .cancellable(tokio::net::lookup_host((h.as_str(), 0)))
                .await?
            {
                Ok(it) => it.map(|a| a.ip()).collect(),
                // The name does not resolve (or resolves only on the proxy side). No connection to an
                // excluded IP can happen anyway: the target client's resolver checks addresses at connect
                // time, and TCP modules connect only to verified IPs.
                Err(_) => return Ok(Vec::new()),
            },
        };
        let scope = read_scope(&self.inner.scope);
        if let Some(ip) = ips.iter().find(|ip| ip_excluded(&scope, **ip)) {
            return Err(NetError::OutOfScope {
                host: h,
                reason: format!("резолвленный IP {ip} в исключениях"),
            });
        }
        Ok(ips)
    }

    /// Checks the policy and logs a denial.
    pub async fn authorize_logged(
        &self,
        module: &str,
        method: &str,
        url: &str,
        host: &str,
        access: &Access,
    ) -> Result<Vec<IpAddr>, NetError> {
        match self.authorize(host, access).await {
            Ok(v) => Ok(v),
            Err(e) => {
                let mut rec = self.draft(module, method, url, host, access);
                rec.blocked = e.is_scope_denial();
                rec.error = Some(format!("{}: {e}", e.code()));
                self.record(rec);
                Err(e)
            }
        }
    }

    /// Runs a future that is aborted on cancellation.
    pub async fn cancellable<F: std::future::Future>(&self, f: F) -> Result<F::Output, NetError> {
        if self.cancel.is_cancelled() {
            return Err(NetError::Cancelled);
        }
        tokio::select! {
            _ = self.cancel.cancelled() => Err(NetError::Cancelled),
            v = f => Ok(v),
        }
    }

    fn source_bucket(&self, module: &str) -> Option<Arc<TokenBucket>> {
        let rate = *self.inner.cfg.source_rps.get(module)?;
        let mut m = match self.inner.per_source.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        Some(
            m.entry(module.to_string())
                .or_insert_with(|| Arc::new(TokenBucket::new(rate, 1.0)))
                .clone(),
        )
    }

    /// Waits for the rate limiter (global and per module), then for the end of a pause.
    pub async fn rate_limit(&self, module: &str) -> Result<(), NetError> {
        self.hold().await?;
        if let Some(g) = &self.inner.global {
            g.acquire(&self.cancel).await?;
        }
        if let Some(b) = self.source_bucket(module) {
            b.acquire(&self.cancel).await?;
        }
        // a request that got its token during a pause still waits for the resume
        self.hold().await
    }

    /// Acquires a concurrency slot; hold it for the duration of the exchange.
    pub async fn permit(&self) -> Result<OwnedSemaphorePermit, NetError> {
        let sem = self.inner.sem.clone();
        self.cancellable(sem.acquire_owned())
            .await?
            .map_err(|_| NetError::Cancelled)
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let base = self.inner.cfg.backoff_base.as_millis() as u64;
        let exp = base.saturating_mul(1u64 << attempt.min(16));
        let max = self.inner.cfg.backoff_max.as_millis() as u64;
        // Deterministic jitter without `rand`: ±25% derived from the clock's nanoseconds.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        let ms = exp.min(max);
        let jitter = if ms > 4 { nanos % (ms / 2) } else { 0 };
        Duration::from_millis(ms - ms / 4 + jitter)
    }

    async fn sleep(&self, d: Duration) -> Result<(), NetError> {
        self.cancellable(tokio::time::sleep(d)).await
    }

    /// Returns `true` if a host from `shared_limit_hosts` has already returned a final 429.
    pub fn host_limited(&self, host: &str) -> bool {
        self.inner
            .limited
            .lock()
            .map(|g| g.contains(host))
            .unwrap_or(false)
    }

    fn mark_limited(&self, host: &str) {
        if self
            .inner
            .cfg
            .shared_limit_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
        {
            if let Ok(mut g) = self.inner.limited.lock() {
                g.insert(host.to_string());
            }
            tracing::warn!(target: "foca::net", "{host}: лимит запросов (429): до конца скана не обращаемся");
        }
    }

    /// Sends a request: scope check, concurrency slot, rate limit, attempts with retries, then
    /// redirects (each hop is checked and logged). Non-2xx responses are returned as is, including
    /// the final response after retries on 429/5xx are exhausted.
    pub async fn send(&self, req: NetRequest) -> Result<NetResponse, NetError> {
        let mut url = req.url.clone();
        let mut method = req.method.clone();
        let mut body = req.body.clone();
        let mut headers = req.headers.clone();
        let orig_has_auth = headers.iter().any(|(k, _)| is_sensitive_header(k));
        let orig_host = host_of(&url).to_ascii_lowercase();
        let orig_was_loopback = is_loopback_host_name(&orig_host);
        let retries = req.retries.unwrap_or(self.inner.cfg.retries);
        for hop in 0..=self.inner.cfg.max_redirects {
            if self.cancel.is_cancelled() {
                return Err(NetError::Cancelled);
            }
            let host = host_of(&url);
            // effective access class of this hop: a passive request that lands on a target host is
            // checked and logged as a target request
            let access = match &req.access {
                Access::Passive => {
                    match self
                        .passive_access(&host, req.passive_allow.as_ref().map(|v| v.as_slice()))
                    {
                        Ok(a) => a,
                        Err(e) => {
                            let mut rec = self.draft(
                                &req.module,
                                method.as_str(),
                                url.as_str(),
                                &host,
                                &req.access,
                            );
                            rec.blocked = true;
                            rec.error = Some(format!("{}: {e}", e.code()));
                            self.record(rec);
                            return Err(e);
                        }
                    }
                }
                a => a.clone(),
            };
            self.authorize_logged(&req.module, method.as_str(), url.as_str(), &host, &access)
                .await?;
            if self.host_limited(&host) {
                let mut rec =
                    self.draft(&req.module, method.as_str(), url.as_str(), &host, &access);
                rec.error =
                    Some("limit: сервис уже ответил 429 в этом скане, запрос не отправлен".into());
                self.record(rec);
                return Err(NetError::Status(429));
            }
            let permit = self.permit().await?;
            let mut attempt = 0u32;
            let resp = loop {
                self.rate_limit(&req.module).await?;
                let mut rec =
                    self.draft(&req.module, method.as_str(), url.as_str(), &host, &access);
                let client = if access.touches_target() {
                    &self.inner.target
                } else {
                    &self.inner.passive
                };
                let mut rb = client.request(method.clone(), url.clone());
                // Profile headers go first and in profile order (request values override them); otherwise
                // reqwest defaults such as `accept` would come earlier. Other request headers follow.
                let prof = &self.inner.cfg.headers;
                let ordered = prof
                    .iter()
                    .map(|(k, v)| {
                        let own = headers.iter().find(|(rk, _)| rk.eq_ignore_ascii_case(k));
                        (k, own.map(|(_, v)| v).unwrap_or(v))
                    })
                    .chain(
                        headers
                            .iter()
                            .filter(|(k, _)| !prof.iter().any(|(p, _)| p.eq_ignore_ascii_case(k)))
                            .map(|(k, v)| (k, v)),
                    );
                for (k, v) in ordered {
                    if let (Ok(k), Ok(v)) =
                        (HeaderName::try_from(k.as_str()), HeaderValue::from_str(v))
                    {
                        rb = rb.header(k, v);
                    }
                }
                if let Some(b) = &body {
                    rb = rb.body(b.clone());
                }
                if let Some(t) = req.timeout.or(self.inner.cfg.timeout) {
                    rb = rb.timeout(t);
                }
                let t_req = std::time::Instant::now();
                let r = self.cancellable(rb.send()).await;
                let ms = t_req.elapsed().as_millis();
                match r {
                    Err(NetError::Cancelled) => {
                        rec.error = Some("cancelled".into());
                        self.record(rec);
                        return Err(NetError::Cancelled);
                    }
                    Err(e) => return Err(e),
                    Ok(Err(e)) => {
                        let e = map_reqwest(e);
                        rec.blocked = e.is_scope_denial();
                        rec.error = Some(format!("{}: {e}", e.code()));
                        self.record(rec);
                        tracing::warn!(target: "foca::net", "{} {} {} - {}: {e} ({ms} мс, попытка {}/{})",
                            req.module, method, redact_url(url.as_str()), e.code(), attempt + 1, retries + 1);
                        if e.is_transient() && attempt < retries {
                            self.sleep(self.backoff(attempt)).await?;
                            attempt += 1;
                            continue;
                        }
                        return Err(e);
                    }
                    Ok(Ok(resp)) => {
                        let st = resp.status().as_u16();
                        rec.status = Some(st);
                        if st >= 400 {
                            tracing::warn!(target: "foca::net", "{} {} {} [{}]: HTTP {st} ({ms} мс, попытка {}/{})",
                                req.module, method, redact_url(url.as_str()), access.label(), attempt + 1, retries + 1);
                        } else {
                            tracing::debug!(target: "foca::net", "{} {} {} [{}]: HTTP {st} ({ms} мс)",
                                req.module, method, redact_url(url.as_str()), access.label());
                        }
                        if NetError::Status(st).is_transient() && attempt < retries {
                            let wait = retry_after(resp.headers())
                                .map(|d| d.min(Duration::from_secs(30)))
                                .unwrap_or_else(|| self.backoff(attempt));
                            rec.error = Some(format!("retry: HTTP {st}"));
                            self.record(rec);
                            drop(resp);
                            self.sleep(wait).await?;
                            attempt += 1;
                            continue;
                        }
                        if st == 429 {
                            self.mark_limited(&host);
                        }
                        break (resp, rec);
                    }
                }
            };
            let (resp, rec) = resp;
            let st = resp.status().as_u16();
            if req.follow_redirects && matches!(st, 301 | 302 | 303 | 307 | 308) {
                let loc = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|l| url.join(l).ok());
                if let Some(next) = loc {
                    let mut rec = rec;
                    rec.error = Some(format!("redirect → {}", redact_url(next.as_str())));
                    self.record(rec);
                    drop(resp);
                    if hop == self.inner.cfg.max_redirects {
                        return Err(NetError::TooManyRedirects);
                    }
                    if st == 303 || (matches!(st, 301 | 302) && method == Method::POST) {
                        if method != Method::HEAD {
                            method = Method::GET;
                        }
                        body = None;
                    }
                    if !matches!(next.scheme(), "http" | "https") {
                        return Err(NetError::BadUrl(next.to_string()));
                    }
                    let same_origin = url.scheme() == next.scheme()
                        && url.host_str().map(str::to_ascii_lowercase)
                            == next.host_str().map(str::to_ascii_lowercase)
                        && url.port_or_known_default() == next.port_or_known_default();
                    if !same_origin {
                        if url.scheme() == "https" && next.scheme() == "http" && orig_has_auth {
                            return Err(NetError::BadUrl(format!(
                                "запрещён редирект HTTPS → HTTP с авторизацией: {}",
                                redact_url(next.as_str())
                            )));
                        }
                        headers.retain(|(k, _)| !is_sensitive_header(k));
                    }
                    let next_host = host_of(&next).to_ascii_lowercase();
                    if access == Access::Passive
                        && !self.is_local_only()
                        && !orig_was_loopback
                        && is_private_or_loopback_host(&next_host)
                    {
                        return Err(NetError::OutOfScope {
                            host: next_host,
                            reason:
                                "редирект пассивного запроса на локальный/приватный адрес запрещён"
                                    .into(),
                        });
                    }
                    url = next;
                    continue;
                }
            }
            return Ok(NetResponse {
                status: st,
                headers: resp.headers().clone(),
                url: url.clone(),
                resp: Some(resp),
                bytes: 0,
                rec: Some(rec),
                sink: self.inner.sink.clone(),
                cancel: self.cancel.clone(),
                _permit: permit,
            });
        }
        Err(NetError::TooManyRedirects)
    }

    /// Sends a GET and returns the body as text (2xx only), limited to `max_body`.
    pub async fn get_text(
        &self,
        url: &str,
        module: &str,
        access: Access,
    ) -> Result<String, NetError> {
        let r = self.send(NetRequest::get(url, module, access)?).await?;
        let r = r.ensure_success()?;
        let limit = self.inner.cfg.max_body;
        r.text_limited(limit).await
    }

    /// Sends a GET and parses the body as JSON (2xx only).
    pub async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        req: NetRequest,
    ) -> Result<T, NetError> {
        let limit = self.inner.cfg.max_body;
        let r = self.send(req).await?.ensure_success()?;
        let b = r.bytes_limited(limit).await?;
        serde_json::from_slice(&b).map_err(|e| NetError::Parse(e.to_string()))
    }
}

fn retry_after(h: &HeaderMap) -> Option<Duration> {
    let v = h.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    v.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// A response. It is logged on drop, with the actual number of bytes read.
pub struct NetResponse {
    status: u16,
    headers: HeaderMap,
    url: Url,
    resp: Option<reqwest::Response>,
    bytes: u64,
    rec: Option<RequestRecord>,
    sink: Arc<dyn RequestSink>,
    cancel: CancellationToken,
    _permit: OwnedSemaphorePermit,
}

impl std::fmt::Debug for NetResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetResponse")
            .field("status", &self.status)
            .field("url", &self.url.as_str())
            .finish()
    }
}

impl NetResponse {
    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Returns the final URL after redirects.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the declared Content-Length; a hint only, never trust it when downloading.
    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length")
            .and_then(|v| v.trim().parse().ok())
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Returns the number of body bytes read so far.
    pub fn bytes_read(&self) -> u64 {
        self.bytes
    }

    /// Converts a non-2xx response into an error.
    pub fn ensure_success(self) -> Result<Self, NetError> {
        if self.is_success() {
            Ok(self)
        } else {
            Err(NetError::Status(self.status))
        }
    }

    fn set_error(&mut self, e: &NetError) {
        if let Some(r) = self.rec.as_mut() {
            r.error = Some(format!("{}: {e}", e.code()));
        }
    }

    /// Returns the next body chunk, or `None` at the end.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, NetError> {
        let Some(resp) = self.resp.as_mut() else {
            return Ok(None);
        };
        let r = tokio::select! {
            _ = self.cancel.cancelled() => Err(NetError::Cancelled),
            c = resp.chunk() => c.map_err(map_reqwest),
        };
        match r {
            Ok(Some(c)) => {
                self.bytes += c.len() as u64;
                Ok(Some(c))
            }
            Ok(None) => {
                self.resp = None;
                Ok(None)
            }
            Err(e) => {
                self.set_error(&e);
                self.resp = None;
                Err(e)
            }
        }
    }

    /// Reads the whole body up to `limit` bytes; beyond that the stream is cut off with `TooLarge`.
    pub async fn bytes_limited(mut self, limit: u64) -> Result<Vec<u8>, NetError> {
        let mut out = Vec::new();
        while let Some(c) = self.chunk().await? {
            if out.len() as u64 + c.len() as u64 > limit {
                let e = NetError::TooLarge { limit };
                self.set_error(&e);
                self.resp = None;
                return Err(e);
            }
            out.extend_from_slice(&c);
        }
        Ok(out)
    }

    pub async fn text_limited(self, limit: u64) -> Result<String, NetError> {
        let b = self.bytes_limited(limit).await?;
        Ok(String::from_utf8_lossy(&b).into_owned())
    }

    /// Aborts reading; the connection is closed without draining the body.
    pub fn abort(mut self) {
        self.resp = None;
    }
}

impl Drop for NetResponse {
    fn drop(&mut self) {
        if let Some(mut rec) = self.rec.take() {
            rec.bytes = self.bytes;
            self.sink.record(&rec);
        }
    }
}
