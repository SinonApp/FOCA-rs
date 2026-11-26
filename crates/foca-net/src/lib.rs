//! Network layer of FOCA-rs.
//!
//! * [`NetClient`]: the shared HTTP client with HTTP/SOCKS5 proxies, User-Agent, timeouts,
//!   retries with backoff, global and per-module rate limiting (token bucket), a concurrency
//!   semaphore, cancellation ([`CancellationToken`]) and a mandatory log of every outgoing
//!   request ([`RequestSink`]).
//! * Every request carries an [`Access`] class: `Passive` (third-party service: crt.sh,
//!   archive.org, ...), `TouchesTarget` (a target host) or `Active` (an active module). For the
//!   latter two the client checks [`foca_core::Scope`] before any network call, for every
//!   redirect hop and for resolved IPs (exclusions); `Active` additionally requires the active
//!   stage of the scan (`check_active`).
//! * [`dns`]: DNS records (hickory-resolver without system-config: `/etc/resolv.conf`, falling
//!   back to 1.1.1.1/8.8.8.8); [`mail`]: SPF/DMARC/DKIM; [`takeover`]: dangling CNAMEs;
//!   [`ct`]: subdomains from CT logs (crt.sh, CertSpotter); [`rdap`]: RDAP / RIPEstat;
//!   [`tcp`]: TCP liveness; [`axfr`]: zone transfer (active); [`ua`]: consistent browser
//!   profiles (UA plus Client Hints); [`ports`]: TCP ports and banners (active, modeled on
//!   RustScan); [`tls`]: X.509 parsing, certificate audit, TLS handshake inspection,
//!   STARTTLS and legacy protocol/weak cipher probes; [`notify`]: alert delivery to Telegram
//!   and webhooks with secret masking.
//!
//! TLS uses rustls with ring and webpki-roots: no OpenSSL and no JNI initialization on Android
//! (rustls-platform-verifier would require `init_hosted` over JNI before the first request).

pub mod client;
pub mod dns;
pub mod error;
mod intel;
pub mod notify;
pub mod proxy_check;
pub mod ratelimit;
mod scan;
pub mod sink;
pub mod tcp;
#[doc(hidden)]
pub mod testserver;
pub mod tls;
pub mod ua;

use std::future::Future;
use std::pin::Pin;

pub use client::{Access, Method, NetClient, NetConfig, NetRequest, NetResponse};
pub use dns::{axfr, bruteforce, doh, mail, nsec, permute, ptr, takeover};
pub use error::NetError;
pub use intel::{cdn, hibp, m365, rdap, saas};
pub use ratelimit::TokenBucket;
pub use scan::{canary, ports};
pub use sink::{MemorySink, NullSink, RequestRecord, RequestSink};
pub use tls::ct;
pub use tokio_util::sync::CancellationToken;

/// A boxed future, for `dyn`-compatible traits with async methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub type Result<T, E = NetError> = std::result::Result<T, E>;
