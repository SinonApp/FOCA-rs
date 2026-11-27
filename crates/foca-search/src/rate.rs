//! Adaptive request pacing shared by the search sources.
//!
//! Every paginated or multi-request source (Wayback, Common Crawl, the dork engines, the Brave
//! API, own SearXNG instances) keeps one [`Throttle`]. It spaces requests by the current interval,
//! and on HTTP 429/503 it honours `Retry-After`, doubles the interval (slows down) and, after
//! [`Throttle::stop_after`] limited answers in a row, tells the source to stop for this scan. The
//! source then returns what it has (status `ok` with a note) or, with nothing collected, the
//! `limit` status with [`crate::source::limit_message`].

use std::sync::Mutex;
use std::time::{Duration, Instant};

use foca_net::{NetError, NetResponse};

/// Note of a source stopped by the throttle after it had collected something.
pub const THROTTLED_NOTE: &str =
    "сервис ограничил частоту запросов: источник остановлен до следующего скана, собранное сохранено";

/// Upper bound of a single wait (a `Retry-After` of an hour must not hold a scan).
pub const MAX_WAIT: Duration = Duration::from_secs(120);

/// What a source should do after a rate-limited answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Wait this long, then retry the same request.
    Retry(Duration),
    /// Stop querying this service for the rest of the scan.
    Stop,
}

#[derive(Debug)]
struct State {
    interval: Duration,
    strikes: u32,
    last: Option<Instant>,
    stopped: bool,
}

/// Request pacing of one source within a scan.
#[derive(Debug)]
pub struct Throttle {
    base: Duration,
    max: Duration,
    /// Limited answers in a row after which the source stops.
    pub stop_after: u32,
    st: Mutex<State>,
}

impl Throttle {
    /// A throttle with `base` spacing between requests (zero means no spacing until a limit).
    pub fn new(base: Duration) -> Self {
        Throttle {
            base,
            max: Duration::from_secs(60).max(base),
            stop_after: 3,
            st: Mutex::new(State {
                interval: base,
                strikes: 0,
                last: None,
                stopped: false,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Current spacing between requests.
    pub fn interval(&self) -> Duration {
        self.lock().interval
    }

    /// Whether the source was told to stop.
    pub fn stopped(&self) -> bool {
        self.lock().stopped
    }

    /// Waits until the current interval has passed since the previous request, then books the
    /// next slot. Cancellable through the client.
    pub async fn wait(&self, net: &foca_net::NetClient) -> Result<(), NetError> {
        let d = {
            let mut s = self.lock();
            let now = Instant::now();
            let due = s.last.map_or(now, |l| l + s.interval);
            s.last = Some(due.max(now));
            due.saturating_duration_since(now)
        };
        if !d.is_zero() {
            net.cancellable(tokio::time::sleep(d)).await?;
        }
        Ok(())
    }

    /// A normal answer: the strike count resets and the interval eases back towards the base.
    pub fn ok(&self) {
        let mut s = self.lock();
        s.strikes = 0;
        s.interval = (s.interval / 2).max(self.base);
    }

    /// A rate-limited answer (429/503): slows down and decides between a retry and a stop.
    pub fn limited(&self, retry_after: Option<Duration>) -> Verdict {
        let mut s = self.lock();
        s.strikes += 1;
        let doubled = (s.interval * 2).max(Duration::from_secs(1));
        s.interval = doubled.max(retry_after.unwrap_or_default()).min(self.max);
        if s.strikes >= self.stop_after.max(1) {
            s.stopped = true;
            return Verdict::Stop;
        }
        let wait = retry_after.unwrap_or(s.interval).min(MAX_WAIT);
        // the wait itself is the spacing before the retry
        s.last = Some(Instant::now() + wait);
        Verdict::Retry(wait)
    }
}

/// Whether an HTTP status means "slow down" (rate limit or overload).
pub fn is_limit(status: u16) -> bool {
    matches!(status, 429 | 503)
}

/// Parses `Retry-After` (seconds or an HTTP date) of a response.
pub fn retry_after(r: &NetResponse) -> Option<Duration> {
    parse_retry_after(r.header("retry-after")?)
}

/// Parses a `Retry-After` value: delta seconds or an IMF-fixdate.
pub fn parse_retry_after(v: &str) -> Option<Duration> {
    let v = v.trim();
    if let Ok(s) = v.parse::<u64>() {
        return Some(Duration::from_secs(s));
    }
    let f = time::format_description::well_known::Rfc2822;
    let at = time::OffsetDateTime::parse(&v.replace("GMT", "+0000"), &f).ok()?;
    let d = at - time::OffsetDateTime::now_utc();
    Some(Duration::from_secs(d.whole_seconds().max(0) as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slows_down_then_stops() {
        let t = Throttle::new(Duration::from_millis(100));
        assert_eq!(t.limited(None), Verdict::Retry(Duration::from_secs(1)));
        assert_eq!(t.interval(), Duration::from_secs(1));
        // Retry-After wins over the doubled interval
        assert_eq!(
            t.limited(Some(Duration::from_secs(7))),
            Verdict::Retry(Duration::from_secs(7))
        );
        assert_eq!(t.interval(), Duration::from_secs(7));
        assert_eq!(t.limited(None), Verdict::Stop);
        assert!(t.stopped());
    }

    #[test]
    fn ok_resets_strikes_and_eases_interval() {
        let t = Throttle::new(Duration::from_millis(500));
        t.limited(None);
        t.limited(None);
        t.ok();
        assert_eq!(t.interval(), Duration::from_secs(1));
        t.ok();
        assert_eq!(t.interval(), Duration::from_millis(500));
        // the strike count started over: two more limits are retries
        assert!(matches!(t.limited(None), Verdict::Retry(_)));
        assert!(matches!(t.limited(None), Verdict::Retry(_)));
    }

    #[test]
    fn retry_after_forms_and_cap() {
        assert_eq!(parse_retry_after("12"), Some(Duration::from_secs(12)));
        assert_eq!(
            parse_retry_after("Thu, 01 Jan 1970 00:00:00 GMT"),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("soon"), None);
        let t = Throttle::new(Duration::ZERO);
        assert_eq!(
            t.limited(Some(Duration::from_secs(3600))),
            Verdict::Retry(MAX_WAIT)
        );
        assert!(is_limit(429) && is_limit(503) && !is_limit(502));
    }

    #[tokio::test]
    async fn wait_spaces_requests() {
        let net = foca_net::NetClient::new(
            foca_net::NetConfig::default(),
            foca_core::Scope::default(),
            std::sync::Arc::new(foca_net::MemorySink::new()),
        )
        .unwrap();
        let t = Throttle::new(Duration::from_millis(80));
        let t0 = Instant::now();
        t.wait(&net).await.unwrap();
        t.wait(&net).await.unwrap();
        t.wait(&net).await.unwrap();
        assert!(
            t0.elapsed() >= Duration::from_millis(150),
            "{:?}",
            t0.elapsed()
        );
    }
}
