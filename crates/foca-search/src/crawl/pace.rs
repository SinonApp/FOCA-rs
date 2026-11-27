//! Adaptive crawl pace per host.
//!
//! The network client already enforces the global rate limit. On top of it, the crawler keeps a
//! per-host interval: a `429 Too Many Requests` or `503 Service Unavailable` halves the host's
//! rate (doubles the interval), honours `Retry-After`, and after `stop_after` consecutive limited
//! answers the host is stopped for the rest of the crawl with a clear reason. No evasion: the
//! crawler only slows down.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Rate state of a host (and of the crawl as a whole: the worst host wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateState {
    #[default]
    Normal,
    /// The host answered 429/503 and the crawler slowed down.
    Slowed,
    /// The host kept answering 429/503; it is no longer contacted in this crawl.
    Stopped,
}

#[derive(Debug, Clone)]
struct HostPace {
    interval: Duration,
    consecutive: u32,
    next_at: Option<Instant>,
    state: RateState,
}

/// Longest wait honoured from a `Retry-After` header; a longer one stops the host.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(120);

/// Per-host adaptive pacing.
#[derive(Debug, Clone)]
pub struct Pace {
    base: Duration,
    max_interval: Duration,
    stop_after: u32,
    hosts: HashMap<String, HostPace>,
}

/// Parses `Retry-After` in seconds (HTTP dates are not trusted: the device clock may be off).
pub fn parse_retry_after(v: Option<&str>) -> Option<Duration> {
    v?.trim().parse::<u64>().ok().map(Duration::from_secs)
}

impl Pace {
    /// `base` is the starting extra interval (the first limit doubles it, at least to 500 ms);
    /// `stop_after` is the number of consecutive limited answers that stop a host.
    pub fn new(base: Duration, stop_after: u32) -> Self {
        Pace {
            base,
            max_interval: Duration::from_secs(60),
            stop_after: stop_after.max(1),
            hosts: HashMap::new(),
        }
    }

    fn host(&mut self, h: &str) -> &mut HostPace {
        let base = self.base;
        self.hosts.entry(h.to_string()).or_insert(HostPace {
            interval: base,
            consecutive: 0,
            next_at: None,
            state: RateState::Normal,
        })
    }

    /// Time to wait before the next request to `h`, or `None` if the host is stopped.
    pub fn wait_for(&self, h: &str) -> Option<Duration> {
        match self.hosts.get(h) {
            None => Some(Duration::ZERO),
            Some(p) if p.state == RateState::Stopped => None,
            Some(p) => Some(
                p.next_at
                    .map(|t| t.saturating_duration_since(Instant::now()))
                    .unwrap_or_default(),
            ),
        }
    }

    /// Records a request start: the next one to this host waits at least the current interval.
    pub fn started(&mut self, h: &str) {
        let p = self.host(h);
        if !p.interval.is_zero() {
            p.next_at = Some(Instant::now() + p.interval);
        }
    }

    /// A normal answer: the consecutive counter resets; the slower interval stays.
    pub fn ok(&mut self, h: &str) {
        self.host(h).consecutive = 0;
    }

    /// A 429/503 answer: halves the rate, honours `Retry-After` and returns the new state.
    pub fn limited(&mut self, h: &str, retry_after: Option<Duration>) -> RateState {
        let (stop_after, max_interval) = (self.stop_after, self.max_interval);
        let p = self.host(h);
        p.consecutive += 1;
        p.interval = (p.interval * 2)
            .max(Duration::from_millis(500))
            .min(max_interval);
        let wait = retry_after.unwrap_or(p.interval).max(p.interval);
        if p.consecutive >= stop_after || retry_after.is_some_and(|r| r > MAX_RETRY_AFTER) {
            p.state = RateState::Stopped;
        } else {
            p.state = RateState::Slowed;
            p.next_at = Some(Instant::now() + wait);
        }
        p.state
    }

    /// State of one host.
    pub fn state(&self, h: &str) -> RateState {
        self.hosts.get(h).map(|p| p.state).unwrap_or_default()
    }

    /// Worst state over all hosts.
    pub fn overall(&self) -> RateState {
        self.hosts
            .values()
            .map(|p| p.state)
            .max()
            .unwrap_or_default()
    }

    /// Hosts stopped by rate limiting.
    pub fn stopped_hosts(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .hosts
            .iter()
            .filter(|(_, p)| p.state == RateState::Stopped)
            .map(|(h, _)| h.clone())
            .collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limited_answers_halve_rate_then_stop() {
        let mut p = Pace::new(Duration::from_millis(200), 3);
        assert_eq!(p.wait_for("a.example"), Some(Duration::ZERO));
        assert_eq!(p.limited("a.example", None), RateState::Slowed);
        assert_eq!(p.hosts["a.example"].interval, Duration::from_millis(500));
        assert_eq!(p.limited("a.example", None), RateState::Slowed);
        assert_eq!(p.hosts["a.example"].interval, Duration::from_millis(1000));
        assert!(p.wait_for("a.example").unwrap() > Duration::from_millis(500));
        // a normal answer resets the consecutive counter but keeps the slower pace
        p.ok("a.example");
        assert_eq!(p.hosts["a.example"].interval, Duration::from_millis(1000));
        assert_eq!(p.limited("a.example", None), RateState::Slowed);
        assert_eq!(p.limited("a.example", None), RateState::Slowed);
        assert_eq!(p.limited("a.example", None), RateState::Stopped);
        assert_eq!(p.wait_for("a.example"), None);
        assert_eq!(p.overall(), RateState::Stopped);
        assert_eq!(p.stopped_hosts(), vec!["a.example".to_string()]);
        // other hosts are unaffected
        assert_eq!(p.state("b.example"), RateState::Normal);
    }

    #[test]
    fn retry_after_is_honoured_and_a_huge_one_stops() {
        let mut p = Pace::new(Duration::ZERO, 5);
        p.limited("a.example", Some(Duration::from_secs(7)));
        let w = p.wait_for("a.example").unwrap();
        assert!(w > Duration::from_secs(6) && w <= Duration::from_secs(7));
        assert_eq!(
            p.limited("b.example", Some(Duration::from_secs(3600))),
            RateState::Stopped
        );
        assert_eq!(
            parse_retry_after(Some(" 12 ")),
            Some(Duration::from_secs(12))
        );
        assert_eq!(
            parse_retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT")),
            None
        );
        assert_eq!(parse_retry_after(None), None);
    }
}
