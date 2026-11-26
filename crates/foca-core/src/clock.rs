//! Time source. Core code reads time only through [`Clock`] so tests can inject a fixed or
//! controllable clock (timeouts, logs).

use std::sync::Mutex;

use time::{Duration, OffsetDateTime};

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

/// System clock (UTC).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Manually driven clock for tests.
#[derive(Debug)]
pub struct ManualClock(Mutex<OffsetDateTime>);

impl ManualClock {
    pub fn new(t: OffsetDateTime) -> Self {
        ManualClock(Mutex::new(t))
    }

    pub fn set(&self, t: OffsetDateTime) {
        match self.0.lock() {
            Ok(mut g) => *g = t,
            Err(p) => *p.into_inner() = t,
        }
    }

    pub fn advance(&self, d: Duration) {
        let now = self.now();
        self.set(now + d);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> OffsetDateTime {
        match self.0.lock() {
            Ok(g) => *g,
            Err(p) => *p.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn manual_clock_with_scope() {
        let c = ManualClock::new(datetime!(2026-11-30 23:00 UTC));
        let t0 = c.now();
        c.advance(Duration::hours(1));
        assert_eq!(c.now() - t0, Duration::hours(1));
        assert!(SystemClock.now().year() >= 2024);
    }
}
