//! Token bucket for request rate limiting (global and per source module).

use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::NetError;

#[derive(Debug)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    state: Mutex<(f64, Instant)>,
}

impl TokenBucket {
    /// Creates a bucket with `rate` tokens per second (> 0) and capacity `burst` (>= 1).
    pub fn new(rate: f64, burst: f64) -> Self {
        let rate = if rate.is_finite() && rate > 0.0 {
            rate.clamp(0.01, 10_000.0)
        } else {
            1.0
        };
        let burst = if burst.is_finite() {
            burst.clamp(1.0, 100_000.0)
        } else {
            1.0
        };
        TokenBucket {
            rate,
            burst,
            state: Mutex::new((burst, Instant::now())),
        }
    }

    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// Takes a token without waiting; `Err(wait)` tells how long until the next token.
    pub fn try_take(&self) -> Result<(), Duration> {
        let mut g = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(g.1).as_secs_f64();
        g.0 = (g.0 + elapsed * self.rate).min(self.burst);
        g.1 = now;
        if g.0 >= 1.0 {
            g.0 -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - g.0) / self.rate))
        }
    }

    /// Waits for a token, honoring cancellation.
    pub async fn acquire(&self, cancel: &CancellationToken) -> Result<(), NetError> {
        loop {
            match self.try_take() {
                Ok(()) => return Ok(()),
                Err(wait) => {
                    tokio::select! {
                        _ = cancel.cancelled() => return Err(NetError::Cancelled),
                        _ = tokio::time::sleep(wait) => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn limits_rate() {
        let b = TokenBucket::new(20.0, 1.0);
        let c = CancellationToken::new();
        let t = std::time::Instant::now();
        for _ in 0..5 {
            b.acquire(&c).await.unwrap();
        }
        // 1 token immediately plus 4 at 50 ms each
        assert!(
            t.elapsed() >= Duration::from_millis(190),
            "{:?}",
            t.elapsed()
        );
    }

    #[tokio::test]
    async fn cancel_while_waiting() {
        let b = TokenBucket::new(0.1, 1.0);
        let c = CancellationToken::new();
        b.acquire(&c).await.unwrap();
        c.cancel();
        assert_eq!(b.acquire(&c).await, Err(NetError::Cancelled));
    }

    #[test]
    fn extreme_rates_do_not_panic() {
        let tiny = TokenBucket::new(1e-20, 1.0);
        assert!(tiny.try_take().is_ok());
        assert!(tiny.try_take().is_err());

        let inf = TokenBucket::new(f64::INFINITY, f64::NAN);
        assert!(inf.rate().is_finite());
        assert_eq!(inf.rate(), 1.0);
    }
}
