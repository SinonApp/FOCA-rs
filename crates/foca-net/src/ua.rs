//! Client fingerprint: consistent browser profiles.
//!
//! A profile is a User-Agent plus matching headers (Accept, Accept-Language, Client Hints
//! `Sec-CH-UA*` for Chromium only, Sec-Fetch-*) in an order close to a real browser (HTTP/1.1,
//! Title-Case header names). One profile is chosen per scan ([`BrowserProfile::apply`] on the
//! [`NetConfig`] when the client is created), not per request.
//!
//! The Chrome/Firefox major version is computed from the date (piecewise: a release every four
//! weeks, every two weeks from August 2026) and refined from keyless public APIs
//! ([`fetch_versions`]; the caller keeps a 7-day cache, which the engine stores in
//! `settings.net.ua_versions`).
//!
//! The honest mode sends `FOCA-rs/<version>` without disguise.

use serde::{Deserialize, Serialize};
use time::{Date, Month, OffsetDateTime};

pub use crate::client::honest_ua;
use crate::client::{Access, NetClient, NetConfig};

/// Stable Chrome versions for Windows (Google Version History API, keyless).
pub const CHROME_VERSIONS_URL: &str =
    "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions?pageSize=3";
/// Current Firefox versions (Mozilla product-details, keyless).
pub const FIREFOX_VERSIONS_URL: &str =
    "https://product-details.mozilla.org/1.0/firefox_versions.json";
/// Lifetime of the version cache.
pub const CACHE_TTL_SECS: i64 = 7 * 24 * 3600;

/// Mode from `settings.net.ua`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UaMode {
    /// Recent Chrome for Windows (setting value `chrome`, the default; `auto` is a synonym).
    Chrome,
    ChromeAndroid,
    Firefox,
    Safari,
    /// `FOCA-rs/<version>`.
    Honest,
    /// Custom string (User-Agent only, no other headers).
    Custom(String),
}

impl UaMode {
    /// Parses the settings `ua` (`chrome`|`auto`|`chrome_android`|`firefox`|`safari`|`honest`|`custom`;
    /// legacy `foca` means `honest`) and `ua_custom`. Unknown values (such as the legacy `random`) or
    /// an empty custom string fall back to `Chrome` for compatibility.
    pub fn from_setting(ua: &str, custom: &str) -> UaMode {
        match ua.trim() {
            "chrome_android" => UaMode::ChromeAndroid,
            "firefox" => UaMode::Firefox,
            "safari" => UaMode::Safari,
            "honest" | "foca" => UaMode::Honest,
            "custom" if !custom.trim().is_empty() => UaMode::Custom(custom.trim().to_string()),
            _ => UaMode::Chrome,
        }
    }

    /// Returns `true` if the profile needs a Chrome/Firefox version (so refreshing the version cache makes sense).
    pub fn wants_versions(&self) -> bool {
        matches!(
            self,
            UaMode::Chrome | UaMode::ChromeAndroid | UaMode::Firefox
        )
    }
}

/// Version cache from public APIs (`settings.net.ua_versions`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UaVersions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chrome: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firefox: Option<u32>,
    /// Unix time of retrieval.
    #[serde(default)]
    pub fetched: i64,
}

impl UaVersions {
    /// Reads the cache from settings JSON; garbage or absence yields an empty cache.
    pub fn from_json(v: &serde_json::Value) -> UaVersions {
        serde_json::from_value(v.clone()).unwrap_or_default()
    }

    pub fn is_fresh(&self, now: OffsetDateTime) -> bool {
        let age = now.unix_timestamp() - self.fetched;
        self.fetched > 0 && (0..CACHE_TTL_SECS).contains(&age)
    }
}

fn date(y: i32, m: Month, d: u8) -> Date {
    Date::from_calendar_date(y, m, d).expect("valid date")
}

/// Returns the major version from a piecewise model of `(version, release date, step in days)`
/// anchors, using the last anchor not after `day`.
fn major_on(anchors: &[(u32, Date, i64)], day: Date) -> u32 {
    let (v, d, step) = anchors
        .iter()
        .rev()
        .find(|(_, d, _)| *d <= day)
        .copied()
        .unwrap_or(anchors[0]);
    let days = (day - d).whole_days().max(0);
    v + (days / step) as u32
}

/// Returns the stable Chrome major version on a date (anchors checked against the Version History API).
pub fn chrome_major_on(day: Date) -> u32 {
    major_on(
        &[
            (133, date(2025, Month::February, 4), 28),
            (145, date(2026, Month::January, 28), 28),
            (152, date(2026, Month::August, 12), 14),
        ],
        day,
    )
}

/// Returns the Firefox major version on a date (anchors from product-details).
pub fn firefox_major_on(day: Date) -> u32 {
    major_on(
        &[
            (135, date(2025, Month::February, 4), 28),
            (147, date(2026, Month::January, 13), 28),
            (154, date(2026, Month::August, 18), 14),
        ],
        day,
    )
}

/// Returns the Safari version on a date: 18.x until September 2025, then year-based numbering (26 for 2025, 27 for 2026, ...).
pub fn safari_version_on(day: Date) -> String {
    let y = day.year();
    let after_sept = day >= date(y, Month::September, 15);
    if day < date(2025, Month::September, 15) {
        return "18.3".into();
    }
    let n = 26 + (y - 2025) - if after_sept { 0 } else { 1 };
    format!("{n}.0")
}

/// Builds the `Sec-CH-UA` brand list as Chromium does (`GenerateBrandVersionList`, GREASE keyed on the major version).
pub fn sec_ch_ua(major: u32) -> String {
    const GREASE_CHARS: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
    const GREASE_VER: [&str; 3] = ["8", "99", "24"];
    const ORDERS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let s = major as usize;
    let grease = format!(
        "\"Not{}A{}Brand\";v=\"{}\"",
        GREASE_CHARS[s % 11],
        GREASE_CHARS[(s + 1) % 11],
        GREASE_VER[s % 3]
    );
    let order = ORDERS[s % 6];
    let mut list = vec![String::new(); 3];
    list[order[0]] = grease;
    list[order[1]] = format!("\"Chromium\";v=\"{major}\"");
    list[order[2]] = format!("\"Google Chrome\";v=\"{major}\"");
    list.join(", ")
}

/// A consistent profile: the UA and ordered headers (including `User-Agent`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserProfile {
    /// `chrome`, `chrome_android`, `firefox`, `safari`, `honest`, `custom`.
    pub id: String,
    pub user_agent: String,
    /// Headers in browser order (lowercase names; sent in Title-Case on the wire).
    pub headers: Vec<(String, String)>,
}

fn hv(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

const CHROME_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
const GECKO_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

impl BrowserProfile {
    fn chrome(major: u32, android: bool) -> BrowserProfile {
        let ua = if android {
            format!("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Mobile Safari/537.36")
        } else {
            format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36")
        };
        let brands = sec_ch_ua(major);
        let (mobile, platform) = if android {
            ("?1", "\"Android\"")
        } else {
            ("?0", "\"Windows\"")
        };
        BrowserProfile {
            id: if android { "chrome_android" } else { "chrome" }.into(),
            headers: hv(&[
                ("sec-ch-ua", &brands),
                ("sec-ch-ua-mobile", mobile),
                ("sec-ch-ua-platform", platform),
                ("upgrade-insecure-requests", "1"),
                ("user-agent", &ua),
                ("accept", CHROME_ACCEPT),
                ("sec-fetch-site", "none"),
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-user", "?1"),
                ("sec-fetch-dest", "document"),
                ("accept-language", "en-US,en;q=0.9"),
                ("priority", "u=0, i"),
            ]),
            user_agent: ua,
        }
    }

    fn firefox(major: u32) -> BrowserProfile {
        let ua = format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{major}.0) Gecko/20100101 Firefox/{major}.0"
        );
        BrowserProfile {
            id: "firefox".into(),
            headers: hv(&[
                ("user-agent", &ua),
                ("accept", GECKO_ACCEPT),
                ("accept-language", "en-US,en;q=0.5"),
                ("upgrade-insecure-requests", "1"),
                ("sec-fetch-dest", "document"),
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-site", "none"),
                ("sec-fetch-user", "?1"),
                ("priority", "u=0, i"),
            ]),
            user_agent: ua,
        }
    }

    fn safari(version: &str) -> BrowserProfile {
        let ua = format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15");
        BrowserProfile {
            id: "safari".into(),
            headers: hv(&[
                ("accept", GECKO_ACCEPT),
                ("sec-fetch-site", "none"),
                ("sec-fetch-mode", "navigate"),
                ("user-agent", &ua),
                ("accept-language", "en-US,en;q=0.9"),
                ("sec-fetch-dest", "document"),
                ("priority", "u=0, i"),
            ]),
            user_agent: ua,
        }
    }

    fn ua_only(id: &str, ua: String) -> BrowserProfile {
        BrowserProfile {
            id: id.into(),
            headers: vec![("user-agent".into(), ua.clone())],
            user_agent: ua,
        }
    }

    /// Returns the honest profile `FOCA-rs/<version>`.
    pub fn honest() -> BrowserProfile {
        BrowserProfile::ua_only("honest", honest_ua())
    }

    /// Returns the profile for a mode at `now`: the version comes from a fresh cache, otherwise max(cache, date-based estimate).
    pub fn for_mode(mode: &UaMode, now: OffsetDateTime, cache: &UaVersions) -> BrowserProfile {
        let day = now.date();
        let fresh = cache.is_fresh(now);
        let pick = |cached: Option<u32>, calc: u32| match cached {
            Some(c) if fresh => c,
            Some(c) => c.max(calc),
            None => calc,
        };
        match mode {
            UaMode::Chrome => {
                BrowserProfile::chrome(pick(cache.chrome, chrome_major_on(day)), false)
            }
            UaMode::ChromeAndroid => {
                BrowserProfile::chrome(pick(cache.chrome, chrome_major_on(day)), true)
            }
            UaMode::Firefox => BrowserProfile::firefox(pick(cache.firefox, firefox_major_on(day))),
            UaMode::Safari => BrowserProfile::safari(&safari_version_on(day)),
            UaMode::Honest => BrowserProfile::honest(),
            UaMode::Custom(s) => BrowserProfile::ua_only("custom", s.clone()),
        }
    }

    /// Returns a header value (case-insensitive name lookup).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Returns `true` for a browser profile (not honest or custom), which uses Title-Case on the wire like a browser over HTTP/1.1.
    pub fn is_browser(&self) -> bool {
        !matches!(self.id.as_str(), "honest" | "custom")
    }

    /// Applies the profile to the client configuration (once per scan).
    pub fn apply(&self, cfg: &mut NetConfig) {
        cfg.user_agent = self.user_agent.clone();
        cfg.headers = self.headers.clone();
        cfg.title_case_headers = self.is_browser();
    }
}

/// Time of the last refresh attempt in this process (at most once every 6 hours).
static LAST_REFRESH: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// Refreshes the version cache in the background using a separate client with the same settings
/// (including the proxy), logging to `sink` and calling `done(versions)` on success so the caller
/// can persist them. Does nothing and returns `false` without a tokio runtime or if an attempt was made in the last 6 hours.
pub fn spawn_refresh<F>(
    mut cfg: NetConfig,
    sink: std::sync::Arc<dyn crate::RequestSink>,
    done: F,
) -> bool
where
    F: FnOnce(UaVersions) + Send + 'static,
{
    use std::sync::atomic::Ordering;
    let Ok(h) = tokio::runtime::Handle::try_current() else {
        return false;
    };
    let now = OffsetDateTime::now_utc();
    let last = LAST_REFRESH.load(Ordering::Relaxed);
    if now.unix_timestamp() - last < 6 * 3600
        || LAST_REFRESH
            .compare_exchange(
                last,
                now.unix_timestamp(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_err()
    {
        return false;
    }
    cfg.retries = 0;
    cfg.timeout = Some(std::time::Duration::from_secs(20));
    h.spawn(async move {
        let Ok(net) = NetClient::new(cfg, foca_core::Scope::default(), sink) else {
            return;
        };
        match fetch_versions(&net, now).await {
            Ok(v) => done(v),
            Err(e) => tracing::info!(target: "foca::net", "версии браузеров не обновлены: {e}"),
        }
    });
    true
}

/// Extracts the major version from a Version History API response (the maximum `versions[].version`).
pub fn parse_chrome_versions(json: &str) -> Option<u32> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v["versions"]
        .as_array()?
        .iter()
        .filter_map(|x| x["version"].as_str()?.split('.').next()?.parse().ok())
        .max()
}

/// Extracts the major version from `firefox_versions.json` (`LATEST_FIREFOX_VERSION`).
pub fn parse_firefox_versions(json: &str) -> Option<u32> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v["LATEST_FIREFOX_VERSION"]
        .as_str()?
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// Fetches versions from public APIs (passive requests through the same client: proxy, log,
/// cancellation). A failed source leaves its field `None`.
///
/// # Errors
///
/// Fails if neither source answered.
pub async fn fetch_versions(net: &NetClient, now: OffsetDateTime) -> crate::Result<UaVersions> {
    let chrome = net
        .get_text(CHROME_VERSIONS_URL, "ua", Access::Passive)
        .await;
    let firefox = net
        .get_text(FIREFOX_VERSIONS_URL, "ua", Access::Passive)
        .await;
    let out = UaVersions {
        chrome: chrome.as_deref().ok().and_then(parse_chrome_versions),
        firefox: firefox.as_deref().ok().and_then(parse_firefox_versions),
        fetched: now.unix_timestamp(),
    };
    if out.chrome.is_none() && out.firefox.is_none() {
        return Err(chrome.err().or(firefox.err()).unwrap_or_else(|| {
            crate::NetError::Request("версии браузеров: неожиданный ответ".into())
        }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u8, day: u8) -> Date {
        Date::from_calendar_date(y, Month::try_from(m).unwrap(), day).unwrap()
    }

    #[test]
    fn chrome_version_by_date() {
        // actual stable release dates (Version History API)
        for (y, m, day, v) in [
            (2025, 2, 4, 133),
            (2025, 6, 24, 138),
            (2025, 10, 28, 142),
            (2026, 3, 25, 147),
            (2026, 7, 15, 151),
            (2026, 8, 26, 153),
            (2026, 11, 18, 159),
            (2026, 11, 21, 159),
        ] {
            assert_eq!(chrome_major_on(d(y, m, day)), v, "{y}-{m}-{day}");
        }
        // before the first anchor: at least 133
        assert_eq!(chrome_major_on(d(2024, 1, 1)), 133);
    }

    #[test]
    fn firefox_and_safari_by_date() {
        for (y, m, day, v) in [
            (2025, 2, 4, 135),
            (2025, 10, 14, 144),
            (2026, 7, 21, 153),
            (2026, 9, 15, 156),
            (2026, 11, 21, 160),
        ] {
            assert_eq!(firefox_major_on(d(y, m, day)), v, "{y}-{m}-{day}");
        }
        assert_eq!(safari_version_on(d(2025, 3, 1)), "18.3");
        assert_eq!(safari_version_on(d(2025, 10, 1)), "26.0");
        assert_eq!(safari_version_on(d(2026, 5, 1)), "26.0");
        assert_eq!(safari_version_on(d(2026, 11, 21)), "27.0");
    }

    #[test]
    fn sec_ch_ua_matches_real_chrome() {
        // strings taken from real browsers
        assert_eq!(
            sec_ch_ua(120),
            r#""Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120""#
        );
        assert_eq!(
            sec_ch_ua(131),
            r#""Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24""#
        );
        assert_eq!(
            sec_ch_ua(133),
            r#""Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133""#
        );
        assert_eq!(
            sec_ch_ua(138),
            r#""Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138""#
        );
    }

    fn now() -> OffsetDateTime {
        d(2026, 11, 21).midnight().assume_utc()
    }

    #[test]
    fn profiles_are_consistent() {
        let empty = UaVersions::default();
        for mode in [UaMode::Chrome, UaMode::ChromeAndroid] {
            let p = BrowserProfile::for_mode(&mode, now(), &empty);
            assert!(
                p.user_agent.contains("Chrome/159.0.0.0"),
                "{}",
                p.user_agent
            );
            let ch = p.header("Sec-CH-UA").unwrap();
            assert!(ch.contains("\"Google Chrome\";v=\"159\""), "{ch}");
            assert!(ch.contains("\"Chromium\";v=\"159\""), "{ch}");
            let android = mode == UaMode::ChromeAndroid;
            assert_eq!(p.user_agent.contains("Android"), android);
            assert_eq!(p.user_agent.contains("Mobile Safari"), android);
            assert_eq!(
                p.header("sec-ch-ua-mobile"),
                Some(if android { "?1" } else { "?0" })
            );
            assert_eq!(
                p.header("sec-ch-ua-platform"),
                Some(if android {
                    "\"Android\""
                } else {
                    "\"Windows\""
                })
            );
            assert_eq!(p.header("user-agent"), Some(p.user_agent.as_str()));
            assert!(p.is_browser());
        }
        let ff = BrowserProfile::for_mode(&UaMode::Firefox, now(), &empty);
        assert!(ff.user_agent.ends_with("Firefox/160.0") && ff.user_agent.contains("rv:160.0"));
        assert!(ff.headers.iter().all(|(k, _)| !k.starts_with("sec-ch-")));
        let sf = BrowserProfile::for_mode(&UaMode::Safari, now(), &empty);
        assert!(sf.user_agent.contains("Version/27.0 Safari/605.1.15"));
        assert!(sf.headers.iter().all(|(k, _)| !k.starts_with("sec-ch-")));
        let h = BrowserProfile::for_mode(&UaMode::Honest, now(), &empty);
        assert_eq!(h.user_agent, honest_ua());
        assert!(h.user_agent.starts_with("FOCA-rs/"));
        assert_eq!(h.headers.len(), 1);
        assert!(!h.is_browser());
        let c = BrowserProfile::for_mode(&UaMode::Custom("X/1".into()), now(), &empty);
        assert_eq!((c.user_agent.as_str(), c.headers.len()), ("X/1", 1));
    }

    #[test]
    fn modes_from_settings_are_compatible() {
        assert_eq!(UaMode::from_setting("chrome", ""), UaMode::Chrome);
        assert_eq!(UaMode::from_setting("auto", ""), UaMode::Chrome);
        assert_eq!(UaMode::from_setting("", ""), UaMode::Chrome);
        assert_eq!(UaMode::from_setting("custom", " "), UaMode::Chrome);
        assert_eq!(
            UaMode::from_setting("custom", "Bot/2"),
            UaMode::Custom("Bot/2".into())
        );
        assert_eq!(UaMode::from_setting("honest", ""), UaMode::Honest);
        assert_eq!(UaMode::from_setting("foca", ""), UaMode::Honest);
        assert_eq!(UaMode::from_setting("random", ""), UaMode::Chrome);
        assert_eq!(
            UaMode::from_setting("chrome_android", ""),
            UaMode::ChromeAndroid
        );
    }

    #[test]
    fn cache_fresh_wins_stale_only_raises() {
        let n = now();
        let fresh = UaVersions {
            chrome: Some(158),
            firefox: Some(161),
            fetched: n.unix_timestamp() - 3600,
        };
        let p = BrowserProfile::for_mode(&UaMode::Chrome, n, &fresh);
        assert!(p.user_agent.contains("Chrome/158."));
        let stale = UaVersions {
            fetched: n.unix_timestamp() - CACHE_TTL_SECS - 1,
            ..fresh
        };
        assert!(!stale.is_fresh(n));
        // a stale cache below the estimate loses to the estimate; above it, the cache wins
        let p = BrowserProfile::for_mode(&UaMode::Chrome, n, &stale);
        assert!(p.user_agent.contains("Chrome/159."));
        let p = BrowserProfile::for_mode(&UaMode::Firefox, n, &stale);
        assert!(p.user_agent.contains("Firefox/161.0"));
        assert_eq!(
            UaVersions::from_json(&serde_json::json!({"chrome": 150, "fetched": 5})).chrome,
            Some(150)
        );
        assert_eq!(
            UaVersions::from_json(&serde_json::json!("x")),
            UaVersions::default()
        );
    }

    #[test]
    fn parse_live_fixtures() {
        let c = include_str!("../tests/fixtures/chrome_versionhistory_win_stable.json");
        assert_eq!(parse_chrome_versions(c), Some(159));
        let f = include_str!("../tests/fixtures/firefox_versions.json");
        assert_eq!(parse_firefox_versions(f), Some(160));
        assert_eq!(parse_chrome_versions("{}"), None);
    }
}
