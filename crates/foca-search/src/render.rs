//! Render fetcher: loads a page in a real browser engine (a hidden `android.webkit.WebView` on
//! Android, see `platform/RenderFetcher.kt`) and runs a script of steps.
//!
//! Some search engines answer data center or plain HTTP clients with a challenge (Startpage: a
//! JavaScript proof of work; Brave and Mojeek: bot protection). The browser solves it on its own,
//! and cookies persist in the WebView between requests.
//!
//! The core only describes the request ([`RenderRequest`]) and parses the resulting HTML; the
//! [`RenderFetch`] implementation is supplied by the application bridge (`EngineConfig::render`).
//! Without it (CLI, `serve`, host tests), sources that need a browser report [`NO_RENDER`].

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::BoxFuture;

/// Error prefix meaning no embedded browser is available (`run_sources` sets the `unavailable` status).
pub const NO_RENDER: &str = "нужен WebView (только в Android)";

/// Legacy `ua` value for the desktop form of the real WebView UA. Not used for search engines: a desktop UA on a touch phone with mobile Client Hints and screen is an
/// inconsistent fingerprint. Kotlin (`RenderLogic.uaMode`) treats it as `mobile`.
pub const DESKTOP_UA: &str = "desktop";
/// The WebView's own mobile UA without `; wv` (the default for all requests).
pub const MOBILE_UA: &str = "mobile";

/// A script step, executed in the page in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RenderStep {
    /// Waits until the document has loaded (`readyState == complete`), none of the `gone` strings
    /// appear in `body.innerText` and, if set, the `present` element exists. If this does not happen
    /// within `timeout_ms`, the script stops and the response has `wait_timeout: true` and the current HTML.
    Wait {
        #[serde(default)]
        gone: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        present: Option<String>,
        timeout_ms: u64,
        /// Early exit: a lowercase substring of the visible text or page URL (a captcha). The step and
        /// the script stop at once and `RenderPage.aborted` holds the matched string.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        abort: Vec<String>,
    },
    /// Fills the `field` of a form (the first one matching the CSS selector `form`), submits it
    /// (`form.submit()`) and waits for the new document. A missing form is reported in `missing`.
    Submit {
        form: String,
        field: String,
        value: String,
    },
    /// Activates the `sel` element whose text contains `text` (case-insensitive; empty matches any):
    /// a form button triggers `form.submit()`, anything else `click()`; then waits for the new
    /// document. A missing element is reported in `missing`, which tells sources there is no next page.
    Click {
        sel: String,
        #[serde(default)]
        text: String,
    },
    /// Sleeps inside the page.
    Sleep { ms: u64 },
    /// Evaluates a read-only JavaScript expression that returns a string (technology signals,
    /// `foca_recon::tech::browser::probe_script`). The result lands in [`RenderPage::eval`]
    /// (size-capped by the browser side); the step waits at most `timeout_ms`.
    Eval { code: String, timeout_ms: u64 },
}

/// A render fetcher request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderRequest {
    /// Session name: a separate WebView with its own history (`startpage`, `brave`, `mojeek`). Cookies
    /// are shared (CookieManager), so a solved challenge persists between requests.
    pub session: String,
    /// URL to open; `None` continues on the session's current page ("Next" pagination).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default)]
    pub steps: Vec<RenderStep>,
    /// Time limit for the whole script on the browser side, in milliseconds.
    pub timeout_ms: u64,
    /// [`MOBILE_UA`] (`mobile`, the default), the legacy `desktop`, or a literal User-Agent string.
    pub ua: String,
    /// Proxy from `settings.net` (`socks5h://...`, `http://...`). A WebView without proxy support
    /// refuses the request rather than going direct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// Module name for the request log.
    #[serde(default)]
    pub module: String,
    /// Local page to load instead of `url` (fingerprint diagnostics): HTML and base URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// Record the hosts of the requests the page makes while the request runs
    /// ([`RenderPage::hosts`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub collect_hosts: bool,
}

impl RenderRequest {
    pub fn new(session: &str, url: Option<&str>, timeout: Duration) -> Self {
        RenderRequest {
            session: session.into(),
            url: url.map(String::from),
            steps: Vec::new(),
            timeout_ms: timeout.as_millis() as u64,
            ua: MOBILE_UA.into(),
            proxy: None,
            module: session.into(),
            html: None,
            base: None,
            collect_hosts: false,
        }
    }

    /// Records request hosts seen while the page loads ([`RenderPage::hosts`]).
    pub fn collecting_hosts(mut self) -> Self {
        self.collect_hosts = true;
        self
    }

    pub fn step(mut self, s: RenderStep) -> Self {
        self.steps.push(s);
        self
    }

    /// Routes the page load through the proxy from the network settings (`None` = direct).
    pub fn through_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }

    /// Records the request in the log under `module` instead of the session name.
    pub fn logged_as(mut self, module: &str) -> Self {
        self.module = module.into();
        self
    }

    /// Loads a local page (`html` served as if from `base`) instead of a URL.
    pub fn local_page(mut self, html: &str, base: &str) -> Self {
        self.html = Some(html.into());
        self.base = Some(base.into());
        self
    }
}

/// Result of a script run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderPage {
    /// `document.documentElement.outerHTML` after the script (or at the step where it stopped).
    #[serde(default)]
    pub html: String,
    /// Final URL (`location.href`).
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub ms: u64,
    /// A `Wait` step timed out (search engine challenge not passed or page did not load).
    #[serde(default)]
    pub wait_timeout: bool,
    /// A `Submit`/`Click` step did not find its element (step description).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<String>,
    /// HTTP status of the main document if the WebView reported it (0 on a load error).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// The script was stopped by the `abort` condition of a `wait` step (matched string), i.e. a captcha, without waiting for the timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aborted: Option<String>,
    /// Result of the last `eval` step (a string, usually JSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<String>,
    /// Hosts of the requests made while the request ran (with `collect_hosts`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

/// Loads pages in a browser engine (on Android, a bridge to Kotlin).
/// Errors carry the reason as text (no WebView, proxy not supported, script failed).
pub trait RenderFetch: Send + Sync {
    fn fetch<'a>(&'a self, req: RenderRequest) -> BoxFuture<'a, Result<RenderPage, String>>;
}

/// Fingerprint diagnostics page for the embedded browser (Debug → Search engines). The same page
/// is saved to a file so it can be opened in regular Chrome for comparison.
pub const FINGERPRINT_HTML: &str = include_str!("fingerprint.html");

/// Builds a render request for the local fingerprint page that waits for `#done`.
pub fn fingerprint_request(timeout: Duration) -> RenderRequest {
    RenderRequest::new("fingerprint", None, timeout)
        .step(RenderStep::Wait {
            gone: vec![],
            present: Some("#done".into()),
            timeout_ms: 15_000,
            abort: vec![],
        })
        .local_page(FINGERPRINT_HTML, "https://fingerprint.foca.invalid/")
        .logged_as("fingerprint")
}

/// Extracts the fingerprint JSON from `<pre id="out">` in the resulting HTML.
pub fn parse_fingerprint(html: &str) -> Option<serde_json::Value> {
    let i = html.find("id=\"out\"")?;
    let rest = &html[i..];
    let start = rest.find('>')? + 1;
    let end = rest[start..].find("</pre>")? + start;
    let text = rest[start..end]
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&");
    serde_json::from_str(&text)
        .ok()
        .filter(|v: &serde_json::Value| v.is_object())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_roundtrip() {
        let r = fingerprint_request(Duration::from_secs(30));
        assert!(r.url.is_none() && r.html.as_deref().unwrap().contains("userAgentData"));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["ua"], "mobile");
        assert!(v["base"].as_str().unwrap().starts_with("https://"));
        let page = r#"<html><body><pre id="out">{"userAgent":"Mozilla/5.0 (Linux; Android 14) &amp; x","issues":[]}</pre></body></html>"#;
        let fp = parse_fingerprint(page).unwrap();
        assert_eq!(fp["userAgent"], "Mozilla/5.0 (Linux; Android 14) & x");
        assert!(parse_fingerprint("<pre id=\"out\"></pre>").is_none());
    }

    #[test]
    fn request_json_shape_for_kotlin() {
        let r = RenderRequest::new(
            "startpage",
            Some("https://www.startpage.com/"),
            Duration::from_secs(60),
        )
        .step(RenderStep::Wait {
            gone: vec!["Verifying your request".into()],
            present: None,
            timeout_ms: 45_000,
            abort: vec!["/captcha".into()],
        })
        .step(RenderStep::Submit {
            form: "form[action*=search]".into(),
            field: "[name=query]".into(),
            value: "site:a.ua filetype:pdf".into(),
        })
        .step(RenderStep::Click {
            sel: "button".into(),
            text: "Next".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["session"], "startpage");
        assert_eq!(v["timeout_ms"], 60_000);
        assert_eq!(v["steps"][0]["op"], "wait");
        assert_eq!(v["steps"][0]["gone"][0], "Verifying your request");
        assert_eq!(v["steps"][0]["abort"][0], "/captcha");
        assert_eq!(v["steps"][1]["op"], "submit");
        assert_eq!(v["steps"][2]["op"], "click");
        assert!(v.get("proxy").is_none());
        let p: RenderPage = serde_json::from_str(
            r#"{"html":"<html></html>","url":"u","ms":5,"wait_timeout":true}"#,
        )
        .unwrap();
        assert!(p.wait_timeout && p.missing.is_none());
        assert!(p.eval.is_none() && p.hosts.is_empty());
    }

    #[test]
    fn eval_step_and_host_collection_shape() {
        let r = RenderRequest::new(
            "recon",
            Some("https://site.example/"),
            Duration::from_secs(20),
        )
        .step(RenderStep::Eval {
            code: "JSON.stringify({})".into(),
            timeout_ms: 3000,
        })
        .collecting_hosts();
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["steps"][0]["op"], "eval");
        assert_eq!(v["steps"][0]["code"], "JSON.stringify({})");
        assert_eq!(v["collect_hosts"], true);
        let plain =
            serde_json::to_value(RenderRequest::new("x", None, Duration::from_secs(5))).unwrap();
        assert!(plain.get("collect_hosts").is_none());
        let p: RenderPage = serde_json::from_str(
            r#"{"html":"","url":"u","ms":5,"eval":"{\"j\":{}}","hosts":["cdn.example"]}"#,
        )
        .unwrap();
        assert_eq!(p.eval.as_deref(), Some("{\"j\":{}}"));
        assert_eq!(p.hosts, ["cdn.example"]);
    }
}
