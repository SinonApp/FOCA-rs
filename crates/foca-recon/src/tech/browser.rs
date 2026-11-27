//! Browser-only technology signals: global JavaScript variables (`js`), DOM selectors (`dom`) and
//! the hosts of requests made while a page rendered (`xhr`).
//!
//! The core has no JavaScript engine, so these signals are read by the hidden Android WebView
//! after a page render. [`probe_script`] builds ONE read-only script from the loaded rule table:
//! it walks every needed global path and selector, never writes to the page, stops after a time
//! budget and returns a size-capped JSON answer. [`BrowserSignals::from_eval`] parses that answer
//! and [`super::detect_with`] matches it against the rules like any other signal.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{clip, db, Acc, Compiled, Pat};

/// A DOM rule as written by the ingest script: selector plus optional attribute, property and
/// text conditions (each a pattern array).
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(super) struct UpstreamDom {
    s: String,
    a: BTreeMap<String, Vec<serde_json::Value>>,
    p: BTreeMap<String, Vec<serde_json::Value>>,
    t: Option<Vec<serde_json::Value>>,
}

impl UpstreamDom {
    pub(super) fn compile(&self, pat: &mut impl FnMut(&[serde_json::Value]) -> Pat) -> DomRule {
        DomRule {
            sel: self.s.clone(),
            attrs: self.a.iter().map(|(k, v)| (k.clone(), pat(v))).collect(),
            props: self.p.iter().map(|(k, v)| (k.clone(), pat(v))).collect(),
            text: self.t.as_deref().map(&mut *pat),
        }
    }
}

/// A compiled DOM rule. Without conditions the selector matching is enough.
#[derive(Debug)]
pub(super) struct DomRule {
    sel: String,
    attrs: Vec<(String, Pat)>,
    props: Vec<(String, Pat)>,
    text: Option<Pat>,
}

/// What a selector matched: requested attribute and property values of the first matching
/// element that has them, and the text of the first match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DomHit {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub a: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub p: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<String>,
}

/// What the hidden browser read on one rendered page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BrowserSignals {
    /// Rendered page URL.
    pub url: String,
    /// Global path -> value (`""` for a present non-primitive value such as an object).
    pub js: BTreeMap<String, String>,
    /// Selector -> what it matched (only matching selectors).
    pub dom: BTreeMap<String, DomHit>,
    /// Hosts of the requests the page made while rendering.
    pub hosts: Vec<String>,
    /// The script stopped at its time or size budget: some signals were not read.
    pub cut: bool,
}

/// Raw script answer.
#[derive(Deserialize, Default)]
#[serde(default)]
struct EvalAnswer {
    j: BTreeMap<String, String>,
    d: BTreeMap<String, DomHit>,
    cut: bool,
}

/// Largest answer accepted from the browser.
pub const MAX_ANSWER: usize = 256 << 10;
/// Most request hosts kept per page.
pub const MAX_HOSTS: usize = 200;

impl BrowserSignals {
    /// Parses the probe answer (`None` when it is not the expected JSON) plus the request hosts.
    pub fn from_eval(url: &str, eval: &str, hosts: &[String]) -> Option<BrowserSignals> {
        if eval.len() > MAX_ANSWER {
            return None;
        }
        let a: EvalAnswer = serde_json::from_str(eval).ok()?;
        let mut hs: Vec<String> = hosts
            .iter()
            .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        hs.truncate(MAX_HOSTS);
        Some(BrowserSignals {
            url: url.to_string(),
            js: a.j,
            dom: a.d,
            hosts: hs,
            cut: a.cut,
        })
    }

    /// Nothing was read.
    pub fn is_empty(&self) -> bool {
        self.js.is_empty() && self.dom.is_empty() && self.hosts.is_empty()
    }

    /// One log line: how many globals, selectors and hosts were read.
    pub fn summary(&self) -> String {
        format!(
            "JS {}, DOM {}, hosts {}{}",
            self.js.len(),
            self.dom.len(),
            self.hosts.len(),
            if self.cut { ", cut at the budget" } else { "" }
        )
    }

    /// Matches one technology's browser rules against what was read.
    pub(super) fn evaluate(&self, c: &Compiled, acc: &mut Acc) {
        let b = self;
        for (path, p) in &c.globals {
            let Some(v) = b.js.get(path) else { continue };
            if let Some(ver) = p.version(v) {
                let ev = if v.is_empty() {
                    format!("JS: {path}")
                } else {
                    format!("JS: {path} = {}", clip(v, 60))
                };
                acc.hit("js", p.weight(100), ver, ev);
            }
        }
        for r in &c.dom {
            let Some(h) = b.dom.get(&r.sel) else { continue };
            if r.attrs.is_empty() && r.props.is_empty() && r.text.is_none() {
                acc.hit("dom", 75, None, format!("DOM: {}", clip(&r.sel, 80)));
                continue;
            }
            let checks = r
                .attrs
                .iter()
                .map(|(k, p)| (k, p, h.a.get(k)))
                .chain(r.props.iter().map(|(k, p)| (k, p, h.p.get(k))));
            for (k, p, v) in checks {
                let Some(v) = v else { continue };
                if let Some(ver) = p.version(v) {
                    acc.hit(
                        "dom",
                        p.weight(75),
                        ver,
                        format!("DOM: {} [{k}={}]", clip(&r.sel, 60), clip(v, 60)),
                    );
                }
            }
            if let (Some(p), Some(t)) = (&r.text, &h.t) {
                if let Some(ver) = p.version(t) {
                    acc.hit(
                        "dom",
                        p.weight(75),
                        ver,
                        format!("DOM: {} text {}", clip(&r.sel, 60), clip(t, 40)),
                    );
                }
            }
        }
        for p in &c.xhr {
            for h in &b.hosts {
                if let Some(ver) = p.version(h) {
                    acc.hit("xhr", p.weight(75), ver, format!("XHR: {h}"));
                    break;
                }
            }
        }
    }
}

/// The read-only evaluation script. `__P__` = global paths, `__D__` = selector queries
/// `[selector, [attributes], [properties], wants text]`, `__T__` = time budget in ms, `__N__` =
/// most hits returned. Reading a property can run a page getter; nothing is assigned, no
/// navigation or network call is made.
const PROBE_JS: &str = r#"(function(){var P=__P__,D=__D__,T=Date.now()+__T__,N=__N__,o={j:{},d:{},cut:false},n=0;
function g(p){var s=p.split('.'),x=window;for(var i=0;i<s.length;i++){if(x===null||x===undefined)return undefined;try{x=x[s[i]];}catch(e){return undefined;}}return x;}
function v(x){var t=typeof x;return (t==='string'||t==='number'||t==='boolean')?String(x).slice(0,120):'';}
for(var i=0;i<P.length;i++){if((i&63)===0&&Date.now()>T){o.cut=true;break;}var x=g(P[i]);if(x!==undefined&&x!==null){o.j[P[i]]=v(x);if(++n>=N){o.cut=true;break;}}}
for(var k=0;k<D.length&&!o.cut;k++){if((k&15)===0&&Date.now()>T){o.cut=true;break;}var q=D[k],e;try{e=document.querySelectorAll(q[0]);}catch(_){continue;}if(!e.length)continue;var h={},m=Math.min(e.length,10),a,b,y;
if(q[1].length){h.a={};for(a=0;a<q[1].length;a++){for(b=0;b<m;b++){y=e[b].getAttribute(q[1][a]);if(y!==null){h.a[q[1][a]]=String(y).slice(0,200);break;}}}}
if(q[2].length){h.p={};for(a=0;a<q[2].length;a++){for(b=0;b<m;b++){try{y=e[b][q[2][a]];}catch(_){y=undefined;}if(y!==undefined&&y!==null){h.p[q[2][a]]=v(y);break;}}}}
if(q[3]){h.t=String(e[0].textContent||'').replace(/\s+/g,' ').slice(0,200);}
o.d[q[0]]=h;if(++n>=N){o.cut=true;}}
return JSON.stringify(o);})()"#;

/// Most hits (paths plus selectors) one answer may carry.
const MAX_HITS: usize = 1500;

/// Builds the evaluation script for every browser rule of the loaded table, with a time budget
/// of `budget_ms` inside the page. Returns (script, global paths, selectors).
pub fn probe_script(budget_ms: u64) -> (String, usize, usize) {
    let d = db();
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    let mut sels: BTreeMap<&str, (BTreeSet<&str>, BTreeSet<&str>, bool)> = BTreeMap::new();
    for t in &d.techs {
        paths.extend(t.globals.iter().map(|(p, _)| p.as_str()));
        for r in &t.dom {
            let e = sels.entry(r.sel.as_str()).or_default();
            e.0.extend(r.attrs.iter().map(|(k, _)| k.as_str()));
            e.1.extend(r.props.iter().map(|(k, _)| k.as_str()));
            e.2 |= r.text.is_some();
        }
    }
    let queries: Vec<serde_json::Value> = sels
        .iter()
        .map(|(s, (a, p, t))| serde_json::json!([s, a, p, if *t { 1 } else { 0 }]))
        .collect();
    let js = PROBE_JS
        .replace("__P__", &serde_json::to_string(&paths).unwrap_or_default())
        .replace(
            "__D__",
            &serde_json::to_string(&queries).unwrap_or_default(),
        )
        .replace("__T__", &budget_ms.to_string())
        .replace("__N__", &MAX_HITS.to_string());
    (js, paths.len(), queries.len())
}

#[cfg(test)]
mod tests {
    use super::super::{detect_with, PageInput, SiteExtra};
    use super::*;

    fn page() -> PageInput {
        PageInput {
            url: "https://app.example/".into(),
            headers: vec![],
            html: "<html><body><div id=root></div></body></html>".into(),
        }
    }

    #[test]
    fn probe_script_lists_rules_and_stays_bounded() {
        let (js, paths, sels) = probe_script(1500);
        assert!(paths > 3000 && sels > 1000, "{paths} {sels}");
        assert!(js.contains("\"jQuery.fn.jquery\""));
        assert!(js.contains("Date.now()+1500"));
        // read-only: no assignment to the page, no navigation or network APIs
        for bad in [
            "location=",
            "location.href=",
            "fetch(",
            "XMLHttpRequest",
            ".innerHTML=",
            "document.write",
            "setAttribute",
        ] {
            assert!(!js.contains(bad), "{bad}");
        }
        assert!(js.len() < 400 << 10, "{}", js.len());
    }

    #[test]
    fn js_globals_give_versions_with_named_evidence() {
        let eval =
            r#"{"j":{"jQuery.fn.jquery":"3.6.0","Vue.version":"2.6.14"},"d":{},"cut":false}"#;
        let b = BrowserSignals::from_eval("https://app.example/", eval, &[]).unwrap();
        let t = detect_with(
            &page(),
            &SiteExtra {
                browser: Some(&b),
                ..Default::default()
            },
        );
        let jq = t.iter().find(|x| x.name == "jQuery").expect("jQuery");
        assert_eq!(jq.version.as_deref(), Some("3.6.0"));
        assert!(jq
            .evidence
            .iter()
            .any(|e| e == "JS: jQuery.fn.jquery = 3.6.0"));
        assert!(jq.signals.contains(&"js".to_string()));
        let vue = t.iter().find(|x| x.name == "Vue.js").expect("Vue");
        assert_eq!(vue.version.as_deref(), Some("2.6.14"));
    }

    #[test]
    fn dom_attributes_and_request_hosts_match() {
        let eval = r#"{"j":{},"d":{"[ng-version]":{"a":{"ng-version":"17.3.1"}}},"cut":false}"#;
        let hosts = vec!["Widget.10to8.com".to_string(), "cdn.example".into()];
        let b = BrowserSignals::from_eval("https://app.example/", eval, &hosts).unwrap();
        assert_eq!(b.hosts, ["cdn.example", "widget.10to8.com"]);
        let t = detect_with(
            &page(),
            &SiteExtra {
                browser: Some(&b),
                ..Default::default()
            },
        );
        let ng = t.iter().find(|x| x.name == "Angular").expect("Angular");
        assert_eq!(ng.version.as_deref(), Some("17.3.1"));
        assert!(ng.evidence[0].starts_with("DOM: [ng-version]"), "{ng:?}");
        let x = t.iter().find(|x| x.name == "10to8").expect("10to8");
        assert!(x.signals.contains(&"xhr".to_string()));
        // nothing read, nothing detected
        let empty = BrowserSignals::from_eval("u", r#"{"j":{},"d":{}}"#, &[]).unwrap();
        assert!(empty.is_empty());
        assert!(BrowserSignals::from_eval("u", "jserr:x", &[]).is_none());
    }
}
