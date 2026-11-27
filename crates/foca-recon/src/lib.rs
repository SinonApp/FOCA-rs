//! Passive website reconnaissance.
//!
//! Functions take data that has already been downloaded (HTML, JS bodies, document text,
//! Wayback CDX lists) and return serializable (serde) structures plus ready-made
//! [`ReconFinding`]s. Network access goes only through [`foca_net::NetClient`] (scope, limits,
//! request log, cancellation) and only where stated explicitly: [`grepapp`] (third-party API,
//! `Access::Passive`), [`wellknown`] (archive.org, `Access::Passive`) and the optional bucket
//! check in [`buckets`] (opt-in, off by default). [`webaudit`] sends requests to the target only
//! at the standard (GET, `Access::TouchesTarget`) and active (`Access::Active`) levels.
//!
//! Modules:
//! - [`favicon`]: Shodan-compatible favicon hash (`http.favicon.hash`), sha256/md5,
//!   `<link rel=icon>`;
//! - [`tech`]: site technologies via Wappalyzer-style rules (static signals over fetched data,
//!   browser signals read by the hidden Android WebView in [`tech::browser`]), plus analytics
//!   ids (pivots);
//! - [`tech::cmsparts`]: WordPress/Drupal/Joomla/Magento/PrestaShop plugins, themes and modules by
//!   their asset paths, with versions;
//! - [`js`]: endpoints and secrets in JavaScript (secrets are always masked);
//! - [`retire`]: JavaScript library versions and vulnerable ranges (Retire.js data);
//! - [`grepapp`]: where the domain appears in public code (grep.app);
//! - [`wellknown`]: robots.txt / sitemap.xml / security.txt, and snapshot selection from CDX;
//! - [`buckets`]: references to cloud storage (S3, GCS, Azure, DO Spaces, Yandex);
//! - [`collect`]: input collection through `NetClient` (live site or archive copy,
//!   robots/sitemap from CDX);
//! - [`webaudit`]: deep web audit by access class (passive / standard / active) over
//!   its submodules [`headers`] (security headers), [`webaudit::csp`] (policy assessment,
//!   allowed hosts), [`webaudit::sourcemaps`] (JS source maps), [`apidocs`] (Swagger/OpenAPI,
//!   GraphQL, Actuator, openid-configuration) and [`methods`] (OPTIONS/TRACE/PROPFIND,
//!   forged-Origin CORS; never PUT/DELETE);
//! - [`report`]: the combined [`analyze_site`] → [`ReconReport`] with findings.

pub mod buckets;
pub mod collect;
pub mod favicon;
pub mod finding;
pub mod grepapp;
pub mod hash;
pub mod js;
pub mod report;
pub mod retire;
pub mod screenshot;
pub mod tech;
pub mod webaudit;
pub mod wellknown;

pub use finding::ReconFinding;
pub use report::{analyze_site, ReconInput, ReconReport};
pub use webaudit::{apidocs, headers, methods};
