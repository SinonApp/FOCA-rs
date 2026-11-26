//! HTML page shell shared by the full report and the extra templates: the print stylesheet and
//! the Content-Security-Policy.

pub(crate) const CSS: &str = include_str!("../templates/report.css");
/// CSP as defense in depth: even if something slipped through, the browser would neither run
/// scripts nor load resources.
pub(crate) const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'";
