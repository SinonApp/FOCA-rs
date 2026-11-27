//! HTML page shell shared by the full report and the extra templates: the print stylesheet, the
//! Content-Security-Policy and the logo markup (image, company initials or nothing).

use std::fmt::Write as _;

use crate::opts::Logo;
use crate::safe::html as esc;
use crate::Ctx;

pub(crate) const CSS: &str = include_str!("../templates/report.css");
/// CSP as defense in depth: even if something slipped through, the browser would neither run
/// scripts nor load resources.
pub(crate) const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'";

/// Legal entity forms, skipped when building logo initials.
const ORG_FORMS: &[&str] = &[
    "тов", "тоо", "ооо", "пат", "ат", "прат", "пао", "зао", "оао", "фоп", "чп", "пп", "ип", "llc",
    "ltd", "inc", "gmbh", "corp", "plc", "llp", "ag", "sa", "co",
];

/// Returns logo initials from a company name, skipping quotes and legal forms
/// (`LLC "Cyber Audit"` → `CA`).
pub(crate) fn initials(s: &str) -> String {
    let i: String = s
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| !w.is_empty())
        .filter(|w| !ORG_FORMS.contains(&w.trim_end_matches('.').to_lowercase().as_str()))
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect();
    if i.is_empty() {
        "F".into()
    } else {
        i.to_uppercase()
    }
}

/// Markup of the report logo: the image as an embedded `data:` URL, the company initials, or
/// nothing. Shared by the cover and the compact header of the data and standalone templates.
pub(crate) fn logo_html(c: &Ctx) -> String {
    match &c.o.logo {
        Logo::None => String::new(),
        Logo::Initials => format!(
            "<div class=\"initials\" aria-hidden=\"true\">{}</div>",
            esc(&initials(&c.o.company))
        ),
        // The MIME type comes from a whitelisted signature and the base64 alphabet is validated.
        Logo::Image { mime, b64 } => format!(
            "<img src=\"data:{};base64,{}\" alt=\"\">",
            esc(mime),
            esc(b64)
        ),
    }
}

/// Compact header of the data and standalone templates, with the logo on the left when set.
pub(crate) fn head_data(c: &Ctx, h: &mut String, title: &str, sub: &str) {
    let text = format!(
        "<h1>{}</h1><div class=\"muted\">{}</div>",
        esc(title),
        esc(sub)
    );
    let logo = logo_html(c);
    if logo.is_empty() {
        let _ = writeln!(h, "<header class=\"head-data\">{text}</header>");
    } else {
        let _ = writeln!(
            h,
            "<header class=\"head-data with-logo\"><div class=\"logo\">{logo}</div><div>{text}</div></header>"
        );
    }
}
