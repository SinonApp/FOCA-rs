//! Table building blocks shared by the section modules and the format writers: HTML and
//! Markdown table markup and the titled tables handed to the DOCX writer.

use std::fmt::Write as _;

use crate::safe::{html as esc, md as mesc};

/// A titled table handed to the DOCX writer by the section modules (ports, infrastructure,
/// website). Cells hold redacted plain text; the writer escapes XML.
pub(crate) struct DocTable {
    pub title: String,
    pub note: Option<String>,
    pub head: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl DocTable {
    pub fn new(title: &str, note: Option<String>, head: &[&str], rows: Vec<Vec<String>>) -> Self {
        DocTable {
            title: title.to_string(),
            note,
            head: head.iter().map(|h| h.to_string()).collect(),
            rows,
        }
    }
}

/// Renders a table: headers (already in the report language) and rows of ready HTML.
pub(crate) fn html_table(h: &mut String, head: &[&str], rows: &[Vec<String>], num_cols: &[usize]) {
    h.push_str("<table><thead><tr>");
    for (i, th) in head.iter().enumerate() {
        let cls = if num_cols.contains(&i) {
            " class=\"num\""
        } else {
            ""
        };
        let _ = write!(h, "<th{cls}>{}</th>", esc(th));
    }
    h.push_str("</tr></thead><tbody>\n");
    for r in rows {
        h.push_str("<tr>");
        for (i, td) in r.iter().enumerate() {
            let cls = if num_cols.contains(&i) {
                " class=\"num\""
            } else {
                ""
            };
            let _ = write!(h, "<td{cls}>{td}</td>");
        }
        h.push_str("</tr>\n");
    }
    h.push_str("</tbody></table>\n");
}

/// Writes a Markdown table; a table without rows becomes an italic "no data" line, like the
/// HTML report.
pub(crate) fn md_table(no_data: &str, out: &mut String, head: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        let _ = writeln!(out, "*{}*\n", mesc(no_data));
        return;
    }
    out.push('|');
    for h in head {
        let _ = write!(out, " {} |", mesc(h));
    }
    out.push_str("\n|");
    for _ in head {
        out.push_str(" --- |");
    }
    out.push('\n');
    for r in rows {
        out.push('|');
        for c in r {
            let _ = write!(out, " {c} |");
        }
        out.push('\n');
    }
    out.push('\n');
}
