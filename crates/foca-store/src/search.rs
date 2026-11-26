//! Full-text search over document text.
//!
//! The FTS5 table `doc_fts` (schema v8) is an *external content* index over
//! `documents(name, text_excerpt)`: the text is stored once, triggers keep the index in sync on
//! insert/update/hard delete, and soft-deleted documents are filtered out at query time, so
//! `doc_delete`/`doc_restore`/undo affect search immediately without reindexing.
//!
//! Tokenizer: `unicode61 remove_diacritics 2` (Unicode case folding, Cyrillic included; Latin
//! diacritics are folded, `й`/`ї`/`ё` stay distinct letters) with the modifier-letter and
//! typographic apostrophes as separators, so `мʼясо`, `м’ясо` and `м'ясо` tokenize alike.
//!
//! User input never reaches FTS5 syntax: [`fts_query`] rebuilds the query from quoted terms.
//!
//! Snippets are masked, not just flagged: they go to the UI directly (the snapshot masking
//! of `{{s:…}}` does not apply), so every secret/PII value is replaced by its mask before the
//! snippet leaves the store. Detection runs on a margin around the snippet window, so a value
//! cut by the window edge is still recognised and masked in full.

use foca_analysis::pii;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{ProjectDb, Result};

/// Maximum characters of a user query.
pub const MAX_QUERY_CHARS: usize = 512;
/// Maximum terms of a user query.
pub const MAX_TERMS: usize = 16;
/// Longest single term or phrase (in characters) passed to FTS5.
pub const MAX_TERM_CHARS: usize = 64;
/// Maximum results per page.
pub const MAX_LIMIT: usize = 200;
/// Snippet length, characters.
pub const SNIPPET_CHARS: usize = 180;
/// Context before the first highlighted term, characters.
const SNIPPET_LEAD: usize = 60;
/// Detection margin around the snippet window, bytes.
const SCAN_MARGIN: usize = 512;

const HL_START: char = '\u{2}';
const HL_END: char = '\u{3}';

/// Search options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SearchOpts {
    pub limit: usize,
    pub offset: usize,
    /// Include documents in the trash.
    pub include_deleted: bool,
    /// Treat the last bare term as a prefix (search as you type).
    pub prefix_last: bool,
}

impl Default for SearchOpts {
    fn default() -> Self {
        SearchOpts {
            limit: 50,
            offset: 0,
            include_deleted: false,
            prefix_last: true,
        }
    }
}

/// One search result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SearchHit {
    pub doc: u64,
    pub name: String,
    pub url: Option<String>,
    /// Snippet: matched terms as `{{h:…}}`, secrets/PII as `{{s:<mask>}}`, `…` at cut ends.
    pub snippet: String,
    /// The document name matched.
    pub in_name: bool,
    /// Labels of masked ranges in the snippet (`secret:<rule>`, `pii:<kind>`).
    pub masked: Vec<String>,
    /// BM25 rank (lower is better).
    pub rank: f64,
    pub deleted: bool,
}

/// A page of results.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SearchPage {
    pub total: u64,
    pub hits: Vec<SearchHit>,
    /// The FTS5 query actually executed (for diagnostics); empty when nothing to search.
    pub query: String,
}

fn quote(term: &str) -> String {
    format!("\"{}\"", term.replace('"', "\"\""))
}

fn has_word(s: &str) -> bool {
    s.chars().any(char::is_alphanumeric)
}

/// Converts free user input into a safe FTS5 query: `"phrases"`, bare terms (implicit AND),
/// `term*` prefixes and `-term` exclusions (only alongside positive terms). Every term is
/// emitted as a quoted FTS5 string, so operators, column filters, `NEAR`, parentheses and
/// stray quotes in the input are inert. Returns `None` when nothing searchable remains.
pub fn fts_query(input: &str, prefix_last: bool) -> Option<String> {
    let input: String = input
        .chars()
        .take(MAX_QUERY_CHARS)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    // (text, phrase, prefix, negated)
    let mut terms: Vec<(String, bool, bool, bool)> = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let neg = c == '-';
        if neg {
            chars.next();
        }
        if chars.peek() == Some(&'"') {
            chars.next();
            let mut s = String::new();
            for ch in chars.by_ref() {
                if ch == '"' {
                    break;
                }
                s.push(ch);
            }
            let prefix = chars.peek() == Some(&'*');
            if prefix {
                chars.next();
            }
            terms.push((s, true, prefix, neg));
        } else {
            let mut s = String::new();
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() || ch == '"' {
                    break;
                }
                s.push(ch);
                chars.next();
            }
            let prefix = s.ends_with('*');
            let s = s.trim_end_matches('*').to_string();
            terms.push((s, false, prefix, neg));
        }
    }
    // Normalise and cap each term before checking that it is still searchable: a long run of
    // spaces or punctuation inside a phrase must not be cut down to an empty `""` phrase.
    for t in terms.iter_mut() {
        let collapsed = t.0.split_whitespace().collect::<Vec<_>>().join(" ");
        t.0 = collapsed
            .chars()
            .take(MAX_TERM_CHARS)
            .collect::<String>()
            .trim()
            .to_string();
    }
    terms.retain(|t| has_word(&t.0));
    terms.truncate(MAX_TERMS);
    if prefix_last {
        if let Some(t) = terms.last_mut() {
            if !t.1 && !t.3 {
                t.2 = true;
            }
        }
    }
    let render = |t: &(String, bool, bool, bool)| {
        let mut q = quote(&t.0);
        if t.2 {
            q.push('*');
        }
        q
    };
    let pos: Vec<String> = terms.iter().filter(|t| !t.3).map(render).collect();
    let neg: Vec<String> = terms.iter().filter(|t| t.3).map(render).collect();
    if pos.is_empty() {
        return None;
    }
    let mut q = pos.join(" ");
    if !neg.is_empty() {
        q = format!("({q}) NOT ({})", neg.join(" OR "));
    }
    Some(q)
}

/// Splits `highlight()` output into clean text and highlighted byte ranges.
fn parse_highlight(s: &str) -> (String, Vec<(usize, usize)>) {
    let mut clean = String::with_capacity(s.len());
    let mut ranges = Vec::new();
    let mut open: Option<usize> = None;
    for c in s.chars() {
        match c {
            HL_START => open = Some(clean.len()),
            HL_END => {
                if let Some(st) = open.take() {
                    if clean.len() > st {
                        ranges.push((st, clean.len()));
                    }
                }
            }
            _ => clean.push(c),
        }
    }
    (clean, ranges)
}

fn floor_char(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Byte offset `n` characters before `at`.
fn back_chars(s: &str, at: usize, n: usize) -> usize {
    s[..at]
        .char_indices()
        .rev()
        .nth(n.saturating_sub(1))
        .map(|(i, _)| i)
        .unwrap_or(0)
}

/// Byte offset `n` characters after `at`.
fn fwd_chars(s: &str, at: usize, n: usize) -> usize {
    s[at..]
        .char_indices()
        .nth(n)
        .map(|(i, _)| at + i)
        .unwrap_or(s.len())
}

/// Collapses whitespace and defuses literal `{{` so document text cannot fake markers.
fn plain(s: &str, out: &mut String) {
    let mut ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !ws {
                out.push(' ');
            }
            ws = true;
            continue;
        }
        ws = false;
        if c == '{' && out.ends_with('{') {
            out.push('\u{200B}');
        }
        out.push(c);
    }
}

/// Builds the masked snippet of `text` around the first highlighted range.
pub fn build_snippet(text: &str, hl: &[(usize, usize)]) -> (String, Vec<String>) {
    if text.is_empty() {
        return (String::new(), Vec::new());
    }
    let (ws, we) = match hl.first() {
        Some(&(s, e)) => {
            let ws = back_chars(text, s, SNIPPET_LEAD);
            let we = fwd_chars(text, ws, SNIPPET_CHARS).max(e);
            (ws, we)
        }
        None => (0, fwd_chars(text, 0, SNIPPET_CHARS)),
    };
    // Detect sensitive values on a margin around the window.
    let rs = floor_char(text, ws.saturating_sub(SCAN_MARGIN));
    let re = ceil_char(text, we + SCAN_MARGIN);
    let spans: Vec<pii::Span> = pii::sensitive_spans(&text[rs..re])
        .into_iter()
        .map(|mut s| {
            s.start += rs;
            s.end += rs;
            s
        })
        .filter(|s| s.start < we && s.end > ws)
        .collect();
    let mut out = String::new();
    if ws > 0 {
        out.push('…');
    }
    let mut labels = Vec::new();
    let mut at = ws;
    let emit_plain = |from: usize, to: usize, out: &mut String| {
        // Highlights inside [from, to).
        let mut p = from;
        for &(hs, he) in hl {
            let (hs, he) = (hs.max(from), he.min(to));
            if hs >= he {
                continue;
            }
            plain(&text[p..hs], out);
            out.push_str("{{h:");
            plain(&text[hs..he], out);
            out.push_str("}}");
            p = he;
        }
        if p < to {
            plain(&text[p..to], out);
        }
    };
    for s in &spans {
        let st = s.start.max(at);
        emit_plain(at, st, &mut out);
        out.push_str("{{s:");
        out.push_str(&foca_core::api::mask(&text[s.start..s.end]));
        out.push_str("}}");
        labels.push(s.label.clone());
        at = s.end.max(at);
    }
    let end = we.max(at);
    if at < end {
        emit_plain(at, end, &mut out);
    }
    // Personal values are masked before storage (`pii::sanitize`): flag their masks too.
    if text[ws..end].contains("••") && !labels.iter().any(|l| l.starts_with("pii")) {
        labels.push("pii".into());
    }
    if end < text.len() {
        out.push('…');
    }
    (out.trim().to_string(), labels)
}

impl ProjectDb {
    /// Full-text search over the names and text of the project's documents.
    pub fn search_text(&self, input: &str, opts: &SearchOpts) -> Result<SearchPage> {
        let Some(q) = fts_query(input, opts.prefix_last) else {
            return Ok(SearchPage {
                total: 0,
                hits: Vec::new(),
                query: String::new(),
            });
        };
        let limit = opts.limit.clamp(1, MAX_LIMIT) as i64;
        let conn = self.conn();
        let total: i64 = conn.query_row(
            "SELECT count(*) FROM doc_fts JOIN documents d ON d.id = doc_fts.rowid
             WHERE doc_fts MATCH ?1 AND (?2 OR d.deleted_at IS NULL)",
            params![q, opts.include_deleted],
            |r| r.get(0),
        )?;
        let mut st = conn.prepare(
            "SELECT d.id, d.name, d.url, d.deleted_at IS NOT NULL,
                    highlight(doc_fts, 0, char(2), char(3)),
                    highlight(doc_fts, 1, char(2), char(3)),
                    bm25(doc_fts, 4.0, 1.0) AS r
             FROM doc_fts JOIN documents d ON d.id = doc_fts.rowid
             WHERE doc_fts MATCH ?1 AND (?2 OR d.deleted_at IS NULL)
             ORDER BY r, d.id LIMIT ?3 OFFSET ?4",
        )?;
        let rows = st.query_map(
            params![q, opts.include_deleted, limit, opts.offset as i64],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, bool>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, f64>(6)?,
                ))
            },
        )?;
        let mut hits = Vec::new();
        for row in rows {
            let (id, name, url, deleted, hname, htext, rank) = row?;
            let in_name = hname.as_deref().is_some_and(|h| h.contains(HL_START));
            let (text, hl) = parse_highlight(htext.as_deref().unwrap_or(""));
            let (snippet, masked) = build_snippet(&text, &hl);
            hits.push(SearchHit {
                doc: id as u64,
                name,
                url,
                snippet,
                in_name,
                masked,
                rank,
                deleted,
            });
        }
        Ok(SearchPage {
            total: total as u64,
            hits,
            query: q,
        })
    }

    /// Rebuilds the full-text index from `documents` (repair; normally triggers keep it in sync).
    pub fn fts_rebuild(&self) -> Result<()> {
        self.conn()
            .execute("INSERT INTO doc_fts(doc_fts) VALUES ('rebuild')", [])?;
        Ok(())
    }

    /// Runs the FTS5 integrity check against the content table.
    pub fn fts_check(&self) -> Result<()> {
        self.conn().execute(
            "INSERT INTO doc_fts(doc_fts, rank) VALUES ('integrity-check', 1)",
            [],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_escaping() {
        assert_eq!(fts_query("звіт", false).unwrap(), "\"звіт\"");
        assert_eq!(fts_query("звіт", true).unwrap(), "\"звіт\"*");
        assert_eq!(
            fts_query("\"план робіт\" бюдж*", false).unwrap(),
            "\"план робіт\" \"бюдж\"*"
        );
        assert_eq!(
            fts_query("договір -чернетка", true).unwrap(),
            "(\"договір\") NOT (\"чернетка\")"
        );
        // FTS5 syntax in the input is inert.
        assert_eq!(
            fts_query("name:x OR y NEAR(a b) \"un", false).unwrap(),
            "\"name:x\" \"OR\" \"y\" \"NEAR(a\" \"b)\" \"un\""
        );
        assert_eq!(fts_query("a\"b", false).unwrap(), "\"a\" \"b\"");
        assert!(fts_query("", true).is_none());
        assert!(fts_query("* - \"\" ()", true).is_none());
        assert!(fts_query("-only", true).is_none());
        let many = "x ".repeat(100);
        assert_eq!(
            fts_query(&many, false).unwrap().matches('"').count(),
            2 * MAX_TERMS
        );
    }

    #[test]
    fn long_whitespace_in_phrase_never_yields_empty_phrase() {
        let q = format!("\"{}договір\"", " ".repeat(70));
        assert_eq!(fts_query(&q, false).unwrap(), "\"договір\"");
        let q = format!("\"план{}робіт\"", " ".repeat(80));
        assert_eq!(fts_query(&q, false).unwrap(), "\"план робіт\"");
        // A phrase whose first 64 characters hold no word is dropped instead of becoming `""`.
        let q = format!("\"{}x\" звіт", "!".repeat(70));
        assert_eq!(fts_query(&q, false).unwrap(), "\"звіт\"");
        let q = format!("\"{}x\"", "!".repeat(70));
        assert!(fts_query(&q, false).is_none());
    }

    #[test]
    fn snippet_masks_and_highlights() {
        let text = "Вступ. Картка 4111 1111 1111 1111 видана для оплати відряджень.";
        let s = text.find("оплати").unwrap();
        let (sn, labels) = build_snippet(text, &[(s, s + "оплати".len())]);
        assert!(sn.contains("{{h:оплати}}"), "{sn}");
        assert!(!sn.contains("4111 1111 1111 1111"), "{sn}");
        assert!(sn.contains("{{s:41…11}}"), "{sn}");
        assert_eq!(labels, ["pii:card"]);
        // Literal markers in the document are defused.
        let (sn, _) = build_snippet("a {{s:fake}} b", &[]);
        assert!(!sn.contains("{{s:"), "{sn}");
    }

    #[test]
    fn snippet_never_cuts_a_value() {
        // The window edge falls inside the card number: it must still be masked in full.
        let filler = format!(" {} ", "x".repeat(50));
        let text = format!("Картка 4111111111111111{filler}ключове слово тут");
        let s = text.find("ключове").unwrap();
        let (sn, _) = build_snippet(&text, &[(s, s + "ключове".len())]);
        for frag in ["4111", "1111111", "111111"] {
            assert!(!sn.contains(frag), "{frag} leaked in {sn}");
        }
    }
}
