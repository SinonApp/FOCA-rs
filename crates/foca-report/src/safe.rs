//! Escaping and sanitization: HTML/XML/Markdown/CSV, safe file names and links.
//!
//! Everything taken from the metadata of third-party documents (author, title, paths,
//! revisions, …) is hostile input: renderers emit user strings only through these functions.

/// Escapes HTML text and attribute values (in `"` quotes): `& < > " '` become entities;
/// control characters other than `\n` and `\t` are dropped.
pub fn html(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\n' | '\t' => out.push(c),
            c if c.is_control() => {}
            // Invisible bidi controls (used to spoof the text direction of file names).
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {}
            c => out.push(c),
        }
    }
    out
}

/// Escapes XML 1.0 (GraphML) and removes characters not allowed in XML.
pub fn xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            '\u{0}'..='\u{1f}' | '\u{fffe}' | '\u{ffff}' => {}
            c => out.push(c),
        }
    }
    out
}

/// Returns the URL if it is safe to make clickable: only `http(s)://` without spaces or
/// control characters. `javascript:`, `data:`, `file:` and others yield `None` (rendered as
/// text).
pub fn safe_href(url: &str) -> Option<&str> {
    let u = url.trim();
    let lower = u.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return None;
    }
    if u.chars().any(|c| {
        c.is_control() || c.is_whitespace() || c == '"' || c == '<' || c == '>' || c == '`'
    }) {
        return None;
    }
    Some(u)
}

/// Escapes Markdown (CommonMark/Obsidian) in a table row or paragraph: inline markup
/// characters and `|` (cells) are escaped, line breaks become `<br>`, HTML is neutralized
/// with backslash escapes (`\<img\>`), and `&` is escaped only where it would start an
/// entity. Characters that are markup only at the start of a block (`#`, `+`, `=`, `-`, `>`)
/// are escaped only there, so `UTC+2` and `p=reject` stay readable.
pub fn md(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    let mut prev_nl = false;
    let chars: Vec<char> = s.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        let line_start = i == 0 || prev_nl;
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '|' | '~' | '$' | '<' | '>' => {
                out.push('\\');
                out.push(c);
            }
            '#' | '+' | '=' | '-' if line_start => {
                out.push('\\');
                out.push(c);
            }
            '&' => {
                // `&name;` / `&#123;` would be decoded as an entity.
                let rest = &chars[i + 1..];
                let n = rest
                    .iter()
                    .take_while(|c| c.is_ascii_alphanumeric() || **c == '#')
                    .count();
                if n > 0 && rest.get(n) == Some(&';') {
                    out.push('\\');
                }
                out.push('&');
            }
            '\r' => continue,
            '\n' => {
                if !prev_nl {
                    out.push_str("<br>");
                }
                prev_nl = true;
                continue;
            }
            c if c.is_control() => {}
            c => out.push(c),
        }
        prev_nl = false;
    }
    out
}

/// Renders text as an inline Markdown code span: no escaping inside (a code span shows
/// backslashes literally), a backtick fence longer than any run inside, line breaks as
/// spaces.
pub fn md_code_span(s: &str) -> String {
    let body: String = s
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .filter(|c| !c.is_control())
        .collect();
    let mut longest = 0;
    let mut cur = 0;
    for c in body.chars() {
        if c == '`' {
            cur += 1;
            longest = longest.max(cur);
        } else {
            cur = 0;
        }
    }
    let fence = "`".repeat(longest + 1);
    let pad = if body.starts_with('`') || body.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{body}{pad}{fence}")
}

/// Wraps text in a Markdown code block whose fence is longer than any backtick run inside.
pub fn md_code_block(s: &str) -> String {
    let mut longest = 0;
    let mut cur = 0;
    for c in s.chars() {
        if c == '`' {
            cur += 1;
            longest = longest.max(cur);
        } else {
            cur = 0;
        }
    }
    let fence = "`".repeat((longest + 1).max(3));
    let body: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    format!("{fence}text\n{body}\n{fence}")
}

/// Encodes a YAML front matter string: a JSON string is a valid double-quoted YAML scalar;
/// `<`, `>`, `&` become `\uXXXX` escapes in case the front matter is rendered as HTML.
pub fn yaml_str(s: &str) -> String {
    serde_json::to_string(s)
        .unwrap_or_else(|_| "\"\"".into())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

/// Encodes a CSV cell (RFC 4180) with CSV injection protection: values starting with
/// `= + - @ \t \r \n` get a `'` prefix (OWASP), then quoting as needed.
pub fn csv_cell(s: &str, delim: char) -> String {
    let mut v: String = s
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .collect();
    if v.starts_with(['=', '+', '-', '@', '\t', '\r', '\n']) {
        v.insert(0, '\'');
    }
    if v.contains(delim) || v.contains(['"', '\n', '\r']) || v.starts_with(' ') || v.ends_with(' ')
    {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v
    }
}

/// Encodes a CSV row terminated with CRLF (RFC 4180).
pub fn csv_row<S: AsRef<str>>(cells: &[S], delim: char) -> String {
    let mut out = cells
        .iter()
        .map(|c| csv_cell(c.as_ref(), delim))
        .collect::<Vec<_>>()
        .join(&delim.to_string());
    out.push_str("\r\n");
    out
}

/// Returns a safe file name: no `/ \ : * ? " < > |`, control or bidi characters, no `..` or
/// leading dots; spaces become `_`; at most 120 characters; empty input becomes `foca`.
pub fn file_name(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let bad = c.is_control()
            || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        if bad || c.is_whitespace() {
            if !out.ends_with('_') {
                out.push('_');
            }
        } else {
            out.push(c);
        }
    }
    while out.contains("..") {
        out = out.replace("..", ".");
    }
    let t: String = out
        .trim_matches(|c: char| c == '.' || c == '_' || c == '-')
        .chars()
        .take(120)
        .collect();
    let t = t.trim_end_matches(['.', '_']).to_string();
    // Reserved Windows device names.
    let upper = t.to_ascii_uppercase();
    let stem = upper.split('.').next().unwrap_or("");
    if t.is_empty()
        || matches!(stem, "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4)
    {
        return if t.is_empty() {
            "foca".into()
        } else {
            format!("_{t}")
        };
    }
    t
}

/// Returns a safe file name with extension: the stem is sanitized separately and the
/// extension is limited to `[a-z0-9]`.
pub fn file_name_ext(stem: &str, ext: &str) -> String {
    let ext: String = ext
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    let stem = file_name(stem);
    if ext.is_empty() {
        stem
    } else {
        format!("{stem}.{ext}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escapes_everything_dangerous() {
        let s = r#"<script>alert(1)</script>"><img src=x onerror=alert('x')>&"#;
        let e = html(s);
        assert!(!e.contains('<') && !e.contains('>') && !e.contains('"') && !e.contains('\''));
        assert!(e.contains("&lt;script&gt;"));
        assert_eq!(html("a\u{0}b\u{202e}c"), "abc");
    }

    #[test]
    fn href_only_http() {
        assert!(safe_href("javascript:alert(1)").is_none());
        assert!(safe_href(" JaVaScRiPt:alert(1)").is_none());
        assert!(safe_href("data:text/html,<b>").is_none());
        assert!(safe_href("https://x.ua/a b").is_none());
        assert!(safe_href("https://x.ua/\"onmouseover=").is_none());
        assert_eq!(safe_href("https://x.ua/a?b=1"), Some("https://x.ua/a?b=1"));
    }

    #[test]
    fn csv_injection_prefixed() {
        for bad in ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\tx", "\rx", "\n=1+1"] {
            let c = csv_cell(bad, ',');
            let inner = c.trim_start_matches('"');
            assert!(inner.starts_with('\''), "{bad:?} → {c:?}");
        }
        assert_eq!(csv_cell("a,b", ','), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\"", ','), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("ok", ','), "ok");
        assert_eq!(csv_row(&["a", "b;c"], ';'), "a;\"b;c\"\r\n");
    }

    #[test]
    fn file_names_safe() {
        for bad in [
            "../../etc/passwd",
            "a/b\\c",
            "..",
            "con",
            "x\u{0}y\u{202e}gpj.exe",
            "  .hidden  ",
        ] {
            let f = file_name(bad);
            assert!(
                !f.contains('/') && !f.contains('\\') && !f.contains("..") && !f.starts_with('.'),
                "{bad:?} → {f:?}"
            );
            assert!(!f.chars().any(|c| c.is_control()), "{f:?}");
            assert!(!f.is_empty());
        }
        assert_eq!(file_name("con"), "_con");
        assert_eq!(
            file_name_ext("Отчёт пентест/Contoso", "h t/ml"),
            "Отчёт_пентест_Contoso.html"
        );
        assert_eq!(file_name(&"я".repeat(300)).chars().count(), 120);
    }

    #[test]
    fn md_escaped() {
        let e = md("a|b *c* [x](javascript:1) <img>\nnext");
        assert!(
            e.contains("a\\|b")
                && e.contains("\\*c\\*")
                && e.contains("\\[x\\](")
                && e.contains("\\<img\\>")
        );
        assert_eq!(md("MITRE ATT&CK"), "MITRE ATT&CK");
        assert_eq!(md("a &amp; b"), "a \\&amp; b");
        assert_eq!(md("UTC+2, v=spf1 -all"), "UTC+2, v=spf1 -all");
        assert_eq!(md("# x\n+ y"), "\\# x<br>\\+ y");
        assert_eq!(md_code_span("10:42:36+02:00 a_b"), "`10:42:36+02:00 a_b`");
        assert_eq!(md_code_span("a`b"), "``a`b``");
        assert!(e.contains("<br>next"));
        assert!(md_code_block("a ``` b").starts_with("````text"));
        assert_eq!(yaml_str("a\"<b>&"), r#""a\"\u003cb\u003e\u0026""#);
    }
}
