//! Secret scrubbing in logs before export (`logs_export`). Known values (API keys from the key
//! store, project secrets) are replaced with a fixed secret tag; passwords in URLs (`user:pass@`),
//! values of parameters and fields with secret-like names (`key`, `token`, `password`, `secret`,
//! `auth`, ...) and `Bearer ...` tokens become `***`.

const MASK: &str = "***";

/// Parameter names whose values are always hidden (case-insensitive substring match).
const NAMES: &[&str] = &[
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "session",
    "cookie",
    "sig",
    "credential",
];

fn is_secret_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    !n.is_empty() && NAMES.iter().any(|k| n.contains(k))
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

fn is_value_end(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '&' | '"' | '\'' | ',' | ';' | '}' | ')' | ']' | '<' | '>'
        )
}

/// Removes secrets from text. `known` lists values to replace everywhere (length >= 4).
pub fn redact(text: &str, known: &[String]) -> String {
    let mut s = text.to_string();
    let mut known: Vec<&String> = known.iter().filter(|k| k.chars().count() >= 4).collect();
    known.sort_by_key(|k| std::cmp::Reverse(k.len()));
    for k in known {
        s = s.replace(k.as_str(), "[СЕКРЕТ]");
    }
    let s = userinfo(&s);
    let s = bearer(&s);
    pairs(&s)
}

/// Rewrites `scheme://user:pass@host` as `scheme://user:***@host`.
fn userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        out.push_str(&rest[..i + 3]);
        rest = &rest[i + 3..];
        let end = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '"' | '\'' | '?' | '#'))
            .unwrap_or(rest.len());
        let auth = &rest[..end];
        if let Some(at) = auth.rfind('@') {
            let ui = &auth[..at];
            match ui.find(':') {
                Some(c) => {
                    out.push_str(&ui[..c]);
                    out.push(':');
                    out.push_str(MASK);
                }
                None => out.push_str(MASK),
            }
            out.push_str(&auth[at..]);
            rest = &rest[end..];
        }
    }
    out.push_str(rest);
    out
}

/// Rewrites `Bearer xxx` / `Basic xxx` as `Bearer ***`.
fn bearer(s: &str) -> String {
    let mut out = s.to_string();
    for w in ["Bearer ", "bearer ", "Basic ", "basic "] {
        let mut res = String::with_capacity(out.len());
        let mut rest = out.as_str();
        while let Some(i) = rest.find(w) {
            res.push_str(&rest[..i + w.len()]);
            rest = &rest[i + w.len()..];
            let end = rest.find(is_value_end).unwrap_or(rest.len());
            if end > 0 {
                res.push_str(MASK);
            }
            rest = &rest[end..];
        }
        res.push_str(rest);
        out = res;
    }
    out
}

/// Masks the value of `name=value`, `name: value` and `"name":"value"` pairs with a secret-like name.
fn pairs(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '=' || c == ':' {
            // the name to the left (possibly quoted)
            let mut j = out.len();
            let ob = out.as_bytes();
            let mut q = false;
            if j > 0 && (ob[j - 1] == b'"' || ob[j - 1] == b'\'') {
                q = true;
                j -= 1;
            }
            let name_end = j;
            let name_start = out[..name_end]
                .char_indices()
                .rev()
                .take_while(|(_, ch)| is_name_char(*ch))
                .last()
                .map(|(k, _)| k)
                .unwrap_or(name_end);
            let name = &out[name_start..name_end];
            // "://" in a URL is not a pair
            let url = c == ':' && chars.get(i + 1) == Some(&'/');
            if !url && is_secret_name(name) {
                out.push(c);
                i += 1;
                // spaces and an opening quote
                while i < chars.len() && chars[i] == ' ' {
                    out.push(' ');
                    i += 1;
                }
                let quote = match chars.get(i) {
                    Some(&'"') | Some(&'\'') => {
                        let qc = chars[i];
                        out.push(qc);
                        i += 1;
                        Some(qc)
                    }
                    _ => None,
                };
                // leave an already replaced known value alone
                let tag: Vec<char> = "[СЕКРЕТ]".chars().collect();
                if chars[i..].starts_with(&tag) {
                    out.push_str("[СЕКРЕТ]");
                    i += tag.len();
                    continue;
                }
                let start = i;
                while i < chars.len() {
                    let ch = chars[i];
                    let stop = match quote {
                        Some(qc) => ch == qc || ch == '\n',
                        None => is_value_end(ch),
                    };
                    if stop {
                        break;
                    }
                    i += 1;
                }
                if i > start {
                    out.push_str(MASK);
                }
                let _ = q;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_urls_pairs_bearer() {
        let known = vec!["BSAq9fKx77ab12".to_string(), "Buh2023!".to_string()];
        let t = "GET https://api.search.brave.com/res?q=x&key=BSAq9fKx77ab12 200\n\
                 proxy socks5://ivan:Pa55word@10.0.0.1:1080 ok\n\
                 Authorization: Bearer eyJhbGciOi.abc.def\n\
                 {\"api_key\": \"sk-live-123456\", \"name\": \"ok\"}\n\
                 secret in doc: password: Buh2023! end\n\
                 token=abcdef&page=2 https://example.com/a?b=c";
        let r = redact(t, &known);
        for bad in [
            "BSAq9fKx77ab12",
            "Pa55word",
            "eyJhbGciOi",
            "sk-live-123456",
            "Buh2023!",
            "abcdef",
        ] {
            assert!(!r.contains(bad), "{bad} still present: {r}");
        }
        assert!(r.contains("socks5://ivan:***@10.0.0.1:1080"), "{r}");
        assert!(r.contains("key=[СЕКРЕТ] 200"), "{r}");
        assert!(r.contains("\"name\": \"ok\""), "{r}");
        assert!(r.contains("page=2"), "{r}");
        assert!(r.contains("https://example.com/a?b=c"), "{r}");
        assert!(r.contains("q=x"), "{r}");
    }

    #[test]
    fn plain_text_unchanged() {
        let t = "2026-11-20T12:00:00.000 INFO  foca::scan этап search: 12 с, 4 источника";
        assert_eq!(redact(t, &[]), t);
    }
}
