//! Paths and e-mail addresses in text and fields, similar to FOCA's PathAnalysis:
//! `C:\Users\<user>\...`, `\\server\share\...`, `/home/<user>/...` and `file://...` yield a user and a host.

use foca_core::{Metadata, PathKind, PathRef, PersonRole};

/// Result of path analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathInfo {
    pub path: String,
    pub kind: PathKind,
    pub user: Option<String>,
    pub host: Option<String>,
}

const NOT_USERS: &[&str] = &[
    "public",
    "default",
    "default user",
    "all users",
    "shared",
    "guest",
    "desktop.ini",
];
const UNIX_ROOTS: &[&str] = &[
    "/home/", "/Users/", "/root/", "/mnt/", "/media/", "/srv/", "/opt/", "/var/", "/tmp/",
];

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn valid_user(u: &str) -> Option<String> {
    let u = u.trim();
    if u.is_empty()
        || u.len() > 64
        || NOT_USERS.contains(&u.to_lowercase().as_str())
        || u.contains('%')
    {
        return None;
    }
    Some(u.to_string())
}

/// Extracts the user from the path component following `Users` / `Documents and Settings` / `home`.
fn user_after(components: &[&str], markers: &[&str]) -> Option<String> {
    for (i, c) in components.iter().enumerate() {
        if markers.iter().any(|m| c.eq_ignore_ascii_case(m)) {
            if let Some(u) = components.get(i + 1) {
                return valid_user(u);
            }
        }
    }
    None
}

fn valid_host(h: &str) -> Option<String> {
    let h = h.trim();
    if h.is_empty()
        || h.len() > 255
        || h == "."
        || h == "?"
        || h.chars().any(|c| c.is_whitespace() || c == '*')
    {
        return None;
    }
    Some(h.to_string())
}

/// Analyzes a path already extracted from text. Returns `None` if it does not look like an absolute path.
pub fn analyze_path(raw: &str) -> Option<PathInfo> {
    let s = raw.trim().trim_matches('"');
    if s.len() < 3 {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("file:") {
        let orig_rest = &s[5..];
        let after = orig_rest.trim_start_matches('/');
        let slashes = orig_rest.len() - after.len();
        let decoded = pct_decode(after);
        // file:///C:/x is local; file://server/share is UNC
        let b = decoded.as_bytes();
        let inner = if decoded.starts_with("\\\\") {
            decoded.clone()
        } else if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
            decoded.replace('/', "\\")
        } else if slashes == 2 || slashes == 4 || slashes == 5 {
            format!("\\\\{}", decoded.replace('/', "\\"))
        } else {
            format!("/{decoded}")
        };
        let mut info = analyze_path(&inner)?;
        info.path = s.to_string();
        info.kind = PathKind::FileUrl;
        return Some(info);
    }
    let b = s.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
    {
        let comps: Vec<&str> = s[3..]
            .split(['\\', '/'])
            .filter(|c| !c.is_empty())
            .collect();
        return Some(PathInfo {
            path: s.to_string(),
            kind: PathKind::Windows,
            user: user_after(&comps, &["Users", "Documents and Settings", "Profiles"]),
            host: None,
        });
    }
    if let Some(rest) = s.strip_prefix("\\\\").or_else(|| s.strip_prefix("//")) {
        if rest.starts_with('?') || rest.starts_with('.') {
            // \\?\C:\... and \\.\device
            let inner = rest.trim_start_matches(['?', '.']).trim_start_matches('\\');
            if inner.len() >= 3 {
                if let Some(mut i) = analyze_path(inner) {
                    i.path = s.to_string();
                    return Some(i);
                }
            }
            return None;
        }
        let comps: Vec<&str> = rest.split(['\\', '/']).filter(|c| !c.is_empty()).collect();
        let host = valid_host(comps.first()?)?;
        if !host
            .chars()
            .all(|c| c.is_alphanumeric() || "-_.$".contains(c))
        {
            return None;
        }
        return Some(PathInfo {
            path: s.to_string(),
            kind: PathKind::Unc,
            user: user_after(
                &comps[1..],
                &[
                    "Users",
                    "Documents and Settings",
                    "home",
                    "home$",
                    "profiles$",
                ],
            ),
            host: Some(host),
        });
    }
    if s.starts_with('/') && UNIX_ROOTS.iter().any(|r| s.starts_with(r)) || s == "/root" {
        let comps: Vec<&str> = s.split('/').filter(|c| !c.is_empty()).collect();
        let user = if comps.first() == Some(&"root") {
            Some("root".to_string())
        } else {
            user_after(&comps, &["home", "Users"])
        };
        return Some(PathInfo {
            path: s.to_string(),
            kind: PathKind::Unix,
            user,
            host: None,
        });
    }
    None
}

fn is_stop(c: char) -> bool {
    c.is_control() || matches!(c, '"' | '<' | '>' | '|' | '*' | '?' | ';' | '\'' | '`')
}

/// Trims trailing free text: `C:\a\file.txt for details` becomes `C:\a\file.txt`.
fn cut_tail(p: &str) -> &str {
    let mut end = p.len();
    // scan segments left to right: after "name.ext " the path has ended
    let mut seg_start = 0;
    for (i, c) in p.char_indices().chain(std::iter::once((p.len(), '\\'))) {
        if c == '\\' || c == '/' {
            let seg = &p[seg_start..i];
            let mut cut = None;
            for (dot, _) in seg.match_indices('.') {
                let ext_len = seg[dot + 1..]
                    .chars()
                    .take_while(char::is_ascii_alphanumeric)
                    .count();
                let after = dot + 1 + ext_len;
                let rest = &seg[after..];
                if (1..=5).contains(&ext_len)
                    && (rest.starts_with(' ')
                        || rest.starts_with(". ")
                        || rest.starts_with(", ")
                        || rest.starts_with(") "))
                {
                    cut = Some(seg_start + after);
                    break;
                }
            }
            if let Some(c) = cut {
                end = c;
                break;
            }
            seg_start = i + c.len_utf8();
        }
    }
    let mut p = &p[..end];
    // a double space or " http" ends the path
    for stop in ["  ", " http://", " https://"] {
        if let Some(i) = p.find(stop) {
            p = &p[..i];
        }
    }
    p.trim_end_matches([' ', '.', ',', ':', ')', ']', '}'])
}

/// Finds absolute paths in arbitrary text.
pub fn find_paths(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let n = chars.len();
    let mut i = 0;
    while i < n {
        let (pos, c) = chars[i];
        let prev = if i > 0 { Some(chars[i - 1].1) } else { None };
        let boundary = prev.is_none_or(|p| {
            !(p.is_alphanumeric() || p == ':' || p == '/' || p == '\\' || p == '.')
        });
        let rest = &text[pos..];
        let start = boundary
            && ((c.is_ascii_alphabetic()
                && rest.len() > 3
                && rest.as_bytes()[1] == b':'
                && (rest.as_bytes()[2] == b'\\' || rest.as_bytes()[2] == b'/')
                && rest
                    .as_bytes()
                    .get(3)
                    .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'/'))
                || (rest.starts_with("\\\\")
                    && rest[2..]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_alphanumeric()))
                || rest
                    .get(..5)
                    .is_some_and(|p| p.eq_ignore_ascii_case("file:"))
                || UNIX_ROOTS.iter().any(|r| rest.starts_with(r)));
        if start {
            let end = rest
                .char_indices()
                .find(|(_, c)| is_stop(*c))
                .map(|(j, _)| j)
                .unwrap_or(rest.len());
            // cap at 1024 bytes on a char boundary (a multi-byte char may straddle byte 1024)
            let cand = cut_tail(&rest[..crate::util::floor_char_boundary(rest, end.min(1024))]);
            if analyze_path(cand).is_some() && !out.iter().any(|x| x == cand) {
                out.push(cand.to_string());
            }
            let consumed = cand.chars().count().max(1);
            i += consumed;
            continue;
        }
        i += 1;
    }
    out
}

fn is_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "._%+-".contains(c)
}

/// Finds e-mail addresses in text; domains are lowercased.
pub fn find_emails(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (at, _) in text.match_indices('@') {
        let left = &text[..at];
        let lstart = left
            .char_indices()
            .rev()
            .take_while(|(_, c)| is_local_char(*c))
            .last()
            .map(|(i, _)| i);
        let Some(ls) = lstart else { continue };
        let local = left[ls..].trim_start_matches('.');
        let right = &text[at + 1..];
        let rend = right
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '.' || *c == '-'))
            .map(|(i, _)| i)
            .unwrap_or(right.len());
        let domain = right[..rend]
            .trim_end_matches(['.', '-'])
            .to_ascii_lowercase();
        let tld = domain.rsplit('.').next().unwrap_or("");
        if local.is_empty()
            || local.len() > 64
            || !domain.contains('.')
            || tld.len() < 2
            || !tld.chars().all(|c| c.is_ascii_alphabetic())
        {
            continue;
        }
        if domain.split('.').any(str::is_empty) {
            continue;
        }
        let e = format!("{local}@{domain}");
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

/// Adds one raw path (a PDB path, a source file, a share) with an explicit source label.
/// Returns `false` when the text is not a recognisable absolute path.
pub(crate) fn add_path(meta: &mut Metadata, raw: &str, source: &str) -> bool {
    let Some(info) = analyze_path(raw.trim()) else {
        return false;
    };
    if meta.paths.len() < 2000 && !meta.paths.iter().any(|x| x.path == info.path) {
        meta.paths.push(PathRef {
            path: info.path,
            kind: info.kind,
            user: info.user,
            host: info.host,
            source: source.to_string(),
        });
    }
    true
}

/// Post-processes metadata: paths and e-mail addresses from all text fields go to `paths` and
/// `emails`, users from paths to `people`, and UNC hosts to `servers`.
pub fn finalize(meta: &mut Metadata) {
    let mut sources: Vec<(String, String)> = Vec::new();
    let opt = [
        ("title", &meta.title),
        ("subject", &meta.subject),
        ("description", &meta.description),
        ("keywords", &meta.keywords),
        ("author", &meta.author),
        ("last_modified_by", &meta.last_modified_by),
        ("company", &meta.company),
        ("template", &meta.template),
        ("application", &meta.application),
        ("producer", &meta.producer),
        ("category", &meta.category),
    ];
    for (k, v) in opt {
        if let Some(v) = v {
            sources.push((k.to_string(), v.clone()));
        }
    }
    for (k, v) in meta
        .custom
        .iter()
        .chain(meta.fields.iter())
        .chain(meta.xmp.iter())
    {
        sources.push((k.clone(), v.clone()));
    }
    for l in &meta.links {
        sources.push(("link".into(), l.clone()));
    }
    for p in &meta.printers {
        sources.push(("printer".into(), p.clone()));
    }
    for c in &meta.comments {
        sources.push((c.source.clone(), c.text.clone()));
    }
    for r in &meta.revisions {
        sources.push(("revision".into(), r.text.clone()));
    }
    for o in &meta.old_versions {
        for (k, v) in &o.fields {
            sources.push((format!("old_version.{}.{k}", o.revision), v.clone()));
        }
    }
    for (src, text) in &sources {
        for p in find_paths(text) {
            if meta.paths.iter().any(|x| x.path == p) {
                continue;
            }
            if let Some(info) = analyze_path(&p) {
                meta.paths.push(PathRef {
                    path: info.path,
                    kind: info.kind,
                    user: info.user,
                    host: info.host,
                    source: src.clone(),
                });
            }
        }
        for e in find_emails(text) {
            Metadata::add_unique(&mut meta.emails, &e);
        }
    }
    let derived: Vec<(Option<String>, Option<String>, String)> = meta
        .paths
        .iter()
        .map(|p| (p.user.clone(), p.host.clone(), p.path.clone()))
        .collect();
    for (user, host, path) in derived {
        if let Some(u) = user {
            meta.add_person(&u, PersonRole::PathUser, &path);
        }
        if let Some(h) = host {
            meta.add_server(&h, "path");
        }
    }
    for p in meta
        .people
        .iter()
        .map(|p| p.name.clone())
        .collect::<Vec<_>>()
    {
        for e in find_emails(&p) {
            Metadata::add_unique(&mut meta.emails, &e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze() {
        let p = analyze_path(r"C:\Users\o.kovalenko\Documents\Звіти\2024").unwrap();
        assert_eq!(p.kind, PathKind::Windows);
        assert_eq!(p.user.as_deref(), Some("o.kovalenko"));
        let p = analyze_path(r"\\SRV-FILE01\buh$\Податкова").unwrap();
        assert_eq!(p.host.as_deref(), Some("SRV-FILE01"));
        assert_eq!(p.user, None);
        let p = analyze_path(r"\\NAS02\Users\ivan\x").unwrap();
        assert_eq!(p.user.as_deref(), Some("ivan"));
        let p = analyze_path("/Users/vtkachenko/Work/specs").unwrap();
        assert_eq!(p.user.as_deref(), Some("vtkachenko"));
        let p = analyze_path("/home/bob/x").unwrap();
        assert_eq!((p.kind, p.user.as_deref()), (PathKind::Unix, Some("bob")));
        let p =
            analyze_path("file:///C:/Users/Admin/AppData/Roaming/Microsoft/Templates/Normal.dotm")
                .unwrap();
        assert_eq!(
            (p.kind, p.user.as_deref()),
            (PathKind::FileUrl, Some("Admin"))
        );
        let p = analyze_path("file://SRV-FILE01/public/Шаблони/x.dotx").unwrap();
        assert_eq!(p.host.as_deref(), Some("SRV-FILE01"));
        let p = analyze_path(r"file:///\\SRV-FILE01\public\Шаблони\Договір.dotx").unwrap();
        assert_eq!(
            (p.kind, p.host.as_deref()),
            (PathKind::FileUrl, Some("SRV-FILE01"))
        );
        let p = analyze_path(r"C:\Documents and Settings\All Users\x").unwrap();
        assert_eq!(p.user, None);
        assert!(analyze_path("relative\\path").is_none());
        assert!(analyze_path("http://x/home/a").is_none());
    }

    #[test]
    fn find_in_text() {
        let t = r#"Saved to C:\Users\bob\Desktop\report final.docx for review; also \\FS01\share\a.xls and see /home/alice/x.txt. url http://h/home/zz"#;
        let p = find_paths(t);
        assert_eq!(
            p,
            vec![
                r"C:\Users\bob\Desktop\report final.docx",
                r"\\FS01\share\a.xls",
                "/home/alice/x.txt"
            ]
        );
        assert!(find_paths("ratio 3:1 and a:b").is_empty());
        assert_eq!(
            find_emails("mail: I.Petrenko@Contoso.EXAMPLE, x@y, a@b.c1"),
            vec!["I.Petrenko@contoso.example"]
        );
    }
}
