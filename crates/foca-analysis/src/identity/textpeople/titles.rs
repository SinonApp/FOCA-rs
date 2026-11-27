//! Positions, academic titles, degrees, units and signature blocks around a name.

use std::sync::OnceLock;

use regex::Regex;

use super::lang::{fold, registry, Script};

/// Context of one name: the whole text as lines, the line index and the parts of the line
/// before and after the name (cut at the neighbouring names).
pub struct Ctx<'a> {
    pub lines: &'a [&'a str],
    pub li: usize,
    pub before: &'a str,
    pub after: &'a str,
    /// The only name on its line.
    pub alone: bool,
}

fn re_degree() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)(?:^|[^\p{L}])([дк]\.\s?[а-яіїєґ]{1,9}\.\s?(?:[а-яіїєґ]{1,6}\.\s?)?н\.|ph\.?\s?d\.?|доктор філософії|доктор [а-яіїєґ]+ наук|кандидат [а-яіїєґ]+ наук)",
        )
        .expect("degree regex")
    })
}

fn re_unit() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)(?:^|[^\p{L}])(кафедр[аиіуою]{1,2}|кафедр[аыеуой]{1,2}|факультет[уіаом]{0,2}|навчально-наукового інституту|навчально-науковий інститут|інститут[уі]?|институт[ау]?|відділ[уіом]{0,2}|відділення|отдел[ауеом]{0,2}|лабораторі[яїюєю]{1,2}|лаборатори[яиюей]{1,2}|сектор[уі]?|центр[уі]?|деканат[уі]?|коледж[уі]?|управлінн[яі]|управлени[яе]|department of|dept\. of|faculty of|school of|division of|office of|institute of|abteilung|lehrstuhl für|lehrstuhl|institut für|fachbereich|département|service de|departamento de|facultad de|dipartimento di|facoltà di|katedra|wydział|zakład|instytut|ústav|fakulta|bölümü|fakültesi)\s+([^;:()\[\]\n]{3,90})",
        )
        .expect("unit regex")
    })
}

fn positions_in(s: &str) -> Vec<(usize, &'static str)> {
    let l = fold(s);
    let mut out: Vec<(usize, &'static str)> = Vec::new();
    let mut taken: Vec<(usize, usize)> = Vec::new();
    for t in &registry().titles {
        let pat = t.pat.as_str();
        if pat.is_empty() {
            continue;
        }
        let cjk = pat.chars().next().is_some_and(|c| {
            !matches!(
                Script::of(c),
                Script::Latin | Script::Cyrillic | Script::Other
            )
        });
        let mut from = 0;
        while let Some(i) = l[from..].find(pat) {
            let at = from + i;
            from = at + pat.len();
            let prev_ok = cjk
                || l[..at]
                    .chars()
                    .next_back()
                    .is_none_or(|c| !c.is_alphabetic());
            let next_ok = cjk
                || t.partial
                || pat.ends_with('.')
                || l[from..].chars().next().is_none_or(|c| !c.is_alphabetic());
            // A longer phrase already covers this position.
            let covered = taken.iter().any(|(a, b)| at < *b && *a < from);
            if prev_ok && next_ok && !covered {
                taken.push((at, from));
                out.push((at, t.label.as_str()));
            }
        }
    }
    out.sort();
    out
}

fn degrees_in(s: &str) -> Vec<String> {
    re_degree()
        .captures_iter(s)
        .filter_map(|c| c.get(1))
        .map(|m| {
            m.as_str()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join("")
                .to_lowercase()
        })
        .map(|d| {
            if d.starts_with("ph") {
                "PhD".to_string()
            } else {
                d
            }
        })
        .collect()
}

/// `true` for a short line that holds only a position (signature layouts put the position
/// on the line above the name).
fn title_line(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && t.chars().count() <= 90 && !positions_in(t).is_empty()
}

/// Position, academic title and degree: before the name on its line (closest first), right
/// after it as an apposition (`Петренко І.В., доцент`), or on the line above when the name
/// stands alone.
pub fn title(c: &Ctx) -> Option<String> {
    let before: String = {
        let n = c.before.chars().count();
        c.before.chars().skip(n.saturating_sub(90)).collect()
    };
    let after: String = c.after.chars().take(70).collect();
    let after_ok = {
        let a = after.trim_start();
        a.starts_with(',') || a.starts_with('–') || a.starts_with('-') || a.starts_with('(')
    };
    let mut parts: Vec<String> = Vec::new();
    let mut push = |p: String| {
        if !parts.contains(&p) && parts.len() < 3 {
            parts.push(p);
        }
    };
    let mut pos: Vec<&str> = positions_in(&before)
        .into_iter()
        .rev()
        .map(|(_, l)| l)
        .collect();
    if after_ok {
        pos.extend(positions_in(&after).into_iter().map(|(_, l)| l));
    }
    if pos.is_empty() && c.alone && c.before.trim().chars().count() <= 20 && c.li > 0 {
        let above = c.lines[c.li - 1];
        if title_line(above) {
            pos.extend(positions_in(above).into_iter().map(|(_, l)| l));
        }
    }
    for p in pos {
        push(p.to_string());
    }
    let mut degs = degrees_in(&before);
    if after_ok {
        degs.extend(degrees_in(&after));
    }
    for d in degs {
        push(d);
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

fn nominative_head(w: &str) -> String {
    let l = w.to_lowercase();
    if !l
        .chars()
        .next()
        .is_some_and(|c| Script::of(c) == Script::Cyrillic)
    {
        return w.to_string();
    }
    let head = if l.starts_with("кафедр") {
        "кафедра"
    } else if l.starts_with("факультет") {
        "факультет"
    } else if l.starts_with("навчально-наук") {
        "навчально-науковий інститут"
    } else if l.starts_with("інститут") {
        "інститут"
    } else if l.starts_with("відділення") {
        "відділення"
    } else if l.starts_with("відділ") {
        "відділ"
    } else if l.starts_with("лаборатор") {
        "лабораторія"
    } else if l.starts_with("сектор") {
        "сектор"
    } else if l.starts_with("центр") {
        "центр"
    } else if l.starts_with("деканат") {
        "деканат"
    } else if l.starts_with("коледж") {
        "коледж"
    } else {
        return l;
    };
    head.to_string()
}

/// Trims a unit tail at the first sign of the next clause and caps it at a few words.
fn unit_tail(s: &str) -> Option<String> {
    let mut end = s.len();
    for stop in [" – ", " - ", "\u{2014}", "  ", ". ", "____", "/"] {
        if let Some(i) = s.find(stop) {
            end = end.min(i);
        }
    }
    let t = &s[..end];
    let words: Vec<&str> = t.split_whitespace().take(9).collect();
    // A unit name is lowercase words (`кібербезпеки, інформаційних технологій`) or a quoted /
    // capitalised proper name; stop at the first capitalised word after the first one, which is
    // usually the person's name.
    let mut kept: Vec<&str> = Vec::new();
    for (i, w) in words.iter().enumerate() {
        let cap = w.chars().next().is_some_and(char::is_uppercase);
        let cyr = w
            .chars()
            .next()
            .is_some_and(|c| Script::of(c) == Script::Cyrillic);
        if i > 0 && cap && cyr && !w.starts_with('«') {
            break;
        }
        kept.push(w);
    }
    let out = kept
        .join(" ")
        .trim_end_matches(|c: char| !c.is_alphanumeric() && c != '»' && c != ')')
        .to_string();
    (out.chars().filter(|c| c.is_alphabetic()).count() >= 4).then_some(out)
}

fn unit_in(s: &str) -> Option<String> {
    let cap = re_unit().captures(s)?;
    let head = nominative_head(cap.get(1)?.as_str());
    let tail = unit_tail(cap.get(2)?.as_str())?;
    Some(format!("{head} {tail}"))
}

/// Unit: from the text before the name on its line (`завідувач кафедри цивільного права`),
/// the title line above, or the nearest unit heading within the previous lines.
pub fn unit(c: &Ctx) -> Option<String> {
    if let Some(u) = unit_in(c.before) {
        return Some(u);
    }
    if c.alone && c.li > 0 {
        let above = c.lines[c.li - 1];
        if title_line(above) {
            if let Some(u) = unit_in(above) {
                return Some(u);
            }
        }
    }
    // Nearest heading: a short line that starts with the unit word.
    for k in (c.li.saturating_sub(12)..c.li).rev() {
        let l = c.lines[k].trim();
        if l.is_empty() || l.chars().count() > 110 {
            continue;
        }
        let low = l.to_lowercase();
        if [
            "кафедра ",
            "факультет ",
            "навчально-науковий інститут",
            "відділ ",
            "отдел ",
            "лабораторія ",
            "центр ",
            "department of ",
            "faculty of ",
            "abteilung ",
            "lehrstuhl ",
            "institut für ",
            "département ",
            "departamento de ",
            "dipartimento di ",
            "wydział ",
            "katedra ",
        ]
        .iter()
        .any(|p| low.starts_with(p))
        {
            return unit_in(l);
        }
    }
    None
}

fn sig_marks(s: &str) -> bool {
    let l = s.to_lowercase();
    l.contains("___")
        || l.contains("(підпис")
        || l.contains("( підпис")
        || l.contains("підпис)")
        || l.contains("(подпись")
        || l.contains("м.п.")
        || l.contains("м. п.")
        || l.contains("(ініціали")
        || l.contains("(прізвище")
        || l.contains("(власне ім")
        || l.contains("(signature")
        || l.contains("signature:")
        || l.contains("unterschrift")
        || l.contains("подпись")
        || l.contains("podpis")
        || l.contains("firma:")
        || l.contains("签字")
        || l.contains("签名")
        || l.contains("署名")
        || l.contains("서명")
}

/// A signatory: the name sits in a signature block (underscores, `(підпис)`, `М.П.`, slashes
/// around the name) on its own line or right below the signature line.
pub fn signatory(c: &Ctx) -> bool {
    let line = c.lines[c.li];
    let slashed = c.before.trim_end().ends_with('/') && c.after.trim_start().starts_with('/');
    if slashed || sig_marks(line) {
        return true;
    }
    let near = |k: usize| {
        c.lines
            .get(k)
            .is_some_and(|l| sig_marks(l) && l.trim().chars().count() <= 90)
    };
    c.alone && (near(c.li + 1) || c.li > 0 && near(c.li - 1))
}
