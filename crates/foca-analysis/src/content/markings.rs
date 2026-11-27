//! Access restriction stamps in document text (`ДСК`, `ЦІЛКОМ ТАЄМНО`, `CONFIDENTIAL`,
//! `VS-NUR FÜR DEN DIENSTGEBRAUCH`, `DIFFUSION RESTREINTE`, …).
//!
//! A marking counts only when it is written as a stamp:
//!
//! * the whole trimmed line is the marking, optionally after «Гриф» / "Classification" and
//!   before a copy number («Прим. № 2», «Примірник № 1», "Copy No. 3", «Пункт 4»);
//! * the stamp starts with a capital letter (abbreviations such as `ДСК` must be all caps);
//! * the line sits at the top or bottom of the document or of a text block (page header or
//!   footer area), not in the middle of running text;
//! * a number or `№` right after the word (diploma series `ДСК № 119127`) or a lowercase word
//!   on the same line (a sentence that mentions the level) rejects it;
//! * a run of three or more different levels on adjacent lines is a list describing the
//!   levels, not a stamp (two lines such as «ЦІЛКОМ ТАЄМНО» + «ОСОБЛИВОЇ ВАЖЛИВОСТІ» are).
//!
//! State secret levels are rated High, «for official use» and commercial secret stamps Medium,
//! drafts Low.

use std::sync::OnceLock;

use foca_core::Severity;
use regex::Regex;

/// A stamp found in text: byte range of the line, normalised label and severity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    pub start: usize,
    pub end: usize,
    pub label: &'static str,
    pub sev: Severity,
}

/// How a stamp form must be written.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    /// First letter capital («Таємно», "Confidential", "TOP SECRET").
    Title,
    /// Every letter capital (`ДСК`, `ДСП`).
    Upper,
}

/// Normalised stamp form (lowercase, single spaces) → label, severity, case rule.
const FORMS: &[(&str, &str, Severity, Case)] = &[
    // UA
    (
        "особливої важливості",
        "Особливої важливості",
        Severity::High,
        Case::Title,
    ),
    (
        "цілком таємно",
        "Цілком таємно",
        Severity::High,
        Case::Title,
    ),
    ("таємно", "Таємно", Severity::High, Case::Title),
    (
        "для службового користування",
        "ДСК",
        Severity::Medium,
        Case::Title,
    ),
    ("дск", "ДСК", Severity::Medium, Case::Upper),
    (
        "комерційна таємниця",
        "Комерційна таємниця",
        Severity::Medium,
        Case::Title,
    ),
    (
        "конфіденційно",
        "Конфіденційно",
        Severity::Medium,
        Case::Title,
    ),
    ("чернетка", "Draft", Severity::Low, Case::Title),
    // RU
    (
        "особой важности",
        "Особливої важливості",
        Severity::High,
        Case::Title,
    ),
    (
        "совершенно секретно",
        "Цілком таємно",
        Severity::High,
        Case::Title,
    ),
    ("секретно", "Таємно", Severity::High, Case::Title),
    (
        "для служебного пользования",
        "ДСК",
        Severity::Medium,
        Case::Title,
    ),
    ("дсп", "ДСК", Severity::Medium, Case::Upper),
    (
        "коммерческая тайна",
        "Комерційна таємниця",
        Severity::Medium,
        Case::Title,
    ),
    (
        "конфиденциально",
        "Конфіденційно",
        Severity::Medium,
        Case::Title,
    ),
    ("черновик", "Draft", Severity::Low, Case::Title),
    // EN
    ("top secret", "Top Secret", Severity::High, Case::Title),
    ("secret", "Secret", Severity::High, Case::Title),
    (
        "strictly confidential",
        "Strictly Confidential",
        Severity::Medium,
        Case::Title,
    ),
    (
        "confidential",
        "Confidential",
        Severity::Medium,
        Case::Title,
    ),
    (
        "internal use only",
        "Internal Only",
        Severity::Medium,
        Case::Title,
    ),
    (
        "for internal use only",
        "Internal Only",
        Severity::Medium,
        Case::Title,
    ),
    (
        "internal only",
        "Internal Only",
        Severity::Medium,
        Case::Title,
    ),
    (
        "for official use only",
        "Internal Only",
        Severity::Medium,
        Case::Title,
    ),
    ("restricted", "Restricted", Severity::Medium, Case::Title),
    (
        "not for distribution",
        "Not for distribution",
        Severity::Medium,
        Case::Title,
    ),
    (
        "not for public distribution",
        "Not for distribution",
        Severity::Medium,
        Case::Title,
    ),
    ("draft", "Draft", Severity::Low, Case::Title),
    // DE
    ("streng geheim", "Top Secret", Severity::High, Case::Title),
    ("geheim", "Secret", Severity::High, Case::Title),
    (
        "vs-vertraulich",
        "Confidential",
        Severity::High,
        Case::Title,
    ),
    (
        "vs-nur für den dienstgebrauch",
        "VS-NfD",
        Severity::Medium,
        Case::Title,
    ),
    (
        "nur für den dienstgebrauch",
        "VS-NfD",
        Severity::Medium,
        Case::Title,
    ),
    ("vs-nfd", "VS-NfD", Severity::Medium, Case::Title),
    (
        "streng vertraulich",
        "Strictly Confidential",
        Severity::Medium,
        Case::Title,
    ),
    ("vertraulich", "Confidential", Severity::Medium, Case::Title),
    // FR
    ("très secret", "Top Secret", Severity::High, Case::Title),
    ("secret défense", "Secret", Severity::High, Case::Title),
    (
        "confidentiel défense",
        "Confidential",
        Severity::High,
        Case::Title,
    ),
    (
        "confidentiel",
        "Confidential",
        Severity::Medium,
        Case::Title,
    ),
    (
        "diffusion restreinte",
        "Diffusion restreinte",
        Severity::Medium,
        Case::Title,
    ),
];

/// Longest stamp line considered (characters); longer lines are prose.
const MAX_LINE_CHARS: usize = 90;
/// Lines from the edge of the document or of a text block that count as header/footer.
const EDGE_LINES: usize = 3;

fn re_prefix() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"^(?i:гриф(?:\s+(?:секретності|секретности|обмеження\s+доступу|ограничения\s+доступа|доступу|доступа))?|classification|einstufung)\s*[:\-]?\s*",
        )
        .expect("builtin marking regex")
    })
}

fn re_tail() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)[\s,.;]*(?:прим\.?|примірник|прим\.\s*№|экз\.?|экземпляр|пункт|п\.|літ\.?|лит\.?|copy(?:\s+no\.?)?|ex\.?|exemplaire|ausfertigung)\s*(?:№|no\.?|nr\.?)?\s*\d+[\p{L}\d/\-]*\s*\.?$",
        )
        .expect("builtin marking regex")
    })
}

/// Parses one trimmed line as a stamp: the label and severity.
fn parse_line(t: &str) -> Option<(&'static str, Severity)> {
    if t.is_empty() || t.chars().count() > MAX_LINE_CHARS || t.split_whitespace().count() > 8 {
        return None;
    }
    let mut s = re_prefix().find(t).map_or(t, |m| &t[m.end()..]);
    for _ in 0..3 {
        match re_tail().find(s) {
            Some(m) if m.start() > 0 => s = &s[..m.start()],
            _ => break,
        }
    }
    let s = s.trim_matches(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '«' | '»' | '"' | '\'' | '“' | '”' | '„' | '(' | ')' | '[' | ']'
            )
    });
    let s = s.trim_end_matches(['.', ':', ';', ',', '!']).trim();
    let norm = s
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" - ", "-")
        .to_lowercase();
    let (_, label, sev, case) = FORMS.iter().find(|f| f.0 == norm)?;
    let mut letters = s.chars().filter(|c| c.is_alphabetic());
    let ok = match case {
        Case::Upper => s
            .chars()
            .filter(|c| c.is_alphabetic())
            .all(char::is_uppercase),
        Case::Title => letters.next().is_some_and(char::is_uppercase),
    };
    ok.then_some((*label, *sev))
}

/// All stamps in `text`, one per label, in text order.
pub fn find(text: &str) -> Vec<Stamp> {
    // (byte start, trimmed line, block index, index in block); blank lines split blocks.
    let mut lines: Vec<(usize, &str, usize, usize)> = Vec::new();
    let mut block = 0;
    let mut at = 0;
    let mut in_block = 0;
    for raw in text.split('\n') {
        let t = raw.trim();
        if t.is_empty() {
            if in_block > 0 {
                block += 1;
            }
            in_block = 0;
        } else {
            let lead = raw.len() - raw.trim_start().len();
            lines.push((at + lead, t, block, in_block));
            in_block += 1;
        }
        at += raw.len() + 1;
    }
    let mut block_len = vec![0usize; block + 1];
    for l in &lines {
        block_len[l.2] += 1;
    }
    let parsed: Vec<Option<(&'static str, Severity)>> =
        lines.iter().map(|l| parse_line(l.1)).collect();
    let n = lines.len();
    // Runs of adjacent stamp lines with three or more different labels are level lists.
    let mut listed = vec![false; n];
    let mut i = 0;
    while i < n {
        let mut j = i;
        while j < n && parsed[j].is_some() {
            j += 1;
        }
        let mut distinct: Vec<&str> = parsed[i..j].iter().flatten().map(|p| p.0).collect();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() >= 3 {
            listed[i..j].iter_mut().for_each(|x| *x = true);
        }
        i = j.max(i + 1);
    }
    let mut out: Vec<Stamp> = Vec::new();
    for (i, p) in parsed.iter().enumerate() {
        let Some((label, sev)) = *p else { continue };
        let (start, t, b, k) = lines[i];
        let edge = i < EDGE_LINES
            || i + EDGE_LINES >= n
            || k < EDGE_LINES
            || k + EDGE_LINES >= block_len[b];
        // An all-caps abbreviation followed by a number on the next line is a series code.
        let series = t.chars().count() <= 3
            && lines
                .get(i + 1)
                .and_then(|l| l.1.chars().next())
                .is_some_and(|c| c == '№' || c.is_ascii_digit());
        if !edge || listed[i] || series || out.iter().any(|s| s.label == label) {
            continue;
        }
        out.push(Stamp {
            start,
            end: start + t.len(),
            label,
            sev,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(t: &str) -> Vec<&'static str> {
        find(t).into_iter().map(|s| s.label).collect()
    }

    const PROSE: &str = "Розділ 2. Загальні положення\nДокумент описує порядок роботи кафедри.\n";

    #[test]
    fn prose_and_series_codes_are_not_stamps() {
        let cases = [
            // Running prose that mentions a level.
            "у підлітковому віці спілкування з однолітками набуває особливої важливості для\nособистості.",
            "З огляду на курс реформ особливої важливості набуває\nпитання якості освіти.",
            "інформації з обмеженим доступом присвоюється гриф «для службового користування».",
            "відомості для підрозділу «цілком таємно»);\nта інших рівнів",
            // Diploma series.
            "Освіта: диплом спеціаліста ДСК № 100200, 2001 р.",
            "ДСК 100300,\nвиданий університетом",
            "диплом спеціаліста ДСК\n№ 100400",
            "спеціаліста ДСК ЕК № 100500",
            // Ordinary sentence and a lowercase stamp-like line.
            "3.5. Особові справи видаються для службового користування лише посадовим особам.",
            "Відомості становлять (комерційна таємниця).",
            "комерційна таємниця",
            "Стільниця ДСП 18 мм",
        ];
        for c in cases {
            assert!(labels(&format!("{PROSE}{c}\n{PROSE}")).is_empty(), "{c}");
        }
    }

    #[test]
    fn level_lists_are_not_stamps() {
        let t =
            "Рівні доступу:\nЦілком таємно\nТаємно\nДля службового користування\nкінець переліку";
        assert!(labels(t).is_empty());
    }

    #[test]
    fn stamps_in_five_languages() {
        let cases = [
            ("ДЛЯ СЛУЖБОВОГО КОРИСТУВАННЯ", "ДСК", Severity::Medium),
            ("Для службового користування", "ДСК", Severity::Medium),
            ("«Для службового користування»", "ДСК", Severity::Medium),
            ("ДСК", "ДСК", Severity::Medium),
            ("ДСК\nПримірник № 2", "ДСК", Severity::Medium),
            ("ЦІЛКОМ ТАЄМНО Прим. № 2", "Цілком таємно", Severity::High),
            ("ТАЄМНО", "Таємно", Severity::High),
            (
                "ОСОБЛИВОЇ ВАЖЛИВОСТІ",
                "Особливої важливості",
                Severity::High,
            ),
            ("Гриф: Конфіденційно", "Конфіденційно", Severity::Medium),
            (
                "Комерційна таємниця",
                "Комерційна таємниця",
                Severity::Medium,
            ),
            ("ДСП", "ДСК", Severity::Medium),
            ("Совершенно секретно", "Цілком таємно", Severity::High),
            ("Экз. № 1\nСЕКРЕТНО", "Таємно", Severity::High),
            ("CONFIDENTIAL", "Confidential", Severity::Medium),
            ("INTERNAL USE ONLY", "Internal Only", Severity::Medium),
            ("RESTRICTED", "Restricted", Severity::Medium),
            ("SECRET", "Secret", Severity::High),
            ("VERTRAULICH", "Confidential", Severity::Medium),
            ("VS-NUR FÜR DEN DIENSTGEBRAUCH", "VS-NfD", Severity::Medium),
            (
                "VS - Nur für den Dienstgebrauch",
                "VS-NfD",
                Severity::Medium,
            ),
            ("CONFIDENTIEL", "Confidential", Severity::Medium),
            (
                "DIFFUSION RESTREINTE",
                "Diffusion restreinte",
                Severity::Medium,
            ),
        ];
        for (stamp, label, sev) in cases {
            // Top of the document, before a long body.
            let body = "Текст документа.\n".repeat(20);
            let s = find(&format!("{stamp}\n{body}"));
            assert_eq!(s.len(), 1, "{stamp}");
            assert_eq!((s[0].label, s[0].sev), (label, sev), "{stamp}");
            // Footer of a page: last lines of a block.
            let s = find(&format!("{body}{stamp}\n\n{body}"));
            assert_eq!(s.len(), 1, "footer {stamp}");
        }
    }

    #[test]
    fn two_line_top_stamp_is_kept() {
        let t = format!(
            "ЦІЛКОМ ТАЄМНО\nОСОБЛИВОЇ ВАЖЛИВОСТІ\nПрим. № 1\n{}",
            "Текст.\n".repeat(9)
        );
        assert_eq!(labels(&t), ["Цілком таємно", "Особливої важливості"]);
        let t = format!("ДСК\n№ 100600\n{}", "Текст.\n".repeat(9));
        assert!(labels(&t).is_empty());
    }

    #[test]
    fn stamp_in_the_middle_of_a_block_is_ignored() {
        let body = "Текст документа.\n".repeat(10);
        assert!(labels(&format!("{body}ТАЄМНО\n{body}")).is_empty());
    }

    #[test]
    fn stamp_range_covers_the_line() {
        let t = "  ДСК  \nТекст";
        let s = &find(t)[0];
        assert_eq!(&t[s.start..s.end], "ДСК");
    }
}
