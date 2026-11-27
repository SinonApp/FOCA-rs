//! Glyph names and single-byte base encodings used by simple PDF fonts: WinAnsi, MacRoman and
//! Standard encodings, Adobe glyph names (`uniXXXX`, `uXXXX`, `afii100xx` Cyrillic, Latin
//! names) for `/Differences`.

/// Names of the printable ASCII glyphs, 0x20..=0x7E.
const ASCII_NAMES: [&str; 95] = [
    "space",
    "exclam",
    "quotedbl",
    "numbersign",
    "dollar",
    "percent",
    "ampersand",
    "quotesingle",
    "parenleft",
    "parenright",
    "asterisk",
    "plus",
    "comma",
    "hyphen",
    "period",
    "slash",
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "colon",
    "semicolon",
    "less",
    "equal",
    "greater",
    "question",
    "at",
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "bracketleft",
    "backslash",
    "bracketright",
    "asciicircum",
    "underscore",
    "grave",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "braceleft",
    "bar",
    "braceright",
    "asciitilde",
];

/// Names of the Latin-1 glyphs, 0xA1..=0xFF.
const LATIN1_NAMES: [&str; 95] = [
    "exclamdown",
    "cent",
    "sterling",
    "currency",
    "yen",
    "brokenbar",
    "section",
    "dieresis",
    "copyright",
    "ordfeminine",
    "guillemotleft",
    "logicalnot",
    "sfthyphen",
    "registered",
    "macron",
    "degree",
    "plusminus",
    "twosuperior",
    "threesuperior",
    "acute",
    "mu",
    "paragraph",
    "periodcentered",
    "cedilla",
    "onesuperior",
    "ordmasculine",
    "guillemotright",
    "onequarter",
    "onehalf",
    "threequarters",
    "questiondown",
    "Agrave",
    "Aacute",
    "Acircumflex",
    "Atilde",
    "Adieresis",
    "Aring",
    "AE",
    "Ccedilla",
    "Egrave",
    "Eacute",
    "Ecircumflex",
    "Edieresis",
    "Igrave",
    "Iacute",
    "Icircumflex",
    "Idieresis",
    "Eth",
    "Ntilde",
    "Ograve",
    "Oacute",
    "Ocircumflex",
    "Otilde",
    "Odieresis",
    "multiply",
    "Oslash",
    "Ugrave",
    "Uacute",
    "Ucircumflex",
    "Udieresis",
    "Yacute",
    "Thorn",
    "germandbls",
    "agrave",
    "aacute",
    "acircumflex",
    "atilde",
    "adieresis",
    "aring",
    "ae",
    "ccedilla",
    "egrave",
    "eacute",
    "ecircumflex",
    "edieresis",
    "igrave",
    "iacute",
    "icircumflex",
    "idieresis",
    "eth",
    "ntilde",
    "ograve",
    "oacute",
    "ocircumflex",
    "otilde",
    "odieresis",
    "divide",
    "oslash",
    "ugrave",
    "uacute",
    "ucircumflex",
    "udieresis",
    "yacute",
    "thorn",
    "ydieresis",
];

/// Other common glyph names.
const EXTRA_NAMES: &[(&str, char)] = &[
    ("Euro", '\u{20AC}'),
    ("Lslash", '\u{0141}'),
    ("OE", '\u{0152}'),
    ("Scaron", '\u{0160}'),
    ("Ydieresis", '\u{0178}'),
    ("Zcaron", '\u{017D}'),
    ("bullet", '\u{2022}'),
    ("caron", '\u{02C7}'),
    ("circumflex", '\u{02C6}'),
    ("dagger", '\u{2020}'),
    ("daggerdbl", '\u{2021}'),
    ("dotlessi", '\u{0131}'),
    ("ellipsis", '\u{2026}'),
    ("emdash", '\u{2014}'),
    ("endash", '\u{2013}'),
    ("fi", '\u{FB01}'),
    ("fl", '\u{FB02}'),
    ("florin", '\u{0192}'),
    ("fraction", '\u{2044}'),
    ("guilsinglleft", '\u{2039}'),
    ("guilsinglright", '\u{203A}'),
    ("lslash", '\u{0142}'),
    ("minus", '\u{2212}'),
    ("nbspace", '\u{00A0}'),
    ("oe", '\u{0153}'),
    ("perthousand", '\u{2030}'),
    ("quotedblbase", '\u{201E}'),
    ("quotedblleft", '\u{201C}'),
    ("quotedblright", '\u{201D}'),
    ("quoteleft", '\u{2018}'),
    ("quoteright", '\u{2019}'),
    ("quotesinglbase", '\u{201A}'),
    ("scaron", '\u{0161}'),
    ("tilde", '\u{02DC}'),
    ("trademark", '\u{2122}'),
    ("zcaron", '\u{017E}'),
    ("afii61352", '\u{2116}'),
    ("afii00208", '\u{2015}'),
    ("ring", '\u{02DA}'),
    ("breve", '\u{02D8}'),
    ("dotaccent", '\u{02D9}'),
    ("hungarumlaut", '\u{02DD}'),
    ("ogonek", '\u{02DB}'),
];

/// Cyrillic `afii100xx` glyph names outside the contiguous alphabet ranges.
const AFII_EXTRA: &[(u32, u32)] = &[
    (10023, 0x0401),
    (10050, 0x0490),
    (10051, 0x0402),
    (10052, 0x0403),
    (10053, 0x0404),
    (10054, 0x0405),
    (10055, 0x0406),
    (10056, 0x0407),
    (10057, 0x0408),
    (10058, 0x0409),
    (10059, 0x040A),
    (10060, 0x040B),
    (10061, 0x040C),
    (10062, 0x040E),
    (10071, 0x0451),
    (10098, 0x0491),
    (10099, 0x0452),
    (10100, 0x0453),
    (10101, 0x0454),
    (10102, 0x0455),
    (10103, 0x0456),
    (10104, 0x0457),
    (10105, 0x0458),
    (10106, 0x0459),
    (10107, 0x045A),
    (10108, 0x045B),
    (10109, 0x045C),
    (10110, 0x045E),
    (10145, 0x040F),
    (10193, 0x045F),
];

fn afii(n: u32) -> Option<char> {
    let cp = match n {
        10017..=10022 => 0x0410 + (n - 10017),
        10024..=10049 => 0x0416 + (n - 10024),
        10065..=10070 => 0x0430 + (n - 10065),
        10072..=10097 => 0x0436 + (n - 10072),
        _ => AFII_EXTRA.iter().find(|(a, _)| *a == n)?.1,
    };
    char::from_u32(cp)
}

fn hex_char(h: &str) -> Option<char> {
    char::from_u32(u32::from_str_radix(h, 16).ok()?)
}

/// Maps a glyph name to text. Ligature names (`f_i`) and `uniXXXXYYYY` sequences may give
/// several characters; suffixes such as `.sc` or `.alt` are ignored.
pub(crate) fn glyph_text(name: &str) -> Option<String> {
    let base = name.split('.').next().unwrap_or(name);
    if base.is_empty() {
        return None;
    }
    if base.contains('_') {
        let parts: Option<String> = base.split('_').map(glyph_text).collect();
        return parts.filter(|s| !s.is_empty());
    }
    if let Some(h) = base.strip_prefix("uni") {
        if h.len() >= 4 && h.len().is_multiple_of(4) && h.bytes().all(|c| c.is_ascii_hexdigit()) {
            let units: Vec<u16> = h
                .as_bytes()
                .chunks(4)
                .filter_map(|c| u16::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
                .collect();
            return Some(String::from_utf16_lossy(&units));
        }
    }
    if let Some(h) = base.strip_prefix('u') {
        if (4..=6).contains(&h.len()) && h.bytes().all(|c| c.is_ascii_hexdigit()) {
            return hex_char(h).map(String::from);
        }
    }
    if let Some(n) = base.strip_prefix("afii") {
        if let Some(c) = n.parse::<u32>().ok().and_then(afii) {
            return Some(c.to_string());
        }
    }
    if let Some(i) = ASCII_NAMES.iter().position(|n| *n == base) {
        return char::from_u32(0x20 + i as u32).map(String::from);
    }
    if let Some(i) = LATIN1_NAMES.iter().position(|n| *n == base) {
        return char::from_u32(0xA1 + i as u32).map(String::from);
    }
    if let Some((_, c)) = EXTRA_NAMES.iter().find(|(n, _)| *n == base) {
        return Some(c.to_string());
    }
    // `g123` / `cid123` / `glyph12` are glyph indices without a meaning
    None
}

/// Single-byte base encodings of simple fonts.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum BaseEncoding {
    WinAnsi,
    MacRoman,
    Standard,
}

impl BaseEncoding {
    pub(crate) fn from_name(n: &str) -> Option<BaseEncoding> {
        match n {
            "WinAnsiEncoding" => Some(BaseEncoding::WinAnsi),
            "MacRomanEncoding" | "MacExpertEncoding" => Some(BaseEncoding::MacRoman),
            "StandardEncoding" => Some(BaseEncoding::Standard),
            _ => None,
        }
    }

    /// The character of code `c`, or `None` for unassigned codes.
    pub(crate) fn char_of(self, c: u8) -> Option<char> {
        match self {
            BaseEncoding::WinAnsi => {
                let s = crate::util::decode_codepage(&[c], 1252);
                s.chars().next().filter(|ch| !ch.is_control())
            }
            BaseEncoding::MacRoman => {
                if c < 0x80 {
                    Some(c as char).filter(|ch| !ch.is_control())
                } else {
                    crate::formats::media::isobmff::MAC_ROMAN
                        .chars()
                        .nth(usize::from(c - 0x80))
                }
            }
            BaseEncoding::Standard => match c {
                0x27 => Some('\u{2019}'),
                0x60 => Some('\u{2018}'),
                0x20..=0x7E => Some(c as char),
                _ => STANDARD_HIGH
                    .iter()
                    .find(|(k, _)| *k == c)
                    .map(|(_, ch)| *ch),
            },
        }
    }
}

/// StandardEncoding above 0x7F.
const STANDARD_HIGH: &[(u8, char)] = &[
    (0xA1, '¡'),
    (0xA2, '¢'),
    (0xA3, '£'),
    (0xA4, '\u{2044}'),
    (0xA5, '¥'),
    (0xA6, 'ƒ'),
    (0xA7, '§'),
    (0xA8, '¤'),
    (0xA9, '\''),
    (0xAA, '\u{201C}'),
    (0xAB, '«'),
    (0xAC, '\u{2039}'),
    (0xAD, '\u{203A}'),
    (0xAE, '\u{FB01}'),
    (0xAF, '\u{FB02}'),
    (0xB1, '\u{2013}'),
    (0xB2, '\u{2020}'),
    (0xB3, '\u{2021}'),
    (0xB4, '·'),
    (0xB6, '¶'),
    (0xB7, '\u{2022}'),
    (0xB8, '\u{201A}'),
    (0xB9, '\u{201E}'),
    (0xBA, '\u{201D}'),
    (0xBB, '»'),
    (0xBC, '\u{2026}'),
    (0xBD, '\u{2030}'),
    (0xBF, '¿'),
    (0xC1, '`'),
    (0xC2, '´'),
    (0xC3, '\u{02C6}'),
    (0xC4, '\u{02DC}'),
    (0xC5, '¯'),
    (0xC6, '\u{02D8}'),
    (0xC7, '\u{02D9}'),
    (0xC8, '¨'),
    (0xCA, '\u{02DA}'),
    (0xCB, '¸'),
    (0xCD, '\u{02DD}'),
    (0xCE, '\u{02DB}'),
    (0xCF, '\u{02C7}'),
    (0xD0, '\u{2014}'),
    (0xE1, 'Æ'),
    (0xE3, 'ª'),
    (0xE8, 'Ł'),
    (0xE9, 'Ø'),
    (0xEA, 'Œ'),
    (0xEB, 'º'),
    (0xF1, 'æ'),
    (0xF5, 'ı'),
    (0xF8, 'ł'),
    (0xF9, 'ø'),
    (0xFA, 'œ'),
    (0xFB, 'ß'),
];

/// Expands typographic ligatures (`ﬁ` to `fi`) so words stay searchable.
pub(crate) fn expand_ligature(c: char) -> Option<&'static str> {
    Some(match c {
        '\u{FB00}' => "ff",
        '\u{FB01}' => "fi",
        '\u{FB02}' => "fl",
        '\u{FB03}' => "ffi",
        '\u{FB04}' => "ffl",
        '\u{FB05}' | '\u{FB06}' => "st",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glyph_names() {
        assert_eq!(glyph_text("A").as_deref(), Some("A"));
        assert_eq!(glyph_text("space").as_deref(), Some(" "));
        assert_eq!(glyph_text("uni0416").as_deref(), Some("Ж"));
        assert_eq!(glyph_text("uni00660069").as_deref(), Some("fi"));
        assert_eq!(glyph_text("u1F600").as_deref(), Some("\u{1F600}"));
        assert_eq!(glyph_text("afii10017").as_deref(), Some("А"));
        assert_eq!(glyph_text("afii10049").as_deref(), Some("Я"));
        assert_eq!(glyph_text("afii10023").as_deref(), Some("Ё"));
        assert_eq!(glyph_text("afii10065").as_deref(), Some("а"));
        assert_eq!(glyph_text("afii10097").as_deref(), Some("я"));
        assert_eq!(glyph_text("afii10103").as_deref(), Some("і"));
        assert_eq!(glyph_text("afii10050").as_deref(), Some("Ґ"));
        assert_eq!(glyph_text("eacute").as_deref(), Some("é"));
        assert_eq!(glyph_text("f_i").as_deref(), Some("fi"));
        assert_eq!(glyph_text("a.sc").as_deref(), Some("a"));
        assert_eq!(glyph_text("g123"), None);
        assert_eq!(glyph_text(""), None);
    }

    #[test]
    fn base_encodings() {
        assert_eq!(BaseEncoding::WinAnsi.char_of(0x93), Some('\u{201C}'));
        assert_eq!(BaseEncoding::WinAnsi.char_of(b'A'), Some('A'));
        assert_eq!(BaseEncoding::MacRoman.char_of(0x80), Some('Ä'));
        assert_eq!(BaseEncoding::Standard.char_of(0x27), Some('\u{2019}'));
        assert_eq!(BaseEncoding::Standard.char_of(0xE8), Some('Ł'));
        assert_eq!(BaseEncoding::Standard.char_of(0x90), None);
    }
}
