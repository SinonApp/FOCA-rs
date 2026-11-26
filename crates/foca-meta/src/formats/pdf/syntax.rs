//! PDF object syntax: the object model, the tokenizer/parser for objects and content-stream
//! operands, and string decoding. Shared by document parsing, redaction scanning and cleaning.

use crate::util::{utf16be, utf16le};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Obj {
    Null,
    Bool(bool),
    Num(f64),
    Str(Vec<u8>),
    Name(String),
    Arr(Vec<Obj>),
    Dict(Dict),
    Ref(u32, u16),
    /// Stream dictionary and the raw data range in the source buffer.
    Stream(Dict, usize, usize),
    Kw(String),
}

pub(crate) type Dict = Vec<(String, Obj)>;

pub(crate) fn dget<'a>(d: &'a Dict, k: &str) -> Option<&'a Obj> {
    d.iter().find(|(key, _)| key == k).map(|(_, v)| v)
}

pub(crate) fn dname<'a>(d: &'a Dict, k: &str) -> Option<&'a str> {
    match dget(d, k) {
        Some(Obj::Name(n)) => Some(n.as_str()),
        _ => None,
    }
}

impl Obj {
    pub(crate) fn dict(&self) -> Option<&Dict> {
        match self {
            Obj::Dict(d) | Obj::Stream(d, _, _) => Some(d),
            _ => None,
        }
    }
    pub(crate) fn num(&self) -> Option<f64> {
        match self {
            Obj::Num(n) => Some(*n),
            _ => None,
        }
    }
}

pub(crate) fn is_ws(c: u8) -> bool {
    matches!(c, 0 | 9 | 10 | 12 | 13 | 32)
}

pub(crate) fn is_delim(c: u8) -> bool {
    matches!(
        c,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

pub(crate) struct Lex<'a> {
    b: &'a [u8],
    p: usize,
    max_depth: usize,
}

impl<'a> Lex<'a> {
    pub(crate) fn new(b: &'a [u8], p: usize, max_depth: usize) -> Self {
        Lex { b, p, max_depth }
    }

    /// Returns `true` once the whole input has been consumed.
    pub(crate) fn at_end(&self) -> bool {
        self.p >= self.b.len()
    }

    /// After a stream dictionary: if the `stream` keyword follows, returns the offset where
    /// the stream data starts (past the end-of-line marker). Otherwise the position is left
    /// unchanged.
    pub(crate) fn stream_data_start(&mut self) -> Option<usize> {
        let save = self.p;
        self.skip_ws();
        if self.b.get(self.p..self.p + 6) != Some(b"stream") {
            self.p = save;
            return None;
        }
        let mut s = self.p + 6;
        if self.b.get(s) == Some(&b'\r') {
            s += 1;
        }
        if self.b.get(s) == Some(&b'\n') {
            s += 1;
        }
        Some(s)
    }

    /// After the `ID` operator of a content stream: skips the inline image data up to and
    /// including the `EI` operator (which must be preceded by whitespace).
    pub(crate) fn skip_inline_image(&mut self) {
        let data = self.b;
        let mut i = self.p;
        while i + 2 <= data.len() {
            if data.get(i..i + 2) == Some(b"EI")
                && i > 0
                && data.get(i - 1).is_some_and(|c| c.is_ascii_whitespace())
                && data.get(i + 2).is_none_or(|c| c.is_ascii_whitespace())
            {
                break;
            }
            i += 1;
        }
        self.p = (i + 2).min(data.len());
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.p).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if is_ws(c) {
                self.p += 1;
            } else if c == b'%' {
                while let Some(c) = self.peek() {
                    if c == b'\n' || c == b'\r' {
                        break;
                    }
                    self.p += 1;
                }
            } else {
                break;
            }
        }
    }

    fn token_end(&self, from: usize) -> usize {
        let mut i = from;
        while let Some(&c) = self.b.get(i) {
            if is_ws(c) || is_delim(c) {
                break;
            }
            i += 1;
        }
        i
    }

    pub(crate) fn parse(&mut self, depth: usize) -> Option<Obj> {
        if depth > self.max_depth {
            return None;
        }
        self.skip_ws();
        let c = self.peek()?;
        match c {
            b'/' => {
                let end = self.token_end(self.p + 1);
                let raw = self.b.get(self.p + 1..end)?;
                self.p = end;
                Some(Obj::Name(decode_name(raw)))
            }
            b'(' => self.literal().map(Obj::Str),
            b'<' => {
                if self.b.get(self.p + 1) == Some(&b'<') {
                    self.p += 2;
                    self.dict(depth).map(Obj::Dict)
                } else {
                    self.hex().map(Obj::Str)
                }
            }
            b'[' => {
                self.p += 1;
                let mut v = Vec::new();
                loop {
                    self.skip_ws();
                    match self.peek() {
                        None => break,
                        Some(b']') => {
                            self.p += 1;
                            break;
                        }
                        _ => {
                            let before = self.p;
                            match self.parse(depth + 1) {
                                Some(o) => v.push(o),
                                None => {
                                    if self.p == before {
                                        self.p += 1;
                                    }
                                    if depth + 1 > self.max_depth {
                                        return None;
                                    }
                                }
                            }
                        }
                    }
                    if v.len() > 1_000_000 {
                        break;
                    }
                }
                Some(Obj::Arr(v))
            }
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                let end = self.token_end(self.p);
                let s = std::str::from_utf8(self.b.get(self.p..end)?).ok()?;
                self.p = end.max(self.p + 1);
                let n: f64 = s.parse().unwrap_or(0.0);
                // N G R ?
                if s.bytes().all(|b| b.is_ascii_digit()) {
                    let save = self.p;
                    self.skip_ws();
                    let ge = self.token_end(self.p);
                    if let Some(g) = self
                        .b
                        .get(self.p..ge)
                        .filter(|g| !g.is_empty() && g.iter().all(u8::is_ascii_digit))
                    {
                        let g: Option<u16> =
                            std::str::from_utf8(g).ok().and_then(|g| g.parse().ok());
                        self.p = ge;
                        self.skip_ws();
                        if self.peek() == Some(b'R')
                            && self
                                .b
                                .get(self.p + 1)
                                .is_none_or(|&c| is_ws(c) || is_delim(c))
                        {
                            if let (Ok(num), Some(g)) = (s.parse::<u32>(), g) {
                                self.p += 1;
                                return Some(Obj::Ref(num, g));
                            }
                        }
                    }
                    self.p = save;
                }
                Some(Obj::Num(n))
            }
            b')' | b'>' | b']' | b'}' | b'{' => {
                self.p += 1;
                Some(Obj::Kw((c as char).to_string()))
            }
            _ => {
                let end = self.token_end(self.p).max(self.p + 1);
                let kw = String::from_utf8_lossy(self.b.get(self.p..end)?).into_owned();
                self.p = end;
                Some(match kw.as_str() {
                    "true" => Obj::Bool(true),
                    "false" => Obj::Bool(false),
                    "null" => Obj::Null,
                    _ => Obj::Kw(kw),
                })
            }
        }
    }

    fn dict(&mut self, depth: usize) -> Option<Dict> {
        let mut d = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                None => break,
                Some(b'>') => {
                    self.p += if self.b.get(self.p + 1) == Some(&b'>') {
                        2
                    } else {
                        1
                    };
                    break;
                }
                _ => {}
            }
            let before = self.p;
            let key = match self.parse(depth + 1) {
                Some(Obj::Name(k)) => k,
                Some(Obj::Kw(k)) if k == "endobj" || k == "stream" => {
                    self.p = before;
                    break;
                }
                Some(_) => continue,
                None => {
                    if self.p == before {
                        self.p += 1;
                    }
                    if depth + 1 > self.max_depth {
                        return None;
                    }
                    continue;
                }
            };
            self.skip_ws();
            if self.peek() == Some(b'>') {
                d.push((key, Obj::Null));
                continue;
            }
            let val = self.parse(depth + 1).unwrap_or(Obj::Null);
            d.push((key, val));
            if d.len() > 100_000 {
                break;
            }
        }
        Some(d)
    }

    fn literal(&mut self) -> Option<Vec<u8>> {
        self.p += 1;
        let mut out = Vec::new();
        let mut lvl = 1usize;
        while let Some(c) = self.peek() {
            self.p += 1;
            match c {
                b'\\' => {
                    let Some(e) = self.peek() else { break };
                    self.p += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.p += 1;
                            }
                        }
                        b'\n' => {}
                        b'0'..=b'7' => {
                            let mut v = u32::from(e - b'0');
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        v = v * 8 + u32::from(d - b'0');
                                        self.p += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push((v & 0xFF) as u8);
                        }
                        other => out.push(other),
                    }
                }
                b'(' => {
                    lvl += 1;
                    out.push(c);
                }
                b')' => {
                    lvl -= 1;
                    if lvl == 0 {
                        break;
                    }
                    out.push(c);
                }
                _ => out.push(c),
            }
        }
        Some(out)
    }

    fn hex(&mut self) -> Option<Vec<u8>> {
        self.p += 1;
        let mut out = Vec::new();
        let mut hi: Option<u8> = None;
        while let Some(c) = self.peek() {
            self.p += 1;
            if c == b'>' {
                break;
            }
            let v = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => continue,
            };
            match hi.take() {
                Some(h) => out.push(h << 4 | v),
                None => hi = Some(v),
            }
        }
        if let Some(h) = hi {
            out.push(h << 4);
        }
        Some(out)
    }
}

fn decode_name(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#' {
            let h = raw.get(i + 1).and_then(|c| (*c as char).to_digit(16));
            let l = raw.get(i + 2).and_then(|c| (*c as char).to_digit(16));
            if let (Some(h), Some(l)) = (h, l) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const PDFDOC_80: [u16; 33] = [
    0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x0192, 0x2044, 0x2039, 0x203A, 0x2212, 0x2030,
    0x201E, 0x201C, 0x201D, 0x2018, 0x2019, 0x201A, 0x2122, 0xFB01, 0xFB02, 0x0141, 0x0152, 0x0160,
    0x0178, 0x017D, 0x0131, 0x0142, 0x0153, 0x0161, 0x017E, 0xFFFD, 0x20AC,
];

/// Decodes a PDF string to text (UTF-16 with BOM, UTF-8, PDFDocEncoding).
pub(crate) fn pdf_str(b: &[u8]) -> String {
    if let Some(r) = b.strip_prefix(&[0xFE, 0xFF]) {
        return utf16be(r);
    }
    if let Some(r) = b.strip_prefix(&[0xFF, 0xFE]) {
        return utf16le(r);
    }
    if let Some(r) = b.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(r).into_owned();
    }
    if b.iter().any(|&c| c >= 0x80) {
        if let Ok(s) = std::str::from_utf8(b) {
            return s.to_string();
        }
    }
    b.iter()
        .map(|&c| match c {
            0x80..=0xA0 => {
                char::from_u32(u32::from(PDFDOC_80[usize::from(c - 0x80)])).unwrap_or('\u{FFFD}')
            }
            _ => c as char,
        })
        .collect()
}

/// Decodes a content stream string: UTF-16BE if it looks like it, otherwise PDFDocEncoding; non-printable characters are dropped.
pub(crate) fn content_str(s: &[u8]) -> String {
    let zeros = s.iter().step_by(2).filter(|&&c| c == 0).count();
    let t = if s.len() >= 2 && zeros * 2 >= s.len() / 2 {
        utf16be(s)
    } else {
        pdf_str(s)
    };
    t.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexer() {
        let mut l = Lex::new(
            b"<< /A (x\\(y\\)\\101) /B [1 0 R 2.5 <414243>] /C /N#20m >>",
            0,
            16,
        );
        let o = l.parse(0).unwrap();
        let d = o.dict().unwrap();
        assert_eq!(dget(d, "A"), Some(&Obj::Str(b"x(y)A".to_vec())));
        assert_eq!(
            dget(d, "B"),
            Some(&Obj::Arr(vec![
                Obj::Ref(1, 0),
                Obj::Num(2.5),
                Obj::Str(b"ABC".to_vec())
            ]))
        );
        assert_eq!(dget(d, "C"), Some(&Obj::Name("N m".into())));
        // deep nesting must not overflow the stack
        let deep = "[".repeat(10_000);
        let _ = Lex::new(deep.as_bytes(), 0, 64).parse(0);
        assert_eq!(pdf_str(&[0xFE, 0xFF, 0x04, 0x1F]), "П");
    }
}
