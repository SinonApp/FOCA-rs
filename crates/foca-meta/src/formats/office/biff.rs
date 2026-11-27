//! Excel 97-2003 workbook stream (BIFF8, and BIFF5/7 strings through the CODEPAGE record):
//! cell text and selected numbers, shared strings, sheet and defined names, external
//! workbook paths, hyperlinks, comments with their authors, data validation lists, hidden
//! sheets, rows and columns, last saved by and the password protection flag.
//!
//! Record layouts follow MS-XLS; the string pool rules (CONTINUE splits with a fresh flag
//! byte) follow Apache POI HSSF `SSTDeserializer` and calamine (MIT).

use std::collections::HashMap;

use foca_core::{CommentRef, HiddenContent, Metadata, PersonRole};

use crate::util::{clean_str, decode_codepage, rd_u16le, rd_u32le, truncate, utf16le};

/// Characters of workbook text kept.
const MAX_TEXT: usize = 16 << 20;
/// Numeric cells looked at (first two sheets only): huge price lists would only bloat the
/// text index, and only long integers (IDs, phones, card and account numbers) matter there.
const MAX_NUMBERS: usize = 20_000;
const NUMBER_SHEETS: usize = 2;
const MAX_RECORDS: usize = 2_000_000;
const MAX_HIDDEN: usize = 500;

/// One record: type, stream offset and data.
struct Rec<'a> {
    ty: u16,
    off: usize,
    data: &'a [u8],
}

fn records(wb: &[u8]) -> Vec<Rec<'_>> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while let (Some(ty), Some(len)) = (rd_u16le(wb, p), rd_u16le(wb, p + 2)) {
        let len = usize::from(len);
        let Some(data) = wb.get(p + 4..p + 4 + len) else {
            break;
        };
        out.push(Rec { ty, off: p, data });
        p += 4 + len;
        if out.len() >= MAX_RECORDS {
            break;
        }
    }
    out
}

/// Reads across a record and its CONTINUE records. A string that crosses a boundary gets a
/// new option byte (high-byte flag) at the start of the next segment.
struct Segs<'a> {
    segs: Vec<&'a [u8]>,
    i: usize,
    p: usize,
}

impl<'a> Segs<'a> {
    fn new(segs: Vec<&'a [u8]>) -> Self {
        Segs { segs, i: 0, p: 0 }
    }

    fn cur(&mut self) -> Option<&'a [u8]> {
        while self.i < self.segs.len() && self.p >= self.segs[self.i].len() {
            self.i += 1;
            self.p = 0;
        }
        self.segs.get(self.i).copied()
    }

    fn u8(&mut self) -> Option<u8> {
        let s = self.cur()?;
        let v = s[self.p];
        self.p += 1;
        Some(v)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from(self.u8()?) | u16::from(self.u8()?) << 8)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from(self.u16()?) | u32::from(self.u16()?) << 16)
    }

    fn skip(&mut self, mut n: usize) -> Option<()> {
        while n > 0 {
            let s = self.cur()?;
            let k = (s.len() - self.p).min(n);
            self.p += k;
            n -= k;
        }
        Some(())
    }

    /// `cch` characters starting in compressed (Latin-1) or UTF-16 form.
    fn chars(&mut self, cch: usize, mut hi: bool) -> Option<String> {
        let mut out = String::new();
        let mut left = cch;
        // a split inside the characters (also right after the header) restarts the next
        // segment with an option byte
        let mut seg = self.i;
        while left > 0 {
            let s = self.cur()?;
            if self.i != seg && self.p == 0 {
                seg = self.i;
                hi = s[0] & 1 != 0;
                self.p = 1;
                continue;
            }
            let avail = s.len() - self.p;
            let w = if hi { 2 } else { 1 };
            let n = (avail / w).min(left);
            if n == 0 {
                self.p = s.len();
                continue;
            }
            let raw = &s[self.p..self.p + n * w];
            if hi {
                out.push_str(&utf16le(raw));
            } else {
                out.extend(raw.iter().map(|&c| c as char));
            }
            self.p += n * w;
            left -= n;
        }
        Some(out)
    }

    /// XLUnicodeRichExtendedString (SST item).
    fn rich_string(&mut self) -> Option<String> {
        let cch = usize::from(self.u16()?);
        let flags = self.u8()?;
        let runs = if flags & 0x08 != 0 { self.u16()? } else { 0 };
        let ext = if flags & 0x04 != 0 { self.u32()? } else { 0 };
        let s = self.chars(cch, flags & 1 != 0)?;
        self.skip(usize::from(runs) * 4)?;
        self.skip(ext as usize)?;
        Some(s)
    }
}

/// XLUnicodeString (u16 cch, flags, chars) in BIFF8, or a byte string in the code page for
/// BIFF5/7. Returns the string and the bytes consumed.
fn xl_string(d: &[u8], off: usize, biff8: bool, cp: u16) -> Option<(String, usize)> {
    let cch = usize::from(rd_u16le(d, off)?);
    if !biff8 {
        let raw = d.get(off + 2..off + 2 + cch)?;
        return Some((decode_codepage(raw, cp), 2 + cch));
    }
    let flags = *d.get(off + 2)?;
    let (s, n) = short_chars(d, off + 3, cch, flags)?;
    Some((s, 3 + n))
}

/// Characters after a flags byte (`fHighByte`, ignoring rich/ext parts).
fn short_chars(d: &[u8], off: usize, cch: usize, flags: u8) -> Option<(String, usize)> {
    if flags & 1 != 0 {
        let raw = d.get(off..off + cch * 2)?;
        Some((utf16le(raw), cch * 2))
    } else {
        let raw = d.get(off..off + cch)?;
        Some((raw.iter().map(|&c| c as char).collect(), cch))
    }
}

/// Value of an RK number.
pub(crate) fn rk_value(rk: u32) -> f64 {
    let v = if rk & 2 != 0 {
        f64::from((rk as i32) >> 2)
    } else {
        f64::from_bits(u64::from(rk & 0xFFFF_FFFC) << 32)
    };
    if rk & 1 != 0 {
        v / 100.0
    } else {
        v
    }
}

/// Keeps integers of 6 to 19 digits (identifiers, phone, card and account numbers); amounts,
/// dates and small counters are dropped.
pub(crate) fn interesting_number(v: f64) -> Option<String> {
    if !v.is_finite() || v.fract() != 0.0 {
        return None;
    }
    let a = v.abs();
    if !(100_000.0..1e19).contains(&a) {
        return None;
    }
    Some(format!("{}", v as i64))
}

/// External workbook path of a SUPBOOK record (MS-XLS VirtualPath encoding).
fn virt_path(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    if it.peek() != Some(&'\u{1}') {
        return s.to_string();
    }
    it.next();
    while let Some(c) = it.next() {
        match c {
            '\u{1}' => match it.next() {
                Some('@') => out.push_str("\\\\"),
                Some(v) => {
                    out.push(v);
                    out.push_str(":\\");
                }
                None => {}
            },
            '\u{2}' | '\u{3}' => out.push('\\'),
            '\u{4}' => out.push_str("..\\"),
            '\u{5}' => {
                // long volume: a length char and the volume (server) name
                let n = it.next().map_or(0, |c| c as usize);
                out.push_str("\\\\");
                for _ in 0..n {
                    if let Some(v) = it.next() {
                        out.push(v);
                    }
                }
                out.push('\\');
            }
            '\u{6}' => out.push_str("<startup>\\"),
            '\u{7}' => out.push_str("<alt-startup>\\"),
            '\u{8}' => out.push_str("<library>\\"),
            c => out.push(c),
        }
    }
    out
}

fn looks_like_link(s: &str) -> bool {
    s.chars().count() >= 4
        && (s.contains("://")
            || s.contains(":\\")
            || s.starts_with("\\\\")
            || s.starts_with("mailto:"))
}

/// Strings of 4+ characters that look like URLs or file paths (HLINK records): UTF-16 for
/// URL monikers, ANSI for the short path of file monikers.
fn link_strings(d: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for shift in [0usize, 1] {
        let mut cur = String::new();
        let units = d.get(shift..).unwrap_or(&[]).as_chunks::<2>().0;
        for ch in units {
            let u = u16::from_le_bytes(*ch);
            match char::from_u32(u32::from(u)) {
                Some(c) if u >= 0x20 && !c.is_control() => cur.push(c),
                _ => {
                    if looks_like_link(&cur) {
                        out.push(std::mem::take(&mut cur));
                    }
                    cur.clear();
                }
            }
        }
    }
    for run in d.split(|c| *c < 0x20 || *c >= 0x7F) {
        let s = String::from_utf8_lossy(run);
        if looks_like_link(&s) && !out.iter().any(|o| *o == s) {
            out.push(s.into_owned());
        }
    }
    out
}

/// Parses a workbook stream: fills `meta` and returns the text.
pub(crate) fn parse(wb: &[u8], meta: &mut Metadata) -> String {
    let recs = records(wb);
    let mut text = String::new();
    let push = |text: &mut String, s: &str| {
        if text.len() < MAX_TEXT {
            text.push_str(s);
        }
    };
    let mut biff8 = true;
    let mut cp: u16 = 1252;
    let mut sst: Vec<String> = Vec::new();
    // BOUNDSHEET: BOF offset -> (name, hidden)
    let mut sheets: Vec<(usize, String)> = Vec::new();
    let mut sheet_idx: Option<usize> = None;
    let mut sheet_name = String::new();
    let mut bofs = 0usize;
    let mut last_row: Option<u16> = None;
    let mut numbers = 0usize;
    let mut pending_string = false;
    let mut last_obj: Option<u16> = None;
    let mut txo: HashMap<u16, String> = HashMap::new();
    let mut hidden_rows: Vec<u16> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < recs.len() {
        let r = &recs[i];
        let d = r.data;
        // gather CONTINUE records of the current record
        let mut j = i + 1;
        while j < recs.len() && recs[j].ty == 0x003C {
            j += 1;
        }
        let conts = &recs[i + 1..j];
        match r.ty {
            0x0809 | 0x0209 | 0x0409 => {
                flush_hidden_rows(meta, &sheet_name, &mut hidden_rows);
                bofs += 1;
                if let Some(v) = rd_u16le(d, 0) {
                    if bofs == 1 {
                        biff8 = v >= 0x0600;
                    }
                }
                if bofs > 1 {
                    let k = sheets.iter().position(|(o, _)| *o == r.off);
                    sheet_idx = Some(k.unwrap_or(bofs - 2));
                    sheet_name = k
                        .and_then(|k| sheets.get(k))
                        .map(|(_, n)| n.clone())
                        .unwrap_or_default();
                    if !sheet_name.is_empty() {
                        push(&mut text, "\n");
                        push(&mut text, &sheet_name);
                        push(&mut text, "\n");
                    }
                    last_row = None;
                }
            }
            0x0042 => {
                if let Some(v) = rd_u16le(d, 0) {
                    if v != 1200 && v != 0 {
                        cp = v;
                        meta.fields.insert("xls:CodePage".into(), v.to_string());
                    }
                }
            }
            0x002F => {
                meta.encrypted = true;
                break;
            }
            0x005C => {
                if let Some((u, _)) = xl_string(d, 0, biff8, cp) {
                    if let Some(u) = clean_str(&u) {
                        meta.add_person(&u, PersonRole::LastModifiedBy, "xls:WRITEACCESS");
                        meta.fields.insert("xls:WriteAccess".into(), u);
                    }
                }
            }
            0x0085 => {
                let pos = rd_u32le(d, 0).unwrap_or(0) as usize;
                let state = d.get(4).copied().unwrap_or(0) & 0x03;
                let cch = usize::from(d.get(6).copied().unwrap_or(0));
                let name = if biff8 {
                    short_chars(d, 8, cch, d.get(7).copied().unwrap_or(0)).map(|x| x.0)
                } else {
                    d.get(7..7 + cch).map(|r| decode_codepage(r, cp))
                };
                if let Some(nm) = name {
                    if state != 0 {
                        Metadata::add_unique(&mut meta.hidden_sheets, &nm);
                        if state == 2 {
                            meta.fields
                                .insert(format!("xls:veryHidden:{nm}"), "true".into());
                        }
                    }
                    if sheets.len() < 4096 {
                        sheets.push((pos, nm));
                    }
                }
            }
            0x00FC => {
                let mut segs = vec![d];
                segs.extend(conts.iter().map(|c| c.data));
                let mut s = Segs::new(segs);
                let _total = s.u32();
                let unique = s.u32().unwrap_or(0) as usize;
                for _ in 0..unique.min(2_000_000) {
                    match s.rich_string() {
                        Some(x) => sst.push(x),
                        None => break,
                    }
                }
            }
            0x0018 => {
                // NAME: user-defined names (built-in ones are one-character codes)
                let grbit = rd_u16le(d, 0).unwrap_or(0);
                let cch = usize::from(d.get(3).copied().unwrap_or(0));
                if grbit & 0x20 == 0 && biff8 {
                    if let Some((n, _)) = d
                        .get(14)
                        .and_then(|&f| short_chars(d, 15, cch, f))
                        .and_then(|(n, k)| clean_str(&n).map(|n| (n, k)))
                    {
                        if !n.starts_with("_xlnm") && names.len() < 1000 {
                            names.push(n);
                        }
                    }
                }
            }
            0x01AE => {
                let cch = rd_u16le(d, 2).unwrap_or(0);
                if cch != 0x0401 && cch != 0x3A01 && biff8 {
                    if let Some((p, n)) = d
                        .get(4)
                        .and_then(|&f| short_chars(d, 5, usize::from(cch), f))
                    {
                        let path = virt_path(&p);
                        if let Some(path) = clean_str(&path) {
                            Metadata::add_unique(&mut meta.links, &truncate(&path, 2048));
                            let k = format!("xls:ExternalBook{}", meta.links.len());
                            meta.fields.insert(k, truncate(&path, 2048));
                        }
                        // sheet names of the external book
                        let mut q = 5 + n;
                        let ctab = rd_u16le(d, 0).unwrap_or(0);
                        for _ in 0..ctab.min(256) {
                            match xl_string(d, q, true, cp) {
                                Some((s, k)) => {
                                    push(&mut text, &s);
                                    push(&mut text, "\n");
                                    q += k;
                                }
                                None => break,
                            }
                        }
                    }
                }
            }
            0x004D => {
                // PLS: a DEVMODE whose dmDeviceName (32 UTF-16 chars) names the printer
                if let Some(raw) = d.get(2..66) {
                    if let Some(p) = clean_str(&crate::util::utf16le_z(raw)) {
                        Metadata::add_unique(&mut meta.printers, &p);
                    }
                }
            }
            0x01B8 => {
                for l in link_strings(d) {
                    if meta.links.len() < 2000 {
                        Metadata::add_unique(&mut meta.links, &truncate(&l, 2048));
                    }
                }
            }
            0x005D => {
                // OBJ: ftCmo carries the object id used by NOTE
                if rd_u16le(d, 0) == Some(0x15) {
                    last_obj = rd_u16le(d, 6);
                }
            }
            0x01B6 => {
                // TXO: text in the first CONTINUE (flags byte + chars)
                let cch = usize::from(rd_u16le(d, 10).unwrap_or(0));
                if let Some(c) = conts.first() {
                    let flags = c.data.first().copied().unwrap_or(0);
                    let mut segs: Vec<&[u8]> = vec![c.data.get(1..).unwrap_or(&[])];
                    // long texts continue in further CONTINUE records before the runs
                    segs.extend(conts.iter().skip(1).map(|x| x.data));
                    let mut s = Segs::new(segs);
                    if let Some(t) = s.chars(cch, flags & 1 != 0) {
                        push(&mut text, &t);
                        push(&mut text, "\n");
                        if let Some(id) = last_obj {
                            if txo.len() < 10_000 {
                                txo.insert(id, t);
                            }
                        }
                    }
                }
            }
            0x001C if biff8 && sheet_idx.is_some() => {
                // NOTE: comment author
                let id = rd_u16le(d, 6);
                if let Some((a, _)) = xl_string(d, 8, true, cp) {
                    let author = clean_str(&a);
                    if let Some(a) = &author {
                        meta.add_person(a, PersonRole::Comment, "xls:NOTE");
                    }
                    let body = id.and_then(|id| txo.get(&id)).cloned().unwrap_or_default();
                    if meta.comments.len() < 2000 {
                        meta.comments.push(CommentRef {
                            author,
                            initials: None,
                            date: None,
                            text: truncate(body.trim(), 2048),
                            source: format!("xls:{sheet_name}"),
                        });
                    }
                }
            }
            0x01BE => {
                // DV: prompt/error titles and texts, then a list formula with a tStr token
                let mut q = 4usize;
                for _ in 0..4 {
                    match xl_string(d, q, biff8, cp) {
                        Some((s, k)) => {
                            let s = s.trim_matches('\0');
                            if !s.is_empty() {
                                push(&mut text, s);
                                push(&mut text, "\n");
                            }
                            q += k;
                        }
                        None => break,
                    }
                }
                let cce = usize::from(rd_u16le(d, q).unwrap_or(0));
                if let Some(f) = d.get(q + 4..q + 4 + cce) {
                    if f.first() == Some(&0x17) {
                        let n = usize::from(f.get(1).copied().unwrap_or(0));
                        if let Some((s, _)) = f.get(2).and_then(|&fl| short_chars(f, 3, n, fl)) {
                            push(&mut text, &s.replace('\0', ", "));
                            push(&mut text, "\n");
                        }
                    }
                }
            }
            0x0208 if sheet_idx.is_some() => {
                // ROW: fDyZero = hidden row
                if rd_u16le(d, 12).is_some_and(|g| g & 0x20 != 0) && hidden_rows.len() < 10_000 {
                    if let Some(row) = rd_u16le(d, 0) {
                        hidden_rows.push(row);
                    }
                }
            }
            0x007D if sheet_idx.is_some() => {
                // COLINFO: fHidden
                if rd_u16le(d, 8).is_some_and(|g| g & 1 != 0)
                    && meta.hidden_content.len() < MAX_HIDDEN
                {
                    let (a, b) = (rd_u16le(d, 0).unwrap_or(0), rd_u16le(d, 2).unwrap_or(0));
                    if b < 0x3FFF && b.saturating_sub(a) < 256 {
                        meta.hidden_content.push(HiddenContent {
                            kind: "column".into(),
                            location: format!(
                                "{sheet_name}!{}:{}",
                                u32::from(a) + 1,
                                u32::from(b) + 1
                            ),
                            text: String::new(),
                        });
                    }
                }
            }
            0x00FD | 0x0204 | 0x00D6 | 0x0203 | 0x027E | 0x00BD | 0x0006 | 0x0207 => {
                let row = rd_u16le(d, 0).unwrap_or(0);
                let cell = |text: &mut String, s: &str, last: &mut Option<u16>| {
                    if text.len() >= MAX_TEXT || s.is_empty() {
                        return;
                    }
                    if r.ty != 0x0207 {
                        match *last {
                            Some(l) if l == row => text.push('\t'),
                            Some(_) => text.push('\n'),
                            None => {}
                        }
                        *last = Some(row);
                    } else {
                        text.push('\t');
                    }
                    text.push_str(s);
                };
                let nums_ok = sheet_idx.is_some_and(|k| k < NUMBER_SHEETS);
                match r.ty {
                    0x00FD => {
                        let isst = rd_u32le(d, 6).unwrap_or(u32::MAX) as usize;
                        if let Some(s) = sst.get(isst) {
                            let s = s.clone();
                            cell(&mut text, &s, &mut last_row);
                        }
                    }
                    0x0204 | 0x00D6 => {
                        if let Some((s, _)) = xl_string(d, 6, biff8, cp) {
                            cell(&mut text, &s, &mut last_row);
                        }
                    }
                    0x0207 => {
                        if pending_string {
                            if let Some((s, _)) = xl_string(d, 0, biff8, cp) {
                                cell(&mut text, &s, &mut last_row);
                            }
                        }
                    }
                    0x0006 => {
                        let res = d.get(6..14);
                        let is_str = res.is_some_and(|x| x[6] == 0xFF && x[7] == 0xFF);
                        pending_string = is_str && res.is_some_and(|x| x[0] == 0);
                        if !is_str && nums_ok && numbers < MAX_NUMBERS {
                            numbers += 1;
                            if let Some(v) = res
                                .and_then(|x| x.try_into().ok())
                                .map(f64::from_le_bytes)
                                .and_then(interesting_number)
                            {
                                cell(&mut text, &v, &mut last_row);
                            }
                        }
                    }
                    0x0203 if nums_ok && numbers < MAX_NUMBERS => {
                        numbers += 1;
                        if let Some(v) = d
                            .get(6..14)
                            .and_then(|x| x.try_into().ok())
                            .map(f64::from_le_bytes)
                            .and_then(interesting_number)
                        {
                            cell(&mut text, &v, &mut last_row);
                        }
                    }
                    0x027E if nums_ok && numbers < MAX_NUMBERS => {
                        numbers += 1;
                        if let Some(v) = rd_u32le(d, 6).map(rk_value).and_then(interesting_number) {
                            cell(&mut text, &v, &mut last_row);
                        }
                    }
                    0x00BD if nums_ok => {
                        let n = d.len().saturating_sub(6) / 6;
                        for k in 0..n {
                            if numbers >= MAX_NUMBERS {
                                break;
                            }
                            numbers += 1;
                            if let Some(v) = rd_u32le(d, 4 + k * 6 + 2)
                                .map(rk_value)
                                .and_then(interesting_number)
                            {
                                cell(&mut text, &v, &mut last_row);
                            }
                        }
                    }
                    _ => {}
                }
                if r.ty != 0x0006 && r.ty != 0x0207 {
                    pending_string = false;
                }
            }
            _ => {}
        }
        i = j;
    }
    flush_hidden_rows(meta, &sheet_name, &mut hidden_rows);
    if !names.is_empty() {
        meta.fields
            .insert("xls:DefinedNames".into(), truncate(&names.join("; "), 2048));
        push(&mut text, "\n");
        push(&mut text, &names.join("\n"));
    }
    if !sheets.is_empty() {
        let all: Vec<&str> = sheets.iter().map(|(_, n)| n.as_str()).collect();
        meta.fields
            .insert("xls:Sheets".into(), truncate(&all.join("; "), 2048));
    }
    text.push('\n');
    text
}

/// Records hidden rows of one sheet as `Sheet!5:7` ranges.
fn flush_hidden_rows(meta: &mut Metadata, sheet: &str, rows: &mut Vec<u16>) {
    rows.sort_unstable();
    rows.dedup();
    let mut start: Option<(u16, u16)> = None;
    let mut out: Vec<(u16, u16)> = Vec::new();
    for &r in rows.iter() {
        match start {
            Some((s, e)) if e + 1 == r => start = Some((s, r)),
            Some(x) => {
                out.push(x);
                start = Some((r, r));
            }
            None => start = Some((r, r)),
        }
    }
    out.extend(start);
    for (s, e) in out {
        if meta.hidden_content.len() >= MAX_HIDDEN {
            break;
        }
        let loc = if s == e {
            format!("{sheet}!{}", u32::from(s) + 1)
        } else {
            format!("{sheet}!{}:{}", u32::from(s) + 1, u32::from(e) + 1)
        };
        meta.hidden_content.push(HiddenContent {
            kind: "row".into(),
            location: loc,
            text: String::new(),
        });
    }
    rows.clear();
}

#[cfg(test)]
mod tests;
