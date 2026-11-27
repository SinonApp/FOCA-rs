//! RTF: the document information group (`\info`), generator and template, user properties,
//! revision and annotation authors, field targets (HYPERLINK, INCLUDEPICTURE, INCLUDETEXT,
//! DDE), hidden and deleted text, RSIDs, embedded OLE objects (`\objdata`, parsed
//! recursively) and pictures (`\pict`, EXIF of JPEG/PNG), and the text decoded through the
//! document and font code pages (`\ansicpg`, `\fcharset`, `\cpg`, `\uN`).
//!
//! Control words follow the RTF 1.9.1 specification; the information tag set mirrors ExifTool
//! RTF.pm, the OLE1 object layout (ObjectHeader + native data) follows oletools rtfobj (BSD-2).

use foca_core::{
    Attachment, CommentRef, DocFormat, HiddenContent, Metadata, PersonRole, RevisionKind,
    RevisionRef,
};

use crate::util::{clean_str, decode_codepage, rd_u32le, truncate};
use crate::{Ctx, MetaError};

/// Maximum group nesting that is still interpreted; deeper groups are skipped.
const MAX_DEPTH: usize = 512;
/// Maximum characters of body text kept.
const MAX_TEXT: usize = 16 << 20;
const MAX_ITEMS: usize = 2000;
const MAX_ATTACHMENTS: usize = 500;

/// Returns `true` when the bytes start with the RTF magic `{\rtf`.
pub(crate) fn is_rtf(b: &[u8]) -> bool {
    b.starts_with(b"{\\rtf")
}

/// What the text of the current group belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dest {
    /// Document text.
    Body,
    /// Ignored group (unknown starred destination, font names, colour table, ...).
    Skip,
    /// A group whose own text is dropped but whose children may open destinations
    /// (`\info`, `\userprops`, `\shpinst`, `\fonttbl`).
    Container,
    /// Text collected into the capture on top of the stack.
    Capture,
}

/// Kind of a captured destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cap {
    Info(&'static str),
    Time(&'static str),
    Generator,
    Template,
    PropName,
    PropValue,
    RevTbl,
    AtnAuthor,
    AtnId,
    AtnDate,
    Annotation,
    FldInst,
    ObjData,
    ObjClass,
    ObjName,
    Pict,
    Ud,
}

impl Cap {
    fn binary(self) -> bool {
        matches!(self, Cap::ObjData | Cap::Pict)
    }
}

struct Capture {
    cap: Cap,
    depth: usize,
    text: String,
    bytes: Vec<u8>,
    /// Pending high nibble of hex data.
    nibble: Option<u8>,
    /// `\yr \mo \dy \hr \min \sec` of a date group.
    time: [u32; 6],
    /// Picture kind from `\jpegblip`, `\pngblip`, `\emfblip`, `\wmetafile`.
    pict_kind: &'static str,
    overflow: bool,
}

#[derive(Debug, Clone, Copy)]
struct State {
    dest: Dest,
    /// `\ucN`: characters to skip after `\uN`.
    uc: u32,
    cp: u16,
    hidden: bool,
    deleted: bool,
    revauth: Option<u32>,
    /// `\fN` inside the font table.
    font: Option<i32>,
}

struct Parser<'a, 'c> {
    b: &'a [u8],
    pos: usize,
    ctx: &'a Ctx<'c>,
    meta: Metadata,
    body: String,
    stack: Vec<State>,
    caps: Vec<Capture>,
    ansi_cp: u16,
    def_font: i32,
    fonts: Vec<(i32, u16)>,
    /// `\'hh` bytes waiting to be decoded together (double-byte code pages).
    pending: Vec<u8>,
    pending_cp: u16,
    /// Characters still to skip after `\uN`.
    skip: u32,
    high_surrogate: Option<u16>,
    star: bool,
    revtbl: Vec<String>,
    atn_author: Option<String>,
    atn_id: Option<String>,
    atn_date: Option<String>,
    prop_name: Option<String>,
    obj_class: Option<String>,
    obj_name: Option<String>,
    hidden_buf: String,
    deleted_buf: (String, Option<u32>, Option<String>),
    rev_date: Option<String>,
    objects: usize,
    picts: usize,
    want_children: bool,
}

/// Parses an RTF document and returns its metadata and text.
fn parse(b: &[u8], ctx: &Ctx, want_children: bool) -> Result<(Metadata, String), MetaError> {
    let mut p = Parser {
        b,
        pos: 0,
        ctx,
        meta: Metadata::new(DocFormat::Rtf),
        body: String::new(),
        stack: Vec::new(),
        caps: Vec::new(),
        ansi_cp: 1252,
        def_font: 0,
        fonts: Vec::new(),
        pending: Vec::new(),
        pending_cp: 1252,
        skip: 0,
        high_surrogate: None,
        star: false,
        revtbl: Vec::new(),
        atn_author: None,
        atn_id: None,
        atn_date: None,
        prop_name: None,
        obj_class: None,
        obj_name: None,
        hidden_buf: String::new(),
        deleted_buf: (String::new(), None, None),
        rev_date: None,
        objects: 0,
        picts: 0,
        want_children,
    };
    p.run()?;
    p.finish();
    let Parser { meta, body, .. } = p;
    Ok((meta, body))
}

impl Parser<'_, '_> {
    fn state(&self) -> State {
        self.stack.last().copied().unwrap_or(State {
            dest: Dest::Body,
            uc: 1,
            cp: self.ansi_cp,
            hidden: false,
            deleted: false,
            revauth: None,
            font: None,
        })
    }

    fn state_mut(&mut self) -> Option<&mut State> {
        self.stack.last_mut()
    }

    fn run(&mut self) -> Result<(), MetaError> {
        while self.pos < self.b.len() {
            let c = self.b[self.pos];
            self.pos += 1;
            match c {
                b'{' => self.open(),
                b'}' => self.close()?,
                b'\\' => self.control()?,
                b'\r' | b'\n' | 0 => {}
                _ => self.byte(c),
            }
        }
        while !self.stack.is_empty() {
            self.close()?;
        }
        Ok(())
    }

    fn open(&mut self) {
        self.flush_pending();
        self.skip = 0;
        self.star = false;
        let mut s = self.state();
        if self.stack.len() >= MAX_DEPTH {
            s.dest = Dest::Skip;
        }
        self.stack.push(s);
    }

    fn close(&mut self) -> Result<(), MetaError> {
        self.flush_pending();
        self.skip = 0;
        self.star = false;
        let depth = self.stack.len();
        while self.caps.last().is_some_and(|c| c.depth >= depth) {
            if let Some(cap) = self.caps.pop() {
                self.finish_capture(cap)?;
            }
        }
        let before = self.state();
        self.stack.pop();
        let after = self.state();
        if before.hidden && !after.hidden {
            self.flush_hidden();
        }
        if before.deleted && !after.deleted {
            self.flush_deleted();
        }
        Ok(())
    }

    /// Starts collecting a destination in the current group.
    fn begin(&mut self, cap: Cap) {
        let depth = self.stack.len();
        if let Some(s) = self.state_mut() {
            s.dest = Dest::Capture;
        }
        self.caps.push(Capture {
            cap,
            depth,
            text: String::new(),
            bytes: Vec::new(),
            nibble: None,
            time: [0; 6],
            pict_kind: "",
            overflow: false,
        });
    }

    fn set_dest(&mut self, d: Dest) {
        if let Some(s) = self.state_mut() {
            s.dest = d;
        }
    }

    fn byte(&mut self, c: u8) {
        if self.state().dest == Dest::Capture {
            if let Some(cap) = self.caps.last_mut() {
                if cap.cap.binary() {
                    push_hex(cap, c, self.ctx);
                    return;
                }
            }
        }
        if self.skip > 0 {
            self.skip -= 1;
            return;
        }
        if c < 0x80 {
            self.flush_pending();
            self.emit(c as char);
        } else {
            self.raw(c);
        }
    }

    /// Queues a code page byte (`\'hh` or a literal 8-bit byte).
    fn raw(&mut self, c: u8) {
        let cp = self.state().cp;
        if !self.pending.is_empty() && cp != self.pending_cp {
            self.flush_pending();
        }
        self.pending_cp = cp;
        self.pending.push(c);
        if self.pending.len() > 4096 {
            self.flush_pending();
        }
    }

    fn flush_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let bytes = std::mem::take(&mut self.pending);
        let s = decode_codepage(&bytes, self.pending_cp);
        for ch in s.chars() {
            self.emit(ch);
        }
    }

    fn emit(&mut self, ch: char) {
        let st = self.state();
        match st.dest {
            Dest::Skip | Dest::Container => {}
            Dest::Capture => {
                if let Some(cap) = self.caps.last_mut() {
                    if cap.text.len() < 1 << 20 {
                        cap.text.push(ch);
                    }
                }
            }
            Dest::Body => {
                if st.deleted {
                    if self.deleted_buf.0.len() < 4096 {
                        self.deleted_buf.0.push(ch);
                    }
                    self.deleted_buf.1 = st.revauth;
                    self.deleted_buf.2.clone_from(&self.rev_date);
                    return;
                }
                if st.hidden && self.hidden_buf.len() < 4096 {
                    self.hidden_buf.push(ch);
                }
                if self.body.len() < MAX_TEXT {
                    self.body.push(ch);
                }
            }
        }
    }

    fn emit_str(&mut self, s: &str) {
        self.flush_pending();
        for ch in s.chars() {
            self.emit(ch);
        }
    }

    fn control(&mut self) -> Result<(), MetaError> {
        let Some(&c) = self.b.get(self.pos) else {
            return Ok(());
        };
        if !c.is_ascii_alphabetic() {
            self.pos += 1;
            return self.symbol(c);
        }
        let start = self.pos;
        while self.pos < self.b.len() && self.b[self.pos].is_ascii_alphabetic() {
            self.pos += 1;
            if self.pos - start > 32 {
                break;
            }
        }
        let word = std::str::from_utf8(&self.b[start..self.pos]).unwrap_or("");
        let word = word.to_string();
        let mut param: Option<i32> = None;
        let neg = self.b.get(self.pos) == Some(&b'-');
        let digits_at = if neg { self.pos + 1 } else { self.pos };
        let mut q = digits_at;
        let mut v: i64 = 0;
        while q < self.b.len() && self.b[q].is_ascii_digit() && q - digits_at < 10 {
            v = v * 10 + i64::from(self.b[q] - b'0');
            q += 1;
        }
        if q > digits_at {
            let v = if neg { -v } else { v };
            param = Some(v.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32);
            self.pos = q;
        }
        if self.b.get(self.pos) == Some(&b' ') {
            self.pos += 1;
        }
        let star = std::mem::take(&mut self.star);
        if word == "bin" {
            let n = param.unwrap_or(0).max(0) as usize;
            let end = self.pos.saturating_add(n).min(self.b.len());
            if self.state().dest == Dest::Capture {
                if let Some(cap) = self.caps.last_mut() {
                    if cap.cap.binary() && !cap.overflow {
                        if (cap.bytes.len() + (end - self.pos)) as u64 > self.ctx.remaining() {
                            cap.overflow = true;
                        } else {
                            cap.bytes.extend_from_slice(&self.b[self.pos..end]);
                        }
                    }
                }
            }
            self.pos = end;
            return Ok(());
        }
        if self.skip > 0 && word != "u" {
            self.skip -= 1;
            return Ok(());
        }
        if word != "u" {
            self.flush_pending();
        }
        self.word(&word, param, star);
        Ok(())
    }

    fn symbol(&mut self, c: u8) -> Result<(), MetaError> {
        match c {
            b'\'' => {
                let h = self.b.get(self.pos..self.pos + 2).and_then(|h| {
                    std::str::from_utf8(h)
                        .ok()
                        .and_then(|s| u8::from_str_radix(s, 16).ok())
                });
                if let Some(v) = h {
                    self.pos += 2;
                    if self.state().dest == Dest::Capture
                        && self.caps.last().is_some_and(|c| c.cap.binary())
                    {
                        return Ok(());
                    }
                    if self.skip > 0 {
                        self.skip -= 1;
                        return Ok(());
                    }
                    self.raw(v);
                }
            }
            b'*' => self.star = true,
            b'\\' | b'{' | b'}' => {
                if self.skip > 0 {
                    self.skip -= 1;
                } else {
                    self.flush_pending();
                    self.emit(c as char);
                }
            }
            b'~' => self.emit_str("\u{a0}"),
            b'_' => self.emit_str("-"),
            b'\r' | b'\n' => self.emit_str("\n"),
            _ => {}
        }
        Ok(())
    }

    fn word(&mut self, w: &str, param: Option<i32>, star: bool) {
        let n = param.unwrap_or(0);
        let np = || u32::try_from(n).unwrap_or(0);
        match w {
            "u" => {
                self.flush_pending();
                let unit = (n as i64).rem_euclid(65536) as u16;
                self.unicode(unit);
                self.skip = self.state().uc;
            }
            "uc" => {
                if let Some(s) = self.state_mut() {
                    s.uc = np().min(8);
                }
            }
            "ansicpg" => {
                if n > 0 && n < 65536 {
                    self.ansi_cp = n as u16;
                    if let Some(s) = self.state_mut() {
                        s.cp = n as u16;
                    }
                    self.meta
                        .fields
                        .insert("rtf:CodePage".into(), n.to_string());
                }
            }
            "mac" => self.ansi_cp = 10000,
            "pc" => self.ansi_cp = 437,
            "pca" => self.ansi_cp = 850,
            "deff" => self.def_font = n,
            "f" => {
                let in_fonttbl = self.state().font.is_some();
                if in_fonttbl {
                    if let Some(s) = self.state_mut() {
                        s.font = Some(n);
                    }
                } else {
                    let cp = self.font_cp(n);
                    if let Some(s) = self.state_mut() {
                        s.cp = cp;
                    }
                }
            }
            "fcharset" | "cpg" => {
                if let Some(f) = self.state().font {
                    let cp = if w == "cpg" {
                        u16::try_from(n).unwrap_or(0)
                    } else {
                        charset_cp(n)
                    };
                    if cp != 0 {
                        self.fonts.retain(|(id, _)| *id != f);
                        if self.fonts.len() < 4096 {
                            self.fonts.push((f, cp));
                        }
                    }
                }
            }
            "plain" => {
                let cp = self.font_cp(self.def_font);
                if let Some(s) = self.state_mut() {
                    s.cp = cp;
                    s.hidden = false;
                    s.deleted = false;
                }
            }
            "v" => {
                let on = param != Some(0);
                if !on {
                    self.flush_hidden();
                }
                if let Some(s) = self.state_mut() {
                    s.hidden = on;
                }
            }
            "deleted" => {
                let on = param != Some(0);
                if !on {
                    self.flush_deleted();
                }
                if let Some(s) = self.state_mut() {
                    s.deleted = on;
                }
            }
            "revauthdel" | "revauth" => {
                if let Some(s) = self.state_mut() {
                    s.revauth = Some(np());
                }
            }
            "revdttmdel" | "revdttm" => self.rev_date = dttm_iso(n as u32),
            "par" | "line" | "sect" | "page" | "row" | "lbr" => self.emit_str("\n"),
            "tab" | "cell" => self.emit_str("\t"),
            "emdash" => self.emit_str("\u{2014}"),
            "endash" => self.emit_str("\u{2013}"),
            "bullet" => self.emit_str("\u{2022}"),
            "lquote" => self.emit_str("\u{2018}"),
            "rquote" => self.emit_str("\u{2019}"),
            "ldblquote" => self.emit_str("\u{201C}"),
            "rdblquote" => self.emit_str("\u{201D}"),
            "emspace" | "enspace" | "qmspace" => self.emit_str(" "),
            // information group numbers (ExifTool RTF.pm tags)
            "version" | "vern" | "edmins" | "nofpages" | "nofwords" | "nofchars" | "nofcharsws"
            | "id" => self.info_number(w, n),
            "yr" | "mo" | "dy" | "hr" | "min" | "sec" => {
                let i = ["yr", "mo", "dy", "hr", "min", "sec"]
                    .iter()
                    .position(|x| *x == w)
                    .unwrap_or(0);
                if let Some(cap) = self.caps.last_mut() {
                    if matches!(cap.cap, Cap::Time(_)) {
                        cap.time[i] = np();
                    }
                }
            }
            "rsid" | "insrsid" | "rsidroot" => {
                if self.meta.rsids.len() < 10_000 && n > 0 {
                    Metadata::add_unique(&mut self.meta.rsids, &format!("{:08X}", n as u32));
                }
            }
            "jpegblip" | "pngblip" | "emfblip" | "wmetafile" | "macpict" | "dibitmap"
            | "wbitmap" => {
                if let Some(cap) = self.caps.last_mut() {
                    if cap.cap == Cap::Pict {
                        cap.pict_kind = match w {
                            "jpegblip" => "jpg",
                            "pngblip" => "png",
                            "emfblip" => "emf",
                            "wmetafile" => "wmf",
                            "macpict" => "pict",
                            _ => "bmp",
                        };
                    }
                }
            }
            _ => self.destination(w, star),
        }
    }

    /// Handles a control word that may open a destination group.
    fn destination(&mut self, w: &str, star: bool) {
        // destinations only matter as the first word of a group; later words keep the state
        let info_key = match w {
            "title" => Some("title"),
            "subject" => Some("subject"),
            "author" => Some("author"),
            "manager" => Some("manager"),
            "company" => Some("company"),
            "operator" => Some("operator"),
            "category" => Some("category"),
            "keywords" => Some("keywords"),
            "comment" => Some("comment"),
            "doccomm" => Some("doccomm"),
            "hlinkbase" => Some("hlinkbase"),
            _ => None,
        };
        if let Some(k) = info_key {
            self.begin(Cap::Info(k));
            return;
        }
        match w {
            "creatim" => self.begin(Cap::Time("created")),
            "revtim" => self.begin(Cap::Time("modified")),
            "printim" => self.begin(Cap::Time("printed")),
            "buptim" => self.begin(Cap::Time("backup")),
            "generator" => self.begin(Cap::Generator),
            "template" => self.begin(Cap::Template),
            "propname" => self.begin(Cap::PropName),
            "staticval" => self.begin(Cap::PropValue),
            "revtbl" => self.begin(Cap::RevTbl),
            "atnauthor" => self.begin(Cap::AtnAuthor),
            "atnid" => self.begin(Cap::AtnId),
            "atndate" => self.begin(Cap::AtnDate),
            "annotation" => self.begin(Cap::Annotation),
            "fldinst" => self.begin(Cap::FldInst),
            "objdata" => self.begin(Cap::ObjData),
            "objclass" => self.begin(Cap::ObjClass),
            "objname" => self.begin(Cap::ObjName),
            "pict" => self.begin(Cap::Pict),
            "ud" => {
                // the Unicode variant of a \upr pair replaces the ANSI one
                let parent = self.stack.len().checked_sub(2).map(|i| self.stack[i]);
                let d = parent.map_or(Dest::Body, |p| p.dest);
                self.set_dest(d);
                if d == Dest::Capture {
                    self.begin(Cap::Ud);
                }
            }
            "upr" => self.set_dest(Dest::Skip),
            "fonttbl" => {
                self.set_dest(Dest::Container);
                if let Some(s) = self.state_mut() {
                    s.font = Some(-1);
                }
            }
            "info" | "userprops" | "shpinst" | "shppict" | "nonshppict" | "object" | "result"
            | "field" | "shp" | "sp" => {
                if matches!(w, "info" | "userprops" | "shpinst") {
                    self.set_dest(Dest::Container);
                }
            }
            "colortbl" | "stylesheet" | "listtable" | "listoverridetable" | "filetbl"
            | "rsidtbl" | "xmlnstbl" | "themedata" | "colorschememapping" | "datastore"
            | "latentstyles" | "pgdsctbl" | "mmathPr" | "fldtype" | "datafield" | "sn"
            | "bkmkstart" | "bkmkend" | "pntext" | "pntxta" | "pntxtb" | "listtext" | "falt"
            | "panose" | "fname" | "blipuid" | "picprop" | "atnref" | "atntime" | "atnicn"
            | "objalias" | "objsect" | "xe" | "tc" | "txe" | "rxe" | "header_rsid" => {
                if w == "rsidtbl" {
                    // \rsidN words inside are still recorded; only text is skipped
                    self.set_dest(Dest::Container);
                } else {
                    self.set_dest(Dest::Skip);
                }
            }
            _ => {
                if star {
                    self.set_dest(Dest::Skip);
                }
            }
        }
    }

    fn info_number(&mut self, w: &str, n: i32) {
        let n = n.max(0) as u64;
        match w {
            "nofpages" => {
                self.meta.stats.insert("pages".into(), n);
            }
            "nofwords" => {
                self.meta.stats.insert("words".into(), n);
            }
            "nofchars" => {
                self.meta.stats.insert("characters".into(), n);
            }
            "nofcharsws" => {
                self.meta.stats.insert("characters_with_spaces".into(), n);
            }
            "edmins" => self.meta.edit_time_secs = Some(n.saturating_mul(60)),
            "version" => self.meta.revision = Some(n.to_string()),
            "vern" => {
                self.meta
                    .fields
                    .insert("rtf:InternalVersionNumber".into(), n.to_string());
            }
            _ => {
                self.meta.fields.insert("rtf:id".into(), n.to_string());
            }
        }
    }

    fn unicode(&mut self, unit: u16) {
        if (0xD800..0xDC00).contains(&unit) {
            self.high_surrogate = Some(unit);
            return;
        }
        let ch = if (0xDC00..0xE000).contains(&unit) {
            match self.high_surrogate.take() {
                Some(h) => char::decode_utf16([h, unit]).next().and_then(Result::ok),
                None => None,
            }
        } else {
            self.high_surrogate = None;
            char::from_u32(u32::from(unit))
        };
        if let Some(ch) = ch {
            self.emit(ch);
        }
    }

    fn font_cp(&self, f: i32) -> u16 {
        self.fonts
            .iter()
            .find(|(id, _)| *id == f)
            .map_or(self.ansi_cp, |(_, cp)| *cp)
    }

    fn flush_hidden(&mut self) {
        let t = std::mem::take(&mut self.hidden_buf);
        let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
        if !t.is_empty() && self.meta.hidden_content.len() < 500 {
            self.meta.hidden_content.push(HiddenContent {
                kind: "vanish".into(),
                location: "rtf".into(),
                text: truncate(&t, 512),
            });
        }
    }

    fn flush_deleted(&mut self) {
        let (t, auth, date) = std::mem::take(&mut self.deleted_buf);
        let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
        if t.is_empty() || self.meta.revisions.len() >= MAX_ITEMS {
            return;
        }
        let author = auth
            .and_then(|i| self.revtbl.get(i as usize))
            .and_then(|a| clean_str(a));
        self.meta.revisions.push(RevisionRef {
            kind: RevisionKind::Delete,
            author,
            date,
            text: truncate(&t, 512),
        });
    }

    fn finish_capture(&mut self, cap: Capture) -> Result<(), MetaError> {
        let text = clean_str(&cap.text);
        match cap.cap {
            Cap::Info(k) => {
                let Some(v) = text else { return Ok(()) };
                let m = &mut self.meta;
                match k {
                    "title" => m.title = Some(v),
                    "subject" => m.subject = Some(v),
                    "author" => {
                        m.add_person(&v, PersonRole::Author, "rtf:author");
                        m.author = Some(v);
                    }
                    "operator" => {
                        m.add_person(&v, PersonRole::LastModifiedBy, "rtf:operator");
                        m.last_modified_by = Some(v);
                    }
                    "manager" => {
                        m.add_person(&v, PersonRole::Other, "rtf:manager");
                        m.manager = Some(v);
                    }
                    "company" => m.company = Some(v),
                    "category" => m.category = Some(v),
                    "keywords" => m.keywords = Some(v),
                    "doccomm" => m.description = Some(v),
                    _ => {
                        m.fields.insert(format!("rtf:{k}"), truncate(&v, 2048));
                    }
                }
            }
            Cap::Time(k) => {
                let [y, mo, d, h, mi, s] = cap.time;
                if (1900..=2200).contains(&y) && (1..=12).contains(&mo) && (1..=31).contains(&d) {
                    let iso = format!(
                        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}",
                        h.min(23),
                        mi.min(59),
                        s.min(59)
                    );
                    match k {
                        "created" => self.meta.created = Some(iso),
                        "modified" => self.meta.modified = Some(iso),
                        "printed" => self.meta.printed = Some(iso),
                        _ => {
                            self.meta.fields.insert("rtf:backup".into(), iso);
                        }
                    }
                }
            }
            Cap::Generator => {
                if let Some(g) = text.map(|t| t.trim_end_matches(';').trim().to_string()) {
                    if !g.is_empty() {
                        Metadata::add_unique(&mut self.meta.software, &g);
                        self.meta.application = Some(g);
                    }
                }
            }
            Cap::Template => self.meta.template = text,
            Cap::PropName => self.prop_name = text,
            Cap::PropValue => {
                if let (Some(n), Some(v)) = (self.prop_name.take(), text) {
                    if self.meta.custom.len() < MAX_ITEMS {
                        self.meta.custom.insert(n, truncate(&v, 2048));
                    }
                }
            }
            Cap::RevTbl => {
                for a in cap.text.split(';') {
                    let a = a.trim();
                    if self.revtbl.len() < 4096 {
                        self.revtbl.push(a.to_string());
                    }
                    if !a.is_empty() && a != "Unknown" {
                        self.meta.add_person(a, PersonRole::Revision, "rtf:revtbl");
                    }
                }
            }
            Cap::AtnAuthor => self.atn_author = text,
            Cap::AtnId => self.atn_id = text,
            Cap::AtnDate => {
                self.atn_date = text
                    .and_then(|t| t.trim().parse::<i64>().ok())
                    .and_then(|v| dttm_iso(v as u32));
            }
            Cap::Annotation => {
                let author = self.atn_author.take();
                if let Some(a) = &author {
                    self.meta
                        .add_person(a, PersonRole::Comment, "rtf:atnauthor");
                }
                if self.meta.comments.len() < MAX_ITEMS {
                    self.meta.comments.push(CommentRef {
                        author,
                        initials: self.atn_id.take(),
                        date: self.atn_date.take(),
                        text: truncate(text.as_deref().unwrap_or(""), 2048),
                        source: "rtf:annotation".into(),
                    });
                }
            }
            Cap::FldInst => {
                if let Some(t) = text {
                    self.field(&t);
                }
            }
            Cap::ObjClass => self.obj_class = text,
            Cap::ObjName => self.obj_name = text,
            Cap::ObjData => self.object(cap)?,
            Cap::Pict => self.picture(cap)?,
            Cap::Ud => {
                if let Some(t) = text {
                    // the \ud text belongs to the enclosing capture
                    if let Some(parent) = self.caps.last_mut() {
                        parent.text.push_str(&t);
                    }
                }
            }
        }
        Ok(())
    }

    /// Field instructions: external targets of HYPERLINK, INCLUDEPICTURE, INCLUDETEXT, LINK,
    /// IMPORT and DDE fields (`\\` is a backslash inside quoted field arguments).
    fn field(&mut self, inst: &str) {
        let mut it = inst.split_whitespace();
        let Some(kw) = it.next() else { return };
        let kw = kw.to_ascii_uppercase();
        if !matches!(
            kw.as_str(),
            "HYPERLINK" | "INCLUDEPICTURE" | "INCLUDETEXT" | "LINK" | "IMPORT" | "DDE" | "DDEAUTO"
        ) {
            return;
        }
        let rest = inst.trim_start()[kw.len().min(inst.trim_start().len())..].trim();
        let target = if kw.starts_with("DDE") || kw == "LINK" {
            // LINK/DDE: application, then the topic (file) in quotes or bare
            rest.to_string()
        } else {
            first_arg(rest)
        };
        let target = target.replace("\\\\", "\\");
        let target = target.trim();
        if target.is_empty() {
            return;
        }
        if kw.starts_with("DDE") {
            self.meta
                .fields
                .insert("rtf:dde".into(), truncate(target, 1024));
        } else if kw == "LINK" {
            self.meta
                .fields
                .insert("rtf:link".into(), truncate(target, 1024));
        } else if self.meta.links.len() < MAX_ITEMS {
            Metadata::add_unique(&mut self.meta.links, &truncate(target, 2048));
        }
    }

    /// `\objdata`: an OLE1 ObjectHeader (version, format id, class, topic, item, native size)
    /// followed by the native data; Package objects carry an Ole10Native-style stream with the
    /// original and temporary paths, other classes a compound file.
    fn object(&mut self, cap: Capture) -> Result<(), MetaError> {
        self.objects += 1;
        let class = self.obj_class.take();
        let label = self
            .obj_name
            .take()
            .or_else(|| class.clone())
            .unwrap_or_else(|| format!("object{}", self.objects));
        let data = cap.bytes;
        if data.is_empty() {
            return Ok(());
        }
        self.ctx.spend(data.len() as u64)?;
        let (header_class, native, linked) = ole1_object(&data);
        let class = class.or(header_class);
        if let Some(c) = &class {
            self.meta.fields.insert(
                format!("rtf:object{}:class", self.objects),
                truncate(c, 128),
            );
        }
        if let Some(path) = linked {
            self.meta.fields.insert(
                format!("rtf:object{}:link", self.objects),
                truncate(&path, 1024),
            );
        }
        let Some(native) = native else {
            return Ok(());
        };
        let before = self.meta.embedded.len() + self.meta.attachments.len();
        if class
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case("Package"))
        {
            let mut stream = Vec::with_capacity(native.len() + 4);
            stream.extend_from_slice(&(native.len() as u32).to_le_bytes());
            stream.extend_from_slice(native);
            let path = format!("rtf:object{}", self.objects);
            super::ole::parse_ole10_native(&mut self.meta, self.ctx, &path, &stream, self.ansi_cp)?;
        } else if self.want_children {
            self.ctx
                .attach_child(&mut self.meta, native, &label, &label)?;
        }
        if self.meta.embedded.len() + self.meta.attachments.len() == before
            && self.meta.attachments.len() < MAX_ATTACHMENTS
        {
            self.meta.attachments.push(Attachment {
                name: truncate(&label, 256),
                size: Some(native.len() as u64),
                mime: None,
            });
        }
        Ok(())
    }

    fn picture(&mut self, cap: Capture) -> Result<(), MetaError> {
        if cap.bytes.is_empty() {
            return Ok(());
        }
        self.picts += 1;
        self.ctx.spend(cap.bytes.len() as u64)?;
        let ext = if cap.pict_kind.is_empty() {
            "bin"
        } else {
            cap.pict_kind
        };
        let name = format!("pict{}.{ext}", self.picts);
        let before = self.meta.embedded.len() + self.meta.attachments.len();
        if self.want_children && matches!(ext, "jpg" | "png") {
            self.ctx
                .attach_child(&mut self.meta, &cap.bytes, &name, &name)?;
        }
        if self.meta.embedded.len() + self.meta.attachments.len() == before
            && self.meta.attachments.len() < MAX_ATTACHMENTS
        {
            let mime = match ext {
                "jpg" => "image/jpeg",
                "png" => "image/png",
                "emf" => "image/emf",
                "wmf" => "image/wmf",
                _ => "application/octet-stream",
            };
            self.meta.attachments.push(Attachment {
                name,
                size: Some(cap.bytes.len() as u64),
                mime: Some(mime.into()),
            });
        }
        Ok(())
    }

    fn finish(&mut self) {
        self.flush_pending();
        self.flush_hidden();
        self.flush_deleted();
        if !self.meta.fields.contains_key("rtf:CodePage") {
            self.meta
                .fields
                .insert("rtf:CodePage".into(), self.ansi_cp.to_string());
        }
        if self.objects > 0 {
            self.meta
                .stats
                .insert("objects".into(), self.objects as u64);
        }
        if self.picts > 0 {
            self.meta.stats.insert("images".into(), self.picts as u64);
        }
    }
}

/// Adds one hex digit (or ignores other bytes) to binary capture data.
fn push_hex(cap: &mut Capture, c: u8, ctx: &Ctx) {
    let v = match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => return,
    };
    if cap.overflow {
        return;
    }
    match cap.nibble.take() {
        None => cap.nibble = Some(v),
        Some(h) => {
            if cap.bytes.len() as u64 >= ctx.remaining() {
                cap.overflow = true;
                return;
            }
            cap.bytes.push(h << 4 | v);
        }
    }
}

/// Code page of an RTF `\fcharset` value (RTF spec table; 2 = Symbol has no code page).
fn charset_cp(n: i32) -> u16 {
    match n {
        0 => 1252,
        77 => 10000,
        128 => 932,
        129 => 949,
        130 => 1361,
        134 => 936,
        136 => 950,
        161 => 1253,
        162 => 1254,
        163 => 1258,
        177 => 1255,
        178 => 1256,
        186 => 1257,
        204 => 1251,
        222 => 874,
        238 => 1250,
        254 => 437,
        255 => 850,
        _ => 0,
    }
}

/// The first argument of a field instruction: a quoted string or the first word that is not
/// a switch.
fn first_arg(s: &str) -> String {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("").to_string();
    }
    s.split_whitespace()
        .find(|w| !w.starts_with('\\'))
        .unwrap_or("")
        .to_string()
}

/// ISO date of a Word DTTM value (local time, no offset).
fn dttm_iso(v: u32) -> Option<String> {
    let m = super::office_info::dttm_minutes(v)?;
    let t = time::OffsetDateTime::from_unix_timestamp(m * 60).ok()?;
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:00",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute()
    ))
}

/// Splits an OLE1 object: returns the class name, the native data of an embedded object and
/// the topic (file path) of a linked one. Data that already is a compound file is returned
/// as is.
fn ole1_object(d: &[u8]) -> (Option<String>, Option<&[u8]>, Option<String>) {
    const CFB: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    if d.starts_with(&CFB) {
        return (None, Some(d), None);
    }
    let Some(format_id) = rd_u32le(d, 4) else {
        return (None, None, None);
    };
    let mut p = 8usize;
    let read_str = |p: &mut usize| -> Option<String> {
        let n = rd_u32le(d, *p)? as usize;
        let raw = d.get(*p + 4..(*p + 4).checked_add(n)?)?;
        *p += 4 + n;
        clean_str(&decode_codepage(
            raw.split(|c| *c == 0).next().unwrap_or(raw),
            1252,
        ))
    };
    let class = read_str(&mut p);
    let topic = read_str(&mut p);
    let _item = read_str(&mut p);
    match format_id {
        2 => {
            let Some(n) = rd_u32le(d, p).map(|n| n as usize) else {
                return (class, None, None);
            };
            let start = p + 4;
            let end = start.saturating_add(n).min(d.len());
            (class, d.get(start..end), None)
        }
        1 => (class, None, topic),
        _ => (class, None, None),
    }
}

pub fn extract(b: &[u8], ctx: &Ctx) -> Result<Metadata, MetaError> {
    crate::guard("rtf", || parse(b, ctx, true).map(|(m, _)| m))
}

/// Returns the document text, followed by the annotation (comment) texts.
pub fn text(b: &[u8], ctx: &Ctx) -> Result<String, MetaError> {
    crate::guard("rtf", || {
        let (m, mut t) = parse(b, ctx, false)?;
        for c in &m.comments {
            t.push('\n');
            t.push_str(&c.text);
        }
        Ok(t)
    })
}

#[cfg(test)]
mod tests;
