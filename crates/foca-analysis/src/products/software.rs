//! Software and OS detection from the signature table (`signatures/software.toml`,
//! embedded in the binary).

use std::sync::OnceLock;

use foca_core::Metadata;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Built-in signature table.
pub const BUILTIN_TOML: &str = include_str!("../../signatures/software.toml");

#[derive(Debug, Clone, Deserialize)]
struct VerDef {
    v: String,
    id: Option<String>,
    name: Option<String>,
    released: Option<i32>,
    eol: Option<String>,
    #[serde(default)]
    legacy: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct SigDef {
    id: String,
    name: String,
    #[serde(default)]
    kind: Option<String>,
    re: String,
    #[serde(default)]
    versions: Vec<VerDef>,
    released: Option<i32>,
    eol: Option<String>,
    #[serde(default)]
    legacy: bool,
    /// Versions whose leading number is below this value (`3.0` → 3, `m84` → 84) are out of
    /// support (legacy). Defaults to the lowest version in a numeric `versions` table, so that
    /// e.g. Distiller 3.0, older than anything in the table, is not reported as current.
    legacy_below: Option<u32>,
}

/// Returns the leading number of a version: `3.0` → 3, `m84` → 84, `CS3` → 3.
fn lead_num(v: &str) -> Option<u32> {
    let d: String = v
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    d.parse().ok()
}

/// Returns the "older than anything we know" threshold: an explicit `legacy_below`, or the
/// lowest version of the table when all its keys are numbers.
fn legacy_threshold(d: &SigDef) -> Option<u32> {
    if d.legacy_below.is_some() {
        return d.legacy_below;
    }
    let nums: Option<Vec<u32>> = d
        .versions
        .iter()
        .map(|vd| {
            vd.v.chars()
                .next()
                .filter(char::is_ascii_digit)
                .and_then(|_| lead_num(&vd.v))
        })
        .collect();
    nums.and_then(|n| n.into_iter().min())
}

#[derive(Debug, Deserialize)]
struct SigFile {
    #[serde(default)]
    software: Vec<SigDef>,
    #[serde(default)]
    os: Vec<SigDef>,
}

#[derive(Debug, Clone)]
struct Sig {
    def: SigDef,
    re: Regex,
}

/// A signature match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwMatch {
    pub id: String,
    pub name: String,
    pub ver: String,
    pub kind: String,
    pub released: Option<i32>,
    pub eol_date: Option<String>,
    /// Out of support with no exact end date.
    pub legacy: bool,
    /// The metadata string the signature matched.
    pub matched: String,
}

impl SwMatch {
    /// Returns `true` if the software is end-of-life on `today` (`YYYY-MM-DD`).
    pub fn is_eol(&self, today: &str) -> bool {
        self.legacy || self.eol_date.as_deref().is_some_and(|d| d < today)
    }
}

/// A compiled signature table.
#[derive(Debug, Clone)]
pub struct Signatures {
    software: Vec<Sig>,
    os: Vec<Sig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigError(pub String);

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn app_id(app: &str) -> String {
    match app.to_ascii_lowercase().as_str() {
        "powerpoint" => "ppt".into(),
        other => other.to_string(),
    }
}

fn alnum(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn ver_matches(key: &str, v: &str) -> bool {
    let (k, v) = (key.to_ascii_lowercase(), v.to_ascii_lowercase());
    v == k || v.starts_with(&format!("{k}.")) || v.starts_with(&format!("{k} "))
}

impl Signatures {
    /// Parses a signature TOML (the format is documented in `signatures/software.toml`).
    ///
    /// # Errors
    ///
    /// Returns [`SigError`] if the TOML is malformed or a pattern does not compile.
    pub fn parse(text: &str) -> Result<Signatures, SigError> {
        let f: SigFile = toml::from_str(text).map_err(|e| SigError(e.to_string()))?;
        let compile = |defs: Vec<SigDef>| -> Result<Vec<Sig>, SigError> {
            defs.into_iter()
                .map(|d| {
                    let re = Regex::new(&d.re).map_err(|e| SigError(format!("{}: {e}", d.id)))?;
                    Ok(Sig { def: d, re })
                })
                .collect()
        };
        Ok(Signatures {
            software: compile(f.software)?,
            os: compile(f.os)?,
        })
    }

    /// Returns the built-in table, compiled once.
    pub fn builtin() -> &'static Signatures {
        static S: OnceLock<Signatures> = OnceLock::new();
        S.get_or_init(|| match Signatures::parse(BUILTIN_TOML) {
            Ok(s) => s,
            // The table is embedded and covered by a test; an empty table is a safe fallback.
            Err(_) => Signatures {
                software: vec![],
                os: vec![],
            },
        })
    }

    pub fn len(&self) -> (usize, usize) {
        (self.software.len(), self.os.len())
    }

    fn find(list: &[Sig], s: &str, default_kind: &str) -> Option<SwMatch> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        for sig in list {
            let Some(c) = sig.re.captures(s) else {
                continue;
            };
            let d = &sig.def;
            let app = c
                .name("app")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let version = c
                .name("v")
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
            let ver_def = if version.is_empty() {
                None
            } else {
                d.versions
                    .iter()
                    .filter(|vd| ver_matches(&vd.v, &version))
                    .max_by_key(|vd| vd.v.len())
            };
            let key = ver_def.map(|vd| alnum(&vd.v)).unwrap_or_default();
            let subst = |t: &str| -> String {
                t.replace("{app_id}", &app_id(&app))
                    .replace("{app}", &app)
                    .replace("{version}", &version)
                    .replace("{ver_id}", &alnum(&version))
                    .replace("{key}", &key)
            };
            let id = match ver_def {
                Some(vd) => match &vd.id {
                    Some(t) => subst(t),
                    None if d.id.contains("{ver_id}") || d.id.contains("{key}") => subst(&d.id),
                    None => format!("{}{}", subst(&d.id), key),
                },
                None => subst(&d.id),
            };
            let name = match ver_def.and_then(|vd| vd.name.as_deref()) {
                Some(n) => subst(n),
                None => {
                    let base = subst(&d.name);
                    if !version.is_empty() && !d.name.contains("{version}") {
                        format!("{base} {version}")
                    } else {
                        base
                    }
                }
            };
            let below = ver_def.is_none()
                && legacy_threshold(d)
                    .zip(lead_num(&version))
                    .is_some_and(|(t, v)| v < t);
            return Some(SwMatch {
                id,
                name: name.trim().to_string(),
                ver: version,
                kind: d.kind.clone().unwrap_or_else(|| default_kind.to_string()),
                released: ver_def.and_then(|v| v.released).or(d.released),
                eol_date: ver_def
                    .and_then(|v| v.eol.clone())
                    .or_else(|| ver_def.is_none().then(|| d.eol.clone()).flatten()),
                legacy: ver_def.map(|v| v.legacy).unwrap_or(false) || d.legacy || below,
                matched: s.to_string(),
            });
        }
        None
    }

    pub fn match_software(&self, s: &str) -> Option<SwMatch> {
        Signatures::find(&self.software, s, "office")
    }

    pub fn match_os(&self, s: &str) -> Option<SwMatch> {
        Signatures::find(&self.os, s, "os")
    }
}

/// Returns the document's camera as "Make Model" without repeating the manufacturer.
pub fn camera_label(meta: &Metadata) -> Option<String> {
    let cam = meta.camera.as_ref()?;
    let make = cam.make.as_deref().unwrap_or("").trim();
    let model = cam.model.as_deref().unwrap_or("").trim();
    if make.is_empty() && model.is_empty() {
        return None;
    }
    let first = make.split_whitespace().next().unwrap_or("").to_lowercase();
    if !first.is_empty() && model.to_lowercase().starts_with(&first) {
        Some(model.to_string())
    } else {
        Some(format!("{make} {model}").trim().to_string())
    }
}

/// Returns candidate strings for signature matching in priority order (the first match is
/// the document's software).
pub fn candidates(meta: &Metadata) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: &str| {
        let s = s.trim();
        if !s.is_empty() && !out.iter().any(|x| x == s) {
            out.push(s.to_string());
        }
    };
    if let Some(cam) = &meta.camera {
        let make = cam.make.as_deref().unwrap_or("").trim();
        let model = cam.model.as_deref().unwrap_or("").trim();
        if !make.is_empty() || !model.is_empty() {
            let sw = meta
                .fields
                .get("exif:Software")
                .or(meta.application.as_ref())
                .map(|s| s.as_str())
                .unwrap_or("");
            if !sw.is_empty() {
                push(&format!("{make} {model} | {sw}"));
            }
            push(&format!("{make} {model}"));
        }
    }
    for s in &meta.software {
        push(s);
    }
    for s in [&meta.application, &meta.producer].into_iter().flatten() {
        push(s);
    }
    for k in [
        "xmp:CreatorTool",
        "pdf:Producer",
        "xmpMM:History/stEvt:softwareAgent",
    ] {
        if let Some(v) = meta.xmp.get(k) {
            push(v);
        }
    }
    if let Some(v) = meta.fields.get("exif:Software") {
        push(v);
    }
    out
}

/// Returns candidate strings for OS detection: the OS field (OLE), then the software strings
/// (platform hints such as `$Win32`, `(Windows)`, `Quartz PDFContext`, camera).
pub fn os_candidates(meta: &Metadata) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(os) = &meta.os {
        out.push(os.clone());
    }
    out.extend(candidates(meta));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sw(s: &str) -> SwMatch {
        Signatures::builtin()
            .match_software(s)
            .unwrap_or_else(|| panic!("no signature for {s}"))
    }

    #[test]
    fn table_parses() {
        let s = Signatures::parse(BUILTIN_TOML).unwrap();
        let (a, b) = s.len();
        assert!(a > 50 && b > 15, "{a} {b}");
    }

    /// Versions older than the table and the CS line are legacy (real-world strings).
    #[test]
    fn ancient_versions_are_legacy() {
        let old = [
            "Acrobat Distiller 3.0 for Power Macintosh",
            "Adobe PDF Library 8.00",
            "Skia/PDF m84",
            "Adobe Illustrator CS3",
            "Adobe InDesign CS3 (5.0)",
            "Adobe Illustrator 10.0",
        ];
        for s in old {
            assert!(sw(s).is_eol("2026-11-20"), "{s}");
        }
        for s in [
            "Adobe PDF Library 17.0",
            "Skia/PDF m131",
            "Adobe Illustrator 28.0",
            "Adobe InDesign 19.0",
        ] {
            assert!(!sw(s).is_eol("2026-11-20"), "{s}");
        }
    }

    #[test]
    fn office_versions() {
        let m = sw("Microsoft Office Word 15.0000");
        assert_eq!(
            (m.id.as_str(), m.eol_date.as_deref()),
            ("word2013", Some("2023-04-11"))
        );
        assert!(m.is_eol("2026-11-20"));
        assert_eq!(sw("Microsoft Excel 14.0300").id, "excel2010");
        assert_eq!(sw("Microsoft Office Excel 11.8000").id, "excel2003");
        assert_eq!(sw("Microsoft Office PowerPoint 12.0000").id, "ppt2007");
        let m = sw("Microsoft Office PowerPoint 16.0000");
        assert_eq!(m.id, "ppt2016");
        assert!(!m.is_eol("2026-11-20"), "16.0 is ambiguous (2016-2024/365)");
        assert_eq!(sw("Microsoft® Word 2013").id, "word2013");
        assert_eq!(
            sw("Microsoft® Word 2019").eol_date.as_deref(),
            Some("2025-10-14")
        );
        assert_eq!(sw("Microsoft® Excel® 2021").id, "excel2021");
        assert_eq!(sw("Microsoft® Word 2024").id, "word2024");
        assert!(!sw("Microsoft® Word 2024").is_eol("2026-11-20"));
        assert_eq!(sw("Microsoft® Word for Microsoft 365").id, "word365");
        assert_eq!(sw("Microsoft Office Word").id, "word");
        assert_eq!(sw("Microsoft Macintosh Word 12.0000").id, "macword2008");
        assert_eq!(sw("Microsoft Macintosh PowerPoint").id, "macppt");
        assert_eq!(sw("Microsoft: Print To PDF").id, "msprint2pdf");
    }

    #[test]
    fn office_suites_and_pdf() {
        let m = sw("LibreOffice/7.2.5.2$Windows_X86_64 LibreOffice_project/499f");
        assert_eq!((m.id.as_str(), m.ver.as_str()), ("lo72", "7.2.5.2"));
        assert!(m.is_eol("2026-11-20"));
        assert_eq!(sw("LibreOffice 25.8").id, "lo258");
        assert_eq!(
            sw("OpenOffice.org/3.2$Win32 OpenOffice.org_project/320m12").id,
            "ooo3"
        );
        assert_eq!(
            sw("OpenOffice/4.1.14$Win32 OpenOffice.org_project/4114m1").id,
            "aoo41"
        );
        assert_eq!(sw("Adobe Acrobat Pro XI 11.0.23").id, "acro11");
        assert_eq!(sw("Acrobat Distiller 9.0.0 (Windows)").id, "distiller9");
        assert_eq!(sw("Adobe PDF Library 15.0").id, "pdflib");
        assert_eq!(sw("GPL Ghostscript 9.50").ver, "9.50");
        assert_eq!(sw("pdfTeX-1.40.21").id, "pdftex");
        assert_eq!(sw("iText 2.1.7 by 1T3XT").id, "itext2");
        assert_eq!(sw("iText® 5.5.13 ©2000-2019 iText Group NV").id, "itext");
        assert_eq!(sw("Mac OS X 10.15.7 Quartz PDFContext").id, "quartz");
        assert_eq!(sw("PDFCreator 3.2.0").id, "pdfcreator");
    }

    #[test]
    fn images_cameras_scanners() {
        assert_eq!(sw("Adobe Photoshop CC 2019 (Windows)").id, "ps2019");
        assert_eq!(sw("Adobe Photoshop 7.0").id, "ps7");
        assert_eq!(sw("Adobe Photoshop CS6 (Windows)").id, "pscs6");
        assert_eq!(sw("GIMP 2.10.34").id, "gimp");
        assert_eq!(sw("Inkscape 1.1.2").id, "inkscape");
        let m = sw("Apple iPhone 13 Pro | 16.6");
        assert_eq!((m.id.as_str(), m.kind.as_str()), ("ios166", "camera"));
        assert_eq!(m.eol_date.as_deref(), Some("2024-09-16"));
        assert_eq!(sw("samsung SM-G991B | G991BXXU5CVF1").id, "android-samsung");
        assert_eq!(sw("Canon Canon EOS DIGITAL REBEL").id, "canon-camera");
        assert_eq!(sw("NIKON CORPORATION NIKON D750").id, "nikon");
        assert_eq!(sw("SONY ILCE-7M3").id, "sony-camera");
        assert_eq!(sw("Canon iR-ADV C5535 PDF 1.2").kind, "scanner");
        assert!(Signatures::builtin().match_software("16.6").is_none());
        assert!(Signatures::builtin()
            .match_software("1cestart.exe")
            .is_none());
    }

    #[test]
    fn os_detection() {
        let os = |s: &str| Signatures::builtin().match_os(s).map(|m| m.id);
        assert_eq!(os("Windows 7/Server 2008 R2").as_deref(), Some("win7"));
        assert_eq!(os("Windows XP x64/Server 2003").as_deref(), Some("winxp64"));
        assert_eq!(os("Windows XP").as_deref(), Some("winxp"));
        assert_eq!(os("Windows 10/11").as_deref(), Some("win10"));
        assert_eq!(os("Macintosh").as_deref(), Some("macos"));
        assert_eq!(
            os("Mac OS X 10.15.7 Quartz PDFContext").as_deref(),
            Some("macos10")
        );
        assert_eq!(os("Apple iPhone 13 Pro | 16.6").as_deref(), Some("ios166"));
        assert_eq!(
            os("Adobe Photoshop CC 2019 (Windows)").as_deref(),
            Some("windows")
        );
        assert_eq!(
            os("LibreOffice/7.2.5.2$Windows_X86_64 LibreOffice_project").as_deref(),
            Some("windows")
        );
        assert_eq!(os("GPL Ghostscript 9.50"), None);
    }
}
