//! Result of parsing a single document (`foca-meta::extract`).
//!
//! All fields are optional; empty ones are skipped during serialization so the JSON stays
//! compact and stable for golden tests. Dates are ISO 8601 strings (`2024-03-14T18:42:00Z`
//! when the offset is known, otherwise without an offset suffix).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Document format, detected by signature rather than by file extension.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocFormat {
    Docx,
    Xlsx,
    Pptx,
    Odt,
    Ods,
    Odp,
    Odg,
    /// StarOffice/OpenOffice 1.x (sxw, sxc, sxi).
    Sxw,
    Pdf,
    Jpeg,
    Png,
    Tiff,
    Doc,
    Xls,
    Ppt,
    /// Any other OLE2 container (msg, vsd, ...); only property sets are read.
    Ole,
    Svg,
    Rdp,
    Ica,
    /// Windows shell link (MS-SHLLINK).
    Lnk,
    /// Internet message (RFC 5322 / MIME).
    Eml,
    /// Outlook message (MS-OXMSG, OLE2).
    Msg,
    /// Visio 2013+ drawing (OPC package).
    Vsdx,
    /// Visio 2003-2010 drawing (OLE2).
    Vsd,
    /// Microsoft Publisher (OLE2).
    Pub,
    /// Adobe InDesign document.
    Indd,
    /// WordPerfect document.
    Wpd,
    /// Microsoft Works word processor document.
    Wps,
    /// Microsoft Works spreadsheet.
    Wks,
    /// iCalendar.
    Ics,
    /// vCard.
    Vcf,
    /// ISO base media file (MPEG-4).
    Mp4,
    /// QuickTime movie.
    Mov,
    /// HEIF/HEIC/AVIF image.
    Heic,
    /// Plain ZIP archive (not an office package).
    Zip,
    /// EPUB e-book container (ZIP + OPF/Dublin Core).
    Epub,
    /// MPEG-1/2 Audio Layer III with ID3v1/ID3v2 tags.
    Mp3,
    /// Adobe Photoshop document (8BPS + 8BIM Image Resources / XMP / EXIF).
    Psd,
    /// 7-Zip archive container.
    SevenZ,
    /// Windows PE executable or library (exe, dll, sys, scr).
    Exe,
    /// Windows Installer package (OLE2 summary information).
    Msi,
    /// Java archive (jar, war, ear) with `META-INF/MANIFEST.MF`.
    Jar,
    /// Android package (apk, aab).
    Apk,
    /// AutoCAD binary drawing.
    Dwg,
    /// AutoCAD drawing exchange format (text).
    Dxf,
    /// PostScript, EPS or Illustrator file with DSC comments.
    Eps,
    /// Windows enhanced metafile.
    Emf,
    /// Windows metafile (placeable or plain).
    Wmf,
    /// Tape archive (ustar/GNU).
    Tar,
    /// Gzip stream (RFC 1952).
    Gzip,
    /// Bzip2 stream.
    Bzip2,
    /// XZ stream.
    Xz,
    /// RAR archive (v4 or v5).
    Rar,
    /// RIFF WAVE audio.
    Wav,
    /// RIFF AVI video.
    Avi,
    /// Matroska or WebM (EBML).
    Mkv,
    /// Advanced Systems Format (wmv, wma, asf).
    Asf,
    /// FLAC audio with Vorbis comments.
    Flac,
    /// Ogg container (Vorbis, Opus) with Vorbis comments.
    Ogg,
    /// Keyhole Markup Language (Google Earth).
    Kml,
    /// Zipped KML.
    Kmz,
    /// GPS exchange format.
    Gpx,
    /// JavaScript source map (JSON).
    SourceMap,
    /// Jupyter notebook (JSON).
    Ipynb,
    #[default]
    Unknown,
}

impl DocFormat {
    /// Returns the typical file extension.
    pub fn ext(self) -> &'static str {
        match self {
            DocFormat::Docx => "docx",
            DocFormat::Xlsx => "xlsx",
            DocFormat::Pptx => "pptx",
            DocFormat::Odt => "odt",
            DocFormat::Ods => "ods",
            DocFormat::Odp => "odp",
            DocFormat::Odg => "odg",
            DocFormat::Sxw => "sxw",
            DocFormat::Pdf => "pdf",
            DocFormat::Jpeg => "jpg",
            DocFormat::Png => "png",
            DocFormat::Tiff => "tiff",
            DocFormat::Doc => "doc",
            DocFormat::Xls => "xls",
            DocFormat::Ppt => "ppt",
            DocFormat::Ole => "ole",
            DocFormat::Svg => "svg",
            DocFormat::Rdp => "rdp",
            DocFormat::Ica => "ica",
            DocFormat::Lnk => "lnk",
            DocFormat::Eml => "eml",
            DocFormat::Msg => "msg",
            DocFormat::Vsdx => "vsdx",
            DocFormat::Vsd => "vsd",
            DocFormat::Pub => "pub",
            DocFormat::Indd => "indd",
            DocFormat::Wpd => "wpd",
            DocFormat::Wps => "wps",
            DocFormat::Wks => "wks",
            DocFormat::Ics => "ics",
            DocFormat::Vcf => "vcf",
            DocFormat::Mp4 => "mp4",
            DocFormat::Mov => "mov",
            DocFormat::Heic => "heic",
            DocFormat::Zip => "zip",
            DocFormat::Epub => "epub",
            DocFormat::Mp3 => "mp3",
            DocFormat::Psd => "psd",
            DocFormat::SevenZ => "7z",
            DocFormat::Exe => "exe",
            DocFormat::Msi => "msi",
            DocFormat::Jar => "jar",
            DocFormat::Apk => "apk",
            DocFormat::Dwg => "dwg",
            DocFormat::Dxf => "dxf",
            DocFormat::Eps => "eps",
            DocFormat::Emf => "emf",
            DocFormat::Wmf => "wmf",
            DocFormat::Tar => "tar",
            DocFormat::Gzip => "gz",
            DocFormat::Bzip2 => "bz2",
            DocFormat::Xz => "xz",
            DocFormat::Rar => "rar",
            DocFormat::Wav => "wav",
            DocFormat::Avi => "avi",
            DocFormat::Mkv => "mkv",
            DocFormat::Asf => "wmv",
            DocFormat::Flac => "flac",
            DocFormat::Ogg => "ogg",
            DocFormat::Kml => "kml",
            DocFormat::Kmz => "kmz",
            DocFormat::Gpx => "gpx",
            DocFormat::SourceMap => "map",
            DocFormat::Ipynb => "ipynb",
            DocFormat::Unknown => "bin",
        }
    }

    pub fn is_ooxml(self) -> bool {
        matches!(self, DocFormat::Docx | DocFormat::Xlsx | DocFormat::Pptx)
    }

    pub fn is_image(self) -> bool {
        matches!(self, DocFormat::Jpeg | DocFormat::Png | DocFormat::Tiff)
    }
}

/// Where in the document a person was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonRole {
    Author,
    LastModifiedBy,
    Creator,
    Comment,
    Revision,
    /// From a path such as `C:\Users\<user>`.
    PathUser,
    /// Account from an RDP/ICA file.
    Account,
    /// Camera owner or EXIF Artist.
    Owner,
    PrintedBy,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PersonRef {
    pub name: String,
    pub role: PersonRole,
    /// Source field (`core.xml:dc:creator`, `comments.xml`, `path`, ...).
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    /// `C:\...`
    Windows,
    /// `\\server\share\...`
    Unc,
    /// `/home/...`, `/Users/...`
    Unix,
    /// `file://...`
    FileUrl,
}

/// A path found in a document, with the user and host derived from it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathRef {
    pub path: String,
    pub kind: PathKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerRef {
    pub name: String,
    pub source: String,
}

/// A secret from metadata (a password in .rdp/.ica and similar). Stored verbatim; the UI masks it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretRef {
    pub kind: String,
    pub value: String,
    pub source: String,
}

/// A comment (Word/Excel/PowerPoint comment or ODF annotation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initials: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionKind {
    Insert,
    Delete,
    Format,
    Other,
}

/// A tracked change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionRef {
    pub kind: RevisionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// Text of the change (deleted text is especially valuable), truncated to 512 characters.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
}

/// A previous version of the metadata (incremental PDF revision, Word save history).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OldVersion {
    /// Revision number starting at 1 (1 is the oldest).
    pub revision: u32,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
}

/// An embedded document, parsed recursively.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Embedded {
    pub name: String,
    pub metadata: Box<Metadata>,
}

/// GPS position in decimal degrees (south and west are negative).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Gps {
    pub lat: f64,
    pub lon: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Camera {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub make: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

/// EXIF thumbnail (IFD1), used to detect a thumbnail that differs from the photo. Base64 in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thumbnail {
    pub mime: String,
    #[serde(with = "crate::b64")]
    pub data: Vec<u8>,
    /// Whether the thumbnail differs noticeably from the photo (pixel comparison in `foca-meta`).
    /// `None` if not compared or the comparison failed; no thumbnail finding is raised then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub differs: Option<bool>,
}

/// A geographic point from geodata (KML, GPX, ...).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoPoint {
    pub lat: f64,
    pub lon: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Where it was found (`kml:Placemark`, `gpx:trkpt`, ...).
    pub source: String,
}

/// Signs that an image was made by a generative AI tool.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AiGenerated {
    /// Generator (`ComfyUI`, `Automatic1111`, C2PA claim generator, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Prompt text, truncated. Shown on the document card only, never in reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Where the evidence was found (`png:parameters`, `c2pa`, `xmp:DigitalSourceType`).
    pub source: String,
}

/// A data connection (spreadsheet connection, Power Query source, mail merge data source).
/// Passwords are never stored: `has_password` only records that one was present.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DataConnection {
    /// `odbc`, `oledb`, `web`, `text`, `powerquery`, `mailmerge`, ...
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// URL, file path or query target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub has_password: bool,
    pub source: String,
}

/// One hop of a mail transport path (`Received:` header), newest first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MailHop {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// The sending side is a private or internal address.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub internal: bool,
}

/// A form field (PDF AcroForm) with its current or default value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FormField {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Document metadata.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Metadata {
    pub format: DocFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
    /// Template (name or path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Creating application (app.xml Application, PDF Creator, ODF generator, EXIF Software).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    /// PDF Producer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Document revision number, as recorded in the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// Total editing time in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edit_time_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub printed: Option<String>,
    /// Statistics: pages, words, characters, lines, paragraphs, slides, notes, ...
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub stats: BTreeMap<String, u64>,
    /// Custom properties (custom.xml, meta:user-defined, DocumentSummary user section).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, String>,
    /// All people with their roles (including author and last_modified_by).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub people: Vec<PersonRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<PathRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<ServerRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub printers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub software: Vec<String>,
    /// Hyperlinks and external links.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<CommentRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub revisions: Vec<RevisionRef>,
    /// Word editing session RSIDs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rsids: Vec<String>,
    /// Hidden Excel sheets (`hidden`/`veryHidden`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hidden_sheets: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub has_macros: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub macro_modules: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub has_javascript: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub encrypted: bool,
    /// Number of incremental PDF updates (0 means the file was saved once).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incremental_updates: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub old_versions: Vec<OldVersion>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub embedded: Vec<Embedded>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gps: Option<Gps>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub camera: Option<Camera>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<Thumbnail>,
    /// Flattened XMP pairs (`dc:creator`, `xmp:CreatorTool`, ...).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub xmp: BTreeMap<String, String>,
    /// Other raw format fields (EXIF tags, RDP keys, PDF Info entries, ...).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    /// Non-fatal parse problems.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Structured `xmpMM:History` events (the flat `xmp` keys are kept as well).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub xmp_history: Vec<crate::XmpEvent>,
    /// `xmpMM:DocumentID`/`InstanceID`/`DerivedFrom` for clone correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xmp_ids: Option<crate::XmpIds>,
    /// Digital signatures (PDF, OOXML, VBA).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<crate::Signature>,
    /// Incremental PDF revisions with per-revision metadata and text diff.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pdf_revisions: Vec<crate::PdfRevision>,
    /// Text left under opaque redaction boxes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bad_redactions: Vec<crate::BadRedaction>,
    /// The document consists of page images only (a scan without a text layer).
    #[serde(skip_serializing_if = "is_false")]
    pub scan_without_text: bool,
    /// Hidden text, rows and columns.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hidden_content: Vec<crate::HiddenContent>,
    /// Personal data summary computed before storage (values are masked; the raw text and
    /// metadata strings are masked at the same time, see `foca-analysis::pii::sanitize`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pii: Vec<crate::PiiFound>,
    /// Points from geodata (KML/GPX), capped.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub geo_points: Vec<GeoPoint>,
    /// Generative AI markers (PNG generator parameters, C2PA digital source type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_generated: Option<AiGenerated>,
    /// Data connections (spreadsheets, Power Query, mail merge). Passwords are never stored.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<DataConnection>,
    /// Mail transport hops from `Received:` headers, newest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mail_hops: Vec<MailHop>,
    /// Fonts used by the document (subset prefixes stripped).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fonts: Vec<String>,
    /// Form fields with values (PDF AcroForm).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub form_fields: Vec<FormField>,
}

impl Metadata {
    pub fn new(format: DocFormat) -> Self {
        Metadata {
            format,
            ..Default::default()
        }
    }

    /// Adds a person unless already present; empty and whitespace-only names are ignored.
    pub fn add_person(&mut self, name: &str, role: PersonRole, source: &str) {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        let p = PersonRef {
            name: name.to_string(),
            role,
            source: source.to_string(),
        };
        if !self
            .people
            .iter()
            .any(|x| x.name == p.name && x.role == p.role)
        {
            self.people.push(p);
        }
    }

    pub fn add_server(&mut self, name: &str, source: &str) {
        let name = name.trim();
        if name.is_empty()
            || self
                .servers
                .iter()
                .any(|s| s.name.eq_ignore_ascii_case(name))
        {
            return;
        }
        self.servers.push(ServerRef {
            name: name.to_string(),
            source: source.to_string(),
        });
    }

    pub fn add_unique(list: &mut Vec<String>, value: &str) {
        let v = value.trim();
        if !v.is_empty() && !list.iter().any(|x| x == v) {
            list.push(v.to_string());
        }
    }

    /// Returns the unique person names (for quick checks and the UI).
    pub fn person_names(&self) -> Vec<&str> {
        let mut v: Vec<&str> = Vec::new();
        for p in &self.people {
            if !v.contains(&p.name.as_str()) {
                v.push(&p.name);
            }
        }
        v
    }
}
