//! Document forensics records attached to [`crate::Metadata`]: XMP edit history, digital
//! signatures (PDF, OOXML, VBA) with Ukrainian qualified certificate fields, PDF revisions,
//! bad redactions and hidden content.

use serde::{Deserialize, Serialize};

/// One `xmpMM:History` event (`stEvt:*`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct XmpEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Normalized date of the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// Changed parts (`/`, `/metadata`, `/content`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<String>,
    /// Free-form parameters (`converted from image/png to image/jpeg`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<String>,
}

/// XMP Media Management identifiers used to correlate copies and derivatives.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct XmpIds {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_document_id: Option<String>,
    /// `xmpMM:DerivedFrom/stRef:documentID`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_from_document_id: Option<String>,
    /// `xmpMM:DerivedFrom/stRef:instanceID`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_from_instance_id: Option<String>,
}

impl XmpIds {
    pub fn is_empty(&self) -> bool {
        *self == XmpIds::default()
    }
}

/// Container that carries a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureKind {
    /// PDF `/Sig` field with a PKCS#7/CMS blob in `/Contents`.
    Pdf,
    /// OOXML `_xmlsignatures/*.xml` (XML-DSig).
    Ooxml,
    /// `vbaProjectSignature.bin` (Authenticode-style PKCS#7 over the VBA project).
    Vba,
    /// Authenticode signature in the PE certificate table.
    Authenticode,
    /// JAR/APK signature block (`META-INF/*.RSA`, `*.DSA`, `*.EC`).
    Jar,
    /// A CMS/PKCS#7 SignedData file wrapping the document (Ukrainian КЕП `.p7s`, a signed
    /// `.pdf` published as such a wrapper).
    Cms,
}

/// Identity fields of an X.509 certificate. Personal tax numbers are never stored in full.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CertInfo {
    /// Full subject DN (RFC 4514-like), with the personal tax number masked.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_unit: Option<String>,
    /// Job title (`T`, 2.5.4.12).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Ukrainian legal entity code (ЄДРПОУ), 8 digits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edrpou: Option<String>,
    /// Ukrainian personal tax number (РНОКПП), always masked (`********78`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rnokpp_masked: Option<String>,
    /// Whether the (unstored) personal tax number has a valid check digit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rnokpp_valid: Option<bool>,
    /// Issuer DN (the certification authority, АЦСК/КНЕДП).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_cn: Option<String>,
    /// Certificate serial number, hex.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub serial: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

/// RFC 3161 time-stamp token (`TSTInfo`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Timestamp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gen_time: Option<String>,
    /// `TSTInfo.tsa` general name, or the TSA certificate subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsa: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
}

/// A digital signature found in a document. Only extraction and coverage checks are done;
/// the certificate chain is not validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub kind: SignatureKind,
    /// Where it was found (`pdf:obj 12`, `_xmlsignatures/sig1.xml`, `vbaProjectSignature.bin`).
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<CertInfo>,
    /// Number of certificates embedded in the signature.
    #[serde(default)]
    pub certificates: u32,
    /// Claimed signing time (CMS `signingTime`, PDF `/M`, XAdES `SigningTime`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
    /// Digest algorithm name or OID (`sha256`, `1.2.804.2.1.1.1.1.2.1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_algorithm: Option<String>,
    /// PDF `/SubFilter` (`adbe.pkcs7.detached`, `ETSI.CAdES.detached`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_filter: Option<String>,
    /// PDF `/Name`, `/Reason`, `/Location`, `/ContactInfo`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// PDF `/ByteRange` `[a b c d]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub byte_range: Vec<u64>,
    /// Bytes of the file after the signed range (an incremental update after signing when
    /// non-zero).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_after: Option<u64>,
    /// The file was changed after this signature was applied.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub modified_after_signing: bool,
    /// `messageDigest` matches the signed bytes (`None` if not checked).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_valid: Option<bool>,
}

/// One incremental revision of a PDF (1 is the oldest).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PdfRevision {
    pub revision: u32,
    /// Offset just after this revision's `%%EOF`.
    pub end_offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    /// Objects written in this revision.
    pub objects: u32,
    /// Text lines present in the previous revision but gone in this one (truncated).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub removed_text: Vec<String>,
    /// Text lines added in this revision (truncated).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub added_text: Vec<String>,
}

/// Text that is still present in a PDF content stream under an opaque filled rectangle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BadRedaction {
    /// Page number starting at 1.
    pub page: u32,
    /// Short fragment of the covered text.
    pub text: String,
    /// `black` or `white`.
    pub fill: String,
    /// Covering rectangle in page space `[x0, y0, x1, y1]`.
    pub rect: [f32; 4],
}

/// Hidden but recoverable content (Word `w:vanish`, hidden Excel rows/columns).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenContent {
    /// `vanish`, `row`, `column`.
    pub kind: String,
    /// Part and position (`word/document.xml`, `Sheet1!5`, `Sheet1!C:D`).
    pub location: String,
    /// Text fragment (empty for rows/columns without cached text).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
}

/// Personal data of one kind found in a document (text and metadata strings). Holds only
/// masked samples: the full values never leave the parser/analysis boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PiiFound {
    /// `rnokpp` | `edrpou` | `iban` | `card` | `passport` | `id_card` | `phone` | `marking`.
    pub kind: String,
    pub sev: crate::severity::Severity,
    pub count: u32,
    /// Up to three masked context lines (`… ІПН ********90 …`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub samples: Vec<String>,
    /// Non-sensitive details: card brands, the marking text.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
    /// First location (`текст, строка 3`, `поле description`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub location: String,
}
