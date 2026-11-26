# foca-meta

↑ [Core Crates](README.md) · [Developer Guide](../README.md) · [Architecture](../architecture.md)

- [Purpose](#purpose)
- [Modules](#modules)
- [Public API](#public-api)
- [Tests](#tests)
- [Pitfalls](#pitfalls)

Path: `crates/foca-meta/` · `src/` lines: 17,493 · tests: 83 · depends on: [foca-core](foca-core.md)

## Purpose

`foca-meta` performs pure, offline document metadata extraction, forensic inspection, hygiene grading, and verified metadata cleaning (`F-10`-`F-12`, `I-1`-`I-3`, `I-7`).

All functions are pure (no network, no filesystem): bytes in, `Metadata` / clean bytes out.

- `extract`: detects format strictly by magic signature (filename is used only as a hint for plain-text RDP/ICA files) and extracts structured metadata and forensics records.
- `text`: extracts plain text for secret/PII scanning and full-text indexing (`I-4`).
- `clean` / `clean_with_options` / `clean_and_verify`: strips metadata from OOXML, ODF, PDF (full rewrite), JPEG, and PNG, then re-parses the cleaned copy (`src/verify.rs`) to compute a before/after field diff and hygiene verdict.
- `hygiene`: `grade_document` / `grade_set` assigns an A-F hygiene grade with structured `IssueCode` items and concrete `FixCode` steps.
- `detect`: signature-only format detection.
- `for_each_zip_member`: streams ZIP archive entries in memory under a shared decompression budget.

### Supported Formats & Forensics

- **Office & Documents**: OOXML (`docx`/`xlsx`/`pptx`), ODF (`odt`/`ods`/`odp`/`odg`, StarOffice), OLE2 (`doc`/`xls`/`ppt` 97-2003), PDF (in-house parser, no `lopdf`), Visio (`.vsdx`/`.vsdm`), Publisher (`.pub`), InDesign (`.indd`/`.indt`), WordPerfect (`.wpd`) & Works, EPUB (`.epub`).
- **Mail, PIM & Remote**: EML (RFC 5322/MIME), Outlook MSG (MS-OXMSG), iCalendar (`.ics`), vCard (`.vcf`), Windows Shell Links (`.lnk`), RDP & Citrix ICA.
- **Images, Media & Archives**: JPEG/PNG/TIFF (EXIF, XMP, GPS, thumbnail mismatch `thumbcmp.rs`), SVG, Photoshop (`.psd`/`.psb`), MP4/MOV/HEIF/HEIC/AVIF (`formats/media/isobmff.rs`), MP3 (ID3v1/ID3v2, `formats/media/mp3.rs`), ZIP (`formats/archive/zipfile.rs` with recursive child extraction and Zip-Slip detection), 7-Zip (`.7z`, `formats/archive/sevenz.rs`).
- **Forensics (`foca_core::forensics`)**: XMP edit history & document IDs (`xmp.rs`), PDF incremental revisions with text diff & scan-without-text detection (`formats/pdf/mod.rs`), broken PDF redaction detector (`formats/pdf/redaction.rs`), hidden OOXML text/rows/columns (`formats/office/ooxml.rs`), PDF/OOXML/VBA CMS/PKCS#7 & RFC 3161 digital signatures (`formats/signature/mod.rs`), and Ukrainian qualified electronic signature (KEP) certificate fields (`formats/signature/kep.rs`, with RNOKPP strictly masked).

### Security Model (`N-3`)

All input files are untrusted: zero `unwrap()`/`panic!` on input data, bounds-checked reads throughout, shared decompression byte budgets via `Limits`, bounded attachment recursion and XML nesting depth, no XXE entity expansion in `quick-xml`, and cycle/depth guards on PDF indirect references.

Reference corpus: [tests/corpus/SOURCES.md](../../../tests/corpus/SOURCES.md) (`tests/golden.rs`).

## Modules

Layout and dependency direction (lower rows never use higher ones):

- `lib.rs`: public entry points; builds the parse context `Ctx` and dispatches by detected format.
- `verify.rs`, `hygiene.rs`: use `clean/` and `extract`.
- `clean/`: cleaners per format; the shared vocabulary lives in `clean/output.rs`. Format parsers never depend on it (OLE and ISO BMFF rewrites return plain bytes).
- `formats/`: one module per family (`office/`, `pdf/`, `media/`, `mail/`, `archive/`, `signature/`) plus `formats/detect.rs`. Embedded documents are parsed through `Ctx::attach_child` / `Ctx::extract_child`, which call back into the dispatcher injected by `lib.rs`.
- `util.rs`, `xml.rs`, `xmp.rs`, `zipx.rs`, `paths.rs`, `thumbcmp.rs`: leaf primitives.

| File | Lines | Contents |
|---|---|---|
| `src/lib.rs` | 433 | Top-level `extract`, `text`, `Limits`, `MetaError`, parse context `Ctx` (limits, budget, embedded-document parser), re-exports |
| `src/formats/archive/epub.rs` | 169 | EPUB e-book container (`.epub`) metadata & OPF/DC fields |
| `src/formats/archive/sevenz.rs` | 214 | 7-Zip archive container (`.7z`) header & entry inspection |
| `src/formats/archive/zipfile.rs` | 173 | Plain ZIP archives: entries, timestamps, archive comment, Zip-Slip detection, `for_each_zip_member` |
| `src/formats/detect.rs` | 235 | Magic-signature format detection (file extensions untrusted) |
| `src/formats/lnk.rs` | 352 | Windows shell links (`.lnk`, MS-SHLLINK): LinkInfo, UNC/local paths, timestamps, machine IDs |
| `src/formats/mail/eml.rs` | 1,171 | Internet messages (`.eml`, RFC 5322 / MIME): headers, `Received` hops, attachments |
| `src/formats/mail/ics.rs` | 415 | iCalendar (`.ics`, RFC 5545): organizers, attendees, producers, events |
| `src/formats/mail/msg.rs` | 395 | Outlook messages (`.msg`, MS-OXMSG OLE2 compound file) |
| `src/formats/mail/vcf.rs` | 213 | vCard (`.vcf` 2.1-4.0): names, e-mails, phones, organizations |
| `src/formats/media/image.rs` | 495 | JPEG/PNG/TIFF: EXIF camera/serials/software/dates/GPS, IPTC, XMP |
| `src/formats/media/indesign.rs` | 74 | Adobe InDesign (`.indd`/`.indt`): master-page header and embedded XMP |
| `src/formats/media/isobmff.rs` | 804 | ISO Base Media files (MP4, QuickTime MOV, HEIF/HEIC/AVIF), including in-place cleaning |
| `src/formats/media/mp3.rs` | 281 | MPEG Audio Layer III (`.mp3`): ID3v2.2/2.3/2.4 and ID3v1 tags |
| `src/formats/media/psd.rs` | 196 | Adobe Photoshop (`.psd`/`.psb`, `8BPS`): image resources & embedded XMP |
| `src/formats/media/svg.rs` | 82 | SVG: RDF metadata, Inkscape/Sodipodi paths and export attributes |
| `src/formats/office/legacy_office.rs` | 100 | Legacy office formats: WordPerfect (`.wpd`) and Microsoft Works |
| `src/formats/office/odf.rs` | 255 | ODF (`odt`/`ods`/`odp`/`odg`) and StarOffice 1.x |
| `src/formats/office/ole.rs` | 1,046 | OLE2 (`doc`/`xls`/`ppt` 97-2003): property sets, user names, OLE cleaning |
| `src/formats/office/ooxml.rs` | 1,076 | OOXML (`docx`/`xlsx`/`pptx`): core/app/custom props, comments, tracked changes, connections, hidden content |
| `src/formats/office/publisher.rs` | 38 | Microsoft Publisher (`.pub`, OLE2 property sets) |
| `src/formats/office/visio.rs` | 179 | Microsoft Visio (`.vsd`, `.vsdx`/`.vsdm`) |
| `src/formats/pdf/mod.rs` | 1,443 | In-house PDF parser (no `lopdf`): object table, trailers, Info, XMP, revisions, text, signatures |
| `src/formats/pdf/redaction.rs` | 589 | Bad-redaction detector over PDF content streams |
| `src/formats/pdf/syntax.rs` | 475 | PDF object model, lexer and string decoding, shared by parsing, redaction scan and cleaning |
| `src/formats/remote.rs` | 124 | RDP and Citrix ICA configuration files |
| `src/formats/signature/kep.rs` | 153 | Ukrainian qualified electronic signature (KEP) certificate OIDs & masked RNOKPP |
| `src/formats/signature/mod.rs` | 757 | Digital signatures: CMS/PKCS#7 (PDF `/Contents`, VBA), OOXML XML-DSig, RFC 3161 timestamps |
| `src/clean/mod.rs` | 154 | Cleaning entry points (`clean`, `clean_with_options`, `can_clean`) and per-format dispatch |
| `src/clean/odf.rs` | 388 | OpenDocument cleaner (uncompressed `mimetype` first, stripped `meta.xml`/`settings.xml`, no thumbnails/signatures) |
| `src/clean/ooxml.rs` | 372 | OOXML cleaner: empty core/app/custom parts, blanked authors, template/printer/connection paths |
| `src/clean/output.rs` | 71 | `CleanOptions`, `CleanOutput`, `CleanWarning` |
| `src/clean/pdf.rs` | 457 | Full PDF rewrite keeping only reachable catalog objects, single xref/`%%EOF`, stripping Info/XMP/revisions/signatures |
| `src/clean/raster.rs` | 82 | JPEG/PNG cleaners, also used for images embedded in office packages and PDFs |
| `src/hygiene.rs` | 637 | Document hygiene grade (A-F), penalties, `IssueCode`, and concrete `FixCode` steps |
| `src/verify.rs` | 514 | Post-clean self-verification: re-parses cleaned output, diffs fields, checks remaining sensitive data |
| `src/paths.rs` | 470 | Path and e-mail extraction from text and metadata fields (FOCA PathAnalysis style) |
| `src/thumbcmp.rs` | 151 | Pixel comparison between an EXIF thumbnail and the main photo |
| `src/util.rs` | 362 | Shared decoding, date parsing, and bounds-checked integer helpers |
| `src/xml.rs` | 319 | Depth- and node-bounded minimal XML DOM over `quick-xml` |
| `src/xmp.rs` | 410 | XMP (RDF/XML) flattening and mapping onto `Metadata` / `xmp_history` |
| `src/zipx.rs` | 169 | Safe ZIP helper with entry cap and shared decompression byte budget |
| `src/tests/new_formats.rs` | 745 | Unit tests for 1.3 and 2.0 formats |
| `src/tests/robust.rs` | 212 | Robustness tests: random bytes, mutated signatures, zip bombs, limits |

## Public API

Re-exports in `src/lib.rs`:

- `foca_core::{DocFormat, Metadata}`
- `formats::archive::zipfile::for_each_zip_member`
- `clean::{clean, clean_with_limits, clean_with_options, CleanOptions, CleanOutput, CleanWarning, ...}`
- `formats::detect::detect`
- `hygiene::{grade_document, grade_set, FixCode, Grade, HygieneIssue, HygieneReport, IssueCode, ...}`
- `paths::{analyze_path, find_emails, find_paths, PathInfo}`
- `verify::{clean_and_verify, verify_clean, ChangeKind, CleanResult, FieldChange, VerifyReport}`

Top-level items: `extract()`, `text()`, `Limits`, `MetaError` (`ZipBomb`, `TooManyEntries`, `TooLarge`, ...), and module `thumbcmp`.

Full API docs: `cargo doc -p foca-meta --no-deps --open`.

## Tests

`cargo test -p foca-meta`: 52 unit tests in `src/` + 30 integration tests in `tests/`:

| File | Tests |
|---|---|
| `tests/forensics.rs` | 253 |
| `tests/golden.rs` | 346 |
| `tests/hygiene.rs` | 487 |
| `tests/thumbcmp.rs` | 70 |

## Pitfalls

- Never call `unwrap()` or `panic!` on document bytes. Engine calls still wrap `extract` in `catch_unwind` (requiring `panic = "unwind"`, [ADR-0005](../../adr/0005-panic-strategy.md)).
- Format detection is magic-byte driven (`formats/detect.rs`); file extensions are ignored except as hints for text RDP/ICA.
- `Limits` decompression budgets are shared across a parent document and all nested attachments to stop zip bombs.
- OLE2 embedded signatures (`\x05DigitalSignature`, `_VBA_PROJECT_CUR` in legacy `.doc`/`.xls`) are not parsed; Word style-inherited `w:vanish` is not resolved.
- Redaction detection approximates glyph width at ~0.5 em, ignores form XObjects/transparency/clipping, and skips boxes > 80% of `MediaBox`. Revision text diffs skip PDFs with `pages × revisions > 5000`.
- Signature digest verification (`digest_valid`) covers SHA-256/384/512 only (`None` for DSTU/GOST/SHA-1); certificate chains are not validated online.
- PDF plain-text extraction skips `/Contents` of signature dictionaries (binary PKCS#7) so binary noise never pollutes FTS5.
- JPEGs larger than 100 MP are skipped by `thumbcmp.rs` to prevent OOM.
