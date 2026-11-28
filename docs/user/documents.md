# Documents: Formats, Forensics, Search, Rules & Offline Analysis

↑ [User Guide](README.md) · [Documentation](../README.md)

FOCA-rs parses a wide matrix of office, archive, messaging, publishing, and media formats, surfacing hidden information that lives alongside visible text: digital signatures and Ukrainian QES (КЕП), incremental PDF revisions, broken redactions, hidden content, embedded OLE objects, and personal data (PII). Short offline summaries are also available in ⋮ → Help → Documents & forensics.

- [Supported Formats](#supported-formats)
- [Forensics in the Document Card](#forensics-in-the-document-card)
- [Personal Data (PII)](#personal-data-pii)
- [Full-Text Document Search](#full-text-document-search)
- [Custom Search Rules](#custom-search-rules)
- [Offline File & Folder Analysis](#offline-file--folder-analysis)
- [Re-analyse Documents](#re-analyse-documents)
- [Optional Offline OCR (Play Flavor)](#optional-offline-ocr-play-flavor)
- [Limitations](#limitations)

## Supported Formats

| Format | What is extracted |
|---|---|
| Office (`DOC`/`DOCX`, `XLS`/`XLSX`, `PPT`/`PPTX`), OpenDocument (`ODT`/`ODS`/`ODP`), `RTF` | Author, last modifier, company, template, disk/UNC paths, printers, tracked changes & comments, hidden Word text (`w:vanish`), hidden Excel rows/columns/sheets, data connections with redacted passwords, Power Query sources, external links, mail merge sources, fonts, document variables, URLs, paths and hosts found in VBA macros (never the full source), pivot tables, XML-DSig & VBA macro signatures; deep binary OLE2 extraction (`\x01Ole10Native` embedded files, original/temp paths, `SttbSavedBy` revision authors); embedded OLE objects (whole Word/Excel/PowerPoint documents, `Package` parts, PowerPoint `ExOleObjStg`) and pictures parsed recursively (depth 3, shared size budget), picture source paths and alt text from drawing properties, the `CompObj` product name; `XLS`/`XLSB` cell text, sheet and defined names, external workbook paths, comments with authors, data validation lists (numbers only when they look like IDs or phone/card/account numbers); `PPT` slide and notes text, comment authors, save count; `RTF` info group (author, operator, company, dates, counts), generator, user properties, revision and comment authors, hidden and deleted text, `HYPERLINK`/`INCLUDEPICTURE`/`DDE` targets, embedded objects and pictures, code pages (`\ansicpg`, font charsets, `\uN`); `ODF` printer, driver and port from `settings.xml`; document thumbnails; hidden ODF/PPTX sheets, rows and slides; encrypted OOXML in a compound file; visually hidden text (white on white, font colour equal to the fill, 3 pt or less, `;;;` number formats, collapsed rows, shapes outside the slide); Publisher story text and temp paths |
| `PDF` | Author, producer/creator software, XMP edit history, incremental-save revisions with text diff, text remaining under redaction boxes, signatures (`/ByteRange`, CAdES, RFC 3161 TSA timestamps), "scan without text layer" detection, embedded images with EXIF, form field names and values, font names, output intent and ICC profile, XFA and portfolio flags |
| `Visio` (`VSDX`/`VSD`), `Publisher`, `InDesign`, `WordPerfect`, `Works` | Metadata, pages, comments, Visio data connections, XMP |
| `EPUB` | Container (`META-INF/container.xml`) & `.opf` Dublin Core metadata (`creator`, `contributor`, `publisher`, `date`, `identifier`, generator), recursive extraction of embedded cover images |
| `PSD` (Adobe Photoshop) | `8BPS` header and `8BIM` Image Resource Blocks: XMP edit history, TIFF/EXIF metadata, IPTC, caption, URL, writer application, slice group and saved path names, layer names, JPEG thumbnails, embedded signatures |
| `MP3` | `ID3v1` and `ID3v2.2/2.3/2.4` tags (author/composer, publisher/studio, encoding software and LAME/Lavc encoder tag, comments, copyright, user text frames such as source paths, URL frames, private frame owners, release dates) + recursive EXIF/GPS extraction from embedded cover art (`APIC`/`PIC`); MP3 files without tags are recognised too |
| Windows Shortcuts (`LNK`) | Computer name, MAC address, volume serial number & label, local and network (`UNC`) paths |
| E-mails (`EML`/`MSG`) | Sender, recipients, `Reply-To`, `Message-ID`, mail client, `Received` hop chain with internal relays & IPs, `X-Originating-IP`, Microsoft 365 tenant, X.500 addresses, recursive analysis of attachments |
| Calendars (`ICS`) & Contacts (`VCF`) | Organizer, attendees, locations, online meeting links; phone numbers, addresses, birthdays; embedded VCF photos |
| Photos & Video (`JPEG`, `PNG`, `TIFF`, `HEIC`/`AVIF`, `GIF`, `WebP`, `JPEG XL`, `JPEG 2000`, `MP4`, `MOV`) | Camera/phone model, body and lens serial numbers, owner, lens, timestamps, GPS coordinates (also from drone XMP), EXIF thumbnail mismatch vs. main image; maker notes (Canon owner and serial, Nikon serial and shutter count, Fujifilm, Olympus/OM System, Panasonic, Pentax, Samsung, Sony serials, Apple ids), IPTC (byline, city, credit, contact, keywords, UTF-8 text), XMP toolkit and edit history, ICC profile, GIF comments and XMP, WebP EXIF/XMP chunks, PNG `eXIf`/`tIME`, AI generator, model and prompt from PNG text and XMP (prompt only on the document card), C2PA manifest and claim generator; video compressor (encoder) and track handler names |
| Camera RAW (`CR2`, `CR3`, `CRW`, `NEF`, `ARW`, `DNG`, `ORF`, `RW2`, `RAF`, `MRW`, `X3F`, `PEF`) | Camera, serial numbers, lens, owner, firmware, GPS and dates; preview and thumbnail JPEGs, with the thumbnail compared to the largest preview |
| Executables and installers (`EXE`/`DLL`, `MSI`) | Version info (company, product, versions, original file name, copyright), build time, PDB debug path with the developer user name and project folder, Authenticode signer (subject, issuer, serial), .NET assembly; MSI summary (author, last saved by, package code, platform, creating tool) |
| Java and Android packages (`JAR`/`WAR`/`EAR`, `APK`/`AAB`) | `MANIFEST.MF` (Built-By user, Created-By JDK, vendor and version, OSGi bundle), Maven `pom.properties`, signer certificate; APK package name, version and v1/v2 signer |
| AutoCAD (`DWG`, `DXF`), PostScript (`EPS`/`PS`/`AI`), `EMF`/`WMF` | DWG release and embedded paths; DXF version, creation and update dates, last saved by, xref and image paths; DSC comments (`%%Creator`, `%%For`, `%%Title`, `%%CreationDate`); metafile descriptions; SVG comments and `data:image` pictures parsed as embedded images |
| Audio and video (`WAV`, `AVI`, `MKV`/`WebM`, `WMV`/`WMA`, `FLAC`, `OGG`) | RIFF INFO tags and broadcast `bext` originator, Matroska muxing and writing app, title and date, ASF author and encoder, Vorbis comments; FLAC pictures parsed as embedded images, repeated Vorbis comments kept |
| Geodata (`KML`/`KMZ`, `GPX`) | Coordinates with names and times (shown as points), author and creating tool |
| Developer files (`.map` source maps, `.ipynb` notebooks) | Source paths with user names and project folders, embedded sources count; kernel, language version, paths and e-mails in outputs and tracebacks |
| Archives (`ZIP`, `7z`, `TAR`, `gzip`, `bzip2`, `xz`, `RAR`) | Member listing, recursive extraction of contained documents (up to 2 nested levels within shared byte/count budgets), Zip-Slip (`../`) traversal path detection; ZIP host OS, entry comments, Unix owner ids and NTFS times; TAR owner names and ids; gzip original name and time; RAR host OS and times. bzip2 and xz are identified but not unpacked |

Document extensions for online discovery can be filtered by category in the launch wizard (Advanced → Document types). Large video files are fetched partially: only metadata atoms are downloaded.

All major document and media containers (`PDF`, `OOXML`, `ODF`, `JPEG`, binary `OLE2` `.doc`/`.xls`/`.ppt`/`.vsd`/`.pub`, and `ISO-BMFF` `.mp4`/`.mov`/`.heic`) also support metadata sanitization with automatic "Before / After" verification, see [Document Hygiene & Sanitization](analytics-and-hygiene.md#document-hygiene--sanitization).

## Forensics in the Document Card

Open any file under Data → Documents → `<document>` to view its Forensics section beneath basic metadata. Subsections start collapsed on mobile screens, displaying record count and highest severity badge on the right:

| Section | What it shows |
|---|---|
| **Signatures & QES (КЕП)** | Signer name, title, organization, EDRPOU (ЄДРПОУ), RNOKPP (РНОКПП), CA/ACSK, signing time, RFC 3161 TSA timestamp & skew, "modified after signing" (a PAdES-LTV increment with only DSS, OCSP/CRL/certificates or a document timestamp does not count), SHA-2 hash check; CMS/PKCS#7 wrappers (`.p7s`, or a `.pdf` that is really one) are recognised by content and the signed document inside is parsed |
| **Broken redaction** | Page number, box fill color, and a short snippet of recoverable text sitting underneath the drawn rectangle |
| **PDF revisions** | Incremental save history: who saved with which tool, plus removed (`−`) and added (`+`) text lines |
| **Hidden content** | Hidden Word text (`w:vanish`), hidden Excel rows, columns, and worksheets containing data |
| **Data connections** | Database connection strings (passwords shown as `***`), `.odc` files, Power Query and mail merge sources, pivot tables (refresh author & source), external chart links |
| **Mail headers / Shortcut / Calendar / Contacts / Media** | Format-specific artifacts (see table above); internal relays highlighted in `Received` chains |
| **Personal data (PII)** | Detected categories, counts, and the values in context |
| **Cloud links & tokens** | Google Drive, SharePoint, Notion, Jira, Azure/S3 URLs; embedded tokens are shown and listed, SAS tokens & webhooks flagged Critical |
| **Edit history (XMP)** | Software lineage (created, converted, saved), `DocumentID`, and `DerivedFrom` |
| **Attachments / Archive entries** | Nested files and formats; unsafe archive traversal paths (`Zip-Slip`) and `Ole10Native` embedded sources |
| **Mail path (Received) / Geodata / AI-generated / Form fields / Fonts** | Parsed mail hops with internal ones marked; KML/GPX points; generator, model and prompt of an AI image; PDF form field names and values; font names |
| **Same author or computer** | Other documents that share a full template path, a program build folder, a printer with the same author or a camera serial |

Each forensic indicator generates a typed finding (`doc.bad_redaction`, `doc.modified_after_signing`, `mail.internal_relay`, `pii`, etc.) with a one-line explanation and a Jump to document button. A group of documents by the same author or computer is reported once as `doc.author_cluster`. List badges show a shield for forensic hits and a person icon for PII; the Only with findings filter includes both.

## Personal Data (PII)

FOCA-rs detects Ukrainian RNOKPP (РНОКПП / ІПН), EDRPOU (ЄДРПОУ), IBAN, payment card numbers, passports & ID cards, phone numbers, and classification markings. Numbers are validated with checksums (RNOKPP, EDRPOU, IBAN mod-97, Luhn for cards).

- **Full values in the app:** The values are stored in the encrypted project on the device and shown in full on every screen (lists, cards, findings, search). Logs, crash reports and the Debug log export mask them. Reports and exports contain them unless "Mask personal data and secrets" is on in the report builder; the AI summary masks them before sending unless the filter is off in Settings > AI.
- **Projects analysed before 2.0.0-beta.5** hold masks (`••••••••90`) written by the older version. Re-analyse documents (the update banner offers it) to restore the full values from the downloaded files.
- One finding is created per PII type per document with an occurrence counter. Organizational EDRPOU codes are public registry identifiers and are logged at `Info` severity.
- Reports show the categories, counts and sample lines; with the masking option the values in them are masked.
- **Classification markings count only as stamps:** the whole line is the marking (optionally with a copy number such as `Прим. № 2`), at the top or bottom of a page or text block, written in capitals or title case: `ДСК`, `ДЛЯ СЛУЖБОВОГО КОРИСТУВАННЯ`, `ЦІЛКОМ ТАЄМНО`, `ДСП`, `Совершенно секретно`, `CONFIDENTIAL`, `INTERNAL USE ONLY`, `SECRET`, `VS-NUR FÜR DEN DIENSTGEBRAUCH`, `DIFFUSION RESTREINTE` and similar. A level mentioned inside a sentence, a series code such as `ДСК № 123456` (diplomas) and a list of levels are ignored. State secret stamps are High, "for official use", confidential and commercial secret stamps Medium, drafts Low; a state secret stamp becomes Critical only when the same document also holds personal data.

## Full-Text Document Search

Open Data → Documents → Full-text search (or global project search → Inside document text). Runs completely offline against the project's SQLite FTS5 index:

- Multiple words match documents containing all terms; `"quoted phrase"` matches exact phrases; `-word` excludes terms; `energ*` performs prefix matching.
- Matches are highlighted in short snippets; PII and secrets inside snippets are highlighted and listed in an inline notice (e.g., *"In snippet: IBAN, phone"*).
- Toggle Include trash to search documents removed from the project.

## Custom Search Rules

Configure per-project rules under ⋮ → Search rules or Scope → Document analysis → Search rules:

- **Built-in presets:** Ukrainian government document identifiers (order/outgoing/restricted inventory numbers), credentials in text, internal infrastructure (`UNC`, RDP/SSH endpoints), cryptocurrency wallets, and free-form PII patterns.
- **Custom regex rules:** Name, pattern, severity, and case-insensitivity toggle. A named capture group `(?P<v>…)` extracts the matched value. Use Test on sample text to verify patterns locally.
- Validation errors appear inline. Guardrails: pattern length ≤ 512 chars, up to 64 rules per project, and patterns cannot match empty strings.
- Tap Save & recalculate to generate `doc.user_rule` findings immediately without re-scanning.

## Offline File & Folder Analysis

Open Projects → Analyze files offline (or from the ⋮ menu anywhere):

1. Choose the destination: a new project (with name and optional domain for e-mail pattern matching) or the current project.
2. Pick Select folder (recursive via Android SAF) or Files or ZIP.
3. Tap Analyze: live per-file progress with a Cancel button (already-parsed files are kept).
4. Review the summary (added, duplicates, skipped files and reasons) → Open project.

Zero network requests are made: selected files are copied into private app storage, parsed locally on the phone, and temporary import copies are deleted once analysis completes. Limits: up to 500 files and 512 MB per batch, 100 MB per file, 30-second per-file parse timeout.

## Re-analyse Documents

New versions read more from the same files (better PDF text, people and contacts from text, new formats). To apply them to a project without a new search, use Re-analyse documents on the project overview or in Data → Documents (or select documents and tap Re-analyse):

1. Choose what to parse: downloaded files only (no network), or also download missing files from their saved links. The sheet shows how many files are missing and the expected traffic; downloads follow the project scope, the network settings, Wi-Fi only and the mobile data limit.
2. Tap Start. Progress shows the current file; Stop ends the run after the current file, and the next start continues from there (also after the app was closed or killed).
3. The result compares before and after: documents with text, people, e-mails, phones and findings by severity, with a link to new findings.

Finding statuses, notes, deleted documents and document ids stay. Findings the new analysis no longer produces leave the findings list, the counts and reports (a later scan does not list them as fixed); their status and notes come back if the same finding appears again. A running scan has priority: re-analysis cannot start during a scan and pauses when one starts.

After an update the overview shows a banner when documents were analysed by an older version ("The new version extracts more data from documents"). Not now hides it for this project until the next parser change.

## Optional Offline OCR (Play Flavor)

When analyzing scanned PDFs or images without an embedded text layer (`< 40` extracted characters), the `play` Android flavor supports optional 100% on-device OCR powered by Google ML Kit (`com.google.mlkit:text-recognition`):

- **Disabled by default** (`settings.ocr.enabled = false`). Enable and configure `max_pages` (default 10) and `max_mb` (default 15 MB) under Settings → Signature databases & OCR (`/settings/signatures`).
- Runs entirely locally on your phone (zero cloud API calls); recognized text (capped at 256 KiB per file) is indexed into FTS5 full-text search and scanned by the PII and forensics detectors.
- In the pure open-source `foss` build (F-Droid / direct `GPL-3.0` release), ML Kit is excluded and OCR cleanly reports `unavailable_in_foss_build`.

## Limitations

- Signatures inside legacy binary `.doc`/`.xls` OLE2 streams (`\x05DigitalSignature`) are not parsed; certificate chain validation and CRL/OCSP revocation are not performed.
- Ukrainian QES (КЕП) OIDs follow ETSI EN 319 412-1 and national certificate profiles; verify critical findings against official validation tooling.
- Hidden Word text applied exclusively through custom style definitions (rather than run-level `w:vanish`) is not detected.
- The broken-redaction detector approximates glyph widths (~0.5 em), does not descend into nested form XObjects, ignores transparency/clipping masks, and skips rectangles covering > 80% of the page.
- Full-text search indexes the first 64 KiB of extracted text per document; scanned PDFs/images are searchable only when optional ML Kit OCR is enabled in the `play` build.
- `RAR` archives are not supported (pure-Rust archive extraction covers `ZIP` and `7z`).
