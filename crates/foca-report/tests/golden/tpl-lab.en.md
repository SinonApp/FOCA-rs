---
title: "Laboratory work: contoso.example"
project: "contoso.example"
client: "ТОВ «Контосо Енерджі»"
date: 2026-11-20
template: lab
lang: en
risk: 88
findings: 110
---

# Laboratory work

contoso.example · ТОВ «Контосо Енерджі» · 20 Nov 2026

## 1. Goal

Study open sources about «contoso.example» with OSINT methods: collect published documents, extract metadata, find information leaks and map the findings to information security standards.

## 2. Method

- **Check profile:** Standard
- **Sources:** Document forensics, EXIF, Metadata, People and e-mail, People from document text, Personal data, Secrets in documents, Software → EOL
- **Tool:** FOCA-rs 2.0.0-beta.4.1
- **Network requests:** 5
- **Limitations:** Only publicly available data and the provided files were used, with no attempt to bypass protection. The conclusions reflect the state of the sources on the study date.

## 3. Input data

- **Object:** contoso.example
- **Client:** ТОВ «Контосо Енерджі»
- **Targets (scope):** contoso.example, \*.contoso-group.example, 203.0.113.0/24
- **Exclusions:** mail.contoso.example, 10.10.1.0/24
- **Report date:** 20 Nov 2026

## 4. Course of the study

1. Document collection: 67 (65 analysed).
2. Metadata extraction: people 24, e-mail addresses 25, hosts 27, software 33.
3. Analysis: findings 110 (critical 4, high 27, medium 40, low 34, info 5).
4. Network requests: 5 (passive 2, active 2).

## 5. Findings with standards mapping

| No. | Severity | Finding | MITRE ATT&CK v20 | CWE / OWASP Top 10:2025 | ISO 27001 | NIST SP 800-53 / НД ТЗІ 3.6-006-24 | НД ТЗІ 2.5-004-99 | НД ТЗІ 3.7-003-05 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Critical | Bad redaction: the text under the box is readable (redacted.pdf) | T1213 | CWE-212 | 8.11, 8.12 | AC-22 | \- | 6.1.2.5 |
| 2 | Critical | Links to cloud workspaces and URLs with tokens in personal.docx | T1213.003 | \- | \- | \- | \- | \- |
| 3 | Critical | Password in a connection string | T1552.001 | CWE-798, A07:2025 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 4 | Critical | ICA file with a plaintext password (buh.ica) | T1552.001 | CWE-256, A06:2025 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 5 | High | Internal mail servers and addresses in the message headers (budget.msg) | T1590.005 | CWE-497, A01:2025 | 8.12, 8.21 | AC-22 | \- | 6.1.2.4 |
| 6 | High | Individual tax number (RNOKPP) in the document (signed\_hidden.docx) | T1213 | CWE-359, A01:2025 | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 7 | High | LNK shortcut reveals the computer name and MAC address (report.lnk) | T1592.001 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 8 | High | LNK shortcut reveals the computer name and MAC address (network.lnk) | T1592.001 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 9 | High | LNK shortcut reveals the computer name and MAC address (backup.zip) | T1592.001 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 10 | High | Deleted text is recoverable from older PDF revisions (revisions.pdf) | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 11 | High | Payment card number in the document (personal.docx) | T1213 | CWE-359, A01:2025 | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 12 | High | Individual tax number (RNOKPP) in the document (personal.docx) | T1213 | CWE-359, A01:2025 | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 13 | High | RDP file with a saved password (SRV-TS01.rdp) | T1552.001 | CWE-256, A06:2025 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 14 | High | Deleted text is recoverable from older PDF revisions (signed\_modified.pdf) | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 15 | High | Password in document text · objstm.pdf | T1552.001 | CWE-798, A07:2025 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 16 | High | Hidden text and hidden rows/columns in hidden.xlsx | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 17 | High | IBAN account number in the document (personal.docx) | T1213 | CWE-359, A01:2025 | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 18 | High | Document modified after signing (signed\_modified.pdf) | T1565.001 | \- | 8.24 | \- | ЦВ, НА | 6.1.2.5 |
| 19 | High | Archive with dangerous paths (Zip-Slip): backup.zip | T1204.002 | CWE-22 (Top 25), A01:2025 | 8.7 | SI-10 | \- | \- |
| 20 | High | External data sources in schedule.xlsx | T1590 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 21 | High | Password in document text · legacy.doc | T1552.001 | CWE-798, A07:2025 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 22 | High | Sender IP address in the message headers (budget.msg) | \- | CWE-497, A01:2025 | 8.21 | AC-22 | \- | 6.1.2.4 |
| 23 | High | Internal mail servers and addresses in the message headers (backup.zip) | T1590.005 | CWE-497, A01:2025 | 8.12, 8.21 | AC-22 | \- | 6.1.2.4 |
| 24 | High | Password in a data connection string | T1552.001 | CWE-798, A07:2025 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 25 | High | Hidden text and hidden rows/columns in signed\_hidden.docx | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 26 | High | Sender IP address in the message headers (backup.zip) | \- | CWE-497, A01:2025 | 8.21 | AC-22 | \- | 6.1.2.4 |
| 27 | High | Azure SAS token | T1552.001 | CWE-798, A07:2025 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 28 | High | Sender IP address in the message headers (budget.eml) | \- | CWE-497, A01:2025 | 8.21 | AC-22 | \- | 6.1.2.4 |
| 29 | High | Individual tax number (RNOKPP) in the document (signed.pdf) | T1213 | CWE-359, A01:2025 | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 30 | High | Passport series and number in the document (personal.docx) | T1213 | CWE-359, A01:2025 | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 31 | High | Individual tax number (RNOKPP) in the document (signed\_modified.pdf) | T1213 | CWE-359, A01:2025 | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 32 | Medium | Signer data (qualified signature) in the document signed.pdf: Іван Петренко | T1589.001 | \- | 5.34 | SI-12(1) | \- | 6.1.2.7 |
| 33 | Medium | Signer data (qualified signature) in the document signed\_hidden.docx: John Doe | T1589.001 | \- | 5.34 | SI-12(1) | \- | 6.1.2.7 |
| 34 | Medium | Adobe Acrobat Pro XI (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 35 | Medium | Contacts of people in document text: 1 person | T1589.003, T1589.002 | CWE-359, A01:2025 | 5.34, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 36 | Medium | Document with VBA macros: legacy.doc | T1059.005 | \- | 8.7 | SC-18 | \- | \- |
| 37 | Medium | Internal domain in Message-ID (budget.msg) | \- | \- | \- | \- | \- | \- |
| 38 | Medium | Document with VBA macros: budget.xls | T1059.005 | \- | 8.7 | SC-18 | \- | \- |
| 39 | Medium | Adobe Photoshop CC 2019 (EOL) in 2 documents | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 40 | Medium | GPS coordinates in 6 photos | T1591.001 | CWE-359, A01:2025 | 5.34, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 41 | Medium | Outdated OS iOS 16.6 in 1 document | T1592.002 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 42 | Medium | Document with VBA macros: schedule.xlsx | T1059.005 | \- | 8.7 | SC-18 | \- | \- |
| 43 | Medium | Reply-To differs from the sender (budget.eml) | T1566 | \- | 6.3 | AT-2(3) | \- | 6.1.2.7 |
| 44 | Medium | Exchange structure (X.500) in the message (budget.msg) | \- | \- | \- | \- | \- | \- |
| 45 | Medium | Personal contacts in business cards (contacts.vcf) | \- | CWE-359, A01:2025 | 5.34, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 46 | Medium | iOS 16.6 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 47 | Medium | Reply-To differs from the sender (backup.zip) | T1566 | \- | 6.3 | AT-2(3) | \- | 6.1.2.7 |
| 48 | Medium | Outdated OS iOS 17.4 in 2 documents | T1592.002 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 49 | Medium | LNK shortcut points to a network share (network.lnk) | T1135 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 50 | Medium | Internal domain in Message-ID (budget.eml) | \- | \- | \- | \- | \- | \- |
| 51 | Medium | EXIF thumbnail may differ from the photo (photo.jpg) | T1591 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 52 | Medium | Internal domain in Message-ID (backup.zip) | \- | \- | \- | \- | \- | \- |
| 53 | Medium | Online meeting links in the calendar (meeting.ics) | \- | \- | \- | \- | \- | \- |
| 54 | Medium | Tracked changes and deleted text kept in contract.docx | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 55 | Medium | Device serial number in a media file (iphone.mov) | T1592.001 | \- | 8.12 | AC-22 | \- | 6.1.2.4 |
| 56 | Medium | External data sources in hidden.xlsx | T1590 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 57 | Medium | Document with VBA macros: vbaProject.bin | T1059.005 | \- | 8.7 | SC-18 | \- | \- |
| 58 | Medium | Personal contacts in business cards (backup.zip) | \- | CWE-359, A01:2025 | 5.34, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 59 | Medium | Different authors or programs in PDF revisions (signed\_modified.pdf) | \- | CWE-212 | 8.10 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 60 | Medium | PDF contains JavaScript: report.pdf | T1204.002 | \- | 8.7 | SC-18 | \- | \- |
| 61 | Medium | Hidden sheets in budget.xls: Зарплати, Службовий | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 62 | Medium | Hidden sheets in schedule.xlsx: Зарплати, Паролі | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 63 | Medium | Tracked changes and deleted text kept in letter.odt | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 64 | Medium | Different authors or programs in PDF revisions (report.pdf) | \- | CWE-212 | 8.10 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 65 | Medium | iOS 17.4 (EOL) in 2 documents | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 66 | Medium | Access restriction marking in the document (personal.docx) | T1213 | CWE-359, A01:2025 | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 67 | Medium | Different authors or programs in PDF revisions (revisions.pdf) | \- | CWE-212 | 8.10 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 68 | Medium | Signer data (qualified signature) in the document signed\_modified.pdf: Іван Петренко | T1589.001 | \- | 5.34 | SI-12(1) | \- | 6.1.2.7 |
| 69 | Medium | External data sources in network.vsdx | T1590 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 70 | Medium | Device serial number in a media file (photo.heic) | T1592.001 | \- | 8.12 | AC-22 | \- | 6.1.2.4 |
| 71 | Medium | Microsoft Office Word 2013 (EOL) in 2 documents | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 72 | Low | Microsoft Excel 2010 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 73 | Low | Microsoft PowerPoint 2002 (XP) (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 74 | Low | Reviewer comments kept in schedule.xlsx | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 75 | Low | Adobe Photoshop 7.0 (EOL) in 3 documents | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 76 | Low | Internal addresses and host names in the document (2) · budget.msg | T1590.005 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 77 | Low | Reviewer comments kept in report.pdf | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 78 | Low | Old PDF revisions kept in report.pdf | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 79 | Low | Microsoft Office PowerPoint 2003 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 80 | Low | Microsoft Word 2010 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 81 | Low | Old PDF revisions kept in signed\_modified.pdf | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 82 | Low | Reviewer comments kept in strategy.pptx | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 83 | Low | Internal addresses and host names in the document (1) · contract.docx | T1590.005 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 84 | Low | Internal paths and logins in the metadata of 17 documents | T1592 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 85 | Low | Internal addresses and host names in the document (1) · buh.ica | T1590.005 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 86 | Low | Outdated OS Windows 7 / Server 2008 R2 in 1 document | T1592.002 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 87 | Low | Outdated OS Windows XP in 2 documents | T1592.002 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 88 | Low | Microsoft 365 tenant ID in the message (budget.eml) | \- | \- | \- | \- | \- | \- |
| 89 | Low | Reviewer comments kept in network.vsdx | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 90 | Low | Internal addresses and host names in the document (4) | T1590.005 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 91 | Low | Microsoft Office Word 2007 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 92 | Low | Microsoft 365 tenant ID in the message (backup.zip) | \- | \- | \- | \- | \- | \- |
| 93 | Low | Microsoft Word 2008 for Mac (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 94 | Low | Old PDF revisions kept in revisions.pdf | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 95 | Low | Previous metadata versions kept in legacy.doc | T1213 | CWE-212 | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 96 | Low | LibreOffice 7.2.5.2 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 97 | Low | Internal addresses and host names in the document (2) · budget.eml | T1590.005 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 98 | Low | Names of 9 computers and servers of the internal network | T1590 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 99 | Low | Microsoft Office Excel 2007 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 100 | Low | Signing time and TSA time stamp differ by more than a day (signed\_hidden.docx) | \- | \- | 8.24 | \- | НА | \- |
| 101 | Low | Remote access settings exposed in the file SRV-TS01.rdp | T1590.002 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 102 | Low | OpenOffice.org 3.2 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | 8.8 | SA-22 | \- | 6.1.2.4 |
| 103 | Low | Remote access settings exposed in the file buh.ica | T1590.002 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 104 | Low | Names and logins of 19 employees exposed | T1589.003 | CWE-359, A01:2025 | 5.34, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 105 | Low | Internal addresses and host names in the document (1) · network.vsdx | T1590.005 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 106 | Info | Corporate e-mail pattern identified: {f}.{last}@contoso.example | T1589.002 | \- | 6.3 | AT-2(3) | \- | 6.1.2.7 |
| 107 | Info | Scan without a text layer: exiftool-PDF.pdf | \- | \- | \- | \- | \- | \- |
| 108 | Info | Scan without a text layer: scan.pdf | \- | \- | \- | \- | \- | \- |
| 109 | Info | Scan without a text layer: exiftool-PDF2.pdf | \- | \- | \- | \- | \- | \- |
| 110 | Info | Shared/service accounts in metadata: Administrator, admin, author, scan, user name | T1087 | CWE-497, A01:2025 | 8.12 | AC-22 | \- | 6.1.2.7 |

НД ТЗІ 2.5-004-99 and НД ТЗІ 3.7-003-05 are given for systems certified under КСЗІ. НД ТЗІ 3.6-006-24 measure codes are the NIST SP 800-53 codes.

## 6. Conclusions and recommendations

Overall risk level: High (88/100). Findings: 110.

- Published files still contain what was believed to be deleted or blacked out.
- Passwords or access keys are publicly available: anyone can use them.
- Files reveal the internal network: computer and server names, paths.
- Personal data of employees or customers is published.
- A signed document was changed after signing: its authenticity cannot be confirmed.
- A security problem that needs attention was found.
- Outdated software with known vulnerabilities is in use.

1. Clean documents before publishing: tracked changes, hidden sheets, blacked-out text, metadata.
2. Change the exposed passwords and keys immediately and remove the files from the site.
3. Remove internal paths, computer and server names from documents before publishing.
4. Remove personal data from public files and check the legal basis for processing it.
5. Re-sign the documents and publish only final signed versions.

> **Auditor's disclaimer.** The standards mapping is a guide for the auditor, not the conclusion of a state КСЗІ (complex information security system) examination or certification. The final conformity assessment is made by an authorised expert against the primary documents.

**Performed by:** ______________________ (Name, signature, date)

**Checked by:** ______________________ (Name, signature, date)

---

Generated by FOCA-rs 2.0.0-beta.4.1 · 20 Nov 2026
