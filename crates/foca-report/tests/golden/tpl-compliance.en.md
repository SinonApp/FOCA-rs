---
title: "КСЗІ / Standards compliance: contoso.example"
project: "contoso.example"
client: "ТОВ «Контосо Енерджі»"
date: 2026-11-20
template: compliance
lang: en
risk: 88
findings: 107
---

# КСЗІ / Standards compliance

contoso.example · ТОВ «Контосо Енерджі» · 20 Nov 2026

*Findings are mapped to MITRE ATT&CK v20, CWE (flagging the 2025 CWE Top 25), OWASP Top 10:2025, OWASP WSTG v4.2, ISO/IEC 27001:2022 (ДСТУ ISO/IEC 27001:2023), NIST SP 800-53 Rev. 5 / НД ТЗІ 3.6-006-24 measures, GDPR and Law of Ukraine No. 2297-VI "On Personal Data Protection" articles for findings with personal data and, for systems certified under КСЗІ, to the functional services of НД ТЗІ 2.5-004-99 and the КСЗІ creation stages of НД ТЗІ 3.7-003-05.*

**Overall risk level: 88/100 - High**

> **Auditor's disclaimer.** The standards mapping is a guide for the auditor, not the conclusion of a state КСЗІ (complex information security system) examination or certification. The final conformity assessment is made by an authorised expert against the primary documents.

## Findings and standards

| No. | Severity | Finding | MITRE ATT&CK v20 | CWE / OWASP Top 10:2025 | WSTG v4.2 | ISO 27001 | NIST SP 800-53 / НД ТЗІ 3.6-006-24 | НД ТЗІ 2.5-004-99 | НД ТЗІ 3.7-003-05 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Critical | Bad redaction: the text under the box is readable (redacted.pdf) | T1213 | CWE-212 | \- | 8.11, 8.12 | AC-22 | \- | 6.1.2.5 |
| 2 | Critical | Links to cloud workspaces and URLs with tokens in personal.docx | T1213.003 | \- | \- | \- | \- | \- | \- |
| 3 | Critical | Password in a connection string | T1552.001 | CWE-798, A07:2025 | WSTG-INFO-01 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 4 | Critical | ICA file with a plaintext password (buh.ica) | T1552.001 | CWE-256, A06:2025 | \- | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 5 | High | Internal mail servers and addresses in the message headers (budget.msg) | T1590.005 | CWE-497, A01:2025 | \- | 8.12, 8.21 | AC-22 | \- | 6.1.2.4 |
| 6 | High | LNK shortcut reveals the computer name and MAC address (report.lnk) | T1592.001 | CWE-497, A01:2025 | \- | 8.12 | AC-22 | \- | 6.1.2.4 |
| 7 | High | LNK shortcut reveals the computer name and MAC address (network.lnk) | T1592.001 | CWE-497, A01:2025 | \- | 8.12 | AC-22 | \- | 6.1.2.4 |
| 8 | High | LNK shortcut reveals the computer name and MAC address (backup.zip) | T1592.001 | CWE-497, A01:2025 | \- | 8.12 | AC-22 | \- | 6.1.2.4 |
| 9 | High | Deleted text is recoverable from older PDF revisions (revisions.pdf) | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 10 | High | Payment card number in the document (personal.docx) | T1213 | CWE-359, A01:2025 | \- | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 11 | High | Individual tax number (RNOKPP) in the document (personal.docx) | T1213 | CWE-359, A01:2025 | \- | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 12 | High | RDP file with a saved password (SRV-TS01.rdp) | T1552.001 | CWE-256, A06:2025 | \- | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 13 | High | Deleted text is recoverable from older PDF revisions (signed\_modified.pdf) | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 14 | High | Password in document text · objstm.pdf | T1552.001 | CWE-798, A07:2025 | WSTG-INFO-01 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 15 | High | Hidden text and hidden rows/columns in hidden.xlsx | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 16 | High | IBAN account number in the document (personal.docx) | T1213 | CWE-359, A01:2025 | \- | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 17 | High | Document modified after signing (signed\_modified.pdf) | T1565.001 | \- | \- | 8.24 | \- | ЦВ, НА | 6.1.2.5 |
| 18 | High | Archive with dangerous paths (Zip-Slip): backup.zip | T1204.002 | CWE-22 (Top 25), A01:2025 | \- | 8.7 | SI-10 | \- | \- |
| 19 | High | External data sources in schedule.xlsx | T1590 | CWE-497, A01:2025 | \- | 8.12 | AC-22 | \- | 6.1.2.4 |
| 20 | High | Password in document text · legacy.doc | T1552.001 | CWE-798, A07:2025 | WSTG-INFO-01 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 21 | High | Sender IP address in the message headers (budget.msg) | \- | CWE-497, A01:2025 | \- | 8.21 | AC-22 | \- | 6.1.2.4 |
| 22 | High | Internal mail servers and addresses in the message headers (backup.zip) | T1590.005 | CWE-497, A01:2025 | \- | 8.12, 8.21 | AC-22 | \- | 6.1.2.4 |
| 23 | High | Password in a data connection string | T1552.001 | CWE-798, A07:2025 | WSTG-INFO-01 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 24 | High | Hidden text and hidden rows/columns in signed\_hidden.docx | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 25 | High | Sender IP address in the message headers (backup.zip) | \- | CWE-497, A01:2025 | \- | 8.21 | AC-22 | \- | 6.1.2.4 |
| 26 | High | Azure SAS token | T1552.001 | CWE-798, A07:2025 | WSTG-INFO-01 | 5.17, 8.12 | IA-5(7) | НИ | 6.1.2.5 |
| 27 | High | Sender IP address in the message headers (budget.eml) | \- | CWE-497, A01:2025 | \- | 8.21 | AC-22 | \- | 6.1.2.4 |
| 28 | High | Passport series and number in the document (personal.docx) | T1213 | CWE-359, A01:2025 | \- | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 29 | Medium | Signer data (qualified signature) in the document signed.pdf: Іван Петренко | T1589.001 | \- | \- | 5.34 | SI-12(1) | \- | 6.1.2.7 |
| 30 | Medium | Signer data (qualified signature) in the document signed\_hidden.docx: John Doe | T1589.001 | \- | \- | 5.34 | SI-12(1) | \- | 6.1.2.7 |
| 31 | Medium | Adobe Acrobat Pro XI (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 32 | Medium | Contacts of people in document text: 1 person | T1589.003, T1589.002 | CWE-359, A01:2025 | \- | 5.34, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 33 | Medium | Document with VBA macros: legacy.doc | T1059.005 | \- | \- | 8.7 | SC-18 | \- | \- |
| 34 | Medium | Internal domain in Message-ID (budget.msg) | \- | \- | \- | \- | \- | \- | \- |
| 35 | Medium | Document with VBA macros: budget.xls | T1059.005 | \- | \- | 8.7 | SC-18 | \- | \- |
| 36 | Medium | Adobe Photoshop CC 2019 (EOL) in 2 documents | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 37 | Medium | GPS coordinates in 6 photos | T1591.001 | CWE-359, A01:2025 | \- | 5.34, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 38 | Medium | Outdated OS iOS 16.6 in 1 document | T1592.002 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 39 | Medium | Document with VBA macros: schedule.xlsx | T1059.005 | \- | \- | 8.7 | SC-18 | \- | \- |
| 40 | Medium | Reply-To differs from the sender (budget.eml) | T1566 | \- | \- | 6.3 | AT-2(3) | \- | 6.1.2.7 |
| 41 | Medium | Exchange structure (X.500) in the message (budget.msg) | \- | \- | \- | \- | \- | \- | \- |
| 42 | Medium | Personal contacts in business cards (contacts.vcf) | \- | CWE-359, A01:2025 | \- | 5.34, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 43 | Medium | iOS 16.6 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 44 | Medium | Reply-To differs from the sender (backup.zip) | T1566 | \- | \- | 6.3 | AT-2(3) | \- | 6.1.2.7 |
| 45 | Medium | Outdated OS iOS 17.4 in 2 documents | T1592.002 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 46 | Medium | LNK shortcut points to a network share (network.lnk) | T1135 | CWE-497, A01:2025 | \- | 8.12 | AC-22 | \- | 6.1.2.4 |
| 47 | Medium | Internal domain in Message-ID (budget.eml) | \- | \- | \- | \- | \- | \- | \- |
| 48 | Medium | EXIF thumbnail may differ from the photo (photo.jpg) | T1591 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 49 | Medium | Internal domain in Message-ID (backup.zip) | \- | \- | \- | \- | \- | \- | \- |
| 50 | Medium | Online meeting links in the calendar (meeting.ics) | \- | \- | \- | \- | \- | \- | \- |
| 51 | Medium | Tracked changes and deleted text kept in contract.docx | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 52 | Medium | Device serial number in a media file (iphone.mov) | T1592.001 | \- | \- | 8.12 | AC-22 | \- | 6.1.2.4 |
| 53 | Medium | External data sources in hidden.xlsx | T1590 | CWE-497, A01:2025 | \- | 8.12 | AC-22 | \- | 6.1.2.4 |
| 54 | Medium | Document with VBA macros: vbaProject.bin | T1059.005 | \- | \- | 8.7 | SC-18 | \- | \- |
| 55 | Medium | Personal contacts in business cards (backup.zip) | \- | CWE-359, A01:2025 | \- | 5.34, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 56 | Medium | Different authors or programs in PDF revisions (signed\_modified.pdf) | \- | CWE-212 | \- | 8.10 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 57 | Medium | PDF contains JavaScript: report.pdf | T1204.002 | \- | \- | 8.7 | SC-18 | \- | \- |
| 58 | Medium | Hidden sheets in budget.xls: Зарплати, Службовий | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 59 | Medium | Hidden sheets in schedule.xlsx: Зарплати, Паролі | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 60 | Medium | Tracked changes and deleted text kept in letter.odt | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 61 | Medium | Different authors or programs in PDF revisions (report.pdf) | \- | CWE-212 | \- | 8.10 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 62 | Medium | iOS 17.4 (EOL) in 2 documents | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 63 | Medium | Access restriction marking in the document (personal.docx) | T1213 | CWE-359, A01:2025 | \- | 5.34, 8.11, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.5 |
| 64 | Medium | Different authors or programs in PDF revisions (revisions.pdf) | \- | CWE-212 | \- | 8.10 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 65 | Medium | Signer data (qualified signature) in the document signed\_modified.pdf: Іван Петренко | T1589.001 | \- | \- | 5.34 | SI-12(1) | \- | 6.1.2.7 |
| 66 | Medium | External data sources in network.vsdx | T1590 | CWE-497, A01:2025 | \- | 8.12 | AC-22 | \- | 6.1.2.4 |
| 67 | Medium | Device serial number in a media file (photo.heic) | T1592.001 | \- | \- | 8.12 | AC-22 | \- | 6.1.2.4 |
| 68 | Medium | Microsoft Office Word 2013 (EOL) in 2 documents | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 69 | Low | Microsoft Excel 2010 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 70 | Low | Microsoft PowerPoint 2002 (XP) (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 71 | Low | Reviewer comments kept in schedule.xlsx | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 72 | Low | Adobe Photoshop 7.0 (EOL) in 3 documents | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 73 | Low | Internal addresses and host names in the document (2) · budget.msg | T1590.005 | CWE-497, A01:2025 | WSTG-INFO-01 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 74 | Low | Reviewer comments kept in report.pdf | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 75 | Low | Old PDF revisions kept in report.pdf | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 76 | Low | Microsoft Office PowerPoint 2003 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 77 | Low | Microsoft Word 2010 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 78 | Low | Old PDF revisions kept in signed\_modified.pdf | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 79 | Low | Reviewer comments kept in strategy.pptx | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 80 | Low | Internal addresses and host names in the document (1) · contract.docx | T1590.005 | CWE-497, A01:2025 | WSTG-INFO-01 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 81 | Low | Internal paths and logins in the metadata of 17 documents | T1592 | CWE-497, A01:2025 | WSTG-INFO-01 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 82 | Low | Internal addresses and host names in the document (1) · buh.ica | T1590.005 | CWE-497, A01:2025 | WSTG-INFO-01 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 83 | Low | Outdated OS Windows 7 / Server 2008 R2 in 1 document | T1592.002 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 84 | Low | Outdated OS Windows XP in 2 documents | T1592.002 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 85 | Low | Microsoft 365 tenant ID in the message (budget.eml) | \- | \- | \- | \- | \- | \- | \- |
| 86 | Low | Reviewer comments kept in network.vsdx | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 87 | Low | Internal addresses and host names in the document (4) | T1590.005 | CWE-497, A01:2025 | WSTG-INFO-01 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 88 | Low | Microsoft Office Word 2007 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 89 | Low | Microsoft 365 tenant ID in the message (backup.zip) | \- | \- | \- | \- | \- | \- | \- |
| 90 | Low | Microsoft Word 2008 for Mac (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 91 | Low | Old PDF revisions kept in revisions.pdf | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 92 | Low | Previous metadata versions kept in legacy.doc | T1213 | CWE-212 | \- | 8.10, 8.12 | AC-22 | \- | 6.1.2.5 |
| 93 | Low | LibreOffice 7.2.5.2 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 94 | Low | Internal addresses and host names in the document (2) · budget.eml | T1590.005 | CWE-497, A01:2025 | WSTG-INFO-01 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 95 | Low | Names of 9 computers and servers of the internal network | T1590 | CWE-497, A01:2025 | WSTG-INFO-01 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 96 | Low | Microsoft Office Excel 2007 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 97 | Low | Signing time and TSA time stamp differ by more than a day (signed\_hidden.docx) | \- | \- | \- | 8.24 | \- | НА | \- |
| 98 | Low | Remote access settings exposed in the file SRV-TS01.rdp | T1590.002 | CWE-497, A01:2025 | WSTG-INFO-01 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 99 | Low | OpenOffice.org 3.2 (EOL) in 1 document | T1203 | CWE-1104, A03:2025 | \- | 8.8 | SA-22 | \- | 6.1.2.4 |
| 100 | Low | Remote access settings exposed in the file buh.ica | T1590.002 | CWE-497, A01:2025 | WSTG-INFO-01 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 101 | Low | Names and logins of 19 employees exposed | T1589.003 | CWE-359, A01:2025 | WSTG-INFO-01 | 5.34, 8.12 | AC-22, SI-12(1) | \- | 6.1.2.7 |
| 102 | Low | Internal addresses and host names in the document (1) · network.vsdx | T1590.005 | CWE-497, A01:2025 | WSTG-INFO-01 | 8.12 | AC-22 | \- | 6.1.2.4 |
| 103 | Info | Corporate e-mail pattern identified: {f}.{last}@contoso.example | T1589.002 | \- | WSTG-INFO-01 | 6.3 | AT-2(3) | \- | 6.1.2.7 |
| 104 | Info | Scan without a text layer: exiftool-PDF.pdf | \- | \- | \- | \- | \- | \- | \- |
| 105 | Info | Scan without a text layer: scan.pdf | \- | \- | \- | \- | \- | \- | \- |
| 106 | Info | Scan without a text layer: exiftool-PDF2.pdf | \- | \- | \- | \- | \- | \- | \- |
| 107 | Info | Shared/service accounts in metadata: Administrator, admin, author, scan, user name | T1087 | CWE-497, A01:2025 | \- | 8.12 | AC-22 | \- | 6.1.2.7 |

НД ТЗІ 2.5-004-99 and НД ТЗІ 3.7-003-05 are given for systems certified under КСЗІ. НД ТЗІ 3.6-006-24 measure codes are the NIST SP 800-53 codes.

## НД ТЗІ 3.6-006-24 / NIST SP 800-53 Rev. 5 security measures

| Control | Name | Findings |
| --- | --- | --- |
| AC-22 | Publicly Accessible Content | 56 |
| AT-2(3) | Literacy Training and Awareness \| Social Engineering and Mining | 3 |
| IA-5(7) | Authenticator Management \| No Embedded Unencrypted Static Authenticators | 7 |
| SA-22 | Unsupported System Components | 19 |
| SC-18 | Mobile Code | 5 |
| SI-10 | Information Input Validation | 1 |
| SI-12(1) | Information Management and Retention \| Limit Personally Identifiable Information Elements | 16 |

## Personal data protection (GDPR, Law No. 2297-VI)

| Name | Findings |
| --- | --- |
| GDPR Art. 5(1)(c): data minimisation | 17 |
| GDPR Art. 5(1)(f): integrity and confidentiality | 16 |
| GDPR Art. 32: security of processing | 17 |
| Law of Ukraine No. 2297-VI "On Personal Data Protection", Art. 6(3): data relevant, adequate and not excessive | 17 |
| Law of Ukraine No. 2297-VI "On Personal Data Protection", Art. 24: protection of personal data | 17 |

## НД ТЗІ 2.5-004-99 functional services (for systems certified under КСЗІ)

| Code | Service | Clause | Findings |
| --- | --- | --- | --- |
| НА | Sender authentication | 9.8 | 2 |
| НИ | Identification and authentication | 9.2 | 7 |
| ЦВ | Integrity during exchange | 7.4 | 1 |

## ISO/IEC 27001:2022 (ДСТУ ISO/IEC 27001:2023) Annex A controls

| Control | Name | Findings |
| --- | --- | --- |
| A.5.17 | Authentication information | 7 |
| A.5.34 | Privacy and protection of PII | 13 |
| A.6.3 | Information security awareness, education and training | 3 |
| A.8.7 | Protection against malware | 6 |
| A.8.8 | Management of technical vulnerabilities | 19 |
| A.8.10 | Information deletion | 20 |
| A.8.11 | Data masking | 6 |
| A.8.12 | Data leakage prevention | 57 |
| A.8.21 | Security of network services | 5 |
| A.8.24 | Use of cryptography | 2 |

## КСЗІ creation work, НД ТЗІ 3.7-003-05 (for systems certified under КСЗІ)

| Clause | Work | Findings |
| --- | --- | --- |
| 6.1.2.4 | Survey of the ITS computing system | 43 |
| 6.1.2.5 | Survey of the information environment | 33 |
| 6.1.2.7 | Survey of the user environment | 13 |

Findings without a standards mapping: 10.

---

Generated by FOCA-rs 2.0.0-beta.4 · 20 Nov 2026
