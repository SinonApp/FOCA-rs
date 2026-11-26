#!/usr/bin/env python3
"""Generates personal.docx: a fictional certificate letter with synthetic personal data
(valid check digits, no real person), an access marking, a cloud share link and a SAS URL.
Used by the analysis/report goldens and the offline import test. stdlib only."""
import zipfile, sys, os

LINES = [
    "ДСК",
    "Довідка про доходи (вигадана, для тестів FOCA-rs)",
    "Отримувач: Іван Петренко, РНОКПП 3012345670",
    "IBAN UA213223130000026007233566001",
    "Картка 4111 1111 1111 1111",
    "Паспорт серія АВ 123456",
    "Тел. +380 67 123 45 67",
    "Матеріали: https://drive.google.com/drive/folders/1AbCdEfGhIjKlMnOpQrStUvWxYz?usp=sharing",
    "Резервна копія: https://contoso.blob.core.windows.net/backup/db.bak?sv=2022-11-02&sp=r&sig=AbCdEf1234567890abcdef1234567890ABCDEFGHijk%3D",
]

def main(out):
    body = "".join(f'<w:p><w:r><w:t xml:space="preserve">{l}</w:t></w:r></w:p>' for l in LINES)
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           f'<w:body>{body}</w:body></w:document>')
    ct = ('<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
          '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>')
    core = ('<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<dc:creator>Olena Kovalenko</dc:creator><dc:title>Довідка</dc:title>'
            '<dcterms:created xsi:type="dcterms:W3CDTF">2024-03-14T10:00:00Z</dcterms:created></cp:coreProperties>')
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n, data in [("[Content_Types].xml", ct), ("_rels/.rels", rels), ("word/document.xml", doc), ("docProps/core.xml", core)]:
            zi = zipfile.ZipInfo(n, (2024, 3, 14, 10, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "personal.docx"))
