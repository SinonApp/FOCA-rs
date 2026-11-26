#!/usr/bin/env python3
"""Builds the built-in reference offline case (`demo_case_import`): a compact ZIP with twelve
synthetic documents of the fictional company «ТОВ Приклад» (example.test / example.com) that
exercise every forensic feature of the core without a network.

Everything is fictional: people (Іван Петренко, Olena Kovalenko, John Doe), hosts, addresses,
tax numbers (synthetic, valid check digit) and certificates (a throw-away test CA). The script
reuses the existing corpus generators and fixtures:

* `crates/foca-meta/tests/fixtures/forensics/`: PDF with a qualified e-signature (КЕП) of
  «ТОВ Приклад», PDF with a bad redaction, PDF with incremental revisions by two authors,
  XLSX with a hidden sheet and an external data connection;
* `tests/corpus/make_corpus_13.py`: LNK (UNC path, machine id, MAC), EML with `Received`
  chain and internal relays, ICS with a meeting link, VCF with contacts;
* `tests/corpus/make_corpus.py`: TIFF/EXIF helpers for a JPEG with GPS and a camera serial.

New here: a DOCX and its later edit sharing Word editing sessions (`w:rsids`, lineage) and an
ODT letter. The ZIP is deterministic (fixed timestamps, sorted names) apart from the reused
fixture bytes.

    python3 qa/make_demo_case.py   # → crates/foca-engine/assets/demo_case.zip

Requires Python 3 with Pillow (for the JPEG pixels).
"""

import importlib.util
import io
import os
import sys
import zipfile

# The corpus tests walk tests/corpus recursively; never leave __pycache__ there.
sys.dont_write_bytecode = True

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "crates/foca-engine/assets/demo_case.zip")
FX = os.path.join(ROOT, "crates/foca-meta/tests/fixtures/forensics")
STAMP = (2026, 3, 2, 10, 0, 0)


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # make_corpus_13 imports make_corpus by name
    spec.loader.exec_module(mod)
    return mod


c12 = load("tests/corpus/make_corpus.py", "make_corpus")
c13 = load("tests/corpus/make_corpus_13.py", "make_corpus_13")

ORG_EN = "TOV Pryklad (fictional)"
ORG_UK = "ТОВ «Приклад» (вигадана)"


def zwrite(entries):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name, STAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return bio.getvalue()


# ---------------------------------------------------------------- DOCX lineage pair
CT_DOCX = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
    '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
    '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
    "</Types>"
)
RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
    '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
    "</Relationships>"
)
DOC_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>'
    "</Relationships>"
)
W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def docx(title, creator, last, rev, created, modified, rsids, paras):
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>{title}</dc:title><dc:creator>{creator}</dc:creator>"
        f"<cp:lastModifiedBy>{last}</cp:lastModifiedBy><cp:revision>{rev}</cp:revision>"
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>'
        f'<dcterms:modified xsi:type="dcterms:W3CDTF">{modified}</dcterms:modified>'
        "</cp:coreProperties>"
    )
    app = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        "<Template>\\\\FS01.corp.example.test\\templates$\\Наказ.dotx</Template>"
        "<Application>Microsoft Office Word</Application><AppVersion>16.0000</AppVersion>"
        f"<Company>{ORG_UK}</Company></Properties>"
    )
    rs = "".join(f'<w:rsid w:val="{r}"/>' for r in rsids)
    settings = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:settings {W}>'
        f'<w:rsids><w:rsidRoot w:val="{rsids[0]}"/>{rs}</w:rsids></w:settings>'
    )
    body = "".join(
        f'<w:p w:rsidR="{rsids[min(i, len(rsids) - 1)]}"><w:r><w:t xml:space="preserve">{p}</w:t></w:r></w:p>'
        for i, p in enumerate(paras)
    )
    document = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document {W}><w:body>{body}</w:body></w:document>'
    )
    return zwrite(
        [
            ("[Content_Types].xml", CT_DOCX),
            ("_rels/.rels", RELS),
            ("docProps/core.xml", core),
            ("docProps/app.xml", app),
            ("word/_rels/document.xml.rels", DOC_RELS),
            ("word/settings.xml", settings),
            ("word/document.xml", document),
        ]
    )


RSIDS = ["00A1B2C3", "00D4E5F6", "0017A8B9"]
PARAS = [
    "ТОВ «Приклад». Положення про використання ІТ-ресурсів.",
    "Файли відділу зберігаються на \\\\FS01.corp.example.test\\buh$\\Положення.",
    "Відповідальний: Іван Петренко, i.petrenko@example.com.",
]


# ---------------------------------------------------------------- JPEG with GPS
def photo():
    ent, A, B, R, S = c12.ent, c12.ASCII, c12.BYTE, c12.RATIONAL, c12.SHORT
    main = c12.jpeg_bytes((40, 120, 90), (64, 48))
    thumb = c12.jpeg_bytes((40, 120, 90), (16, 12), quality=60)
    ifd0 = [
        ent(0x010E, A, "Склад ТОВ Приклад"),
        ent(0x010F, A, "Apple"),
        ent(0x0110, A, "iPhone 13 Pro"),
        ent(0x0131, A, "17.2"),
        ent(0x0132, A, "2026:02:20 14:10:05"),
        ent(0x013B, A, "Ivan Petrenko"),
    ]
    exif = [
        ent(0x9003, A, "2026:02:20 14:10:05"),
        ent(0xA430, A, "i.petrenko"),
        ent(0xA431, A, "F2LXX0EXAMPLE"),
        ent(0xA434, A, "iPhone 13 Pro back triple camera 5.7mm f/1.5"),
    ]
    gps = [
        ent(0x0000, B, [2, 3, 0, 0]),
        ent(0x0001, A, "N"),
        ent(0x0002, R, [(50, 1), (27, 1), (1000, 100)]),
        ent(0x0003, A, "E"),
        ent(0x0004, R, [(30, 1), (31, 1), (2000, 100)]),
        ent(0x0005, B, [0]),
        ent(0x0006, R, [(1790, 10)]),
    ]
    tiff = c12.build_tiff(ifd0, exif, gps, [ent(0x0103, S, 6)], thumb)
    app1 = c12.seg(0xE1, b"Exif\0\0" + tiff)
    assert main[:4] == b"\xff\xd8\xff\xe0"
    cut = 4 + int.from_bytes(main[4:6], "big")
    return main[:cut] + app1 + main[cut:]


# ---------------------------------------------------------------- ODT
def odt():
    meta = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.3">'
        "<office:meta><meta:generator>LibreOffice/7.6.4.1$Linux_X86_64</meta:generator>"
        "<dc:title>Лист партнеру</dc:title><meta:initial-creator>Olena Kovalenko</meta:initial-creator>"
        "<dc:creator>Іван Петренко</dc:creator><meta:creation-date>2026-02-10T09:12:00</meta:creation-date>"
        "<dc:date>2026-02-12T17:40:00</dc:date><meta:editing-cycles>4</meta:editing-cycles>"
        '<meta:template xlink:href="file:///home/o.kovalenko/Шаблони/Лист.ott" xmlns:xlink="http://www.w3.org/1999/xlink"/>'
        "</office:meta></office:document-meta>"
    )
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:version="1.3">'
        "<office:body><office:text><text:p>Шановні партнери! Договір див. на https://intranet.example.test/contracts/42.</text:p>"
        "</office:text></office:body></office:document-content>"
    )
    manifest = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">'
        '<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>'
        '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
        '<manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/>'
        "</manifest:manifest>"
    )
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        info = zipfile.ZipInfo("mimetype", STAMP)
        info.compress_type = zipfile.ZIP_STORED
        z.writestr(info, "application/vnd.oasis.opendocument.text")
        for n, d in [("META-INF/manifest.xml", manifest), ("meta.xml", meta), ("content.xml", content)]:
            i = zipfile.ZipInfo(n, STAMP)
            i.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(i, d)
    return bio.getvalue()


def fixture(name):
    with open(os.path.join(FX, name), "rb") as f:
        return f.read()


def rebrand(b):
    return b.replace(b"Contoso Energy (fictional)", ORG_EN.encode()).replace(b"contoso-my.", b"pryklad-my.")


def main():
    docs = [
        ("Положення_ІТ.docx", docx("Положення про ІТ", "Іван Петренко", "Іван Петренко", 3,
                                   "2026-01-12T08:00:00Z", "2026-01-14T16:20:00Z", RSIDS, PARAS)),
        ("Положення_ІТ_редакція_2.docx", docx("Положення про ІТ", "Іван Петренко", "Olena Kovalenko", 7,
                                              "2026-01-12T08:00:00Z", "2026-02-03T11:05:00Z",
                                              RSIDS + ["00C0FFEE"], PARAS + ["Зміни погоджено з бухгалтерією."])),
        ("Наказ_підписаний_КЕП.pdf", fixture("signed.pdf")),
        ("Звіт_знеособлений.pdf", fixture("redacted.pdf")),
        ("Кошторис_ревізії.pdf", fixture("revisions.pdf")),
        ("Бюджет_2026.xlsx", fixture("hidden.xlsx")),
        ("Звіт_за_квартал.lnk", c13.make_lnk(net=r"\\FS01.corp.example.test\buh$", suffix=r"Звіти\2026\Q1.xlsx",
                                             machine="buh-pc-07", mac=b"\x00\x15\x5d\x01\x02\x03")),
        ("Лист_кошторис.eml", rebrand(c13.make_eml())),
        ("Фото_складу.jpg", photo()),
        ("Лист_партнеру.odt", odt()),
        ("Нарада.ics", rebrand(c13.make_ics())),
        ("Контакти.vcf", rebrand(c13.make_vcf()).replace(ORG_EN.encode(), ORG_UK.encode())),
    ]
    data = zwrite(sorted(docs))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(data)
    print(f"{OUT}: {len(docs)} documents, {len(data)} bytes")


if __name__ == "__main__":
    main()
