#!/usr/bin/env python3
"""Генератор синтетического корпуса FOCA-rs (N-4). Только stdlib + Pillow (если установлен).

Порядок:
  1. cargo run -p foca-meta --example make_ole_corpus -- tests/corpus   (OLE2: doc/xls/ppt/vbaProject.bin)
  2. python3 tests/corpus/make_corpus.py                                 (всё остальное)
  3. UPDATE_GOLDEN=1 cargo test -p foca-meta --test golden               (обновить *.expected.json)

Все файлы побайтно воспроизводимы (фиксированные даты в zip и в хранилищах OLE). Данные вымышленные (компания «Контосо Енерджі»).
"""
import io
import os
import struct
import zipfile
import zlib

ROOT = os.path.dirname(os.path.abspath(__file__))
ZDATE = (2024, 3, 14, 18, 42, 0)


def out(rel, data):
    p = os.path.join(ROOT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    print(f"{rel}: {len(data)} bytes")


def make_zip(entries, stored_first=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        if stored_first:
            zi = zipfile.ZipInfo(stored_first[0], ZDATE)
            zi.compress_type = zipfile.ZIP_STORED
            z.writestr(zi, stored_first[1])
        for name, data in entries:
            zi = zipfile.ZipInfo(name, ZDATE)
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data.encode("utf-8") if isinstance(data, str) else data)
    return buf.getvalue()


# ---------------------------------------------------------------- TIFF/EXIF
ASCII, SHORT, LONG, RATIONAL, BYTE, UNDEF = 2, 3, 4, 5, 1, 7
TYPE_SIZE = {BYTE: 1, ASCII: 1, SHORT: 2, LONG: 4, RATIONAL: 8, UNDEF: 1}


def ent(tag, typ, value):
    if typ == ASCII:
        b = value.encode("utf-8") + b"\0"
        return (tag, typ, len(b), b)
    if typ == SHORT:
        vals = value if isinstance(value, list) else [value]
        return (tag, typ, len(vals), b"".join(struct.pack("<H", v) for v in vals))
    if typ == LONG:
        vals = value if isinstance(value, list) else [value]
        return (tag, typ, len(vals), b"".join(struct.pack("<I", v) for v in vals))
    if typ == RATIONAL:
        return (tag, typ, len(value), b"".join(struct.pack("<II", n, d) for n, d in value))
    if typ in (BYTE, UNDEF):
        return (tag, typ, len(value), bytes(value))
    raise ValueError(typ)


def build_tiff(ifd0, exif=None, gps=None, ifd1=None, thumb=None):
    """Собрать TIFF (little endian) с указателями на EXIF/GPS IFD и IFD1 с миниатюрой."""
    ifd0 = list(ifd0)
    if exif:
        ifd0.append((0x8769, LONG, 1, b"\0\0\0\0"))
    if gps:
        ifd0.append((0x8825, LONG, 1, b"\0\0\0\0"))
    ifds = [("ifd0", sorted(ifd0))]
    if exif:
        ifds.append(("exif", sorted(exif)))
    if gps:
        ifds.append(("gps", sorted(gps)))
    if ifd1 is not None:
        ifd1 = list(ifd1) + [(0x0201, LONG, 1, b"\0\0\0\0"), (0x0202, LONG, 1, struct.pack("<I", len(thumb)))]
        ifds.append(("ifd1", sorted(ifd1)))
    # раскладка: заголовок, затем каждый IFD с областью данных
    offs = {}
    pos = 8
    for name, entries in ifds:
        offs[name] = pos
        pos += 2 + 12 * len(entries) + 4
        for e in entries:
            if len(e[3]) > 4:
                pos += len(e[3]) + (len(e[3]) & 1)
    thumb_off = pos

    def fix(entries):
        res = []
        for tag, typ, cnt, data in entries:
            if tag == 0x8769:
                data = struct.pack("<I", offs["exif"])
            elif tag == 0x8825:
                data = struct.pack("<I", offs["gps"])
            elif tag == 0x0201:
                data = struct.pack("<I", thumb_off)
            res.append((tag, typ, cnt, data))
        return res

    b = bytearray(b"II*\0" + struct.pack("<I", 8))
    for i, (name, entries) in enumerate(ifds):
        entries = fix(entries)
        start = offs[name]
        assert len(b) == start
        data_pos = start + 2 + 12 * len(entries) + 4
        head = bytearray(struct.pack("<H", len(entries)))
        blob = bytearray()
        for tag, typ, cnt, data in entries:
            if len(data) <= 4:
                head += struct.pack("<HHI", tag, typ, cnt) + data.ljust(4, b"\0")
            else:
                head += struct.pack("<HHII", tag, typ, cnt, data_pos + len(blob))
                blob += data + (b"\0" if len(data) & 1 else b"")
        nxt = offs["ifd1"] if (name == "ifd0" and "ifd1" in offs) else 0
        head += struct.pack("<I", nxt)
        b += head + blob
    if thumb:
        assert len(b) == thumb_off
        b += thumb
    return bytes(b)


def jpeg_bytes(color, size, quality=85):
    from PIL import Image

    im = Image.new("RGB", size, color)
    bio = io.BytesIO()
    im.save(bio, "JPEG", quality=quality)
    return bio.getvalue()


def seg(marker, payload):
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


XMP_PHOTO = """<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/"
 xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#"
 xmp:CreatorTool="Adobe Photoshop CC 2019 (Windows)" xmp:CreateDate="2024-08-02T11:05:33+03:00">
<dc:creator><rdf:Seq><rdf:li>Віктор Ткаченко</rdf:li></rdf:Seq></dc:creator>
<xmpMM:History><rdf:Seq><rdf:li stEvt:action="saved" stEvt:softwareAgent="Adobe Photoshop CC 2019 (Windows)"/></rdf:Seq></xmpMM:History>
</rdf:Description></rdf:RDF></x:xmpmeta>
<?xpacket end="w"?>"""


def iptc_app13():
    def rec(ds, s):
        b = s.encode("utf-8")
        return b"\x1c\x02" + bytes([ds]) + struct.pack(">H", len(b)) + b

    data = rec(80, "Viktor Tkachenko") + rec(116, "(c) Contoso Energy") + rec(25, "ТЕС-2") + rec(25, "будівництво") + rec(90, "Kryvyi Rih")
    res = b"8BIM" + struct.pack(">H", 0x0404) + b"\0\0" + struct.pack(">I", len(data)) + data
    if len(data) & 1:
        res += b"\0"
    return b"Photoshop 3.0\0" + res


def make_photo():
    main = jpeg_bytes((30, 80, 200), (64, 48))
    thumb = jpeg_bytes((220, 30, 30), (16, 12), quality=60)  # миниатюра ≠ фото (I-3)
    ifd0 = [
        ent(0x010E, ASCII, "ТЕС-2, будмайданчик"),
        ent(0x010F, ASCII, "Apple"),
        ent(0x0110, ASCII, "iPhone 13 Pro"),
        ent(0x0131, ASCII, "16.6"),
        ent(0x0132, ASCII, "2024:08:02 11:06:00"),
        ent(0x013B, ASCII, "Viktor Tkachenko"),
        ent(0x013C, ASCII, "ENG-WS11"),
    ]
    exif = [
        ent(0x9003, ASCII, "2024:08:02 11:05:33"),
        ent(0xA430, ASCII, "v.tkachenko"),
        ent(0xA431, ASCII, "F2LXK0QJQ6"),
        ent(0xA434, ASCII, "iPhone 13 Pro back triple camera 5.7mm f/1.5"),
    ]
    gps = [
        ent(0x0000, BYTE, [2, 3, 0, 0]),
        ent(0x0001, ASCII, "N"),
        ent(0x0002, RATIONAL, [(47, 1), (55, 1), (1200, 100)]),
        ent(0x0003, ASCII, "E"),
        ent(0x0004, RATIONAL, [(33, 1), (25, 1), (4800, 100)]),
        ent(0x0005, BYTE, [0]),
        ent(0x0006, RATIONAL, [(1205, 10)]),
    ]
    ifd1 = [ent(0x0103, SHORT, 6)]
    tiff = build_tiff(ifd0, exif, gps, ifd1, thumb)
    app1 = seg(0xE1, b"Exif\0\0" + tiff)
    xmp = seg(0xE1, b"http://ns.adobe.com/xap/1.0/\0" + XMP_PHOTO.encode("utf-8"))
    app13 = seg(0xED, iptc_app13())
    com = seg(0xFE, b"Shot by v.tkachenko for \\\\SRV-FILE01\\photo\\TES2")
    # после SOI+APP0 (JFIF) вставляем свои сегменты
    assert main[:4] == b"\xff\xd8\xff\xe0"
    app0_len = struct.unpack(">H", main[4:6])[0]
    cut = 4 + app0_len
    return main[:cut] + app1 + xmp + app13 + com + main[cut:]


def make_png():
    from PIL import Image
    from PIL.PngImagePlugin import PngInfo

    im = Image.new("RGB", (32, 24), (10, 150, 90))
    info = PngInfo()
    info.add_text("Author", "Марина Шевчук")
    info.add_text("Software", "Greenshot 1.2.10")
    info.add_text("Comment", "C:\\Users\\m.shevchuk\\Pictures\\Screenshots\\portal.png")
    info.add_itxt("XML:com.adobe.xmp", XMP_PHOTO.replace("Віктор Ткаченко", "Марина Шевчук"))
    tiff = build_tiff([ent(0x010F, ASCII, "Samsung"), ent(0x0110, ASCII, "SM-G991B")])
    bio = io.BytesIO()
    im.save(bio, "PNG", pnginfo=info, exif=b"Exif\0\0" + tiff)
    return bio.getvalue()


def make_tiff():
    from PIL import Image
    from PIL.TiffImagePlugin import ImageFileDirectory_v2

    im = Image.new("L", (16, 16), 128)
    ifd = ImageFileDirectory_v2()
    ifd[271] = "Canon"
    ifd[272] = "iR-ADV C5535"
    ifd[305] = "Canon iR-ADV C5535 PDF 1.2"
    ifd[306] = "2023:11:20 09:12:44"
    ifd[315] = "scan"
    ifd[316] = "MFP-2F"
    ifd[270] = "Scan to \\\\SRV-FILE01\\scan$\\2023-11"
    bio = io.BytesIO()
    im.save(bio, "TIFF", tiffinfo=ifd)
    return bio.getvalue()


# ---------------------------------------------------------------- OOXML
CT = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="jpeg" ContentType="image/jpeg"/><Default Extension="png" ContentType="image/png"/><Default Extension="bin" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.printerSettings"/>{overrides}</Types>"""

ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{main}"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/></Relationships>"""


def core_xml(title, creator, last, rev, created, modified, printed=None, keywords=None, category=None):
    extra = ""
    if printed:
        extra += f"<cp:lastPrinted>{printed}</cp:lastPrinted>"
    if keywords:
        extra += f"<cp:keywords>{keywords}</cp:keywords>"
    if category:
        extra += f"<cp:category>{category}</cp:category>"
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>{title}</dc:title><dc:subject>Тендер ТЕС-2</dc:subject><dc:creator>{creator}</dc:creator><dc:description>Внутрішній документ</dc:description><cp:lastModifiedBy>{last}</cp:lastModifiedBy><cp:revision>{rev}</cp:revision>{extra}<dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">{modified}</dcterms:modified><dc:language>uk-UA</dc:language></cp:coreProperties>"""


def app_xml(app, ver, company, template, total, stats):
    st = "".join(f"<{k}>{v}</{k}>" for k, v in stats)
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Template>{template}</Template><TotalTime>{total}</TotalTime>{st}<Application>{app}</Application><DocSecurity>0</DocSecurity><Company>{company}</Company><Manager>Бондар А.</Manager><LinksUpToDate>false</LinksUpToDate><AppVersion>{ver}</AppVersion></Properties>"""


def custom_xml(props):
    items = "".join(
        f'<property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="{i + 2}" name="{k}"><vt:lpwstr>{v}</vt:lpwstr></property>'
        for i, (k, v) in enumerate(props)
    )
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">{items}</Properties>"""


def devmode(name):
    b = name.encode("utf-16-le")[:62].ljust(64, b"\0")
    return b + struct.pack("<HHHH", 0x0401, 0x0601, 220, 0) + b"\0" * 148


W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml"'


def make_docx(photo):
    doc = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document {W}><w:body>
<w:p w:rsidR="00A1B2C3" w:rsidRDefault="00A1B2C3"><w:r><w:t>Договір постачання № 17/24 для ТЕС-2.</w:t></w:r></w:p>
<w:p w:rsidR="00D4E5F6"><w:r><w:t xml:space="preserve">Ціна договору: </w:t></w:r><w:del w:id="1" w:author="a.bondar" w:date="2024-03-14T17:02:00Z"><w:r><w:delText>1 250 000 грн</w:delText></w:r></w:del><w:ins w:id="2" w:author="Ігор Петренко" w:date="2024-03-14T17:05:00Z"><w:r><w:t>980 000 грн</w:t></w:r></w:ins></w:p>
<w:p><w:r><w:t>Доступ до порталу: Server=10.10.1.5;Database=tender;User Id=sa;Password=Tender2024!</w:t></w:r></w:p>
<w:p><w:hyperlink r:id="rId10"><w:r><w:t>Специфікація</w:t></w:r></w:hyperlink><w:commentRangeStart w:id="0"/><w:r><w:t> див. також \\\\SRV-FILE01\\buh$\\Податкова\\2024</w:t></w:r><w:commentRangeEnd w:id="0"/></w:p>
<w:p><w:r><w:drawing><a:blip xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" r:embed="rId11"/></w:drawing></w:r></w:p>
<w:sectPr/></w:body></w:document>"""
    doc_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/><Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="file:///C:\\Users\\a.bondar\\Documents\\Тендер\\Специфікація_v2.xlsx" TargetMode="External"/><Relationship Id="rId12" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://portal.contoso.example/tender/17" TargetMode="External"/><Relationship Id="rId11" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image1.jpeg"/></Relationships>"""
    settings = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings {W}><w:attachedTemplate r:id="rId1"/><w:trackRevisions/><w:rsids><w:rsidRoot w:val="00A1B2C3"/><w:rsid w:val="00A1B2C3"/><w:rsid w:val="00D4E5F6"/><w:rsid w:val="0012F00D"/></w:rsids></w:settings>"""
    settings_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file:///\\\\SRV-FILE01\\public\\Шаблони\\Договір.dotx" TargetMode="External"/></Relationships>"""
    comments = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:comments {W}><w:comment w:id="0" w:author="Олена Коваленко" w:date="2024-03-14T16:40:00Z" w:initials="ОК"><w:p><w:r><w:t>Перевірити реквізити, логін o.kovalenko@contoso.example</w:t></w:r></w:p></w:comment></w:comments>"""
    people = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w15:people {W}><w15:person w15:author="Олена Коваленко"><w15:presenceInfo w15:providerId="AD" w15:userId="S::o.kovalenko@contoso.example::8f3a"/></w15:person></w15:people>"""
    files = [
        ("[Content_Types].xml", CT.format(overrides='<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>')),
        ("_rels/.rels", ROOT_RELS.format(main="word/document.xml")),
        ("docProps/core.xml", core_xml("Договір постачання ТЕС-2", "Андрій Бондар", "a.bondar", 7, "2024-03-01T08:15:00Z", "2024-03-14T18:42:00Z", "2024-03-14T18:30:00Z", "договір; ТЕС-2", "Юридичні")),
        ("docProps/app.xml", app_xml("Microsoft Office Word", "15.0000", "ТОВ «Контосо Енерджі»", "Договір.dotx", 42, [("Pages", 3), ("Words", 512), ("Characters", 2920), ("Lines", 24), ("Paragraphs", 6)])),
        ("docProps/custom.xml", custom_xml([("Проєкт", "ТЕС-2"), ("Відповідальний", "o.kovalenko@contoso.example")])),
        ("word/document.xml", doc),
        ("word/_rels/document.xml.rels", doc_rels),
        ("word/settings.xml", settings),
        ("word/_rels/settings.xml.rels", settings_rels),
        ("word/comments.xml", comments),
        ("word/people.xml", people),
        ("word/printerSettings/printerSettings1.bin", devmode("\\\\SRV-PRN01\\Canon C5535 2F")),
        ("word/media/image1.jpeg", photo),
    ]
    return make_zip(files)


def make_xlsx(vba):
    wb = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Графік" sheetId="1" r:id="rId1"/><sheet name="Зарплати" sheetId="2" state="hidden" r:id="rId2"/><sheet name="Паролі" sheetId="3" state="veryHidden" r:id="rId3"/></sheets></workbook>"""
    sst = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="3" uniqueCount="3"><si><t>Графік відключень</t></si><si><t>AKIAIOSFODNN7EXAMPLE</t></si><si><r><t>Черга </t></r><r><t>3</t></r></si></sst>"""
    sheet = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="inlineStr"><is><t>інлайн текст</t></is></c></row></sheetData></worksheet>"""
    comments = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><authors><author>Віктор Ткаченко</author><author>s.lysenko</author></authors><commentList><comment ref="A1" authorId="0"><text><r><t>Ключ AWS тимчасовий</t></r></text></comment><comment ref="B1" authorId="1"><text><t>ok</t></text></comment></commentList></comments>"""
    ext_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLinkPath" Target="file:///\\\\NAS02\\finance\\Бюджет_2024.xlsx" TargetMode="External"/></Relationships>"""
    conns = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<connections xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><connection id="1" name="billing" type="1" refreshedVersion="6"><dbPr connection="Provider=SQLOLEDB.1;Password=Bill!ng2023;User ID=billing_ro;Data Source=SRV-SQL02;Initial Catalog=billing" command="SELECT * FROM tariffs"/></connection></connections>"""
    persons = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<personList xmlns="http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments"><person displayName="Сергій Лисенко" id="{11111111-2222-3333-4444-555555555555}" userId="s.lysenko@contoso.example" providerId="AD"/></personList>"""
    files = [
        ("[Content_Types].xml", CT.format(overrides='<Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>')),
        ("_rels/.rels", ROOT_RELS.format(main="xl/workbook.xml")),
        ("docProps/core.xml", core_xml("Графік відключень", "s.lysenko", "Віктор Ткаченко", 3, "2023-10-01T07:00:00Z", "2023-11-02T15:20:00Z")),
        ("docProps/app.xml", app_xml("Microsoft Excel", "14.0300", "ТОВ «Контосо Енерджі»", "", 0, [])),
        ("xl/workbook.xml", wb),
        ("xl/sharedStrings.xml", sst),
        ("xl/worksheets/sheet1.xml", sheet),
        ("xl/comments1.xml", comments),
        ("xl/externalLinks/externalLink1.xml", '<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>'),
        ("xl/externalLinks/_rels/externalLink1.xml.rels", ext_rels),
        ("xl/connections.xml", conns),
        ("xl/persons/person.xml", persons),
        ("xl/printerSettings/printerSettings1.bin", devmode("HP LaserJet Pro M404 (BUH)")),
        ("xl/vbaProject.bin", vba),
    ]
    return make_zip(files)


def make_pptx(png):
    authors = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:cmAuthorLst xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cmAuthor id="1" name="Марина Шевчук" initials="МШ" lastIdx="1" clrIdx="0"/></p:cmAuthorLst>"""
    cm = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:cmLst xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cm authorId="1" dt="2024-02-10T12:00:00.000" idx="1"><p:pos x="10" y="10"/><p:text>Прибрати цифри EBITDA до публікації</p:text></p:cm></p:cmLst>"""
    slide = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Стратегія 2026</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>"""
    notes = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:notes xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Нотатка: VPN vpn.contoso.example, логін m.shevchuk</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:notes>"""
    files = [
        ("[Content_Types].xml", CT.format(overrides='<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>')),
        ("_rels/.rels", ROOT_RELS.format(main="ppt/presentation.xml")),
        ("docProps/core.xml", core_xml("Стратегія 2026", "Марина Шевчук", "m.shevchuk", 15, "2024-01-20T09:00:00Z", "2024-02-11T19:30:00Z")),
        ("docProps/app.xml", app_xml("Microsoft Office PowerPoint", "16.0000", "Contoso Energy", "Office Theme", 380, [("Words", 120), ("Paragraphs", 18), ("Slides", 2), ("Notes", 1), ("HiddenSlides", 1)])),
        ("ppt/presentation.xml", '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>'),
        ("ppt/slides/slide1.xml", slide),
        ("ppt/notesSlides/notesSlide1.xml", notes),
        ("ppt/commentAuthors.xml", authors),
        ("ppt/comments/comment1.xml", cm),
        ("ppt/media/image1.png", png),
    ]
    return make_zip(files)


# ---------------------------------------------------------------- ODF
def make_odt(photo):
    meta = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xlink="http://www.w3.org/1999/xlink" office:version="1.3"><office:meta>
<meta:generator>LibreOffice/7.2.5.2$Windows_X86_64 LibreOffice_project/499f9727c189e6ef3471021d6132d4c694f357e5</meta:generator>
<dc:title>Лист-відповідь</dc:title><dc:description>Відповідь на запит</dc:description><dc:subject>Підключення</dc:subject>
<meta:keyword>лист</meta:keyword><meta:keyword>підключення</meta:keyword>
<meta:initial-creator>Тетяна Мельник</meta:initial-creator><dc:creator>t.melnyk</dc:creator>
<meta:creation-date>2022-05-17T10:11:12.345000000</meta:creation-date><dc:date>2022-05-18T08:00:00.123000000</dc:date>
<meta:print-date>2022-05-18T08:05:00</meta:print-date><meta:printed-by>Тетяна Мельник</meta:printed-by>
<dc:language>uk-UA</dc:language><meta:editing-cycles>5</meta:editing-cycles><meta:editing-duration>PT1H23M45S</meta:editing-duration>
<meta:template xlink:type="simple" xlink:actuate="onRequest" xlink:title="Бланк" xlink:href="file:///home/tmelnyk/Шаблони/Бланк.ott"/>
<meta:document-statistic meta:table-count="0" meta:image-count="1" meta:object-count="0" meta:page-count="1" meta:paragraph-count="4" meta:word-count="37" meta:character-count="250"/>
<meta:user-defined meta:name="Відділ">HR</meta:user-defined>
</office:meta></office:document-meta>"""
    content = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"><office:body><office:text>
<text:tracked-changes><text:changed-region text:id="ct1"><text:deletion><office:change-info><dc:creator>Андрій Бондар</dc:creator><dc:date>2022-05-17T15:00:00</dc:date></office:change-info><text:p>Строк: 10 днів</text:p></text:deletion></text:changed-region></text:tracked-changes>
<text:p>Шановні колеги!<office:annotation><dc:creator>i.petrenko</dc:creator><dc:date>2022-05-17T16:00:00</dc:date><text:p>Додати телефон 0441234567</text:p></office:annotation></text:p>
<text:p>Деталі: <text:a xlink:type="simple" xlink:href="https://contoso.example/connect">сайт</text:a> та <text:a xlink:href="file:///\\\\NAS02\\hr\\Накази\\2022">накази</text:a></text:p>
<text:p><draw:frame><draw:image xlink:href="Pictures/photo.jpg"/></draw:frame></text:p>
</office:text></office:body></office:document-content>"""
    manifest = """<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="Pictures/photo.jpg" manifest:media-type="image/jpeg"/></manifest:manifest>"""
    files = [("META-INF/manifest.xml", manifest), ("meta.xml", meta), ("content.xml", content), ("Pictures/photo.jpg", photo)]
    return make_zip(files, stored_first=("mimetype", "application/vnd.oasis.opendocument.text"))


def make_ods():
    meta = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><office:meta><meta:generator>OpenOffice/4.1.14$Win32 OpenOffice.org_project/4114m1$Build-9811</meta:generator><meta:initial-creator>admin</meta:initial-creator><meta:creation-date>2017-02-01T09:00:00</meta:creation-date><meta:document-statistic meta:table-count="2" meta:cell-count="40"/></office:meta></office:document-meta>"""
    manifest = """<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"><manifest:encryption-data manifest:checksum-type="SHA1/1K" manifest:checksum="x"/></manifest:file-entry></manifest:manifest>"""
    files = [("META-INF/manifest.xml", manifest), ("meta.xml", meta), ("content.xml", "ENCRYPTED-BINARY")]
    return make_zip(files, stored_first=("mimetype", "application/vnd.oasis.opendocument.spreadsheet"))


# ---------------------------------------------------------------- PDF
def pdf_str_utf16(s):
    return "<FEFF" + s.encode("utf-16-be").hex().upper() + ">"


class PdfWriter:
    def __init__(self, header=b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"):
        self.buf = bytearray(header)
        self.offsets = {}

    def obj(self, num, body, stream=None):
        self.offsets[num] = len(self.buf)
        if isinstance(body, str):
            body = body.encode("latin-1")
        if stream is None:
            self.buf += f"{num} 0 obj\n".encode() + body + b"\nendobj\n"
        else:
            self.buf += f"{num} 0 obj\n".encode() + body + b"\nstream\n" + stream + b"\nendstream\nendobj\n"

    def xref(self, nums, trailer, prev=None):
        pos = len(self.buf)
        self.buf += b"xref\n"
        if prev is None:
            self.buf += f"0 {max(nums) + 1}\n".encode() + b"0000000000 65535 f \n"
            for n in range(1, max(nums) + 1):
                off = self.offsets.get(n, 0)
                self.buf += f"{off:010d} 00000 n \n".encode()
        else:
            self.buf += b"0 1\n0000000000 65535 f \n"
            for n in sorted(nums):
                self.buf += f"{n} 1\n{self.offsets[n]:010d} 00000 n \n".encode()
        self.buf += b"trailer\n" + trailer.encode("latin-1") + b"\nstartxref\n" + str(pos).encode() + b"\n%%EOF\n"
        return pos


XMP_PDF = """<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:pdf="http://ns.adobe.com/pdf/1.3/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" pdf:Producer="Microsoft® Word 2013" xmp:CreatorTool="Microsoft® Word 2013" xmp:CreateDate="2024-03-14T18:42:00+02:00"><dc:creator><rdf:Seq><rdf:li>o.kovalenko</rdf:li></rdf:Seq></dc:creator><dc:title><rdf:Alt><rdf:li xml:lang="x-default">Річний звіт 2024</rdf:li></rdf:Alt></dc:title><xmpMM:DocumentID>uuid:2B0C7F8E-1111-2222-3333-444455556666</xmpMM:DocumentID></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>"""

RDP_TEXT = """screen mode id:i:2
full address:s:SRV-TS01.corp.contoso.example:3389
gatewayhostname:s:rdgw.contoso.example
username:s:CONTOSO\\i.petrenko
domain:s:CONTOSO
alternate shell:s:C:\\Program Files\\1cv8\\common\\1cestart.exe
shell working directory:s:C:\\Users\\i.petrenko\\Documents
password 51:b:01000000D08C9DDF0115D1118C7A00C04FC297EB0100000052A9E191EA75A948B359790578C9371A0000000008000000
"""


def make_pdf():
    w = PdfWriter()
    w.obj(1, "<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R /OpenAction 8 0 R /Names << /EmbeddedFiles 9 0 R >> >>")
    w.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    w.obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Annots [10 0 R] /Resources << /Font << /F1 7 0 R >> >> >>")
    content = b"BT /F1 12 Tf 72 720 Td (Annual report 2024. Contact: i.petrenko@contoso.example) Tj ET"
    w.obj(4, f"<< /Length {len(content)} >>", content)
    w.obj(5, "<< /Title " + pdf_str_utf16("Річний звіт 2024") + " /Author (o.kovalenko) /Creator (Microsoft\\256 Word 2013) /Producer (Microsoft\\256 Word 2013) /CreationDate (D:20240314184200+02'00') /ModDate (D:20240314184200+02'00') /Company (Contoso Energy) >>")
    xmp = zlib.compress(XMP_PDF.encode("utf-8"))
    w.obj(6, f"<< /Type /Metadata /Subtype /XML /Filter /FlateDecode /Length {len(xmp)} >>", xmp)
    w.obj(7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    w.obj(8, "<< /S /JavaScript /JS (app.alert\\('Перевірка'\\);) >>".encode("utf-8").decode("latin-1"))
    w.obj(9, "<< /Names [(creds.rdp) 11 0 R] >>")
    w.obj(10, "<< /Type /Annot /Subtype /Text /Rect [100 100 120 120] /T " + pdf_str_utf16("Тетяна Мельник") + " /Contents " + pdf_str_utf16("Перевірити суму") + " /M (D:20240315090000Z) >>")
    w.obj(11, "<< /Type /Filespec /F (creds.rdp) /UF (creds.rdp) /EF << /F 12 0 R >> >>")
    emb = zlib.compress(RDP_TEXT.encode("utf-8"))
    w.obj(12, f"<< /Type /EmbeddedFile /Subtype /application#2Fx-rdp /Filter /FlateDecode /Length {len(emb)} /Params << /Size {len(RDP_TEXT.encode())} >> >>", emb)
    first = w.xref(range(1, 13), "<< /Size 13 /Root 1 0 R /Info 5 0 R /ID [<0123456789ABCDEF0123456789ABCDEF> <0123456789ABCDEF0123456789ABCDEF>] >>")
    # инкрементальное обновление: другой автор и ПО
    w.obj(5, "<< /Title " + pdf_str_utf16("Річний звіт 2024") + " /Author (Administrator) /Creator (Microsoft\\256 Word 2013) /Producer (Adobe Acrobat Pro XI 11.0.23) /CreationDate (D:20240314184200+02'00') /ModDate (D:20240320101500+02'00') /Company (Contoso Energy) >>")
    w.xref([5], f"<< /Size 13 /Root 1 0 R /Info 5 0 R /Prev {first} >>", prev=first)
    return bytes(w.buf)


def make_pdf_objstm():
    """PDF 1.5: Info и каталог в потоке объектов, xref-поток, сжатое содержимое."""
    w = PdfWriter(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    content = zlib.compress(b"BT /F1 10 Tf 50 750 Td (Config: password=Winter2024! host=dev.contoso.example) Tj ET")
    w.obj(4, f"<< /Length {len(content)} /Filter /FlateDecode >>", content)
    objs = {
        1: "<< /Type /Catalog /Pages 2 0 R >>",
        2: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>",
        5: "<< /Author (m.shevchuk) /Creator (PDFCreator 3.2.0) /Producer (GPL Ghostscript 9.50) /Title (Presentation) /CreationDate (D:20200105120000Z) >>",
    }
    header, body = [], b""
    for n, s in objs.items():
        header.append(f"{n} {len(body)}")
        body += s.encode() + b"\n"
    hdr = (" ".join(header) + "\n").encode()
    data = zlib.compress(hdr + body)
    w.obj(6, f"<< /Type /ObjStm /N {len(objs)} /First {len(hdr)} /Filter /FlateDecode /Length {len(data)} >>", data)
    # xref-поток (W [1 4 2])
    xref_num = 7
    xref_pos = len(w.buf)
    rows = [(0, 0, 65535)]
    index = {n: i for i, n in enumerate(objs)}
    for n in range(1, 8):
        if n in objs:
            rows.append((2, 6, index[n]))
        elif n == xref_num:
            rows.append((1, xref_pos, 0))
        else:
            rows.append((1, w.offsets[n], 0))
    raw = b"".join(struct.pack(">BIH", *r) for r in rows)
    comp = zlib.compress(raw)
    w.offsets[xref_num] = xref_pos
    w.buf += f"{xref_num} 0 obj\n<< /Type /XRef /Size 8 /W [1 4 2] /Root 1 0 R /Info 5 0 R /Filter /FlateDecode /Length {len(comp)} >>\nstream\n".encode() + comp + b"\nendstream\nendobj\n"
    w.buf += b"startxref\n" + str(xref_pos).encode() + b"\n%%EOF\n"
    return bytes(w.buf)


# ---------------------------------------------------------------- SVG / RDP / ICA
SVG = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!-- Created with Inkscape (http://www.inkscape.org/) -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:cc="http://creativecommons.org/ns#" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd" xmlns:xlink="http://www.w3.org/1999/xlink"
 width="100" height="40" version="1.1" inkscape:version="1.1.2 (0a00cf5339, 2022-02-04)" sodipodi:docname="logo_contoso.svg"
 inkscape:export-filename="C:\\Users\\m.shevchuk\\Desktop\\Презентації\\logo.png" inkscape:export-xdpi="96">
<title>Логотип Контосо</title>
<metadata><rdf:RDF><cc:Work rdf:about=""><dc:format>image/svg+xml</dc:format><dc:creator><cc:Agent><dc:title>Марина Шевчук</dc:title></cc:Agent></dc:creator><dc:date>2021-06-01</dc:date><dc:publisher><cc:Agent><dc:title>Contoso Energy</dc:title></cc:Agent></dc:publisher></cc:Work></rdf:RDF></metadata>
<image xlink:href="/home/mshevchuk/brand/texture.png" width="10" height="10"/>
<a xlink:href="https://contoso.example/"><rect width="100" height="40" fill="#0d9488"/></a>
</svg>"""

ICA = """[WFClient]
Version=2
ProxyType=Auto
HttpBrowserAddress=ctx.contoso.example:8080

[ApplicationServers]
1C Бухгалтерія=

[1C Бухгалтерія]
Address=10.10.1.40:1494
InitialProgram=#1C Бухгалтерія
WorkDirectory=C:\\Users\\o.kovalenko\\AppData\\Local\\1C
Username=o.kovalenko
Domain=CONTOSO
ClearPassword=Buh2023!
SSLProxyHost=*:443
"""


def main():
    vba_path = os.path.join(ROOT, "ole", "vbaProject.bin")
    if not os.path.exists(vba_path):
        raise SystemExit("сначала: cargo run -p foca-meta --example make_ole_corpus -- tests/corpus")
    vba = open(vba_path, "rb").read()
    photo = make_photo()
    png = make_png()
    out("images/photo.jpg", photo)
    out("images/screenshot.png", png)
    out("images/scan.tiff", make_tiff())
    out("ooxml/contract.docx", make_docx(photo))
    out("ooxml/schedule.xlsx", make_xlsx(vba))
    out("ooxml/strategy.pptx", make_pptx(png))
    out("odf/letter.odt", make_odt(photo))
    out("odf/encrypted.ods", make_ods())
    out("pdf/report.pdf", make_pdf())
    out("pdf/objstm.pdf", make_pdf_objstm())
    out("svg/logo.svg", SVG.encode("utf-8"))
    out("remote/SRV-TS01.rdp", b"\xff\xfe" + RDP_TEXT.replace("\n", "\r\n").encode("utf-16-le"))
    out("remote/buh.ica", ICA.encode("utf-8"))


if __name__ == "__main__":
    main()
