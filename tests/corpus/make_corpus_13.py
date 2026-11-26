#!/usr/bin/env python3
"""Synthetic corpus for the FOCA-rs 1.3 formats (LNK, EML, ICS, VCF, MP4/MOV/HEIC, INDD, WPD, WKS,
VSDX, ZIP) plus intentionally broken samples (`broken-*`). Stdlib + Pillow only.

Order:
  1. cargo run -p foca-meta --example make_ole_corpus_13 -- tests/corpus   (MSG/VSD/PUB/WPS, crate `cfb`)
  2. python3 tests/corpus/make_corpus_13.py
  3. UPDATE_GOLDEN=1 cargo test -p foca-meta --test golden

All data is fictional: people "Іван Петренко" / "John Doe" / "Olena Kovalenko", domains
example.com / example.org / *.example.test, private IP ranges and RFC 5737 documentation addresses.
Files are byte-reproducible (fixed dates).
"""
import io
import os
import struct
import sys
import zipfile

sys.dont_write_bytecode = True

from make_corpus import ASCII, BYTE, RATIONAL, ROOT, ZDATE, build_tiff, ent, jpeg_bytes, make_zip, out, seg

U = "utf-8"


# ---------------------------------------------------------------- LNK (MS-SHLLINK)
def filetime(y, mo, d, h, mi, s):
    import calendar

    secs = calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))
    return (secs + 11644473600) * 10_000_000


def guid_v1(time_ft, node):
    """Version 1 GUID (Microsoft byte layout) from a FILETIME and a 6-byte node."""
    ts = time_ft + 5_748_192_000_000_000
    time_low = ts & 0xFFFFFFFF
    time_mid = (ts >> 32) & 0xFFFF
    time_hi = ((ts >> 48) & 0x0FFF) | 0x1000
    return struct.pack("<IHH", time_low, time_mid, time_hi) + bytes([0x9F, 0x21]) + node


def guid_v4(seed):
    b = bytearray((seed * 7 + i * 13) & 0xFF for i in range(16))
    b[7] = (b[7] & 0x0F) | 0x40
    return bytes(b)


def lnk_string(s):
    return struct.pack("<H", len(s)) + s.encode("utf-16-le")


def make_lnk(local=None, net=None, suffix="", machine="ws-042", mac=b"\x0a\x00\x27\x00\x00\x2a"):
    flags = 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x80  # LinkInfo, Name, RelPath, WorkDir, Args, Unicode
    hdr = struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000C000000000000046")
    hdr += struct.pack("<II", flags, 0x20)
    hdr += struct.pack("<QQQ", filetime(2024, 3, 1, 9, 15, 0), filetime(2024, 3, 14, 18, 40, 0), filetime(2024, 3, 12, 16, 5, 30))
    hdr += struct.pack("<IiIH", 48213, 0, 1, 0) + b"\0" * 10
    assert len(hdr) == 0x4C
    # LinkInfo with Unicode offsets (header size 0x24)
    body = bytearray()
    li_flags = 0
    vol_off = local_off = net_off = suffix_off = local_u = suffix_u = 0
    hdr_size = 0x24

    def at():
        return hdr_size + len(body)

    if local:
        li_flags |= 1
        vol_off = at()
        label = b"DATA\0"
        vol = struct.pack("<IIII", 16 + len(label), 3, 0x1A2B3C4D, 16) + label
        body += vol
        local_off = at()
        body += local.encode("ascii", "replace") + b"\0"
        local_u = at()
        body += local.encode("utf-16-le") + b"\0\0"
    if net:
        li_flags |= 2
        net_off = at()
        name = net.encode("ascii") + b"\0"
        cnrl = struct.pack("<IIIII", 0x14 + len(name), 2, 0x14, 0, 0x00020000) + name
        body += cnrl
    suffix_off = at()
    body += suffix.encode("ascii", "replace") + b"\0"
    suffix_u = at()
    body += suffix.encode("utf-16-le") + b"\0\0"
    size = hdr_size + len(body)
    li = struct.pack("<IIIIIIIII", size, hdr_size, li_flags, vol_off, local_off, net_off, suffix_off, local_u, suffix_u) + body
    strings = lnk_string("Звіт за квартал (чернетка)") + lnk_string(r"..\..\Documents\Звіт.docx")
    strings += lnk_string(r"C:\Users\i.petrenko\Documents") + lnk_string("/p")
    # TrackerDataBlock
    droid_time = filetime(2024, 2, 20, 8, 0, 0)
    file_id = guid_v1(droid_time, mac)
    trk = struct.pack("<II", 0x60, 0xA0000003) + struct.pack("<II", 0x58, 0)
    trk += machine.encode("ascii").ljust(16, b"\0")
    trk += guid_v4(1) + file_id + guid_v4(1) + file_id
    assert len(trk) == 0x60
    env_target = r"%USERPROFILE%\Documents\Звіт.docx"
    env = struct.pack("<II", 0x314, 0xA0000001) + env_target.encode("ascii", "replace").ljust(260, b"\0")
    env += env_target.encode("utf-16-le").ljust(520, b"\0")
    return hdr + li + strings + trk + env + struct.pack("<I", 0)


# ---------------------------------------------------------------- EML
def core_xml(creator):
    return (
        '<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties '
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>Кошторис 2024</dc:title><dc:creator>{creator}</dc:creator>"
        "<cp:lastModifiedBy>John Doe</cp:lastModifiedBy>"
        '<dcterms:created xsi:type="dcterms:W3CDTF">2024-03-10T08:00:00Z</dcterms:created>'
        "</cp:coreProperties>"
    )


def tiny_docx():
    return make_zip(
        [
            ("[Content_Types].xml", "<Types/>"),
            ("word/document.xml", "<w:document/>"),
            ("docProps/core.xml", core_xml("Іван Петренко")),
        ]
    )


def b64(data, width=76):
    import base64

    s = base64.b64encode(data).decode()
    return "\r\n".join(s[i : i + width] for i in range(0, len(s), width))


def qp(text):
    import quopri

    return quopri.encodestring(text.encode(U)).decode().replace("\n", "\r\n")


def make_eml():
    inner = (
        "Received: from ws-017.corp.example.test (ws-017.corp.example.test [192.168.10.17])\r\n"
        "\tby EXCH02.corp.example.test (10.20.0.16) with Microsoft SMTP Server; Mon, 11 Mar 2024 09:00:00 +0200\r\n"
        "From: Olena Kovalenko <o.kovalenko@example.com>\r\n"
        "To: Іван Петренко <i.petrenko@example.com>\r\n"
        "Subject: Draft budget\r\n"
        "Date: Mon, 11 Mar 2024 09:00:00 +0200\r\n"
        "Message-ID: <inner-0001@EXCH02.corp.example.test>\r\n"
        "X-Mailer: Microsoft Outlook 16.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        "See \\\\FS01.corp.example.test\\finance$\\2024\\budget.xlsx\r\n"
    )
    subj = "=?UTF-8?B?" + __import__("base64").b64encode("Кошторис на 2024 рік".encode(U)).decode() + "?="
    body_text = "Добрий день!\nДив. https://intranet.example.test/finance/budget?id=42 та таблицю.\n-- \nІван Петренко\nтел. +380 44 000 00 00\n"
    html = '<html><body><p>Добрий день!</p><a href="https://contoso-my.sharepoint.example.test/personal/i_petrenko/Documents/budget.xlsx">budget</a></body></html>'
    msg = (
        "Return-Path: <i.petrenko@example.com>\r\n"
        "Received: from mx1.example.org (mx1.example.org [198.51.100.25])\r\n"
        "\tby mail.example.org (Postfix) with ESMTPS id 4F2A1; Thu, 14 Mar 2024 16:42:10 +0000\r\n"
        "Received: from EXCH01.corp.example.test (unknown [203.0.113.10])\r\n"
        "\tby mx1.example.org (Postfix) with ESMTPS; Thu, 14 Mar 2024 16:42:09 +0000\r\n"
        "Received: from ws-042.corp.example.test (10.20.30.42) by EXCH01.corp.example.test\r\n"
        "\t(10.20.0.15) with Microsoft SMTP Server id 15.2.1118.40; Thu, 14 Mar 2024 18:42:07 +0200\r\n"
        'From: "Петренко Іван" <i.petrenko@example.com>\r\n'
        "To: John Doe <john.doe@example.org>, o.kovalenko@example.com (Olena Kovalenko)\r\n"
        "Cc: buh@example.com\r\n"
        "Reply-To: i.petrenko.private@example.net\r\n"
        f"Subject: {subj}\r\n"
        "Date: Thu, 14 Mar 2024 18:42:07 +0200\r\n"
        "Message-ID: <a1b2c3d4e5@EXCH01.corp.example.test>\r\n"
        "X-Mailer: Microsoft Outlook 16.0\r\n"
        "X-Originating-IP: [10.20.30.42]\r\n"
        "Organization: Contoso Energy (fictional)\r\n"
        "X-MS-Exchange-CrossTenant-Id: 00000000-1111-2222-3333-444444444444\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to; bh=x; b=y\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="outer-b"\r\n'
        "\r\n"
        "This is a multi-part message in MIME format.\r\n"
        "--outer-b\r\n"
        'Content-Type: multipart/alternative; boundary="alt-b"\r\n'
        "\r\n"
        "--alt-b\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        f"{qp(body_text)}\r\n"
        "--alt-b\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        f"{b64(html.encode(U))}\r\n"
        "--alt-b--\r\n"
        "--outer-b\r\n"
        "Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "Content-Disposition: attachment;\r\n"
        " filename*=utf-8''%D0%9A%D0%BE%D1%88%D1%82%D0%BE%D1%80%D0%B8%D1%81.docx\r\n\r\n"
        f"{b64(tiny_docx())}\r\n"
        "--outer-b\r\n"
        "Content-Type: message/rfc822\r\n"
        "Content-Disposition: attachment; filename=\"Draft budget.eml\"\r\n\r\n"
        f"{inner}\r\n"
        "--outer-b--\r\n"
    )
    return msg.encode(U)


def make_eml_broken():
    return (
        "From: John Doe <john.doe@example.org>\r\n"
        "To: =?UTF-8?B?broken?= <x@example.com>\r\n"
        "Subject: =?unknown-charset?Q?=FF=FE?=\r\n"
        "Date: Thu, 99 Foo 2024 25:61:00 +9999\r\n"
        "Received: from [999.1.1.1] by (((( with ;\r\n"
        "Content-Type: multipart/mixed; boundary=\"nb\"\r\n\r\n"
        "--nb\r\nContent-Type: multipart/mixed; boundary=\"nb\"\r\n\r\n--nb\r\n"
        "Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=x.bin\r\n\r\n"
        "!!!!@@@@====AAAA\r\n"
    ).encode(U)


# ---------------------------------------------------------------- ICS / VCF
def make_ics():
    lines = [
        "BEGIN:VCALENDAR",
        "METHOD:REQUEST",
        "PRODID:Microsoft Exchange Server 2010",
        "VERSION:2.0",
        "X-WR-CALNAME:Фінансовий відділ",
        "BEGIN:VTIMEZONE",
        "TZID:FLE Standard Time",
        "BEGIN:STANDARD",
        "DTSTART:16010101T040000",
        "TZOFFSETFROM:+0300",
        "TZOFFSETTO:+0200",
        "END:STANDARD",
        "END:VTIMEZONE",
        "BEGIN:VEVENT",
        "ORGANIZER;CN=Іван Петренко:mailto:i.petrenko@example.com",
        'ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN="Doe, John":mailto:john.doe@example.org',
        "ATTENDEE;ROLE=OPT-PARTICIPANT;CN=Olena Kovalenko:mailto:o.kovalenko@example.com",
        "DESCRIPTION;LANGUAGE=uk-UA:Обговорення кошторису\\n\\nПриєднатися до наради Microsoft Teams\\n"
        "https://teams.microsoft.com/l/meetup-join/19%3ameeting_EXAMPLE%40thread.v2/0?context=%7b%7d\\n"
        "Резерв: https://example.zoom.us/j/1234567890?pwd=EXAMPLE",
        "UID:040000008200E00074C5B7101A82E0080000000012345@exchange.corp.example.test",
        "SUMMARY;LANGUAGE=uk-UA:Кошторис 2024: нарада",
        "DTSTART;TZID=FLE Standard Time:20240318T100000",
        "DTEND;TZID=FLE Standard Time:20240318T110000",
        "CLASS:PUBLIC",
        "LOCATION;LANGUAGE=uk-UA:Переговорна 3 (корпус А)\\, \\\\\\\\FS01\\\\rooms",
        "CREATED:20240314T164500Z",
        "LAST-MODIFIED:20240315T081000Z",
        "DTSTAMP:20240314T164500Z",
        "X-MICROSOFT-SKYPETEAMSMEETINGURL:https://teams.microsoft.com/l/meetup-join/19%3ameeting_EXAMPLE%40thread.v2/0",
        "END:VEVENT",
        "END:VCALENDAR",
    ]
    # fold long lines at 75 octets
    outl = []
    for l in lines:
        b = l.encode(U)
        first = True
        while len(b) > 75:
            cut = 75
            while (b[cut] & 0xC0) == 0x80:
                cut -= 1
            outl.append((b"" if first else b" ") + b[:cut])
            b = b[cut:]
            first = False
        outl.append((b"" if first else b" ") + b)
    return b"\r\n".join(outl) + b"\r\n"


def make_ics_broken():
    return b"BEGIN:VCALENDAR\r\n" + b"BEGIN:VEVENT\r\n" * 20 + b"ORGANIZER;CN=\"unterminated:mailto:\r\n ATTENDEE\r\n:::\r\n"


def contact_photo():
    main = jpeg_bytes((10, 120, 60), (16, 16))
    ifd0 = [ent(0x010F, ASCII, "ExampleCam"), ent(0x0110, ASCII, "Phone X1")]
    gps = [
        ent(0x0000, BYTE, [2, 3, 0, 0]),
        ent(0x0001, ASCII, "N"),
        ent(0x0002, RATIONAL, [(50, 1), (27, 1), (0, 1)]),
        ent(0x0003, ASCII, "E"),
        ent(0x0004, RATIONAL, [(30, 1), (31, 1), (0, 1)]),
    ]
    tiff = build_tiff(ifd0, None, gps)
    app1 = seg(0xE1, b"Exif\0\0" + tiff)
    cut = 4 + struct.unpack(">H", main[4:6])[0]
    return main[:cut] + app1 + main[cut:]


def make_vcf():
    import base64

    photo = base64.b64encode(contact_photo()).decode()
    folded = "\r\n ".join(photo[i : i + 74] for i in range(0, len(photo), 74))
    return (
        "BEGIN:VCARD\r\n"
        "VERSION:3.0\r\n"
        "PRODID:-//Apple Inc.//iPhone OS 17.4//EN\r\n"
        "N:Петренко;Іван;Олексійович;;\r\n"
        "FN:Іван Петренко\r\n"
        "ORG:Contoso Energy (fictional);Фінансовий відділ\r\n"
        "TITLE:Головний бухгалтер\r\n"
        "EMAIL;type=INTERNET;type=WORK;type=pref:i.petrenko@example.com\r\n"
        "TEL;type=CELL;type=VOICE;type=pref:+380 67 000 00 00\r\n"
        "TEL;type=WORK:+380 44 000 00 01\r\n"
        "ADR;type=WORK:;;вул. Прикладна\\, 1;Київ;;01001;Україна\r\n"
        "URL:https://intranet.example.test/people/i.petrenko\r\n"
        "NOTE:VPN: vpn.corp.example.test\\nПК: WS-042\r\n"
        "BDAY:1985-01-01\r\n"
        "REV:2024-03-14T18:00:00Z\r\n"
        f"PHOTO;ENCODING=b;TYPE=JPEG:{folded}\r\n"
        "END:VCARD\r\n"
        "BEGIN:VCARD\r\n"
        "VERSION:2.1\r\n"
        "N:Doe;John\r\n"
        "FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:John Doe =E2=80=A2 =\r\n"
        "IT\r\n"
        "EMAIL;INTERNET:john.doe@example.org\r\n"
        "GEO:50.4501;30.5234\r\n"
        "END:VCARD\r\n"
    ).encode(U)


def make_vcf_broken():
    return b"BEGIN:VCARD\r\nFN;ENCODING=QUOTED-PRINTABLE:=\r\n=\r\n=ZZ\r\nPHOTO;ENCODING=b:!!!!\r\nGEO:999;999\r\n"


# ---------------------------------------------------------------- ISOBMFF
def box(kind, payload):
    return struct.pack(">I", 8 + len(payload)) + kind + payload


def full(kind, ver, flags, payload):
    return box(kind, bytes([ver]) + flags.to_bytes(3, "big") + payload)


MAC1904 = 2082844800


def mvhd(created_unix, modified_unix, duration=12_000, scale=1000):
    p = struct.pack(">IIII", created_unix + MAC1904, modified_unix + MAC1904, scale, duration)
    p += b"\0" * 80
    return full(b"mvhd", 0, 0, p)


def qt_text(kind, text):
    t = text.encode(U)
    return box(kind, struct.pack(">HH", len(t), 0x7FFF) + t)


def data_box(text):
    return box(b"data", struct.pack(">II", 1, 0) + text.encode(U))


XMP_MEDIA = (
    '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    '<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">'
    "<xmp:CreatorTool>Adobe Premiere Pro 2024 (Windows)</xmp:CreatorTool>"
    "<dc:creator><rdf:Seq><rdf:li>John Doe</rdf:li></rdf:Seq></dc:creator>"
    "</rdf:Description></rdf:RDF></x:xmpmeta>"
)
XMP_UUID = bytes.fromhex("BE7ACFCB97A942E89C71999491E3AFAC")


def make_mp4():
    ftyp = box(b"ftyp", b"isom" + struct.pack(">I", 512) + b"isomiso2mp41")
    udta = box(
        b"udta",
        qt_text(b"\xa9xyz", "+50.4501+030.5234+157.000/")
        + qt_text(b"\xa9mak", "ExampleCam")
        + qt_text(b"\xa9mod", "ActionCam 4")
        + box(b"meta", b"\0\0\0\0" + full(b"hdlr", 0, 0, b"\0\0\0\0mdirappl" + b"\0" * 9) + box(b"ilst", box(b"\xa9too", data_box("Lavf60.3.100")) + box(b"\xa9nam", data_box("Site survey TES-2")))),
    )
    moov = box(b"moov", mvhd(1710434520, 1710434580) + udta)
    uuid = box(b"uuid", XMP_UUID + XMP_MEDIA.encode(U))
    mdat = box(b"mdat", b"\0" * 32)
    return ftyp + moov + uuid + mdat


def make_mov():
    ftyp = box(b"ftyp", b"qt  " + struct.pack(">I", 0) + b"qt  ")
    keys = [
        "com.apple.quicktime.make",
        "com.apple.quicktime.model",
        "com.apple.quicktime.software",
        "com.apple.quicktime.location.ISO6709",
        "com.apple.quicktime.creationdate",
        "com.apple.quicktime.camera.serialnumber",
    ]
    vals = ["Apple", "iPhone 15 Pro", "17.4", "+46.4825+030.7233+012.000/", "2024-03-14T18:42:00+0200", "EXAMPLE-SN-0042"]
    kb = struct.pack(">I", len(keys)) + b"".join(struct.pack(">I", 8 + len(k)) + b"mdta" + k.encode() for k in keys)
    ilst = b"".join(box(struct.pack(">I", i + 1), data_box(v)) for i, v in enumerate(vals))
    meta = box(b"meta", full(b"hdlr", 0, 0, b"\0\0\0\0mdta" + b"\0" * 12) + full(b"keys", 0, 0, kb) + box(b"ilst", ilst))
    trak = box(b"trak", box(b"mdia", full(b"hdlr", 0, 0, b"\0\0\0\0vide" + b"\0" * 12)))
    moov = box(b"moov", mvhd(1710434520, 1710434527) + trak + meta)
    return ftyp + box(b"wide", b"") + box(b"mdat", b"\0" * 16) + moov


def make_heic():
    ifd0 = [ent(0x010F, ASCII, "Apple"), ent(0x0110, ASCII, "iPhone 15 Pro"), ent(0x0131, ASCII, "17.4"), ent(0x013B, ASCII, "Іван Петренко")]
    exif = [ent(0x9003, ASCII, "2024:03:14 18:42:00"), ent(0xA431, ASCII, "EXAMPLE-BODY-0042")]
    gps = [
        ent(0x0000, BYTE, [2, 3, 0, 0]),
        ent(0x0001, ASCII, "N"),
        ent(0x0002, RATIONAL, [(46, 1), (28, 1), (5700, 100)]),
        ent(0x0003, ASCII, "E"),
        ent(0x0004, RATIONAL, [(30, 1), (43, 1), (2200, 100)]),
    ]
    exif_item = struct.pack(">I", 6) + b"Exif\0\0" + build_tiff(ifd0, exif, gps)
    xmp_item = XMP_MEDIA.replace("Adobe Premiere Pro 2024 (Windows)", "Adobe Lightroom Classic 13.2").encode(U)
    ftyp = box(b"ftyp", b"heic" + struct.pack(">I", 0) + b"mif1heic")

    def build(exif_off, xmp_off):
        infe = lambda iid, t, extra=b"": full(b"infe", 2, 0, struct.pack(">HH", iid, 0) + t + b"\0" + extra)
        iinf = full(b"iinf", 0, 0, struct.pack(">H", 3) + infe(1, b"hvc1") + infe(2, b"Exif") + infe(3, b"mime", b"application/rdf+xml\0"))
        iloc_p = bytes([0x44, 0x00]) + struct.pack(">H", 2)
        iloc_p += struct.pack(">HHH", 2, 0, 1) + struct.pack(">II", exif_off, len(exif_item))
        iloc_p += struct.pack(">HHH", 3, 0, 1) + struct.pack(">II", xmp_off, len(xmp_item))
        iloc = full(b"iloc", 0, 0, iloc_p)
        hdlr = full(b"hdlr", 0, 0, b"\0\0\0\0pict" + b"\0" * 13)
        pitm = full(b"pitm", 0, 0, struct.pack(">H", 1))
        return full(b"meta", 0, 0, hdlr + pitm + iinf + iloc)

    meta = build(0, 0)
    base = len(ftyp) + len(meta) + 8
    meta = build(base, base + len(exif_item))
    return ftyp + meta + box(b"mdat", exif_item + xmp_item)


def make_mp4_broken():
    ftyp = box(b"ftyp", b"isom\0\0\0\0isom")
    # moov declares far more bytes than present; nested boxes with size 1 (largesize) overflowing
    bad = struct.pack(">I", 0xFFFFFF00) + b"moov" + struct.pack(">I", 1) + b"udta" + struct.pack(">Q", 2**63) + b"\xa9xyz"
    return ftyp + bad + b"\0" * 64


def make_heic_broken():
    h = make_heic()
    # point the Exif item beyond the end of file
    i = h.find(b"iloc")
    b = bytearray(h)
    struct.pack_into(">I", b, i + 4 + 4 + 2 + 2 + 6, 0x7FFFFFF0)
    return bytes(b[: len(b) - 40])


# ---------------------------------------------------------------- InDesign / WordPerfect / Works
XMP_INDD = (
    '<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?>'
    '<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 9.1-c001">'
    '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    '<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/" '
    'xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/" xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#">'
    "<xmp:CreatorTool>Adobe InDesign 19.2 (Windows)</xmp:CreatorTool>"
    "<xmp:CreateDate>2024-03-01T10:00:00+02:00</xmp:CreateDate>"
    "<xmp:ModifyDate>2024-03-14T18:42:00+02:00</xmp:ModifyDate>"
    "<dc:creator><rdf:Seq><rdf:li>Olena Kovalenko</rdf:li></rdf:Seq></dc:creator>"
    "<dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">Річний звіт 2023</rdf:li></rdf:Alt></dc:title>"
    "<xmpMM:DocumentID>xmp.did:0a1b2c3d-0000-4000-8000-000000000001</xmpMM:DocumentID>"
    "<xmpMM:InstanceID>xmp.iid:0a1b2c3d-0000-4000-8000-000000000002</xmpMM:InstanceID>"
    "<xmpMM:History><rdf:Seq><rdf:li rdf:parseType=\"Resource\"><stEvt:action>saved</stEvt:action>"
    "<stEvt:when>2024-03-14T18:42:00+02:00</stEvt:when><stEvt:softwareAgent>Adobe InDesign 19.2 (Windows)</stEvt:softwareAgent>"
    "<stEvt:instanceID>xmp.iid:0a1b2c3d-0000-4000-8000-000000000002</stEvt:instanceID></rdf:li></rdf:Seq></xmpMM:History>"
    "<xmp:Label>\\\\FS01.corp.example.test\\design\\annual-2023\\report.indd</xmp:Label>"
    "</rdf:Description></rdf:RDF></x:xmpmeta>"
    '<?xpacket end="w"?>'
)
INDD_MAGIC = bytes.fromhex("0606EDF5D81D46E5BD31EFE7FE74B71D")


def make_indd():
    mp = INDD_MAGIC + b"DOCUMENT" + bytes([1]) + b"\0" * (4096 - 25)
    xmp = XMP_INDD.encode(U)
    return mp + mp + b"\0" * 1024 + struct.pack("<I", len(xmp)) + xmp + b"\0" * 512


def make_indd_broken():
    return INDD_MAGIC + b"DOCUMENT\x07" + b"\xff" * 64 + b"<x:xmpmeta xmlns:x='adobe:ns:meta/'><rdf:RDF" * 3 + b"</x:xmpmeta>"


def make_wpd():
    hdr = b"\xffWPC" + struct.pack("<I", 0x200) + bytes([1, 0x0A, 2, 1]) + struct.pack("<HH", 0, 0x200)
    return hdr + b"\0" * (0x200 - len(hdr)) + "Кошторис (WordPerfect)".encode("cp1251") + b"\0" * 32


def make_wks():
    # Lotus-format BOF (Works for DOS 0x5404), a label cell and EOF
    rec = lambda t, p: struct.pack("<HH", t, len(p)) + p
    return rec(0, struct.pack("<H", 0x5404)) + rec(15, b"\xff\x00\x00\x00\x00'Budget 2024\0") + rec(1, b"")


# ---------------------------------------------------------------- VSDX / ZIP
def make_vsdx():
    app = (
        '<?xml version="1.0" encoding="UTF-8"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        "<Application>Microsoft Visio</Application><Company>Contoso Energy (fictional)</Company><Manager>John Doe</Manager></Properties>"
    )
    pages = (
        '<?xml version="1.0" encoding="UTF-8"?><Pages xmlns="http://schemas.microsoft.com/office/visio/2012/main">'
        '<Page ID="0" NameU="Page-1" Name="Мережа офісу"/><Page ID="4" NameU="Page-2" Name="Серверна"/></Pages>'
    )
    page1 = (
        '<?xml version="1.0" encoding="UTF-8"?><PageContents xmlns="http://schemas.microsoft.com/office/visio/2012/main"><Shapes>'
        '<Shape ID="1"><Text>DC01 10.20.0.10</Text></Shape><Shape ID="2"><Text>EXCH01.corp.example.test</Text></Shape></Shapes></PageContents>'
    )
    masters = (
        '<?xml version="1.0" encoding="UTF-8"?><Masters xmlns="http://schemas.microsoft.com/office/visio/2012/main">'
        '<Master ID="2" NameU="Server" Name="Сервер"/><Master ID="3" NameU="Firewall" Name="Firewall"/></Masters>'
    )
    comments = (
        '<?xml version="1.0" encoding="UTF-8"?><Comments xmlns="http://schemas.microsoft.com/office/visio/2012/main">'
        '<AuthorList><AuthorEntry ID="0" Name="Іван Петренко" Initials="ІП"/></AuthorList>'
        '<CommentList><CommentEntry AuthorID="0" PageID="0" ShapeID="1" Date="2024-03-14T18:00:00">Пароль адміна на стікері, прибрати</CommentEntry></CommentList></Comments>'
    )
    conns = (
        '<?xml version="1.0" encoding="UTF-8"?><DataConnections xmlns="http://schemas.microsoft.com/office/visio/2012/main">'
        '<DataConnection ID="1" FileName="C:\\Users\\i.petrenko\\Documents\\assets.xlsx" '
        'ConnectionString="Provider=SQLOLEDB;Data Source=SQL01.corp.example.test;Initial Catalog=Assets;Integrated Security=SSPI" Command="SELECT * FROM hosts"/></DataConnections>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
        'Target="file:///\\\\FS01.corp.example.test\\it\\network.vsdx" TargetMode="External"/></Relationships>'
    )
    return make_zip(
        [
            ("[Content_Types].xml", "<Types/>"),
            ("docProps/core.xml", core_xml("Іван Петренко")),
            ("docProps/app.xml", app),
            ("visio/document.xml", '<VisioDocument xmlns="http://schemas.microsoft.com/office/visio/2012/main"/>'),
            ("visio/pages/pages.xml", pages),
            ("visio/pages/page1.xml", page1),
            ("visio/pages/_rels/page1.xml.rels", rels),
            ("visio/masters/masters.xml", masters),
            ("visio/comments.xml", comments),
            ("visio/data/connections.xml", conns),
        ]
    )


def make_archive(lnk, eml, vcf):
    inner = make_zip([("contacts/i.petrenko.vcf", vcf)])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.comment = "Backup of \\\\FS01.corp.example.test\\finance$ by i.petrenko".encode(U)
        for name, data in [
            ("finance/", b""),
            ("finance/Кошторис.docx", tiny_docx()),
            ("finance/Звіт.lnk", lnk),
            ("mail/Кошторис.eml", eml),
            ("nested/inner.zip", inner),
            ("../../evil.txt", b"zip-slip probe\n"),
        ]:
            zi = zipfile.ZipInfo(name, ZDATE)
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data)
    return buf.getvalue()


def make_zip_broken():
    z = make_zip([("a.txt", "hello"), ("b.eml", "From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n\r\nbody")])
    b = bytearray(z)
    # corrupt the compressed data of the first entry and the declared size of the second
    b[40] ^= 0xFF
    i = b.rfind(b"PK\x01\x02")
    struct.pack_into("<I", b, i + 24, 0x7FFFFFFF)
    return bytes(b)


def main():
    lnk = make_lnk(local=r"C:\Users\i.petrenko\Documents\Звіт.docx")
    out("lnk/report.lnk", lnk)
    out("lnk/network.lnk", make_lnk(net=r"\\FS01.corp.example.test\buh$", suffix=r"Звіти\2024\Q1.xlsx", machine="buh-pc-07", mac=b"\x00\x15\x5d\x01\x02\x03"))
    out("lnk/broken-truncated.lnk", lnk[:0x60])
    bad = bytearray(lnk)
    struct.pack_into("<I", bad, 0x4C + 12, 0xFFFFFFF0)  # VolumeID offset far away
    struct.pack_into("<I", bad, 0x4C, 0x7FFFFFFF)  # LinkInfo size larger than the file
    out("lnk/broken-linkinfo.lnk", bytes(bad))
    eml = make_eml()
    out("mail/budget.eml", eml)
    out("mail/broken-mime.eml", make_eml_broken())
    out("pim/meeting.ics", make_ics())
    out("pim/broken.ics", make_ics_broken())
    vcf = make_vcf()
    out("pim/contacts.vcf", vcf)
    out("pim/broken.vcf", make_vcf_broken())
    out("media/survey.mp4", make_mp4())
    out("media/iphone.mov", make_mov())
    out("media/photo.heic", make_heic())
    out("media/broken-boxes.mp4", make_mp4_broken())
    out("media/broken-iloc.heic", make_heic_broken())
    out("legacy/annual.indd", make_indd())
    out("legacy/broken.indd", make_indd_broken())
    out("legacy/budget.wpd", make_wpd())
    out("legacy/broken.wpd", b"\xffWPC\x10\0\0")
    out("legacy/budget.wks", make_wks())
    out("visio/network.vsdx", make_vsdx())
    out("archive/backup.zip", make_archive(lnk, eml, vcf))
    out("archive/broken.zip", make_zip_broken())


if __name__ == "__main__":
    os.chdir(ROOT)
    main()
