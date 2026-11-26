#!/usr/bin/env python3
"""Generates the document forensics fixtures for `tests/forensics.rs`.

Requires only the Python standard library and the `openssl` CLI. All identities are fictional
(Ivan Petrenko / John Doe, example.com) and the tax numbers are synthetic values with a valid
check digit. Keys are generated on every run, so the output is not byte-reproducible; the
committed files are the reference.

    python3 make_forensics.py            # writes next to this script
"""

import base64
import hashlib
import io
import os
import subprocess
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
PHOTO = os.path.join(HERE, "../../../../../tests/corpus/images/photo.jpg")

# --------------------------------------------------------------------------- DER helpers


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def oid(s):
    p = [int(x) for x in s.split(".")]
    out = bytes([p[0] * 40 + p[1]])
    for v in p[2:]:
        enc = [v & 0x7F]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, out)


def parse(b, pos=0):
    """Returns (tag, header_len, body, end)."""
    tag = b[pos]
    l0 = b[pos + 1]
    if l0 < 0x80:
        hl, ln = 2, l0
    else:
        n = l0 & 0x7F
        hl, ln = 2 + n, int.from_bytes(b[pos + 2 : pos + 2 + n], "big")
    body = b[pos + hl : pos + hl + ln]
    return tag, hl, body, pos + hl + ln


def children(body):
    out, p = [], 0
    while p < len(body):
        t, hl, bd, end = parse(body, p)
        out.append((t, body[p:end]))
        p = end
    return out


def add_unsigned_attr(cms, attr_oid, value_der):
    """Appends an unsigned attribute to the first SignerInfo; returns (new_cms, sig_value)."""
    _, _, ci_body, _ = parse(cms)
    ci = children(ci_body)
    _, _, a0_body, _ = parse(ci[1][1])
    _, _, sd_body, _ = parse(a0_body)
    sd = children(sd_body)
    si_set_idx = max(i for i, (t, _) in enumerate(sd) if t == 0x31)
    _, _, sis_body, _ = parse(sd[si_set_idx][1])
    si = children(sis_body)[0][1]
    _, _, si_body, _ = parse(si)
    fields = children(si_body)
    sig_value = next(parse(raw)[2] for t, raw in fields if t == 0x04)
    attr = tlv(0x30, oid(attr_oid) + tlv(0x31, value_der))
    fields.append((0xA1, tlv(0xA1, attr)))
    new_si = tlv(0x30, b"".join(raw for _, raw in fields))
    sd[si_set_idx] = (0x31, tlv(0x31, new_si))
    new_sd = tlv(0x30, b"".join(raw for _, raw in sd))
    return tlv(0x30, ci[0][1] + tlv(0xA0, new_sd)), sig_value


# --------------------------------------------------------------------------- PKI


def run(args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def pki(d):
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
         "-out", "ca.crt", "-days", "3650", "-utf8",
         "-subj", "/C=UA/O=Example Trust Services/organizationIdentifier=NTRUA-00000001/CN=Example Test QTSP CA",
         "-addext", "basicConstraints=critical,CA:true"], d)

    def leaf(name, subj, ext):
        with open(os.path.join(d, name + ".ext"), "w") as f:
            f.write(ext)
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-utf8",
             "-keyout", name + ".key", "-out", name + ".csr", "-subj", subj], d)
        run(["openssl", "x509", "-req", "-in", name + ".csr", "-CA", "ca.crt", "-CAkey", "ca.key",
             "-set_serial", "0x" + hashlib.sha1(name.encode()).hexdigest()[:16], "-days", "1825",
             "-extfile", name + ".ext", "-out", name + ".crt"], d)

    # current UA profile: TINUA-/NTRUA- semantics identifiers in the subject
    leaf("signer",
         "/C=UA/L=Київ/O=ТОВ Приклад/OU=Відділ ІТ/title=Директор/SN=Петренко/GN=Іван"
         "/CN=Іван Петренко/serialNumber=TINUA-1234567899/organizationIdentifier=NTRUA-12345678"
         "/emailAddress=ivan.petrenko@example.com",
         "keyUsage=critical,digitalSignature,nonRepudiation\n")
    # legacy UA profile: SubjectDirectoryAttributes with the UA OIDs
    sda = tlv(0x30,
              tlv(0x30, oid("1.2.804.2.1.1.1.11.1.4.1.1") + tlv(0x31, tlv(0x13, b"1234567899")))
              + tlv(0x30, oid("1.2.804.2.1.1.1.11.1.4.2.1") + tlv(0x31, tlv(0x13, b"87654321"))))
    leaf("legacy", "/C=UA/O=Example LLC/title=Accountant/CN=John Doe/L=Lviv",
         "keyUsage=critical,digitalSignature\n2.5.29.9=DER:" + sda.hex() + "\n")
    leaf("tsa", "/C=UA/O=Example Trust Services/CN=Example Test TSA",
         "extendedKeyUsage=critical,timeStamping\nkeyUsage=critical,digitalSignature\n")
    with open(os.path.join(d, "ts.cnf"), "w") as f:
        f.write("""[ tsa ]
default_tsa = t
[ t ]
dir = .
serial = ./tsaserial
crypto_device = builtin
signer_cert = ./tsa.crt
certs = ./ca.crt
signer_key = ./tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
""")
    with open(os.path.join(d, "tsaserial"), "w") as f:
        f.write("2A\n")


def der_cert(d, name):
    run(["openssl", "x509", "-in", name + ".crt", "-outform", "DER", "-out", name + ".der"], d)
    return open(os.path.join(d, name + ".der"), "rb").read()


def tsa_token(d, data):
    with open(os.path.join(d, "ts.in"), "wb") as f:
        f.write(data)
    run(["openssl", "ts", "-query", "-data", "ts.in", "-sha256", "-cert", "-no_nonce",
         "-out", "q.tsq"], d)
    run(["openssl", "ts", "-reply", "-config", "ts.cnf", "-queryfile", "q.tsq",
         "-out", "tok.der", "-token_out"], d)
    return open(os.path.join(d, "tok.der"), "rb").read()


def cms_sign(d, data, signer="signer", with_tsa=True):
    with open(os.path.join(d, "data.bin"), "wb") as f:
        f.write(data)
    run(["openssl", "cms", "-sign", "-binary", "-in", "data.bin", "-signer", signer + ".crt",
         "-inkey", signer + ".key", "-certfile", "ca.crt", "-md", "sha256", "-outform", "DER",
         "-out", "sig.der"], d)
    cms = open(os.path.join(d, "sig.der"), "rb").read()
    if with_tsa:
        _, sig_value = add_unsigned_attr(cms, "1.2.840.113549.1.9.16.2.14", b"")
        tok = tsa_token(d, sig_value)
        cms, _ = add_unsigned_attr(cms, "1.2.840.113549.1.9.16.2.14", tok)
    return cms


# --------------------------------------------------------------------------- PDF


def pdf(objs, root=1, info=None, prev=None, base=b"", first_num=1):
    """Serializes objects `{num: body}` (appended to `base` as an incremental update)."""
    out = bytearray(base if base else b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offs = {}
    for n in sorted(objs):
        offs[n] = len(out)
        body = objs[n]
        out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n"
    if not base:
        out += b"0 1\n0000000000 65535 f \n"
    for n in sorted(objs):
        out += b"%d 1\n%010d 00000 n \n" % (n, offs[n])
    size = max(objs) + 1 if not base else max(max(objs) + 1, first_num)
    tr = b"<< /Size %d /Root %d 0 R" % (size, root)
    if info:
        tr += b" /Info %d 0 R" % info
    if prev is not None:
        tr += b" /Prev %d" % prev
    out += b"trailer\n" + tr + b" >>\nstartxref\n%d\n%%%%EOF\n" % xref
    return bytes(out), xref


def stream(data, extra=b""):
    return b"<< /Length %d%s >>\nstream\n" % (len(data), extra) + data + b"\nendstream"


FONT = b"<< /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >>"


def page(contents=4, annots=b"", res=FONT):
    return (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Resources "
            % contents + res + annots + b" >>")


def signed_pdf(d):
    content = b"BT /F1 12 Tf 72 700 Td (Contract No 42 between Example LLC and Ivan Petrenko) Tj ET"
    placeholder = b"0" * 16384
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] /SigFlags 3 >> >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: page(annots=b" /Annots [5 0 R]"),
        4: stream(content),
        5: b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /Rect [0 0 0 0] /P 3 0 R /V 6 0 R /F 132 >>",
        6: (b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached "
            b"/ByteRange [0 0000000000 0000000000 0000000000] /Contents <" + placeholder + b"> "
            b"/M (D:20240301100000+02'00') /Name (Ivan Petrenko) /Reason (Approval) "
            b"/Location (Kyiv) /ContactInfo (ivan.petrenko@example.com) >>"),
        7: b"<< /Author (Ivan Petrenko) /Producer (FOCA-rs fixture) /CreationDate (D:20240301095500+02'00') >>",
    }
    b, xref = pdf(objs, info=7)
    b = bytearray(b)
    lt = b.index(b"/Contents <") + len(b"/Contents ")
    gt = lt + 1 + len(placeholder) + 1
    br = b"[0 %010d %010d %010d]" % (lt, gt, len(b) - gt)
    i = b.index(b"[0 0000000000 0000000000 0000000000]")
    b[i : i + len(br)] = br
    cms = cms_sign(d, bytes(b[:lt]) + bytes(b[gt:]))
    h = cms.hex().encode()
    assert len(h) <= len(placeholder), len(h)
    b[lt + 1 : lt + 1 + len(h)] = h
    signed = bytes(b)
    # incremental update after signing: author and content changed
    upd, _ = pdf({4: stream(content.replace(b"No 42", b"No 43")),
                  7: b"<< /Author (Mallory Example) /Producer (FOCA-rs fixture) /ModDate (D:20240305120000+02'00') >>"},
                 info=7, prev=xref, base=signed, first_num=8)
    return signed, upd


def revisions_pdf():
    c1 = (b"BT /F1 12 Tf 72 700 Td (Salary of Ivan Petrenko: 1000 UAH) Tj ET\n"
          b"BT /F1 12 Tf 72 680 Td (Approved by John Doe) Tj ET")
    c2 = b"BT /F1 12 Tf 72 680 Td (Approved by John Doe) Tj ET\nBT /F1 12 Tf 72 660 Td (Final version) Tj ET"
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: page(),
        4: stream(c1),
        5: b"<< /Author (John Doe) /Creator (Writer) /Producer (FOCA-rs fixture) /ModDate (D:20240101100000Z) >>",
    }
    b, xref = pdf(objs, info=5)
    b, _ = pdf({4: stream(c2),
                5: b"<< /Author (Jane Roe) /Creator (Writer) /Producer (Other Producer 2.0) /ModDate (D:20240201100000Z) >>"},
               info=5, prev=xref, base=b, first_num=6)
    return b


def redacted_pdf():
    c1 = (b"BT /F1 12 Tf 72 720 Td (Public statement) Tj ET\n"
          b"BT /F1 12 Tf 72 700 Td (Passport AB123456 Ivan Petrenko) Tj ET\n"
          b"0 0 0 rg 70 695 260 18 re f\n"
          b"q 1 0 0 1 0 -40 cm BT 1 0 0 1 72 700 Tm [(Phone +380 44 000 00 00)] TJ ET Q\n"
          b"q 1 g 70 655 200 16 re f Q")
    c2 = b"BT /F1 12 Tf 72 700 Td (Account UA00 0000 0000 secret) Tj ET"
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 >>",
        3: page(),
        4: stream(c1),
        5: b"<< /Producer (FOCA-rs fixture) >>",
        6: page(contents=7, annots=b" /Annots [8 0 R]"),
        7: stream(c2),
        8: b"<< /Type /Annot /Subtype /Redact /Rect [70 695 330 715] /IC [0 0 0] >>",
    }
    return pdf(objs, info=5)[0]


def scan_pdf():
    jpg = open(PHOTO, "rb").read()
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: page(res=b"<< /XObject << /Im0 5 0 R >> >>"),
        4: stream(b"q 612 0 0 792 0 0 cm /Im0 Do Q"),
        5: stream(jpg, b" /Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace /DeviceRGB "
                       b"/BitsPerComponent 8 /Filter /DCTDecode"),
        6: b"<< /Producer (Scanner Example 1.0) >>",
    }
    return pdf(objs, info=6)[0]


def tsa_only_pdf(d):
    """Document time stamp (/SubFilter /ETSI.RFC3161) with an untouched tail."""
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: page(),
        4: stream(b"BT /F1 12 Tf 72 700 Td (Time stamped) Tj ET"),
        5: (b"<< /Type /DocTimeStamp /SubFilter /ETSI.RFC3161 /ByteRange [0 0000000000 0000000000 0000000000] /Contents <"
            + b"0" * 12000 + b"> >>"),
    }
    b = bytearray(pdf(objs)[0])
    lt = b.index(b"/Contents <") + len(b"/Contents ")
    gt = lt + 12002
    br = b"[0 %010d %010d %010d]" % (lt, gt, len(b) - gt)
    i = b.index(b"[0 0000000000 0000000000 0000000000]")
    b[i : i + len(br)] = br
    tok = tsa_token(d, bytes(b[:lt]) + bytes(b[gt:]))
    h = tok.hex().encode()
    b[lt + 1 : lt + 1 + len(h)] = h
    return bytes(b)


# --------------------------------------------------------------------------- OOXML

ZDATE = (2024, 3, 1, 10, 0, 0)


def zwrite(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            zi = zipfile.ZipInfo(name, ZDATE)
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data)
    return buf.getvalue()


CORE = """<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>John Doe</dc:creator></cp:coreProperties>"""


def docx(d):
    w = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    doc = f"""<?xml version="1.0" encoding="UTF-8"?><w:document {w}><w:body>
<w:p><w:r><w:t>Quarterly plan.</w:t></w:r><w:r><w:rPr><w:vanish/></w:rPr><w:t xml:space="preserve"> Internal note: budget 2M UAH, contact Ivan Petrenko.</w:t></w:r></w:p>
<w:p><w:r><w:rPr><w:vanish w:val="0"/></w:rPr><w:t>Visible despite the tag.</w:t></w:r></w:p>
</w:body></w:document>"""
    cert = der_cert(d, "legacy")
    tok = tsa_token(d, b"xml signature value")
    sig = f"""<?xml version="1.0" encoding="UTF-8"?>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="idPackageSignature">
<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<Reference URI="#idPackageObject"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AAAA</DigestValue></Reference></SignedInfo>
<SignatureValue>AAAA</SignatureValue>
<KeyInfo><X509Data><X509Certificate>{base64.encodebytes(cert).decode()}</X509Certificate></X509Data></KeyInfo>
<Object Id="idPackageObject"><SignatureProperties><SignatureProperty Id="idSignatureTime" Target="#idPackageSignature">
<mdssi:SignatureTime xmlns:mdssi="http://schemas.openxmlformats.org/package/2006/digital-signature"><mdssi:Format>YYYY-MM-DDThh:mm:ssTZD</mdssi:Format><mdssi:Value>2024-03-01T08:00:00Z</mdssi:Value></mdssi:SignatureTime>
</SignatureProperty></SignatureProperties></Object>
<Object Id="idOfficeObject"><SignatureProperties><SignatureProperty Id="idOfficeV1Details" Target="#idPackageSignature">
<SignatureInfoV1 xmlns="http://schemas.microsoft.com/office/2006/digsig"><SignatureComments>Approved for release</SignatureComments></SignatureInfoV1>
</SignatureProperty></SignatureProperties></Object>
<Object><xd:QualifyingProperties xmlns:xd="http://uri.etsi.org/01903/v1.3.2#" Target="#idPackageSignature">
<xd:SignedProperties Id="idSignedProperties"><xd:SignedSignatureProperties><xd:SigningTime>2024-03-01T08:00:01Z</xd:SigningTime>
<xd:SignerRole><xd:ClaimedRoles><xd:ClaimedRole>Chief Accountant</xd:ClaimedRole></xd:ClaimedRoles></xd:SignerRole></xd:SignedSignatureProperties></xd:SignedProperties>
<xd:UnsignedProperties><xd:UnsignedSignatureProperties><xd:SignatureTimeStamp><xd:EncapsulatedTimeStamp>{base64.b64encode(tok).decode()}</xd:EncapsulatedTimeStamp></xd:SignatureTimeStamp></xd:UnsignedSignatureProperties></xd:UnsignedProperties>
</xd:QualifyingProperties></Object>
</Signature>"""
    vba_sig = b"\x00" * 8 + cms_sign(d, b"vba project stream", with_tsa=False)
    return zwrite([
        ("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'),
        ("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin" Target="_xmlsignatures/origin.sigs"/></Relationships>'),
        ("docProps/core.xml", CORE),
        ("word/document.xml", doc),
        ("word/vbaProjectSignature.bin", vba_sig),
        ("_xmlsignatures/origin.sigs", ""),
        ("_xmlsignatures/sig1.xml", sig),
    ])


def xlsx():
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
    wb = f'<?xml version="1.0"?><workbook {ns}><sheets><sheet name="Payroll" sheetId="1" r:id="rId1"/></sheets></workbook>'
    rels = ('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
    sst = f'<?xml version="1.0"?><sst {ns}><si><t>Name</t></si><si><t>Ivan Petrenko</t></si><si><t>Salary</t></si><si><t>John Doe</t></si></sst>'
    sheet = f"""<?xml version="1.0"?><worksheet {ns}>
<cols><col min="1" max="2" width="12"/><col min="3" max="4" hidden="1" width="0"/></cols>
<sheetData>
<row r="1"><c r="A1" t="s"><v>0</v></c><c r="C1" t="s"><v>2</v></c></row>
<row r="2"><c r="A2"><v>1</v></c><c r="C2"><v>5000</v></c></row>
<row r="3" hidden="1"><c r="A3" t="s"><v>1</v></c><c r="B3"><v>12000</v></c></row>
<row r="4" hidden="1"><c r="A4" t="inlineStr"><is><t>Bonus fund</t></is></c></row>
<row r="5"><c r="A5" t="s"><v>3</v></c></row>
</sheetData></worksheet>"""
    pivot = f'<?xml version="1.0"?><pivotCacheDefinition {ns} refreshedBy="Ivan Petrenko" refreshedDate="45352.5" refreshedVersion="8" recordCount="4"><cacheSource type="worksheet"><worksheetSource ref="A1:D10" sheet="Payroll"/></cacheSource></pivotCacheDefinition>'
    conns = (f'<?xml version="1.0"?><connections {ns}><connection id="1" name="srv-sql01 Payroll" type="1" '
             'odcFile="C:\\Users\\ipetrenko\\Documents\\My Data Sources\\srv-sql01 Payroll.odc" refreshedVersion="8">'
             '<dbPr connection="Provider=SQLOLEDB.1;Integrated Security=SSPI;Data Source=srv-sql01.corp.example.com;Initial Catalog=Payroll;User ID=svc_report" command="SELECT * FROM salaries"/></connection></connections>')
    chart = ('<?xml version="1.0"?><c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart"><c:chart><c:plotArea><c:barChart><c:ser>'
             "<c:val><c:numRef><c:f>'C:\\Users\\ipetrenko\\Desktop\\[budget.xlsx]Sheet1'!$A$1:$A$5</c:f></c:numRef></c:val>"
             '</c:ser></c:barChart></c:plotArea></c:chart></c:chartSpace>')
    return zwrite([
        ("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>'),
        ("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'),
        ("docProps/core.xml", CORE),
        ("xl/workbook.xml", wb),
        ("xl/_rels/workbook.xml.rels", rels),
        ("xl/sharedStrings.xml", sst),
        ("xl/worksheets/sheet1.xml", sheet),
        ("xl/pivotCache/pivotCacheDefinition1.xml", pivot),
        ("xl/connections.xml", conns),
        ("xl/charts/chart1.xml", chart),
    ])


def main():
    with tempfile.TemporaryDirectory() as d:
        pki(d)
        signed, modified = signed_pdf(d)
        out = {
            "signed.pdf": signed,
            "signed_modified.pdf": modified,
            "timestamp.pdf": tsa_only_pdf(d),
            "revisions.pdf": revisions_pdf(),
            "redacted.pdf": redacted_pdf(),
            "scan.pdf": scan_pdf(),
            "signed_hidden.docx": docx(d),
            "hidden.xlsx": xlsx(),
        }
        for name, data in out.items():
            with open(os.path.join(HERE, name), "wb") as f:
                f.write(data)
            print(name, len(data))


if __name__ == "__main__":
    main()
