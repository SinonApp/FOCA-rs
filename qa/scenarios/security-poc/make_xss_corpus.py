#!/usr/bin/env python3
"""PoC: a synthetic corpus with an XSS payload in document metadata.
Each field gets its own number: <img src=x onerror=__x(N)>  (Playwright defines window.__x).
usage: make_xss_corpus.py <out_dir>"""
import os, re, sys, zipfile
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.abspath(__file__)) + "/../../.."
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
P = lambda n: f"<img src=x onerror=__x({n})>"
X = lambda n: escape(P(n))

# --- DOCX: core/app/comments/custom ---
src = zipfile.ZipFile(f"{ROOT}/tests/corpus/ooxml/contract.docx")
core = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    f"<dc:title>T{X(1)}</dc:title><dc:subject>S{X(2)}</dc:subject><dc:creator>Ivan {X(3)} Petrov</dc:creator>"
    f"<dc:description>D{X(4)}</dc:description><cp:lastModifiedBy>m{X(5)}</cp:lastModifiedBy>"
    f"<cp:keywords>K{X(6)}</cp:keywords><cp:category>C{X(7)}</cp:category>"
    '<dcterms:created xsi:type="dcterms:W3CDTF">2024-03-01T08:15:00Z</dcterms:created>'
    '<dcterms:modified xsi:type="dcterms:W3CDTF">2024-03-14T18:42:00Z</dcterms:modified></cp:coreProperties>'
)
app_xml = src.read("docProps/app.xml").decode()
app_xml = re.sub(r"<Application>.*?</Application>", f"<Application>Word {X(8)}</Application>", app_xml)
app_xml = re.sub(r"<Company>.*?</Company>", f"<Company>Co{X(9)}</Company>", app_xml)
app_xml = re.sub(r"<Template>.*?</Template>", f"<Template>tpl{X(10)}.dotx</Template>", app_xml)
app_xml = re.sub(r"<Manager>.*?</Manager>", f"<Manager>Mgr{X(11)}</Manager>", app_xml)
com = src.read("word/comments.xml").decode()
com = re.sub(r'w:author="[^"]*"', 'w:author="' + escape(P(12), {'"': "&quot;"}) + '"', com)
com = com.replace("Перевірити реквізити", "Перевірити " + X(13) + " \\\\SRV-" + "FILE01\\share" + X(14))
docx = f"{out}/xss_meta.docx"
with zipfile.ZipFile(docx, "w", zipfile.ZIP_DEFLATED) as z:
    for n in src.namelist():
        if n == "docProps/core.xml":
            z.writestr(n, core)
        elif n == "docProps/app.xml":
            z.writestr(n, app_xml)
        elif n == "word/comments.xml":
            z.writestr(n, com)
        else:
            z.writestr(n, src.read(n))

# --- PDF: Info dictionary ---
def pdf_str(s):
    return "(" + s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")"
objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
    f"<< /Title {pdf_str('PT'+P(21))} /Author {pdf_str('Olena '+P(22))} /Creator {pdf_str('Writer '+P(23))} "
    f"/Producer {pdf_str('LibreOffice 7.1 '+P(24))} /Subject {pdf_str(P(25))} /Keywords {pdf_str(P(26))} >>",
]
b = b"%PDF-1.4\n"
offs = []
for i, o in enumerate(objs, 1):
    offs.append(len(b))
    b += f"{i} 0 obj\n{o}\nendobj\n".encode()
x = len(b)
b += f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode()
for o in offs:
    b += f"{o:010d} 00000 n \n".encode()
b += f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R /Info 4 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
open(f"{out}/xss_info.pdf", "wb").write(b)

# File name carrying the payload (the name ends up in the /upload/<name> URL and in the document name).
fname = f"{out}/{P(31)}.docx"
with open(docx, "rb") as f, open(fname, "wb") as g:
    g.write(f.read() + b"name-variant")
print("ok", sorted(os.listdir(out)))
