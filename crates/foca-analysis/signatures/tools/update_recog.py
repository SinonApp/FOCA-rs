#!/usr/bin/env python3
"""Ingest Rapid7 Recog fingerprints (BSD-2-Clause) for service banners and favicon MD5 hashes.

Outputs:
* `crates/foca-net/data/recog.tsv.gz`: banner fingerprints for the port scanner, one per row
      <proto>\t<i|->\t<regex>\t<product>\t<version>\t<os>\t<cpe>
  `proto` is the FOCA-rs service (`ssh`, `ftp`, `smtp`, `pop3`, `imap`, `telnet`, `http` for the
  `Server` header). `product`, `version` and `os` are literal values or `$N` (capture group N);
  `os` may combine both (`Ubuntu $2`). `cpe` keeps Recog's `{service.version}` placeholder.
* `crates/foca-recon/data/favicons_md5.tsv`: `<md5>\t<label>\t<cpe>` from `favicons.xml`.

Regexes are compiled with the Rust `regex` crate; Ruby-only syntax (lookarounds, `\\h`, ...) is
skipped and counted in `sources.lock.json`. `\\A` / `\\Z` anchors are rewritten to `^` / `$`.

Usage: python3 update_recog.py [--repin]
"""

import re
import xml.etree.ElementTree as ET

import sigsrc

NAME = "recog"
REPO = "rapid7/recog"
COMMIT = "f1191e24332c51d6a3d98457f64fba8dec340784"
OUT_BANNERS = sigsrc.REPO / "crates/foca-net/data/recog.tsv.gz"
OUT_FAVICONS = sigsrc.REPO / "crates/foca-recon/data/favicons_md5.tsv"
BANNERS = {
    "xml/ssh_banners.xml": "ssh", "xml/ftp_banners.xml": "ftp", "xml/smtp_banners.xml": "smtp",
    "xml/pop_banners.xml": "pop3", "xml/imap_banners.xml": "imap",
    "xml/telnet_banners.xml": "telnet", "xml/http_servers.xml": "http",
}
FILES = [*BANNERS, "xml/favicons.xml", "LICENSE", "COPYING"]


def clean(s: str) -> str:
    return " ".join((s or "").replace("\t", " ").split())


def params(fp) -> dict:
    """name -> literal value or `$pos`."""
    out = {}
    for p in fp.findall("param"):
        pos = int(p.get("pos", "0"))
        out[p.get("name")] = f"${pos}" if pos > 0 else clean(p.get("value", ""))
    return out


def join(*parts) -> str:
    seen = []
    for p in parts:
        if p and p not in seen and not any(p in s for s in seen):
            seen.append(p)
    return " ".join(seen)


def translate(rx: str) -> str:
    return rx.replace("\\A", "^").replace("\\Z", "$").replace("\\z", "$")


def main() -> None:
    opts = sigsrc.args()
    files = {p: sigsrc.raw(REPO, COMMIT, p) for p in FILES}
    inputs = sigsrc.verify_inputs(NAME, files, "--repin" in opts)
    # LICENSE is a Debian copyright header naming the license; COPYING holds the text.
    assert "BSD-2-clause" in files["LICENSE"].decode(), "license changed"
    assert "Redistribution and use" in files["COPYING"].decode(), "license changed"
    pending = []
    for path, proto in BANNERS.items():
        root = ET.fromstring(files[path])
        for fp in root.findall("fingerprint"):
            pat = translate(fp.get("pattern", ""))
            icase = "REG_ICASE" in (fp.get("flags") or "")
            p = params(fp)
            product = join(p.get("service.vendor", ""), p.get("service.product", "")) or join(
                p.get("hw.vendor", ""), p.get("hw.product", ""))
            os_ = join(p.get("os.vendor", ""), p.get("os.product", "") or p.get("os.family", ""),
                       p.get("os.version", ""))
            if not product and not os_:
                continue
            pending.append((proto, "i" if icase else "-", pat, product,
                            p.get("service.version", ""), os_, p.get("service.cpe23", "")))
    errs = [None] * len(pending)
    for flag in ("i", "-"):
        idx = [i for i, r in enumerate(pending) if r[1] == flag]
        res = sigsrc.rust_regex_check([pending[i][2] for i in idx], flag == "i")
        for i, e in zip(idx, res):
            errs[i] = e
    skipped = {}
    rows = []
    for r, e in zip(pending, errs):
        if e:
            skipped[e] = skipped.get(e, 0) + 1
            continue
        rows.append("\t".join(clean(x) if k != 2 else x for k, x in enumerate(r)))
    head = f"# recog commit={COMMIT[:12]} fingerprints={len(rows)}"
    size = sigsrc.write_gz(OUT_BANNERS, "\n".join([head, *rows]) + "\n")
    fav = []
    for fp in ET.fromstring(files["xml/favicons.xml"]).findall("fingerprint"):
        m = re.fullmatch(r"\^(?:\(\?:)?([0-9a-f]{32}(?:\|[0-9a-f]{32})*)\)?\$?", fp.get("pattern", ""))
        if not m:
            continue
        p = params(fp)
        label = join(p.get("service.vendor", ""), p.get("service.product", "")) or join(
            p.get("hw.vendor", ""), p.get("hw.product", "")) or clean(fp.findtext("description"))
        cpe = p.get("service.cpe23", "") or p.get("hw.cpe23", "")
        for h in m.group(1).split("|"):
            fav.append(f"{h}\t{label}\t{cpe}")
    fav = sorted(set(fav))
    OUT_FAVICONS.write_text(f"# recog favicons.xml commit={COMMIT[:12]} hashes={len(fav)}\n"
                            + "\n".join(fav) + "\n", "utf-8")
    stats = {"banner_fingerprints_upstream": len(pending), "banner_fingerprints_kept": len(rows),
             "skipped": skipped, "favicon_md5": len(fav)}
    sigsrc.record(NAME, {
        "repo": f"https://github.com/{REPO}", "commit": COMMIT, "license": "BSD-2-Clause",
        "license_file": "COPYING", "license_sha256": sigsrc.sha256(files["COPYING"]),
        "attribution": "Service and favicon fingerprints from Recog, Copyright (c) 2014-2015, "
                       "Rapid7, BSD 2-Clause License, https://github.com/rapid7/recog",
        "inputs": inputs, "outputs": [sigsrc.out_hash(OUT_BANNERS), sigsrc.out_hash(OUT_FAVICONS)],
        "stats": stats,
    })
    print(f"{OUT_BANNERS.name}: {size} bytes gz; {stats}")


if __name__ == "__main__":
    main()
