#!/usr/bin/env python3
"""Ingest endoflife.date (MIT) release cycles into `crates/foca-recon/data/endoflife.tsv.gz`.

Reads the product pages (`products/*.md`, YAML front matter) of the endoflife.date repository at
a pinned commit, keeps the products that map to a technology FOCA-rs detects (joined on the CPE
`vendor:product` of the webappanalyzer table, else on the product title / `NAMES`), and writes
one row per release cycle whose end-of-life DATE is on or before the snapshot date (`SNAPSHOT`,
the commit date). Cycles still supported at the snapshot or with `eol: true/false` only are
dropped, so the table is deterministic and a refresh adds the cycles that reached EOL since:

    # endoflife.date commit=<sha> snapshot=<YYYY-MM-DD> products=<n> cycles=<m>
    <technology>\t<product slug>\t<cycle>\t<eol YYYY-MM-DD>

`foca-recon::tech` reports a detected version whose release cycle is in the table. Run
`update_webappanalyzer.py` first (the join reads its output).

Usage: python3 update_endoflife.py [--repin]
"""

import gzip
import json
import re

import yaml

import sigsrc

NAME = "endoflife"
REPO = "endoflife-date/endoflife.date"
COMMIT = "32423d8113b6b6cbef02c167ce18a0934203d0fd"
SNAPSHOT = "2026-11-27"
OUT = sigsrc.REPO / "crates/foca-recon/data/endoflife.tsv.gz"
WA = sigsrc.REPO / "crates/foca-recon/data/webappanalyzer.json.gz"
HAND = sigsrc.REPO / "crates/foca-recon/data/tech.json"

# endoflife.date product slug -> technology name, where neither CPE nor title join.
NAMES = {
    "nginx": "Nginx", "apache-http-server": "Apache HTTP Server", "iis": "Microsoft IIS",
    "nodejs": "Node.js", "angularjs": "AngularJS", "jquery": "jQuery", "jqueryui": "jQuery UI",
    "dotnet": "ASP.NET", "tomcat": "Apache Tomcat", "rails": "Ruby on Rails",
    "windows-server": "Windows Server", "centos": "CentOS", "typo3": "TYPO3",
    "bootstrap": "Bootstrap", "vue": "Vue.js", "react": "React", "angular": "Angular",
    "nextjs": "Next.js", "nuxt": "Nuxt.js", "magento": "Magento", "moodle": "Moodle",
}


# CPE joins that point at a different product.
WRONG = {("Kubernetes Dashboard", "kubernetes"), ("Java", "oracle-jdk")}


def cpe_key(cpe: str):
    parts = cpe.split(":")
    if cpe.startswith("cpe:2.3:") and len(parts) > 4:
        return f"{parts[3]}:{parts[4]}".lower()
    if cpe.startswith("cpe:/") and len(parts) > 3:
        return f"{parts[2]}:{parts[3]}".lower()
    return None


def front_matter(text: str):
    m = re.match(r"---\n(.*?)\n---", text, re.S)
    return yaml.safe_load(m.group(1)) if m else None


def main() -> None:
    opts = sigsrc.args()
    tree = sigsrc.tarball(REPO, COMMIT)
    files = {p: b for p, b in tree.items() if re.fullmatch(r"products/[^/]+\.md", p)}
    files["LICENSE"] = tree["LICENSE"]
    inputs = sigsrc.verify_inputs(NAME, files, "--repin" in opts)
    assert "Permission is hereby granted, free of charge" in files["LICENSE"].decode()
    techs = json.loads(gzip.decompress(WA.read_bytes()))["technologies"]
    names = {t["name"] for t in json.loads(HAND.read_text("utf-8"))["technologies"]}
    names |= {t["n"] for t in techs}
    by_cpe = {}
    for t in techs:
        k = cpe_key(t.get("cpe", ""))
        if k:
            by_cpe.setdefault(k, t["n"])
    lower = {n.lower(): n for n in names}
    rows, products = [], set()
    for path, data in sorted(files.items()):
        if not path.startswith("products/"):
            continue
        fm = front_matter(data.decode("utf-8"))
        if not fm or not fm.get("releases"):
            continue
        slug = path[len("products/"):-3]
        tech = NAMES.get(slug)
        for ident in fm.get("identifiers") or []:
            k = cpe_key(str(ident.get("cpe", ""))) if isinstance(ident, dict) else None
            if not tech and k in by_cpe:
                tech = by_cpe[k]
        tech = tech or lower.get(str(fm.get("title", "")).lower())
        if not tech or tech not in names or (tech, slug) in WRONG:
            continue
        for rel in fm["releases"]:
            eol = rel.get("eol")
            if not hasattr(eol, "isoformat") or eol.isoformat() > SNAPSHOT:
                continue
            cycle = str(rel.get("releaseCycle", "")).strip()
            if not cycle:
                continue
            rows.append("\t".join([tech, slug, cycle, eol.isoformat()]))
            products.add(slug)
    rows = sorted(set(rows))
    head = (f"# endoflife.date commit={COMMIT[:12]} snapshot={SNAPSHOT} "
            f"products={len(products)} cycles={len(rows)}")
    size = sigsrc.write_gz(OUT, "\n".join([head, *rows]) + "\n")
    stats = {"products_upstream": sum(1 for p in files if p.startswith("products/")),
             "products_kept": len(products), "cycles": len(rows)}
    sigsrc.record(NAME, {
        "repo": f"https://github.com/{REPO}", "commit": COMMIT, "license": "MIT",
        "license_file": "LICENSE", "license_sha256": sigsrc.sha256(files["LICENSE"]),
        "attribution": "End-of-life dates from endoflife.date, Copyright 2020 endoflife.date "
                       "contributors, MIT License, https://endoflife.date",
        "snapshot": SNAPSHOT, "inputs": inputs, "outputs": [sigsrc.out_hash(OUT)],
        "stats": stats,
    })
    print(f"{OUT.name}: {size} bytes gz; {stats}")


if __name__ == "__main__":
    main()
