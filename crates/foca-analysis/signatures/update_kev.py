#!/usr/bin/env python3
"""Refresh the offline CISA KEV snapshot used by foca-analysis (`kev.rs`).

Downloads the CISA Known Exploited Vulnerabilities catalog (public domain, U.S. government
work), keeps only the records comparable with software FOCA-rs detects (`kev_products.toml`),
drops the long free-text fields and writes `kev.tsv.gz` next to this script.

Usage:
    python3 update_kev.py                 # download from cisa.gov
    python3 update_kev.py kev.json        # use a local copy of the feed

Then run `cargo test -p foca-analysis kev` and update the snapshot date in THIRD_PARTY.md.

Output format (UTF-8, gzip, deterministic: sorted by CVE, mtime 0):
    # cisa-kev catalog=<catalogVersion> released=<dateReleased> total=<count> kept=<n>
    <cveID>\t<keys,comma-separated>\t<vendorProject>\t<product>\t<dateAdded>\t<R|->\t<vulnerabilityName>
`R` marks `knownRansomwareCampaignUse == "Known"`.
"""

import gzip
import io
import json
import pathlib
import re
import sys
import tomllib
import urllib.request

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HERE = pathlib.Path(__file__).resolve().parent


def clean(s: str) -> str:
    return " ".join(str(s).replace("\u202f", " ").split())


def main() -> None:
    if len(sys.argv) > 1:
        raw = pathlib.Path(sys.argv[1]).read_bytes()
    else:
        req = urllib.request.Request(URL, headers={"User-Agent": "foca-rs-kev-update"})
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
    feed = json.loads(raw)
    rules = tomllib.loads((HERE / "kev_products.toml").read_text("utf-8"))["product"]
    compiled = [
        (p["key"], {v.lower() for v in p["vendors"]}, re.compile(p["products"], re.I))
        for p in rules
    ]
    rows = []
    for v in feed["vulnerabilities"]:
        vendor, product = clean(v["vendorProject"]), clean(v["product"])
        keys = [k for k, vs, pr in compiled if vendor.lower() in vs and pr.search(product)]
        if not keys:
            continue
        ransom = "R" if v.get("knownRansomwareCampaignUse") == "Known" else "-"
        fields = [v["cveID"], ",".join(keys), vendor, product, v["dateAdded"], ransom,
                  clean(v["vulnerabilityName"])]
        rows.append("\t".join(f.replace("\t", " ") for f in fields))
    rows.sort(key=lambda r: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", r.split("\t")[0])])
    head = (f"# cisa-kev catalog={feed['catalogVersion']} released={feed['dateReleased'][:10]} "
            f"total={feed['count']} kept={len(rows)}")
    text = "\n".join([head, *rows]) + "\n"
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0, filename="") as g:
        g.write(text.encode("utf-8"))
    out = HERE / "kev.tsv.gz"
    out.write_bytes(buf.getvalue())
    print(f"{out.name}: {len(rows)} of {feed['count']} records, {out.stat().st_size} bytes ({head})")


if __name__ == "__main__":
    main()
