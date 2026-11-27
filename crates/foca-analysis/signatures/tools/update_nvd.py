#!/usr/bin/env python3
"""Build the offline CVE table `nvd_cve.tsv.gz` from the NVD CVE JSON 2.0 yearly feeds.

Only CVEs whose configurations reference a CPE `vendor:product` that FOCA-rs can detect are kept:

* (a) every CPE of the webappanalyzer technologies (`crates/foca-recon/data/webappanalyzer.json.gz`),
* (b) the `cpe` fields of the document software and OS signatures (`signatures/software.toml`),
* (c) every CPE whose `target_sw` is `wordpress`, `drupal` or `joomla` (plugins, themes, modules),
  keyed as `vendor:product@<cms>` so the app can also look them up by slug,
* (d) the CPE identifiers of the endoflife.date products (pinned commit of `update_endoflife.py`).

Per CVE the table stores the id, the published year, one CVSS base score with its version (v3.1,
then v4.0, v3.0, v2), CWE numbers, the KEV flag (our CISA KEV snapshot) and the FIRST EPSS score
(same pinned daily file as `update_kev_enrich.py`). Per product it stores the affected version
ranges of `vulnerable=true` CPE matches. No descriptions.

Format (UTF-8 text, deterministic gzip):

    # foca-nvd v1 snapshot=<date> epss=<date> cves=<n> products=<n> ranges=<n> site=<n> plugin=<n> doc=<n> os=<n>
    C\\t<id without CVE->\\t<published year>\\t<score>\\t<cvss version 31|40|30|2>\\t<CWE numbers, comma>\\t<K if in KEV>\\t<EPSS * 10000>
    P\\t<vendor:product[@cms]>\\t<groups: s site, p plugin, d document software, o OS>
    <C index delta from the previous row of this product>\\t<range>[ <range>...]

A range is `*` (every version), `=<version>` (exact) or an interval `[a,b)`, `(a,b]`, `[,b)`, ...
(`[`/`]` inclusive, `(`/`)` exclusive, an empty side is open).

Feeds are read as a stream (one CVE at a time) from `$FOCA_NVD_CACHE` (default
`$FOCA_SIG_CACHE/nvd`), pinned by the snapshot date and the sha256 of every yearly file in
`sources.lock.json`, and deleted after a successful run unless `--keep-cache` is given.

Usage: python3 update_nvd.py [--repin] [--keep-cache]
"""

import codecs
import csv
import gzip
import io
import json
import os
import pathlib
import re
import sys
import tomllib
import urllib.request

import sigsrc

NAME = "nvd"
SNAPSHOT = "2026-11-27"
FIRST_YEAR = 2002
LAST_YEAR = 2026
FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
EPSS_DATE = "2026-11-26"
EPSS_URL = f"https://epss.empiricalsecurity.com/epss_scores-{EPSS_DATE}.csv.gz"
EOL_REPO = "endoflife-date/endoflife.date"
EOL_COMMIT = "32423d8113b6b6cbef02c167ce18a0934203d0fd"
WA = sigsrc.REPO / "crates/foca-recon/data/webappanalyzer.json.gz"
SOFTWARE = sigsrc.SIG / "software.toml"
KEV = sigsrc.SIG / "kev.tsv.gz"
OUT = sigsrc.SIG / "nvd_cve.tsv.gz"
CACHE = pathlib.Path(os.environ.get("FOCA_NVD_CACHE", sigsrc.CACHE / "nvd"))
CMS = ("wordpress", "drupal", "joomla")
OFFICE_APPS = ("word", "excel", "powerpoint", "outlook", "visio", "publisher", "onenote", "access")
ATTRIBUTION = ("This product uses data from the NVD API but is not endorsed or certified by the NVD. "
               "CVE data from the NIST National Vulnerability Database (public domain), "
               "https://nvd.nist.gov")


def unescape(s: str) -> str:
    """CPE 2.3 formatted-string unescape (`joomla\\!` -> `joomla!`)."""
    return re.sub(r"\\(.)", r"\1", s)


def cpe_fields(criteria: str):
    """Splits a CPE 2.3 formatted string into its 13 fields, honouring `\\:` escapes."""
    parts, cur, esc = [], [], False
    for ch in criteria:
        if esc:
            cur.append("\\" + ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts if len(parts) >= 13 and parts[0] == "cpe" else None


def cms_of(target_sw: str):
    t = unescape(target_sw).lower().rstrip("!")
    return t if t in CMS else None


def cpe_key(cpe: str):
    """`vendor:product` of a CPE 2.3 (`cpe:2.3:a:f5:nginx:*...`) or 2.2 (`cpe:/a:f5:nginx`) name."""
    if cpe.startswith("cpe:2.3:"):
        f = cpe_fields(cpe)
        return f"{unescape(f[3])}:{unescape(f[4])}".lower() if f else None
    p = cpe.split(":")
    if cpe.startswith("cpe:/") and len(p) > 3:
        return f"{p[2]}:{p[3]}".lower()
    return None


def software_cpes(toml_text: str) -> dict:
    """`vendor:product` -> group (`d` software, `o` OS) from the `cpe` fields of software.toml."""
    data = tomllib.loads(toml_text)
    out = {}
    for section, group in (("software", "d"), ("os", "o")):
        for sig in data.get(section, []):
            for c in str(sig.get("cpe", "")).split():
                keys = [c.replace("{app_lc}", a) for a in OFFICE_APPS] if "{app_lc}" in c else [c]
                for k in keys:
                    out.setdefault(k.lower(), set()).add(group)
    return out


def webapp_cpes(techs: list) -> set:
    return {k for t in techs if (k := cpe_key(t.get("cpe", "")))}


def eol_cpes(files: dict) -> set:
    out = set()
    for path, data in files.items():
        if path.startswith("products/") and path.endswith(".md"):
            for m in re.finditer(r"cpe:\s*['\"]?(cpe:[^\s'\"]+)", data.decode("utf-8", "replace")):
                if k := cpe_key(m.group(1)):
                    out.add(k)
    return out


def iter_feed(stream, chunk: int = 1 << 20):
    """Yields the `cve` objects of an NVD 2.0 feed one by one without loading the whole file."""
    dec = json.JSONDecoder()
    utf8 = codecs.getincrementaldecoder("utf-8")()

    def text(data) -> str:
        return utf8.decode(data, final=not data) if isinstance(data, bytes) else (data or "")

    buf = ""
    pos = -1
    while pos < 0:
        data = stream.read(chunk)
        if not data:
            return
        buf += text(data)
        m = re.search(r'"vulnerabilities"\s*:\s*\[', buf)
        if m:
            pos = m.end()
    eof = False
    while True:
        while True:
            i = pos
            while i < len(buf) and buf[i] in " \r\n\t,":
                i += 1
            if i < len(buf) and buf[i] == "]":
                return
            try:
                obj, end = dec.raw_decode(buf, i)
            except json.JSONDecodeError:
                break
            pos = end
            yield obj.get("cve", obj)
        if eof:
            return
        data = stream.read(chunk)
        if not data:
            eof = True
        buf = buf[pos:] + text(data)
        pos = 0


def best_cvss(metrics: dict):
    """(score, version code) preferring v3.1, then v4.0, v3.0, v2; NVD primary scores first."""
    for key, code in (("cvssMetricV31", "31"), ("cvssMetricV40", "40"), ("cvssMetricV30", "30"),
                      ("cvssMetricV2", "2")):
        rows = metrics.get(key) or []
        rows = sorted(rows, key=lambda r: r.get("type") != "Primary")
        for r in rows:
            s = (r.get("cvssData") or {}).get("baseScore")
            if s is not None:
                return f"{float(s):g}", code
    return "", ""


def cwes(cve: dict) -> list:
    out = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if v.startswith("CWE-") and v[4:].isdigit() and v[4:] not in out:
                out.append(v[4:])
    return sorted(out, key=int)


def clean_ver(v: str) -> str:
    return re.sub(r"[\s,\[\]()=]+", "_", unescape(v).strip())


def range_of(m: dict, version: str) -> str:
    si, se = m.get("versionStartIncluding"), m.get("versionStartExcluding")
    ei, ee = m.get("versionEndIncluding"), m.get("versionEndExcluding")
    if si or se or ei or ee:
        lo = "[" + clean_ver(si) if si else "(" + clean_ver(se) if se else "["
        hi = clean_ver(ei) + "]" if ei else clean_ver(ee) + ")" if ee else ")"
        return f"{lo},{hi}"
    if version in ("*", "-", ""):
        return "*"
    return "=" + clean_ver(version)


def product_ranges(cve: dict, wanted: dict) -> dict:
    """`key -> sorted ranges` for the vulnerable CPE matches of a CVE that hit `wanted`."""
    out = {}
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                f = cpe_fields(m.get("criteria", ""))
                if not f:
                    continue
                vp = f"{unescape(f[3])}:{unescape(f[4])}".lower()
                cms = cms_of(f[10])
                key = f"{vp}@{cms}" if cms else vp
                if cms:
                    wanted.setdefault(key, {"p"})
                elif vp not in wanted:
                    continue
                out.setdefault(key, set()).add(range_of(m, unescape(f[5])))
    for k, rs in out.items():
        # A version-bounded or exact entry for the product wins over an unbounded one in another
        # configuration (often a platform pairing): "all versions" only when nothing narrower exists.
        narrow = rs - {"*"}
        out[k] = sorted(narrow) if narrow else ["*"]
    return out


def reduce_cve(cve: dict, wanted: dict, kev: set, epss: dict):
    """Returns `(row fields, {key: ranges})` for a kept CVE, else None."""
    if cve.get("vulnStatus") == "Rejected":
        return None
    prods = product_ranges(cve, wanted)
    if not prods:
        return None
    cid = cve["id"]
    score, ver = best_cvss(cve.get("metrics") or {})
    e = epss.get(cid)
    row = [cid[4:], str(cve.get("published", ""))[:4], score, ver, ",".join(cwes(cve)),
           "K" if cid in kev else "", str(round(e * 10000)) if e is not None else ""]
    return row, prods


def build(feeds, wanted: dict, kev: set, epss: dict, header: dict):
    """Builds the table text from CVE iterables. Returns `(text, stats)`."""
    rows = {}
    for feed in feeds:
        for cve in feed:
            r = reduce_cve(cve, wanted, kev, epss)
            if r:
                rows[cve["id"]] = r
    ids = sorted(rows, key=lambda c: (int(c.split("-")[1]), int(c.split("-")[2])))
    index = {c: i for i, c in enumerate(ids)}
    by_key = {}
    for c in ids:
        for k, rs in rows[c][1].items():
            by_key.setdefault(k, []).append((index[c], rs))
    groups = {"s": set(), "p": set(), "d": set(), "o": set()}
    lines = ["C\t" + "\t".join(rows[c][0]) for c in ids]
    n_ranges = 0
    for k in sorted(by_key):
        g = "".join(x for x in "spdo" if x in wanted.get(k, ()))
        lines.append(f"P\t{k}\t{g}")
        prev = 0
        for i, rs in by_key[k]:
            lines.append(f"{i - prev}\t{' '.join(rs)}")
            prev = i
            n_ranges += len(rs)
        for x in g:
            groups[x].update(c for c, _ in by_key[k])
    stats = {"cves": len(ids), "products": len(by_key), "ranges": n_ranges,
             "site": len(groups["s"]), "plugin": len(groups["p"]), "doc": len(groups["d"]),
             "os": len(groups["o"]), "kev": sum(1 for c in ids if rows[c][0][5]),
             "with_epss": sum(1 for c in ids if rows[c][0][6])}
    head = " ".join([f"# foca-nvd v1"] + [f"{k}={v}" for k, v in header.items()] +
                    [f"{k}={stats[k]}" for k in ("cves", "products", "ranges", "site", "plugin",
                                                 "doc", "os")])
    return "\n".join([head, *lines]) + "\n", stats


def load_epss(raw: bytes) -> dict:
    lines = gzip.decompress(raw).decode().splitlines()
    reader = csv.DictReader(io.StringIO("\n".join(l for l in lines if not l.startswith("#"))))
    return {r["cve"]: float(r["epss"]) for r in reader}


def load_kev() -> set:
    text = gzip.decompress(KEV.read_bytes()).decode()
    return {l.split("\t", 1)[0] for l in text.splitlines() if l and not l.startswith("#")}


def wanted_products(techs: list, toml_text: str, eol: set) -> dict:
    wanted = {}
    for k in webapp_cpes(techs) | eol:
        wanted.setdefault(k, set()).add("s")
    for k, g in software_cpes(toml_text).items():
        wanted.setdefault(k, set()).update(g)
    return wanted


def feed_path(year: int) -> pathlib.Path:
    return CACHE / f"nvdcve-2.0-{year}.json.gz"


def fetch_feed(year: int) -> pathlib.Path:
    path = feed_path(year)
    if not path.is_file():
        CACHE.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(FEED_URL.format(year=year), headers={"User-Agent": sigsrc.UA})
        with urllib.request.urlopen(req, timeout=300) as r, open(path, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
    return path


def file_sha(path: pathlib.Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    opts = sigsrc.args()
    repin = "--repin" in opts
    paths = [fetch_feed(y) for y in range(FIRST_YEAR, LAST_YEAR + 1)]
    now = {p.name: file_sha(p) for p in paths}
    prev = sigsrc.load_lock()["sources"].get(NAME, {}).get("inputs", {})
    epss_raw = sigsrc.fetch(EPSS_URL)
    now[f"epss_scores-{EPSS_DATE}.csv.gz"] = sigsrc.sha256(epss_raw)
    if prev and not repin and prev != now:
        bad = sorted(k for k in set(prev) | set(now) if prev.get(k) != now.get(k))
        sys.exit(f"{NAME}: input hash mismatch for {bad[:5]} (new NVD snapshot? use --repin)")
    techs = json.loads(gzip.decompress(WA.read_bytes()))["technologies"]
    tree = sigsrc.tarball(EOL_REPO, EOL_COMMIT)
    wanted = wanted_products(techs, SOFTWARE.read_text("utf-8"), eol_cpes(tree))
    epss = load_epss(epss_raw)
    kev = load_kev()

    def feeds():
        for p in paths:
            with gzip.open(p, "rb") as g:
                yield iter_feed(g)

    text, stats = build(feeds(), wanted, kev, epss, {"snapshot": SNAPSHOT, "epss": EPSS_DATE})
    size = sigsrc.write_gz(OUT, text)
    mapped = sorted(k for k, g in wanted.items() if g & {"d", "o"})
    hit = {l.split("\t")[1].split("@")[0] for l in text.splitlines() if l.startswith("P\t")}
    stats["software_cpes_without_cves"] = [k for k in mapped if k not in hit]
    sigsrc.record(NAME, {
        "url": "https://nvd.nist.gov/vuln/data-feeds", "version": SNAPSHOT,
        "license": "NVD-public-domain",
        "license_note": "NVD data is in the public domain (17 U.S.C. 105); NIST asks for the notice "
                        "'This product uses data from the NVD API but is not endorsed or certified by the NVD.'",
        "attribution": ATTRIBUTION, "snapshot": SNAPSHOT, "epss": EPSS_DATE,
        "inputs": now, "outputs": [sigsrc.out_hash(OUT)], "stats": stats,
    })
    print(f"{OUT.name}: {size} bytes gz; {json.dumps(stats)}")
    if "--keep-cache" not in opts:
        for p in paths:
            p.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
