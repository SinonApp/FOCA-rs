#!/usr/bin/env python3
"""Enrich the KEV snapshot with FIRST EPSS scores and CISA Vulnrichment data.

For every CVE in `kev.tsv.gz` this writes one row to `kev_enrich.tsv.gz`:

    # kev-enrich epss=<model date> vulnrichment=<commit> cves=<n> epss=<n> cvss=<n> cwe=<n>
    <cve>\t<epss 0..1>\t<percentile 0..1>\t<cvss base score>\t<cvss version>\t<CWE ids, comma>\t<ssvc>

`ssvc` is `exploitation/automatable/technical impact` from the CISA ADP SSVC decision points
(`active/yes/total`), empty when absent. CVSS and CWE come from the CNA container first, then
from the CISA ADP container. Missing values are empty.

Sources and terms:
* FIRST EPSS daily scores (https://www.first.org/epss/): free to use; FIRST asks for attribution
  ("EPSS scores from FIRST.org", with the model version / score date).
* cisagov/vulnrichment (CC0-1.0): one JSON record per CVE, read at a pinned commit.

Usage: python3 update_kev_enrich.py [--repin]
"""

import concurrent.futures
import csv
import gzip
import io
import json
import urllib.error

import sigsrc

NAME_EPSS = "epss"
NAME_VR = "vulnrichment"
EPSS_DATE = "2026-11-26"
EPSS_URL = f"https://epss.empiricalsecurity.com/epss_scores-{EPSS_DATE}.csv.gz"
VR_REPO = "cisagov/vulnrichment"
VR_COMMIT = "2872f0a7d9f88cc9fa7077d706b57af184674571"
KEV = sigsrc.SIG / "kev.tsv.gz"
OUT = sigsrc.SIG / "kev_enrich.tsv.gz"


def vr_path(cve: str) -> str:
    _, year, num = cve.split("-")
    return f"{year}/{int(num) // 1000}xxx/{cve}.json"


def vr_fetch(cve: str):
    try:
        return sigsrc.raw(VR_REPO, VR_COMMIT, vr_path(cve))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def cvss_of(container: dict):
    for m in container.get("metrics") or []:
        for key, ver in (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"),
                         ("cvssV2_0", "2.0")):
            if key in m and "baseScore" in m[key]:
                return str(m[key]["baseScore"]), ver
    return None


def cwes_of(container: dict):
    out = []
    for p in container.get("problemTypes") or []:
        for d in p.get("descriptions") or []:
            c = d.get("cweId")
            if c and c.startswith("CWE-") and c not in out:
                out.append(c)
    return out


def ssvc_of(adps: list) -> str:
    for a in adps:
        for m in a.get("metrics") or []:
            o = m.get("other") or {}
            if o.get("type") != "ssvc":
                continue
            opts = {}
            for x in (o.get("content") or {}).get("options") or []:
                opts.update({k.lower(): str(v).lower() for k, v in x.items()})
            vals = [opts.get("exploitation", ""), opts.get("automatable", ""),
                    opts.get("technical impact", "")]
            if any(vals):
                return "/".join(vals)
    return ""


def main() -> None:
    opts = sigsrc.args()
    kev_text = gzip.decompress(KEV.read_bytes()).decode()
    cves = sorted({line.split("\t", 1)[0] for line in kev_text.splitlines()
                   if line and not line.startswith("#")})
    epss_raw = sigsrc.fetch(EPSS_URL)
    epss_in = sigsrc.verify_inputs(NAME_EPSS, {f"epss_scores-{EPSS_DATE}.csv.gz": epss_raw},
                                   "--repin" in opts)
    text = gzip.decompress(epss_raw).decode()
    lines = text.splitlines()
    model = lines[0].lstrip("#") if lines and lines[0].startswith("#") else ""
    reader = csv.DictReader(io.StringIO("\n".join(l for l in lines if not l.startswith("#"))))
    want = set(cves)
    epss = {r["cve"]: (r["epss"], r["percentile"]) for r in reader if r["cve"] in want}

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        docs = dict(zip(cves, ex.map(vr_fetch, cves)))
    vr_files = {vr_path(c): d for c, d in docs.items() if d is not None}
    vr_files["LICENSE"] = sigsrc.raw(VR_REPO, VR_COMMIT, "LICENSE")
    assert "CC0" in vr_files["LICENSE"].decode() or "Creative Commons" in vr_files["LICENSE"].decode()
    vr_in = sigsrc.verify_inputs(NAME_VR, vr_files, "--repin" in opts)

    rows, n_cvss, n_cwe, n_ssvc = [], 0, 0, 0
    for cve in cves:
        e, p = epss.get(cve, ("", ""))
        e = f"{float(e):.4f}" if e else ""
        p = f"{float(p):.4f}" if p else ""
        score = ver = ssvc = ""
        cwes = []
        raw = docs.get(cve)
        if raw:
            c = json.loads(raw).get("containers", {})
            cna, adps = c.get("cna", {}), c.get("adp", [])
            got = cvss_of(cna) or next((x for x in map(cvss_of, adps) if x), None)
            if got:
                score, ver = got
                n_cvss += 1
            cwes = cwes_of(cna) or next((x for x in map(cwes_of, adps) if x), [])
            n_cwe += bool(cwes)
            ssvc = ssvc_of(adps)
            n_ssvc += bool(ssvc)
        rows.append("\t".join([cve, e, p, score, ver, ",".join(cwes), ssvc]))
    head = (f"# kev-enrich epss={EPSS_DATE} model={model.strip()} vulnrichment={VR_COMMIT[:12]} "
            f"cves={len(cves)} epss_n={len(epss)} cvss_n={n_cvss} cwe_n={n_cwe} ssvc_n={n_ssvc}")
    size = sigsrc.write_gz(OUT, "\n".join([head, *rows]) + "\n")
    sigsrc.record(NAME_EPSS, {
        "url": EPSS_URL, "version": EPSS_DATE, "model": model.strip(), "license": "FIRST-EPSS-terms",
        "license_note": "Free to use; FIRST requests attribution (https://www.first.org/epss/faq)",
        "attribution": f"EPSS scores from FIRST.org (https://www.first.org/epss), {EPSS_DATE}",
        "inputs": epss_in, "outputs": [sigsrc.out_hash(OUT)],
        "stats": {"cves": len(cves), "with_epss": len(epss)},
    })
    sigsrc.record(NAME_VR, {
        "repo": f"https://github.com/{VR_REPO}", "commit": VR_COMMIT, "license": "CC0-1.0",
        "license_file": "LICENSE", "license_sha256": sigsrc.sha256(vr_files["LICENSE"]),
        "attribution": "CVSS, CWE and SSVC data from CISA Vulnrichment (CC0-1.0), "
                       "https://github.com/cisagov/vulnrichment",
        "inputs": vr_in, "outputs": [sigsrc.out_hash(OUT)],
        "stats": {"records": len(vr_files) - 1, "with_cvss": n_cvss, "with_cwe": n_cwe,
                  "with_ssvc": n_ssvc},
    })
    print(f"{OUT.name}: {size} bytes gz; {head}")


if __name__ == "__main__":
    main()
