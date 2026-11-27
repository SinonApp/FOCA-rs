#!/usr/bin/env python3
"""Ingest subdomain takeover fingerprints into `crates/foca-net/data/takeover.json`.

Source: EdOverflow/can-i-take-over-xyz `fingerprints.json` (CC-BY-4.0). Kept per service:
CNAME suffixes, status (`vulnerable`, `edge`, `not_vulnerable`), whether NXDOMAIN alone is the
signal, and the HTTP body fingerprint. Changes from the source (CC-BY-4.0 asks to indicate
them): fields renamed and reduced, IP/URL "cname" values and status-code-only fingerprints
dropped, entries without CNAME suffixes dropped, statuses normalized.

nuclei-templates `http/takeovers` (MIT) was evaluated and not ingested: its templates carry body
words and DSL host checks but no CNAME suffixes, so they cannot drive a DNS-based check.

Usage: python3 update_takeover.py [--repin]
"""

import json
import re

import sigsrc

NAME = "can-i-take-over-xyz"
REPO = "EdOverflow/can-i-take-over-xyz"
COMMIT = "5bd4e12837911c8475486f1da922c9b9c706e632"
OUT = sigsrc.REPO / "crates/foca-net/data/takeover.json"
FILES = ["fingerprints.json", "LICENSE"]
STATUS = {"Vulnerable": "vulnerable", "Edge case": "edge", "Not vulnerable": "not_vulnerable"}


def main() -> None:
    opts = sigsrc.args()
    files = {p: sigsrc.raw(REPO, COMMIT, p) for p in FILES}
    inputs = sigsrc.verify_inputs(NAME, files, "--repin" in opts)
    lic = files["LICENSE"].decode()
    assert lic.startswith("Attribution 4.0 International"), "license changed"
    rows = []
    for e in json.loads(files["fingerprints.json"]):
        # Domain suffixes only: IP literals and URLs in the source are not CNAME targets.
        cn = sorted({c.strip().lower().strip(".") for c in e.get("cname") or []
                     if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", c.strip().lower().strip("."))
                     and not re.fullmatch(r"[0-9.]+", c.strip())})
        if not cn:
            continue
        fp = e.get("fingerprint") or ""
        if fp.startswith("HTTP_STATUS"):
            fp = ""  # a status code alone is no body fingerprint
        rows.append({
            "service": " ".join(e["service"].split()),
            "status": STATUS.get(e.get("status"), "edge"),
            "cname": cn,
            "nxdomain": bool(e.get("nxdomain")),
            "fingerprint": "" if fp == "NXDOMAIN" else fp,
        })
    rows.sort(key=lambda r: r["service"].lower())
    doc = {
        "source": f"https://github.com/{REPO} @ {COMMIT[:12]}",
        "license": "CC-BY-4.0",
        "attribution": "Subdomain takeover fingerprints from can-i-take-over-xyz by EdOverflow "
                       "and contributors (CC BY 4.0); fields reduced and renamed by FOCA-rs",
        "services": rows,
    }
    OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", "utf-8")
    stats = {"services_upstream": len(json.loads(files["fingerprints.json"])),
             "services_kept": len(rows),
             "vulnerable": sum(r["status"] == "vulnerable" for r in rows),
             "nuclei_takeovers": "not ingested (no CNAME suffixes in templates)"}
    sigsrc.record(NAME, {
        "repo": f"https://github.com/{REPO}", "commit": COMMIT, "license": "CC-BY-4.0",
        "license_file": "LICENSE", "license_sha256": sigsrc.sha256(files["LICENSE"]),
        "attribution": doc["attribution"] + ", https://github.com/EdOverflow/can-i-take-over-xyz",
        "inputs": inputs, "outputs": [sigsrc.out_hash(OUT)], "stats": stats,
    })
    print(f"{OUT.name}: {stats}")


if __name__ == "__main__":
    main()
