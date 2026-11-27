#!/usr/bin/env python3
"""Ingest the Retire.js repository (Apache-2.0) into `crates/foca-recon/data/retire.json.gz`.

Keeps, per JavaScript library, the version extractors FOCA-rs can evaluate on a script URL or
its content (`uri`, `filename`, `filecontent`; the `§§version§§` placeholder is expanded to the
Retire.js version regex) and the vulnerable ranges (`atOrAbove` / `below`, severity, CVE, CWE,
GHSA id, summary). Dropped: `func` and `ast` extractors (need a JS engine), `hashes` (SHA-1 of the
file), `filecontentreplace`, reference URLs. Regexes the Rust `regex` crate rejects
(backreferences) are skipped and counted in `sources.lock.json`.

Usage: python3 update_retire.py [--repin]
"""

import json

import sigsrc

NAME = "retire"
REPO = "RetireJS/retire.js"
COMMIT = "da66c52a5a5a60f949d19adc04c0bd8ea38a24b9"
OUT = sigsrc.REPO / "crates/foca-recon/data/retire.json.gz"
FILES = ["repository/jsrepository-v4.json", "LICENSE.md", "NOTICE.md"]
VERSION_RE = r"[0-9][0-9.a-z_\-]+"
FIELDS = {"uri": "u", "filename": "f", "filecontent": "c"}


def main() -> None:
    opts = sigsrc.args()
    files = {p: sigsrc.raw(REPO, COMMIT, p) for p in FILES}
    inputs = sigsrc.verify_inputs(NAME, files, "--repin" in opts)
    assert "Apache License" in files["LICENSE.md"].decode(), "license changed"
    repo = json.loads(files["repository/jsrepository-v4.json"])
    pending = []
    for lib, d in repo.items():
        if lib == "retire-example":
            continue
        for field in FIELDS:
            for p in d.get("extractors", {}).get(field, []):
                pending.append((lib, field, p.replace("§§version§§", VERSION_RE)))
    errs = sigsrc.rust_regex_check([p for _, _, p in pending], case_insensitive=False)
    skipped = {"regex": 0}
    libs = {}
    for (lib, field, p), err in zip(pending, errs):
        if err:
            skipped["regex"] += 1
            continue
        libs.setdefault(lib, {"n": lib}).setdefault(FIELDS[field], []).append(p)
    dropped = {"func": 0, "ast": 0, "hashes": 0, "filecontentreplace": 0}
    nvuln = 0
    for lib, d in repo.items():
        ex = d.get("extractors", {})
        for k in dropped:
            v = ex.get(k)
            dropped[k] += len(v) if v else 0
        if lib not in libs:
            continue
        vulns = []
        for v in d.get("vulnerabilities", []):
            ids = v.get("identifiers", {})
            row = {"b": v.get("below", "")}
            if v.get("atOrAbove"):
                row["a"] = v["atOrAbove"]
            row["s"] = v.get("severity", "")
            if ids.get("CVE"):
                row["cve"] = ids["CVE"]
            if v.get("cwe"):
                row["cwe"] = v["cwe"]
            if ids.get("githubID"):
                row["ghsa"] = ids["githubID"]
            if ids.get("summary"):
                row["t"] = " ".join(str(ids["summary"]).split())[:160]
            vulns.append(row)
        nvuln += len(vulns)
        libs[lib]["v"] = vulns
    out = {"source": f"{REPO}@{COMMIT[:12]}", "license": "Apache-2.0",
           "libraries": [libs[k] for k in sorted(libs)]}
    size = sigsrc.write_gz(OUT, json.dumps(out, ensure_ascii=False, separators=(",", ":")))
    stats = {"libraries_upstream": len(repo) - 1, "libraries_kept": len(libs),
             "vulnerabilities": nvuln, "extractors_kept": len(pending) - skipped["regex"],
             "skipped": skipped, "dropped_extractors": dropped}
    sigsrc.record(NAME, {
        "repo": f"https://github.com/{REPO}", "commit": COMMIT, "license": "Apache-2.0",
        "license_file": "LICENSE.md", "license_sha256": sigsrc.sha256(files["LICENSE.md"]),
        "notice": files["NOTICE.md"].decode().strip().splitlines()[0],
        "attribution": "JavaScript library vulnerability data from Retire.js, Copyright 2018 "
                       "Erlend Oftedal, Apache License 2.0, https://github.com/RetireJS/retire.js",
        "inputs": inputs, "outputs": [sigsrc.out_hash(OUT)], "stats": stats,
    })
    print(f"{OUT.name}: {size} bytes gz; {stats}")


if __name__ == "__main__":
    main()
