#!/usr/bin/env python3
"""Moves the pins of the live data feeds (FIRST EPSS, NVD CVE feeds) to a newer snapshot.

The scheduled refresh (`.github/workflows/signatures.yml`) runs this before the ingest scripts:
the EPSS date in `update_kev_enrich.py` and `update_nvd.py`, and the NVD snapshot date and last
feed year in `update_nvd.py` move forward, so the scripts download the new snapshot and record it
with `--repin`. Code-like sources (webappanalyzer, endoflife.date, gitleaks, Retire.js, Recog,
PSL, can-i-take-over-xyz, Vulnrichment) keep their pinned commits.

Usage:
    python3 bump_live_pins.py [--epss-date YYYY-MM-DD|auto] [--nvd-snapshot YYYY-MM-DD] [--dry-run]

`--epss-date auto` (default) picks the newest EPSS file published in the last week; the NVD
snapshot defaults to today (UTC). Prints the old and new pins.
"""

import datetime
import pathlib
import re
import sys
import urllib.error
import urllib.request

TOOLS = pathlib.Path(__file__).resolve().parent
REPO = TOOLS.parents[3]
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
UA = "foca-rs-signature-ingest (+https://github.com/SinonApp/FOCA-rs)"


def published(date: str) -> bool:
    req = urllib.request.Request(EPSS_URL.format(date=date), method="HEAD", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status == 200
    except (urllib.error.URLError, TimeoutError):
        return False


def latest_epss(today: datetime.date) -> str:
    for back in range(0, 8):
        d = (today - datetime.timedelta(days=back)).isoformat()
        if published(d):
            return d
    sys.exit("bump_live_pins: no EPSS file published in the last week")


def set_const(text: str, name: str, value: str, quoted: bool = True) -> tuple[str, str]:
    pat = re.compile(rf'^{name} = ("?)([^"\n]*)\1$', re.M)
    m = pat.search(text)
    if not m:
        sys.exit(f"bump_live_pins: {name} not found")
    new = f'{name} = "{value}"' if quoted else f"{name} = {value}"
    return text[: m.start()] + new + text[m.end():], m.group(2)


def main() -> None:
    args = sys.argv[1:]

    def opt(name: str, default: str) -> str:
        return args[args.index(name) + 1] if name in args else default

    today = datetime.datetime.now(datetime.timezone.utc).date()
    snapshot = opt("--nvd-snapshot", today.isoformat())
    datetime.date.fromisoformat(snapshot)
    epss = opt("--epss-date", "auto")
    epss = latest_epss(today) if epss == "auto" else epss
    datetime.date.fromisoformat(epss)
    edits = {
        "update_kev_enrich.py": [("EPSS_DATE", epss, True)],
        "update_nvd.py": [
            ("SNAPSHOT", snapshot, True),
            ("EPSS_DATE", epss, True),
            ("LAST_YEAR", snapshot[:4], False),
        ],
    }
    olds = {}
    for file, consts in edits.items():
        path = TOOLS / file
        text = path.read_text("utf-8")
        for name, value, quoted in consts:
            text, old = set_const(text, name, value, quoted)
            olds[(file, name)] = old
            print(f"{file}: {name} {old} -> {value}")
        if "--dry-run" not in args:
            path.write_text(text, "utf-8")
    # The attribution lines name the snapshot (qa/gen-licenses.py checks them against the lock).
    notices = {
        "NOTICE": [("EPSS scores from FIRST.org", olds[("update_kev_enrich.py", "EPSS_DATE")], epss)],
        "THIRD_PARTY.md": [
            ("[FIRST EPSS]", olds[("update_kev_enrich.py", "EPSS_DATE")], epss),
            ("[NIST NVD]", olds[("update_nvd.py", "SNAPSHOT")], snapshot),
        ],
    }
    for file, rules in notices.items():
        path = REPO / file
        lines = path.read_text("utf-8").split("\n")
        for marker, old, new in rules:
            hits = [i for i, l in enumerate(lines) if marker in l]
            if not hits:
                sys.exit(f"bump_live_pins: {marker} not found in {file}")
            for i in hits:
                lines[i] = lines[i].replace(old, new)
            print(f"{file}: {marker} {old} -> {new}")
        if "--dry-run" not in args:
            path.write_text("\n".join(lines), "utf-8")


if __name__ == "__main__":
    main()
