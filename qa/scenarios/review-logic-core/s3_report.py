#!/usr/bin/env python3
"""Report on the real core: RU/UK/EN, the site recon and reviewers sections, junk values, finding title language.
   REAL=http://127.0.0.1:8957 python3 qa/scenarios/review-logic-core/s3_report.py <project_id>"""
import html, json, os, re, sys
sys.path.insert(0, os.path.dirname(__file__))
from stand import call

pid = sys.argv[1]
s = call("project_snapshot", {"id": pid})
rv = s.get("recon") or {}
print("snapshot.recon: level=%s tech=%d analytics=%d hidden=%d endpoints=%d secrets=%d buckets=%d" % (
    rv.get("level"), len(rv.get("tech") or []), len(rv.get("analytics") or []), len(rv.get("hidden_paths") or []),
    len(rv.get("endpoints") or []), len(rv.get("secrets") or []), len(rv.get("buckets") or [])))
revs = [p for p in s["people"] if "ецензент" in (p.get("role") or "")]
print("reviewers in snapshot.people:", [(p["login"], p["role"]) for p in revs])
cyr = re.compile(r"[А-Яа-яЁёІіЇїЄєҐґ]{4,}")
for lang in ("RU", "UA", "EN"):
    r = call("report_build", {"project": pid, "opts": {"tpl": "Полный", "tpl_id": "full", "fmt": "html", "lang": lang, "min_sev": "all", "confirmed": False,
                                                        "sections": {"summary": True, "scope": True, "findings": True, "fixed": True, "people": True, "infra": True, "docs": True, "log": True, "appx": True}}})
    t = open(r["path"], encoding="utf-8").read()
    txt = html.unescape(re.sub(r"<style.*?</style>|<script.*?</script>", " ", t, flags=re.S))
    txt = re.sub(r"<[^>]+>", " ", txt)
    bad = sorted(set(re.findall(r"\b(undefined|NaN|null|None|\[object Object\])\b", txt)))
    h2 = re.findall(r"<h2[^>]*>(.*?)</h2>", t, flags=re.S)
    h3 = re.findall(r"<h3[^>]*>(.*?)</h3>", t, flags=re.S)
    heads = [re.sub("<[^>]+>", "", x).strip() for x in h2]
    has_recon = bool(re.search(r"Разведка сайта|Розвідка сайту|Website recon|Site recon|Web reconnaissance", txt, re.I))
    has_rev = bool(re.search(r"Рецензент|Reviewer", txt, re.I))
    print("\n== %s %s size=%d total=%s" % (lang, r["name"], len(t), r["result"]["total"]))
    print("  h2:", heads)
    print("  junk:", bad, "| recon:", has_recon, "| reviewers:", has_rev)
    if lang == "EN":
        ru_lines = [l.strip() for l in txt.splitlines() if cyr.search(l)]
        print("  EN: Cyrillic lines=%d; examples:" % len(ru_lines), [l[:90] for l in ru_lines[:12]])
    if lang == "UA":
        ru_only = sorted(set(re.findall(r"\b\w*[ыэъЁё]\w*\b", txt)))
        print("  UA: words with Russian letters (ы/э/ъ/ё):", len(ru_only), ru_only[:25])
