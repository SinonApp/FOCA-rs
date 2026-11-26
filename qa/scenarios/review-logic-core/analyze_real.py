#!/usr/bin/env python3
"""Checks `foca analyze --json` on real public documents (which are NOT committed to the repository).
   python3 qa/scenarios/review-logic-core/analyze_real.py [FOCA_BIN] [dirs...]
   foca defaults to target/debug/foca; document directories are required"""
import json, subprocess, sys, re
foca = sys.argv[1] if len(sys.argv) > 1 else "target/debug/foca"
dirs = sys.argv[2:] or sys.exit("usage: analyze_real.py <foca> <documents dir>...")
d = json.loads(subprocess.run([foca, "analyze", "--json", *dirs], capture_output=True, check=True).stdout)
P = lambda *a: print(*a)
P("docs", len(d["docs"]), "people", len(d["people"]), "emails", len(d["emails"]), "findings", len(d["findings"]))

P("\n[A1] \"Surname, Name\" → login/e-mail with swapped name:")
for p in d["people"]:
    if "," in p["name"]:
        P("  ", repr(p["name"]), "->", p["login"])
for e in d["emails"]:
    if e.get("name") and "," in e["name"] and not e["found"]:
        P("   generated", e["addr"], "from", repr(e["name"]))

P("\n[A2] Non-people / merged entries in People:")
for p in d["people"]:
    if p["login"] in ("anonymous", "payroll", "planner", "nist", "cbsc") or ";" in p["login"] or "@" in p["login"] \
       or re.search(r"committee|services|employee|cevp", p["name"], re.I):
        P("   %-34s name=%-40r role=%r" % (p["login"], p["name"], p["role"]))

P("\n[A3] E-mail pattern applied to people with a found address in another domain:")
found = {}
for e in d["emails"]:
    if e["found"] and e.get("login"):
        found.setdefault(e["login"], []).append(e["addr"])
for e in d["emails"]:
    if not e["found"] and e.get("login") in found:
        P("   generated %-40s although found %s" % (e["addr"], found[e["login"]]))
P("   patterns:", [(x["p"], x["conf"]) for x in d["patterns"]])

P("\n[A4] Printers/PCs/hosts:")
P("   pcs:", [p["name"] for p in d["pcs"]])
P("   hosts:", [(h["name"], h["internal"]) for h in d["hosts"]])
P("   printers c ipp:", [p for p in d["printers"] if "ipp" in p["name"].lower()])

P("\n[A5] Software without EOL despite obvious age (release ≤ 2012 or CS1-CS6 / Distiller<5 in name):")
for s in d["software"]:
    old = re.search(r"\bCS\d\b|Distiller [34]\.|PDF Library [1-9]\.|Skia/PDF\) m[1-9]\d\b", s["name"])
    if not s["eol"] and (old or (s.get("released") and s["released"] <= 2012)):
        P("   %-34s ver=%-7s eol=%s released=%s docs=%d" % (s["name"], s["ver"], s["eol"], s["released"], s["docs"]))
P("   for comparison EOL=True:", [s["name"] for s in d["software"] if s["eol"]])

P("\n[A6] Finding texts (pluralization, duplicated version):")
for f in d["findings"]:
    t = f["title"] + " | " + (f.get("evidence") or "")
    if re.search(r"\b1 документов|\b[2-4] документов|\b21 документов", t) or re.search(r"(\d[\d.]+) \1\b", t):
        P("  ", t[:140].replace("\n", " "))

P("\n[A7] Events: \"Первый документ из <software>\" before the software release:")
rel = {s["name"]: s.get("released") for s in d["software"]}
for ev in d["events"]:
    m = re.match(r"Первый документ из (.+)", ev["t"])
    if m and rel.get(m.group(1)) and ev["y"] < rel[m.group(1)]:
        P("   %s: %s (release %s): %s" % (ev["y"], m.group(1), rel[m.group(1)], ev["s"]))
