#!/usr/bin/env python3
"""Number consistency on the real core: project_list ↔ snapshot ↔ scans[] ↔ report_build ↔ export_build.
   Harness: qa/e2e-serve.sh (E2E_PORT=8957); REAL=http://127.0.0.1:8957 python3 qa/scenarios/review-logic-core/s1_numbers.py"""
import csv, io, json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from stand import call, listen, accept_terms, wait_scan, ev_of, risk

listen(); accept_terms()
pid = call("project_create", {"name": "logic-num", "client": "ТОВ QA", "targets": ["example.test"], "excludes": []})["id"]
res = {}
for prof in ("passive", "std"):
    st = call("scan_start", {"project": pid, "profile": prof, "active": False, "modules": []})
    wait_scan()
    res[prof] = st["scan_id"]

s = call("project_snapshot", {"id": pid})
live_docs = [d for d in s["docs"] if not d["deleted"]]
act = [f for f in s["findings"] if f["status"] not in ("false", "fixed")]
pl = next(p for p in call("project_list") if p["id"] == pid)
last = s["scans"][-1]
print("docs: snapshot=%d project_list=%d scan.docs=%d snap.docs=%d" % (len(live_docs), pl["docs"], last["docs"], len(last["snapshot"]["docs"])))
print("findings: actual=%d project_list=%d scan.findings=%d snap=%d" % (len(act), pl["findings"], last["findings"], len(last["snapshot"]["findings"])))
print("people: snapshot=%d scan.people=%d snap=%d" % (len(s["people"]), last["people"], len(last["snapshot"]["people"])))
print("hosts: snapshot=%d scan.hosts=%d snap=%d" % (len(s["hosts"]), last["hosts"], len(last["snapshot"]["hosts"])))
print("risk: project_list=%s formula=%s" % (pl["risk"], risk(act)))
print("scans:", [(x["id"], x["profile_id"], x["status"], x["docs"], x["findings"], x["new_findings"] if not isinstance(x["new_findings"], list) else len(x["new_findings"]), x["added"]) for x in s["scans"]])

# Scan counters from events: done.scan vs scans[].
for prof, sid in res.items():
    dn = ev_of(sid, "done")
    if dn:
        sc = dn[-1]["scan"]
        rec = next(x for x in s["scans"] if x["id"] == sid)
        diff = {k: (sc.get(k), rec.get(k)) for k in ("docs", "people", "hosts", "findings") if sc.get(k) != rec.get(k)}
        print("done-event vs scans[%s] %s: %s" % (sid, prof, diff or "match"))
    fev = {e["finding"]["id"] for e in ev_of(sid, "finding")}
    print("finding-events %s: %d" % (prof, len(fev)))

# Reports: JSON and CSV include "everything except false positives" by default.
for fmt in ("json", "csv", "html", "md"):
    r = call("report_build", {"project": pid, "opts": {"tpl": "Полный", "tpl_id": "full", "fmt": fmt, "lang": "ru", "min_sev": "info", "confirmed": False, "sections": {}}}, ok=False)
    if "__error" in r:
        print("report", fmt, "ERR", r["__error"]); continue
    res_ = r["result"]
    print("report %-4s name=%s total=%s ids=%d fixed=%d risk=%s counts=%s" % (fmt, r["name"], res_["total"], len(res_["finding_ids"]), len(res_["fixed_ids"]), res_["risk"], res_["counts"]))
    path = r.get("path")
    if fmt == "json" and path and os.path.exists(path):
        j = json.load(open(path, encoding="utf-8"))
        fl = j.get("findings") or []
        print("   report.json findings=%d keys=%s" % (len(fl), list(j.keys())[:14]))
    if fmt == "csv" and path and os.path.exists(path):
        rows = list(csv.reader(io.StringIO(open(path, encoding="utf-8-sig").read())))
        print("   report.csv rows=%d header=%s" % (len(rows) - 1, rows[0][:8] if rows else None))

for kind in ("findings", "users", "emails", "software", "hosts", "docs"):
    for fmt in ("csv", "json"):
        e = call("export_build", {"project": pid, "kind": kind, "fmt": fmt, "opts": {}}, ok=False)
        if "__error" in e:
            print("export", kind, fmt, "ERR", e["__error"]); continue
        n = None
        if os.path.exists(e["path"]):
            raw = open(e["path"], encoding="utf-8-sig").read()
            if fmt == "json":
                j = json.loads(raw); n = len(j) if isinstance(j, list) else {k: len(v) for k, v in j.items() if isinstance(v, list)}
            else:
                n = len([r for r in csv.reader(io.StringIO(raw), delimiter=";" if raw.count(";") > raw.count(",") else ",")]) - 1
        print("export %-8s %-4s count=%s parsed=%s" % (kind, fmt, e["count"], n))
ref = {"findings": len(act), "findings_all_but_false": len([f for f in s["findings"] if f["status"] != "false"]),
       "users": len(s["people"]), "emails": len(s["emails"]), "software": len(s["software"]), "hosts": len(s["hosts"]), "docs": len(live_docs)}
print("snapshot ref:", ref)
json.dump({"pid": pid, "scans": res}, open("/tmp/foca-e2e/s1.json", "w"))
