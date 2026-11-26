#!/usr/bin/env python3
"""Lifecycle on the real core: triage → rescan, stop/resume, restart, document deletion,
   kill (qa/e2e-serve.sh kill + start) → restart record → resume. Checks for duplicate documents/findings/people.
   REAL=http://127.0.0.1:8957 E2E_DIR=... E2E_PORT=8957 E2E_NET_PORT=8958 FOCA_BIN=... python3 qa/scenarios/review-logic-core/s2_lifecycle.py"""
import collections, json, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from stand import call, listen, accept_terms, wait_scan, ev_of, risk

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
sh = lambda *a: subprocess.run([os.path.join(ROOT, "qa/e2e-serve.sh"), *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()


def stats(pid, tag):
    s = call("project_snapshot", {"id": pid})
    live = [d for d in s["docs"] if not d["deleted"]]
    urls = collections.Counter(d["url"] for d in s["docs"])
    fk = collections.Counter((f["title"], f["host"]) for f in s["findings"])
    pl = next(p for p in call("project_list") if p["id"] == pid)
    act = [f for f in s["findings"] if f["status"] not in ("false", "fixed")]
    print("[%s] docs=%d (total %d, dup url=%d) findings=%d act=%d (dup title+host=%d) people=%d hosts=%d | list: docs=%d findings=%d risk=%s/%s | scans=%s" % (
        tag, len(live), len(s["docs"]), sum(v - 1 for v in urls.values() if v > 1), len(s["findings"]), len(act),
        sum(v - 1 for v in fk.values() if v > 1), len(s["people"]), len(s["hosts"]), pl["docs"], pl["findings"], pl["risk"], risk(act),
        [(x["id"][-4:], x["profile_id"], x["status"], x.get("reason"), x.get("progress"), x["docs"], x["findings"], x["added"]) for x in s["scans"]]))
    return s


def stop_mid(pid, prof, at_stage=("download", "meta"), resume_from=None):
    a = {"project": pid, "profile": prof, "active": False, "modules": []}
    if resume_from: a["resume_from"] = resume_from
    st = call("scan_start", a)
    for _ in range(600):
        ss = call("scan_status")
        if not ss["running"] or ss.get("stage") in at_stage: break
        time.sleep(0.2)
    print("  stopped at stage", ss.get("stage"), ss.get("progress"))
    call("scan_stop", {"reason": "user"}); wait_scan()
    return st["scan_id"]


def main():
    listen(); accept_terms()
    pid = call("project_create", {"name": "logic-life", "client": "QA", "targets": ["example.test"], "excludes": []})["id"]
    print("--- A. reference: full passive scan in a separate project")
    ref = call("project_create", {"name": "logic-ref", "client": "QA", "targets": ["example.test"], "excludes": []})["id"]
    call("scan_start", {"project": ref, "profile": "passive", "active": False, "modules": []}); wait_scan(); stats(ref, "reference")

    print("--- B. stop → resume (slowed testnet)")
    sh("delay", "150")
    sid = stop_mid(pid, "passive")
    s = stats(pid, "after stop")
    call("scan_start", {"project": pid, "profile": "passive", "active": False, "modules": [], "resume_from": sid}); wait_scan()
    s = stats(pid, "after resume")

    print("--- C. user triage + document deletion → rescan")
    f = [x for x in s["findings"]]
    call("finding_set_status", {"project": pid, "id": f[0]["id"], "status": "false"})
    call("finding_update", {"project": pid, "id": f[1]["id"], "patch": {"status": "confirmed", "sev": "crit", "notes": [{"text": "QA", "who": "qa", "time": "2026-11-21T10:00:00"}], "tags": ["r2"]}})
    call("finding_set_status", {"project": pid, "id": f[2]["id"], "status": "fixed"})
    d0 = [d for d in s["docs"] if not d["deleted"] and d["status"] == "analyzed"][0]
    call("doc_delete", {"project": pid, "ids": [d0["id"]]})
    before = {x["id"]: (x["status"], x["sev"], len(x["notes"]), x["tags"]) for x in f[:3]}
    stats(pid, "after triage")
    sh("delay", "0")
    call("scan_start", {"project": pid, "profile": "std", "active": False, "modules": []}); wait_scan()
    s = stats(pid, "after std rescan")
    after = {x["id"]: (x["status"], x["sev"], len(x["notes"]), x["tags"]) for x in s["findings"] if x["id"] in before}
    print("  triage before:", before); print("  triage after:", after)
    dd = next((d for d in s["docs"] if d["id"] == d0["id"]), None)
    print("  deleted document after rescan: deleted=%s; copies with the same url=%d" % (dd and dd["deleted"], sum(1 for d in s["docs"] if d["url"] == d0["url"])))
    fixed = [x for x in s["findings"] if x["id"] == f[2]["id"]]
    print("  fixed finding after rescan:", [(x["status"], x.get("fixed_scan")) for x in fixed])

    print("--- D. stop → \"Начать заново\" (new scan_start without resume_from)")
    sh("delay", "150")
    sid2 = stop_mid(pid, "passive")
    call("scan_start", {"project": pid, "profile": "passive", "active": False, "modules": []}); wait_scan()
    s = stats(pid, "after restart from scratch")

    print("--- E. process kill during scan → restart → resume")
    st = call("scan_start", {"project": pid, "profile": "passive", "active": False, "modules": []})
    for _ in range(300):
        if call("scan_status").get("stage") in ("download", "meta"): break
        time.sleep(0.2)
    sh("kill"); sh("start"); time.sleep(1)
    s = stats(pid, "after kill")
    rec = next((x for x in s["scans"] if x["id"] == st["scan_id"]), None)
    print("  killed scan record:", rec and (rec["status"], rec.get("reason"), rec.get("progress"), rec.get("stage")))
    sh("delay", "0")
    call("scan_start", {"project": pid, "profile": "passive", "active": False, "modules": [], "resume_from": st["scan_id"]}); wait_scan()
    s = stats(pid, "after resuming the killed scan")

    print("--- F. project deletion")
    data = os.path.join(os.environ.get("E2E_DIR", "/tmp/foca-e2e"), "data")
    def files_of(p):
        out = []
        for root, _, fs in os.walk(data):
            out += [os.path.join(root, x) for x in fs if p in os.path.join(root, x)]
        return out
    print("  project files before deletion:", len(files_of(pid)))
    call("project_delete", {"id": pid})
    print("  after: in project_list=%s, files=%d %s" % (any(p["id"] == pid for p in call("project_list")), len(files_of(pid)), files_of(pid)[:5]))
    print("  snapshot of the deleted one:", call("project_snapshot", {"id": pid}, ok=False).get("__error"))
    json.dump({"ref": ref}, open(os.path.join(os.environ.get("E2E_DIR", "/tmp/foca-e2e"), "s2.json"), "w"))


if __name__ == "__main__":
    main()
