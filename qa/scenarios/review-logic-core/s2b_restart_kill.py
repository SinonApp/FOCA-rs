#!/usr/bin/env python3
"""Restart after a stop and a kill during download, on fresh projects (slowed-down testnet).
   E2E_DIR=... E2E_PORT=8957 E2E_NET_PORT=8958 FOCA_BIN=... python3 qa/scenarios/review-logic-core/s2b_restart_kill.py"""
import os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from stand import call, accept_terms, wait_scan
from s2_lifecycle import stats, sh # noqa  (s2 does not run on import, see the guard)

accept_terms()


def until_stage(stages, t=120):
    for _ in range(t * 5):
        ss = call("scan_status")
        if not ss["running"] or ss.get("stage") in stages: return ss
        time.sleep(0.2)
    return ss


sh("delay", "700")
print("--- D. stop → \"Начать заново\"")
p = call("project_create", {"name": "logic-restart", "client": "QA", "targets": ["example.test"], "excludes": []})["id"]
st = call("scan_start", {"project": p, "profile": "passive", "active": False, "modules": []})
ss = until_stage(("download",)); time.sleep(4); ss = call("scan_status"); print("  stopped at", ss.get("stage"), ss.get("progress"))
call("scan_stop", {"reason": "user"}); wait_scan(); stats(p, "after stop")
call("scan_start", {"project": p, "profile": "passive", "active": False, "modules": []}); wait_scan(); stats(p, "after \"Начать заново\"")

print("--- E. kill during download → restart record → resume")
p2 = call("project_create", {"name": "logic-kill", "client": "QA", "targets": ["example.test"], "excludes": []})["id"]
st = call("scan_start", {"project": p2, "profile": "passive", "active": False, "modules": []})
until_stage(("download",)); time.sleep(4); print("  killed at", call("scan_status").get("stage"), call("scan_status").get("progress"))
sh("kill"); sh("start"); time.sleep(1.5)
s = stats(p2, "after kill+start")
rec = next((x for x in s["scans"] if x["id"] == st["scan_id"]), None)
print("  record:", rec and (rec["status"], rec.get("reason"), rec.get("progress"), rec.get("stage")))
print("  scan_status after start:", call("scan_status"))
time.sleep(3); wait_scan()
s = stats(p2, "after auto/manual resume")
if any(x["status"] == "stopped" for x in s["scans"]):
    sid = [x for x in s["scans"] if x["status"] == "stopped"][-1]["id"]
    r = call("scan_start", {"project": p2, "profile": "passive", "active": False, "modules": [], "resume_from": sid}, ok=False)
    print("  resume:", r.get("__error") or "ok"); wait_scan()
    stats(p2, "after resume")
sh("delay", "0")
