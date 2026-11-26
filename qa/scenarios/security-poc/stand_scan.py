#!/usr/bin/env python3
"""Creates a project on the harness and runs a scan. usage: stand_scan.py BASE PROFILE NAME [TARGET] [EXCLUDE]"""
import json, sys, time, urllib.request
base, profile, name = sys.argv[1], sys.argv[2], sys.argv[3]
target = sys.argv[4] if len(sys.argv) > 4 else "example.test"
excl = [sys.argv[5]] if len(sys.argv) > 5 else []
def call(cmd, args={}):
    r = urllib.request.urlopen(urllib.request.Request(base + "/invoke", json.dumps({"cmd": cmd, "args": args}).encode(), method="POST"))
    j = json.load(r)
    if "error" in j: raise RuntimeError(j["error"])
    return j["result"]
if not call("terms_get")["accepted"]: call("terms_accept", {"version": call("terms_get")["version"]})
pid = call("project_create", {"name": name, "client": "QA", "targets": [target], "excludes": excl})["id"]
call("scan_start", {"project": pid, "profile": profile})
for _ in range(1200):
    if not call("scan_status")["running"]: break
    time.sleep(0.5)
s = call("project_open", {"id": pid})
print(json.dumps({"pid": pid, "docs": len(s["docs"]), "people": len(s["people"]), "findings": len(s["findings"]), "hosts": len(s["hosts"])}))
