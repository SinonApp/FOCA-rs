#!/usr/bin/env python3
"""UI settings reach the core: net.ua (via a UA logger in front of testnet), settings.sources.<id>.enabled,
   sources_off, net.source_timeout (timeout_s in running events). Harness with net.json → ua_logger.
   UALOG=/tmp/foca-e2e/ua.log python3 qa/scenarios/review-logic-core/s6_settings.py"""
import collections, os, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from stand import call, listen, accept_terms, wait_scan, ev_of

UALOG = os.environ.get("UALOG", "/tmp/foca-e2e/ua.log")
listen(); accept_terms()


def run(tag, settings=None, **scan):
    if settings: call("settings_set", {"patch": settings})
    open(UALOG, "w").close()
    p = call("project_create", {"name": "logic-set-" + tag, "client": "QA", "targets": ["example.test"], "excludes": []})["id"]
    a = {"project": p, "profile": "passive", "active": False, "modules": []}; a.update(scan)
    sid = call("scan_start", a)["scan_id"]; wait_scan(); time.sleep(0.5)
    uas = collections.Counter(l.rstrip("\n").split("\t")[1] for l in open(UALOG) if "\t" in l)
    paths = collections.Counter(l.split(" ")[1].split("?")[0].split("/")[1] for l in open(UALOG) if " /" in l)
    src = {e["id"]: e["status"] for e in ev_of(sid, "source")}
    tmo = sorted({(e["id"], e.get("timeout_s")) for e in ev_of(sid, "source") if e.get("status") == "running" and e.get("timeout_s")})
    print("[%s] UA=%s" % (tag, dict(uas)))
    print("   top path segments:", dict(paths.most_common(8)))
    print("   sources:", {k: v for k, v in src.items() if k in ("wayback", "cc", "crt", "arquivo", "otx_url", "urlscan", "hudson", "bing")})
    print("   timeout_s:", tmo[:6])
    return sid


print("settings.net before:", {k: call("settings_get")["net"].get(k) for k in ("ua", "source_timeout", "rps", "threads", "timeout", "retries")})
run("chrome", {"net": {"ua": "chrome"}})
run("firefox", {"net": {"ua": "firefox"}})
run("honest", {"net": {"ua": "honest"}})
run("custom", {"net": {"ua": "custom", "ua_custom": "QA-Custom/1.0"}})
run("src-off", {"net": {"ua": "chrome", "source_timeout": 12}, "sources": {"wayback": {"enabled": False}, "cc": {"enabled": False}}})
run("wizard-off", {"sources": {"wayback": {"enabled": True}, "cc": {"enabled": True}}}, sources_off=["wayback"])
call("settings_set", {"patch": {"net": {"source_timeout": 90}}})
