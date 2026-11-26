"""Client for the `foca serve` harness (POST /invoke, SSE /events). REAL=http://127.0.0.1:8957"""
import json, os, threading, time, urllib.request

REAL = os.environ.get("REAL", "http://127.0.0.1:8957")
EVENTS = []


def call(cmd, args=None, ok=True):
    req = urllib.request.Request(REAL + "/invoke", json.dumps({"cmd": cmd, "args": args or {}}).encode(), method="POST")
    j = json.load(urllib.request.urlopen(req, timeout=120))
    if "error" in j:
        if ok:
            raise RuntimeError("%s: %s" % (cmd, j["error"]))
        return {"__error": j["error"]}
    return j["result"]


def _sse():
    while True:
        try:
            r = urllib.request.urlopen(REAL + "/events", timeout=3600)
            for line in r:
                line = line.decode("utf-8", "replace").strip()
                if line.startswith("data:"):
                    try:
                        EVENTS.append(json.loads(line[5:]))
                    except Exception:
                        pass
        except Exception:
            time.sleep(0.5)


def listen():
    threading.Thread(target=_sse, daemon=True).start()
    time.sleep(0.5)


def accept_terms():
    t = call("terms_get")
    if not t["accepted"]:
        call("terms_accept", {"version": t["version"]})


def wait_scan(timeout=900):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if not call("scan_status")["running"]:
            return True
        time.sleep(0.5)
    return False


def ev_of(scan_id, typ=None):
    out = []
    for e in EVENTS:
        p = e.get("payload", e)
        if p.get("scan_id") == scan_id and (typ is None or p.get("type") == typ):
            out.append(p)
    return out


W = {"crit": .25, "high": .12, "warn": .05, "low": .02, "info": 0}


def risk(findings):
    import math
    p = 1.0
    for f in findings:
        p *= 1 - W.get(f["sev"], 0)
    return round(100 * (1 - p))
