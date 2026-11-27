#!/usr/bin/env python3
"""Creates the upgrade fixture data dir with an older `foca` binary through `foca serve`.

Synthetic data only: the corpus files of tests/corpus, a fake local AI endpoint, example.com.
Usage: make_fixture.py <foca binary> <data dir> <port> <tests/corpus dir>
(SIG_UPDATE=1 also checks the published signature bundle, which needs the internet.)
"""
import json, os, shutil, subprocess, sys, time, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

BIN, DATA, PORT, CORPUS = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
AI_PORT = PORT + 1


class Ai(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps({"data": [{"id": "fake-model"}]}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); self.rfile.read(n)
        body = json.dumps({"id": "x", "object": "chat.completion", "model": "fake-model",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant",
            "content": "## Summary\n\nSynthetic AI summary for the upgrade fixture."}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 8}}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)


threading.Thread(target=HTTPServer(("127.0.0.1", AI_PORT), Ai).serve_forever, daemon=True).start()


def inv(cmd, args=None):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/invoke",
        data=json.dumps({"cmd": cmd, "args": args or {}}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        res = json.loads(r.read())
    return res


shutil.rmtree(DATA, ignore_errors=True)
os.makedirs(DATA)
srv = subprocess.Popen([BIN, "serve", "--data", DATA, "--port", str(PORT)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(100):
        try:
            inv("app_info"); break
        except Exception:
            time.sleep(0.2)
    t = inv("terms_get"); print("terms", str(t)[:120])
    ver = (t.get("result") or t).get("version")
    print("accept", inv("terms_accept", {"version": ver}))
    p = inv("project_create", {"name": "Upgrade fixture", "client": "Example Org",
        "targets": ["example.com"]})
    print("create", str(p)[:200])
    pid = (p.get("result") or p)["id"]
    print("settings", str(inv("settings_set", {"patch": {"net": {"rps": 3, "timeout": 17},
        "power": {"wifi_only": False, "lim_on": True, "mob_limit": 321},
        "ai": {"provider": "custom", "base_url": f"http://127.0.0.1:{AI_PORT}/v1", "model": "fake-model"}}}))[:200])
    files = [f"{CORPUS}/ooxml/contract.docx", f"{CORPUS}/pdf/report.pdf",
             f"{CORPUS}/ole/legacy.doc", f"{CORPUS}/ooxml/schedule.xlsx",
             f"{CORPUS}/forensics/scan.pdf"]
    print("import", inv("doc_import", {"project": pid, "paths": files}))
    snap = inv("project_snapshot", {"project": pid})
    s = snap.get("result") or snap
    fs = s.get("findings", [])
    print("findings", len(fs), [f.get("id") for f in fs][:10])
    if fs:
        f0 = fs[0]["id"]
        print("status", str(inv("finding_set_status", {"project": pid, "id": f0, "status": "confirmed"}))[:150])
        print("note", str(inv("finding_update", {"project": pid, "id": f0, "patch": {"notes": [
            {"text": "Checked with the owner", "who": "analyst", "time": "2026-11-20T10:00:00Z"}]}}))[:150])
    if len(fs) > 1:
        print("false", str(inv("finding_set_status", {"project": pid, "id": fs[1]["id"], "status": "false"}))[:150])
    print("key", inv("key_set", {"service": "ai", "value": "sk-fake-upgrade"}))
    print("ai", str(inv("ai_summarize", {"project": pid, "opts": {"provider": "custom",
        "base_url": f"http://127.0.0.1:{AI_PORT}/v1", "model": "fake-model"}}))[:300])
    print("ai list", str(inv("ai_summaries_list", {"project": pid}))[:200])
    if os.environ.get("SIG_UPDATE"):
        print("sig", str(inv("signatures_update"))[:120])
    e = inv("project_export_encrypted", {"project": pid, "password": "upgrade-pass", "include_files": True})
    print("export", str(e)[:300])
finally:
    srv.terminate(); srv.wait()
