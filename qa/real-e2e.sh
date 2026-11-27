#!/bin/bash
# End-to-end UI check against the REAL core (no Android): foca testnet (offline "internet") + foca serve
# (Engine::invoke over HTTP, SSE events) + qa/tauri-shim.js (window.__TAURI__) in Playwright. Exits non-zero on any FAIL.
#   qa/real-e2e.sh             builds foca-cli, runs qa/scenarios/real-core/NN-*.mjs in order, then every route in
#                              qa/routes.txt on a real project (entity ids taken from the snapshot) in 2 configurations
#   qa/real-e2e.sh steps|routes  scenarios only / routes only (the harness restarts with fresh data)
#   E2E_ONLY="01 08"           run only these scenarios
#   E2E_DIR (default /tmp/foca-e2e) is the harness directory; FOCA_BIN is a prebuilt foca binary (skips the build)
cd "$(dirname "$0")/.." || exit 2
ROOT=$(pwd)
export E2E_DIR=${E2E_DIR:-/tmp/foca-e2e}
OUT=${QA_OUT:-$ROOT/qa/out/real-e2e}; mkdir -p "$OUT/logs"
WHAT=${1:-all}
REAL=http://127.0.0.1:${E2E_PORT:-8787}
FAILS=0
fail() { echo "FAIL: $*"; FAILS=$((FAILS+1)); }
pass() { echo "ok:   $*"; }

if [ -z "$FOCA_BIN" ]; then
  . /etc/profile.d/rust.sh 2>/dev/null
  export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
  cargo build -q -p foca-cli 2> "$OUT/logs/build.log" || { echo "FAIL: foca-cli build"; tail -20 "$OUT/logs/build.log"; exit 1; }
fi

# Clean harness: data and "phone files" (unique, so their SHA never matches the "internet" documents).
qa/e2e-serve.sh stop >/dev/null 2>&1; qa/e2e-serve.sh net-stop >/dev/null 2>&1
rm -rf "$E2E_DIR"; mkdir -p "$E2E_DIR/pick"
cp tests/corpus/ooxml/contract.docx "$E2E_DIR/pick/Договір_публікація.docx"; printf 'foca-e2e' >> "$E2E_DIR/pick/Договір_публікація.docx"
cp tests/corpus/images/photo.jpg "$E2E_DIR/pick/IMG_e2e_доказ.jpg"; printf 'foca-e2e' >> "$E2E_DIR/pick/IMG_e2e_доказ.jpg"
qa/e2e-serve.sh net-start || exit 1
qa/e2e-serve.sh start || exit 1
trap 'qa/e2e-serve.sh stop >/dev/null 2>&1; qa/e2e-serve.sh net-stop >/dev/null 2>&1' EXIT

check_steps() { # $1 log, $2 rc; same criteria as qa/run-all.sh
  python3 - "$1" "$2" <<'PY'
import json, re, sys
t = open(sys.argv[1], encoding="utf-8", errors="replace").read(); rc = int(sys.argv[2])
why = []
if rc != 0: why.append("rc=%d" % rc)
m = re.search(r'^\{\n "errors"', t, re.M)
try: d = json.loads(t[m.start():]) if m else None
except Exception: d = None
if d is None: why.append("no shoot.mjs JSON report")
elif d["errors"]: why.append("errors %s" % d["errors"][:3])
fl = [l for l in t.splitlines() if re.match(r"\s*FAIL\b", l)]
if fl: why.append("; ".join(l.strip()[:200] for l in fl[:6]))
for name, arr in re.findall(r"^STEP (\S+) overflow (\[.*?\])", t, re.M):
    if any(v for v in json.loads(arr)): why.append("overflow at step %s %s" % (name, arr))
oks = re.findall(r"(\d+) OK, (\d+) FAIL", t)
if not oks: why.append("no 'N OK, M FAIL' summary")
print(("BAD " + " | ".join(why)) if why else ("OK " + " ".join("%s OK" % a for a, b in oks)))
PY
}

if [ "$WHAT" = all ] || [ "$WHAT" = steps ]; then
  for f in qa/scenarios/real-core/[0-9][0-9]-*.mjs; do
    # E2E_ONLY="01 08" runs only these scenarios (quick rerun; 01 creates the harness project)
    if [ -n "$E2E_ONLY" ]; then case " $E2E_ONLY " in *" $(basename "$f" | cut -c1-2) "*) ;; *) continue ;; esac; fi
    n=$(basename "$f" .mjs); log="$OUT/logs/$n.log"
    qa/shoot.sh --real "$REAL" --routes none --out "$OUT/steps" --steps "$ROOT/$f" > "$log" 2>&1; rc=$?
    res=$(check_steps "$log" $rc)
    case "$res" in OK*) pass "scenario $n ${res#OK }";; *) fail "scenario $n ${res#BAD }";; esac
  done
fi

if [ "$WHAT" = all ] || [ "$WHAT" = routes ]; then
  # The routes check screens, not the lock: 05-report-settings leaves a PIN, and the core reads pin.json on
  # every call, so removing it opens the app without /lock (there is no command to remove a PIN).
  rm -f "$E2E_DIR/data/pin.json"
  # The project with the most data (if no scenarios ran, a passive scan is started through the API).
  python3 - "$REAL" > "$OUT/routes.txt" <<'PY'
import json, sys, time, urllib.request
base = sys.argv[1]
def call(cmd, args={}):
    r = urllib.request.urlopen(urllib.request.Request(base + "/invoke", json.dumps({"cmd": cmd, "args": args}).encode(), method="POST"))
    j = json.load(r)
    if "error" in j: raise RuntimeError(j["error"])
    return j["result"]
# Accept the terms of use, otherwise every route opens the /terms screen.
if not call("terms_get")["accepted"]: call("terms_accept", {"version": call("terms_get")["version"]})
lst = call("project_list")
def richness(p):
    s = call("project_snapshot", {"id": p["id"]})
    return (bool(s["docs"]) and bool(s["findings"]) and bool(s["people"]) and bool(s["hosts"]), len(s["docs"]) + len(s["findings"]))
cands = [p for p in lst if p["scans"]]
pid = max(cands, key=richness)["id"] if cands else None
if not pid:
    pid = lst[0]["id"] if lst else call("project_create", {"name": "example.test", "client": "ТОВ «Приклад»", "targets": ["example.test"], "excludes": []})["id"]
    call("scan_start", {"project": pid, "profile": "passive"})
    for _ in range(600):
        if not call("scan_status")["running"]: break
        time.sleep(0.5)
s = call("project_open", {"id": pid})
docs = [d for d in s["docs"] if not d["deleted"]]
f = s["findings"]; people = s["people"]; hosts = s["hosts"]; pcs = s["pcs"]
sub = {
    "/p/finding/1": "/p/finding/%d" % f[0]["id"], "/p/finding/12": "/p/finding/%d" % f[min(11, len(f) - 1)]["id"],
    "/p/doc/1": "/p/doc/%d" % docs[0]["id"], "/p/doc/2": "/p/doc/%d" % docs[min(1, len(docs) - 1)]["id"],
    "/p/entity/person/a.bondar": "/p/entity/person/" + people[0]["login"],
    "/p/graph/person/a.bondar": "/p/graph/person/" + people[0]["login"],
    "/p/entity/host/mail.contoso.example": "/p/entity/host/" + hosts[0]["name"],
    "/p/entity/pc/BUH-PC07": "/p/entity/pc/" + (pcs[0]["name"] if pcs else "-"),
}
routes = [r.strip() for r in open("qa/routes.txt").read().replace("\n", ",").split(",") if r.strip()]
print(",".join(sub.get(r, r) for r in routes))
PY
  R=$(cat "$OUT/routes.txt")
  N=$(printf '%s' "$R" | tr ',' '\n' | grep -c .)
  [ "$N" -gt 0 ] || fail "routes (core): no route list (see the traceback above)"
  i=0
  [ "$N" -gt 0 ] && for cfg in "--w 393" "--w 360 --fs 2"; do
    i=$((i+1)); log="$OUT/logs/routes_$i.log"
    qa/shoot.sh --real "$REAL" --routes "$R" --out "$OUT/routes" $cfg > "$log" 2>&1; rc=$?
    res=$(python3 - "$log" "$rc" "$N" <<'PY'
import json, sys
t = open(sys.argv[1], encoding="utf-8", errors="replace").read(); rc = int(sys.argv[2])
try: d = json.loads(t[t.find("{\n"):])
except Exception: print("BAD", "rc=%d report not parsed: %s" % (rc, t[-300:].replace("\n", " "))); sys.exit()
ovf = [r["route"] for r in d["report"] if r["overflow"]["sw"] or r["overflow"]["docw"]]
bad = rc != 0 or d["errors"] or ovf or len(d["report"]) < int(sys.argv[3])
print("BAD" if bad else "OK", "rc=%d routes %d errors %s overflow %s" % (rc, len(d["report"]), d["errors"][:4], ovf))
PY
)
    case "$res" in OK*) pass "routes (core) [$cfg] ${res#OK }";; *) fail "routes (core) [$cfg] ${res#BAD }";; esac
  done
fi

# The harness is offline: the request logs of all projects and test-net-external.log (the
# NetConfig.local_only barrier in foca serve --test-net) may contain only 127.0.0.1 / localhost / *.test / RFC 5737.
res=$(python3 - "$E2E_DIR/data" <<'PY'
import glob, ipaddress, os, sqlite3, sys
d = sys.argv[1]
def local(h):
    h = (h or "").strip().strip("[]").rstrip(".").lower()
    if not h: return True
    if h == "localhost" or h.endswith(".localhost") or h == "test" or h.endswith(".test"): return True
    try: ip = ipaddress.ip_address(h)
    except ValueError: return False
    # Loopback and IPv4 documentation ranges (RFC 5737, not routable; used as port scan canaries).
    return ip.is_loopback or any(ip in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24") if ip.version == 4)
bad = {}
for f in glob.glob(os.path.join(d, "**", "*.foca"), recursive=True) + glob.glob(os.path.join(d, "*.db")):
    try:
        con = sqlite3.connect("file:%s?mode=ro" % f, uri=True)
        if not con.execute("select 1 from sqlite_master where name='request_log'").fetchone(): continue
        for h, n in con.execute("select host, count(*) from request_log group by host"):
            if not local(h): bad[h] = bad.get(h, 0) + n
    except sqlite3.Error as e:
        print("BAD could not read log %s: %s" % (f, e)); sys.exit()
ext = os.path.join(d, "test-net-external.log")
if os.path.exists(ext):
    for h in open(ext, encoding="utf-8").read().split():
        if not local(h): bad[h] = bad.get(h, 0) + 1
print(("BAD external hosts: " + ", ".join("%s×%d" % kv for kv in sorted(bad.items()))) if bad else "OK")
PY
)
case "$res" in OK*) pass "harness is offline: no external hosts in the request log";; *) fail "harness is offline: ${res#BAD }";; esac

echo "RESULT (real core): $([ $FAILS -eq 0 ] && echo 'ALL GREEN' || echo "FAIL: $FAILS")"
exit $([ $FAILS -eq 0 ] && echo 0 || echo 1)
