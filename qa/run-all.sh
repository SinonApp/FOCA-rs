#!/bin/bash
# Full FOCA-rs UI check. Exits non-zero on any FAIL.
#   qa/run-all.sh              everything (~15 min; run in the background: qa/run-all.sh > /tmp/qa.out 2>&1 &)
#   qa/run-all.sh routes       routes only; steps: scenarios only; static: node --check + invariants
#   qa/run-all.sh --real [what]  adds a second phase: qa/real-e2e.sh (real core, foca serve)
# Criteria:
#   routes in qa/routes.txt × 4 configurations: errors [] and overflow 0 (page and document scrollWidth);
#   scenarios: shoot.mjs exits 0, its JSON report parses, errors [], no "FAIL" lines,
#     "N OK, M FAIL" / "fail": M counters have M = 0, "STEP … overflow [..]" lines are all zeros;
#   node qa/data-invariants.mjs reports "0 failed"; node --check passes for all JS.
cd "$(dirname "$0")/.." || exit 2
ROOT=$(pwd)
OUT=${QA_OUT:-$ROOT/qa/out/run-all}; mkdir -p "$OUT/logs"
REAL=0; [ "$1" = "--real" ] && { REAL=1; shift; }
WHAT=${1:-all}
FAILS=0
fail() { echo "FAIL: $*"; FAILS=$((FAILS+1)); }
pass() { echo "ok:   $*"; }

if [ "$WHAT" = all ] || [ "$WHAT" = static ]; then
  for f in ui/js/*.js ui/screens/*.js qa/*.mjs qa/scenarios/{launch-wizard,scan-screen,findings-gestures,data-navigation,reports-export,graph-map-tools,project-switch,regression-scan-scope,regression-screens,regression-logic,regression-a11y,regression-round2,first-run-debug,site-fuzz,back-navigation,infra-1-2,forensics-1-3,insights-1-4,real-core,ui-remediation,android-remediation,subdomain-bulk,scan-controls,scan-followup,hosts-parallel,scan-delete,journal-clear,ai-summary,background-setup,standards-2025,beta-note,ux-polish,report-logo,report-preview-scroll,reextract,self-update}/*.mjs qa/scenarios/i18n-*/*.mjs qa/tauri-shim.js; do
    [ -f "$f" ] || continue
    node --check "$f" 2>"$OUT/logs/check.err" || fail "node --check $f: $(head -c 300 "$OUT/logs/check.err")"
  done
  pass "node --check"
  # UI formatting (Prettier) and lint (ESLint); dev dependencies come from `npm ci`.
  if [ -x node_modules/.bin/prettier ] && [ -x node_modules/.bin/eslint ]; then
    npm run -s format:check > "$OUT/logs/format.log" 2>&1 && pass "prettier --check ui" || { fail "prettier --check ui (npm run format)"; grep -E "^\[warn\]" "$OUT/logs/format.log" | head -10; }
    npm run -s lint > "$OUT/logs/lint.log" 2>&1 && pass "eslint ui" || { fail "eslint ui: $(grep -E 'problems?' "$OUT/logs/lint.log" | tail -1)"; head -20 "$OUT/logs/lint.log"; }
  else
    fail "prettier/eslint not installed: run npm ci"
  fi
  node qa/data-invariants.mjs > "$OUT/logs/invariants.log" 2>&1; rc=$?
  line=$(grep -E "checks passed" "$OUT/logs/invariants.log" | tail -1)
  if [ $rc -eq 0 ] && echo "$line" | grep -q " 0 failed"; then pass "invariants: $line"; else fail "invariants (rc=$rc): ${line:-no summary line}"; grep -E "^✗" "$OUT/logs/invariants.log" | head -10; fi
  # i18n: no translations evaluated at script load; every literal F.t key exists in ru/en/uk.
  node qa/check-i18n.mjs > "$OUT/logs/check-i18n.log" 2>&1; rc=$?
  line=$(tail -1 "$OUT/logs/check-i18n.log")
  if [ $rc -eq 0 ]; then pass "i18n static: $line"; else fail "i18n static (rc=$rc): $line"; grep '^FAIL' "$OUT/logs/check-i18n.log" | head -10; fi
  node qa/check-ftext.mjs > "$OUT/logs/check-ftext.log" 2>&1; rc=$?
  line=$(tail -1 "$OUT/logs/check-ftext.log")
  if [ $rc -eq 0 ]; then pass "finding texts: $line"; else fail "finding texts (rc=$rc): $line"; grep '^FAIL' "$OUT/logs/check-ftext.log" | head -10; fi
  # Settings defaults inside their recommended ranges; what's new note matches the app version.
  for chk in check-defaults check-release; do
    node qa/$chk.mjs > "$OUT/logs/$chk.log" 2>&1; rc=$?
    line=$(tail -1 "$OUT/logs/$chk.log")
    if [ $rc -eq 0 ]; then pass "$chk: $line"; else fail "$chk (rc=$rc): $line"; grep '^FAIL' "$OUT/logs/$chk.log" | head -10; fi
  done
  # Links and anchors in every .md file.
  python3 qa/check-docs-links.py > "$OUT/logs/docs-links.log" 2>&1; rc=$?
  line=$(tail -1 "$OUT/logs/docs-links.log")
  if [ $rc -eq 0 ]; then pass "docs links: $line"; else fail "docs links (rc=$rc): $line"; head -10 "$OUT/logs/docs-links.log"; fi
  # Android package and .so JNI symbols <-> external fun (if the .so is built).
  bash qa/check-jni.sh > "$OUT/logs/check-jni.log" 2>&1; rc=$?
  line=$(tail -1 "$OUT/logs/check-jni.log")
  if [ $rc -eq 0 ]; then pass "$line$(grep -q '^SKIP' "$OUT/logs/check-jni.log" && echo ' (no .so, symbols not checked)')"; else fail "check-jni (rc=$rc): $line"; grep '^FAIL' "$OUT/logs/check-jni.log" | head -10; fi
fi

if [ "$WHAT" = all ] || [ "$WHAT" = routes ]; then
  R=$(grep -v '^\s*$' qa/routes.txt | paste -sd,)
  i=0
  for cfg in "--w 393" "--w 360 --fs 1.3 --theme light" "--w 412 --fs 2" "--w 360 --fs 2"; do
    i=$((i+1)); log="$OUT/logs/routes_$i.log"
    qa/shoot.sh --routes "$R" --out "$OUT/routes" $cfg > "$log" 2>&1; rc=$?
    res=$(python3 - "$log" "$rc" <<'PY'
import json, sys
t = open(sys.argv[1], encoding="utf-8", errors="replace").read(); rc = int(sys.argv[2])
try:
    d = json.loads(t[t.find("{\n"):] if "{\n" in t else t[t.find("{"):])
except Exception as e:
    print("BAD", "rc=%d report not parsed: %s" % (rc, t[-300:].replace("\n", " "))); sys.exit()
ovf = [r["route"] for r in d["report"] if r["overflow"]["sw"] or r["overflow"]["docw"]]
bad = rc != 0 or d["errors"] or ovf
print("BAD" if bad else "OK", "rc=%d routes %d errors %s overflow %s" % (rc, len(d["report"]), d["errors"][:4], ovf))
PY
)
    case "$res" in OK*) pass "routes [$cfg] ${res#OK }";; *) fail "routes [$cfg] ${res#BAD }";; esac
  done
fi

if [ "$WHAT" = all ] || [ "$WHAT" = steps ]; then
  # "scenario[@configuration]"; the configuration uses "_" for spaces: regression-round2/a11y@--w_360_--fs_2
  # Localization scenarios are picked up automatically: every qa/scenarios/i18n-*/<name>.mjs runs once.
  # Scenario directories not listed here on purpose:
  #   layout-rc2                  runs in the layout phase below;
  #   real-core, security-poc     need the real core (qa/real-e2e.sh via --real, or a hand-made stand);
  #   review-logic-*, review-ux-* one-off review flows and text dumps without pass/fail checks;
  #   tap-targets, ui-audit       audit reports (tap sizes are gated by regression-round2/a11y).
  # Extra .mjs files next to listed scenarios (screenshot helpers, partial steps) are not run either.
  I18N_STEPS=$(cd qa/scenarios && for f in i18n-*/*.mjs; do [ -f "$f" ] && echo "${f%.mjs}"; done | sort | tr '\n' ' ')
  for item in launch-wizard/steps scan-screen/steps2 findings-gestures/steps data-navigation/steps reports-export/steps \
              graph-map-tools/steps project-switch/steps-proj regression-scan-scope/fix regression-screens/fix \
              regression-logic/fix regression-a11y/fix regression-round2/fix first-run-debug/steps site-fuzz/steps \
              back-navigation/steps back-navigation/scroll search-engines/steps search-engines/steps@--w_360_--theme_light wizard-help-globe/steps \
              wizard-help-globe/steps@--w_360_--theme_light_--fs_2 regression-round2/a11y@--w_393_--fs_1.3 \
              regression-round2/a11y@--w_360_--fs_2 layout-fab/steps layout-fab/steps@--w_360_--theme_light_--fs_2 \
              user-agent/steps site-recon/steps site-recon/steps@--w_360_--theme_light_--fs_2 port-scan/steps \
              port-scan/steps@--w_360_--theme_light_--fs_2 source-statuses/steps \
              source-statuses/steps@--w_360_--theme_light_--fs_2 captcha/steps captcha/steps@--w_360_--theme_light_--fs_2 \
              infra-1-2/steps infra-1-2/steps@--w_360_--theme_light_--fs_2 \
              forensics-1-3/steps forensics-1-3/steps@--w_360_--theme_light_--fs_2 \
              insights-1-4/steps insights-1-4/steps@--w_360_--theme_light_--fs_2 \
              ui-remediation/steps ui-remediation/steps@--w_360_--theme_light_--fs_2 \
              android-remediation/steps subdomain-bulk/steps subdomain-bulk/steps@--w_360_--theme_light_--fs_2 \
              scan-controls/steps scan-controls/steps@--w_360_--theme_light_--fs_2 \
              hosts-parallel/steps hosts-parallel/steps@--w_360_--theme_light_--fs_2 \
              scan-followup/steps scan-followup/steps@--w_360_--theme_light_--fs_2 \
              scan-delete/steps scan-delete/steps@--w_360_--theme_light_--fs_2 \
              journal-clear/steps journal-clear/steps@--w_360_--theme_light_--fs_2 \
              ai-summary/steps ai-summary/steps@--w_360_--theme_light_--fs_2 \
              background-setup/steps ux-polish/steps standards-2025/steps beta-note/steps beta-note/steps@--w_360_--theme_light_--fs_2 \
              report-logo/steps report-logo/steps@--w_360_--theme_light_--fs_2 \
              report-preview-scroll/steps report-preview-scroll/steps@--w_360_--theme_light_--fs_2 \
              reextract/steps reextract/steps@--w_360_--theme_light_--fs_2 \
              self-update/steps self-update/steps@--w_360_--theme_light_--fs_2 \
              $I18N_STEPS; do
    s=${item%%@*}; cfg=""; [ "$item" != "$s" ] && cfg=$(echo "${item#*@}" | tr _ ' ')
    f="$ROOT/qa/scenarios/$s.mjs"; log="$OUT/logs/$(echo $item | tr '/@ ' '___').log"
    [ -f "$f" ] || { fail "scenario $s: file missing"; continue; }
    qa/shoot.sh --routes /p/overview --out "$OUT/steps" $cfg --steps "$f" > "$log" 2>&1; rc=$?
    res=$(python3 - "$log" "$rc" <<'PY'
import json, re, sys
t = open(sys.argv[1], encoding="utf-8", errors="replace").read(); rc = int(sys.argv[2])
why = []
if rc != 0: why.append("rc=%d" % rc)
m = re.search(r'^\{\n "errors"', t, re.M)
try:
    d = json.loads(t[m.start():]) if m else None
except Exception:
    d = None
if d is None: why.append("no shoot.mjs JSON report")
elif d["errors"]: why.append("errors %s" % d["errors"][:3])
fl = [l for l in t.splitlines() if re.match(r"\s*FAIL\b", l)]
if fl: why.append("; ".join(l.strip()[:160] for l in fl[:6]))
for n in re.findall(r"(\d+) FAIL", t):
    if int(n): why.append("%s FAIL" % n)
for n in re.findall(r'"fail":\s*(\d+)', t):
    if int(n): why.append('"fail": %s' % n)
for name, arr in re.findall(r"^STEP (\S+) overflow (\[.*?\])", t, re.M):
    if any(v for v in json.loads(arr)): why.append("overflow at step %s %s" % (name, arr))
oks = re.findall(r"(\d+) OK, (\d+) FAIL", t)
print(("BAD " + " | ".join(why)) if why else ("OK " + (" ".join("%s OK" % a for a, b in oks) or "no errors")))
PY
)
    case "$res" in OK*) pass "scenario $item ${res#OK }";; *) fail "scenario $item ${res#BAD }";; esac
  done
fi

# Second phase: the real core (foca serve + tauri-shim), qa/run-all.sh --real
if [ $REAL -eq 1 ]; then
  qa/real-e2e.sh > "$OUT/logs/real-e2e.log" 2>&1; rc=$?
  grep -E "^(ok|FAIL):" "$OUT/logs/real-e2e.log"
  [ $rc -eq 0 ] && pass "real core (qa/real-e2e.sh)" || fail "real core (qa/real-e2e.sh rc=$rc, log $OUT/logs/real-e2e.log)"
fi

# Layout: qa/layout-sweep.mjs visits every route in UK/EN at 360/393 px with font scale 1 and 2 and fails on
# clipped/overlapping/overflowing elements outside its allow-list; plus the phone layout scenario.
#   qa/run-all.sh layout
if [ "$WHAT" = all ] || [ "$WHAT" = layout ]; then
  log="$OUT/logs/layout-sweep.log"
  (
    [ -f qa/local.env ] && . qa/local.env
    if [ -n "${PW_DIR:-}" ]; then
      export PLAYWRIGHT_BROWSERS_PATH="$PW_DIR/browsers"
      export PW_CORE="${PW_CORE:-$PW_DIR/node_modules/playwright-core/index.js}"
    fi
    flock -w 900 /tmp/foca-pw.lock timeout 900 node qa/layout-sweep.mjs --out "$OUT/layout-sweep"
  ) > "$log" 2>&1; rc=$?
  line=$(grep -E "^layout sweep:" "$log" | tail -1)
  if [ $rc -eq 0 ]; then pass "$line"; else fail "layout sweep (rc=$rc): ${line:-no summary}, $OUT/layout-sweep/report.md"; fi
  for item in layout-rc2/steps layout-rc2/steps@--w_360_--fs_2 layout-rc2/steps@--w_393_--fs_1; do
    s=${item%%@*}; cfg=""; [ "$item" != "$s" ] && cfg=$(echo "${item#*@}" | tr _ ' ')
    log="$OUT/logs/$(echo $item | tr '/@ ' '___').log"
    qa/shoot.sh --routes none --out "$OUT/steps" $cfg --steps "$ROOT/qa/scenarios/$s.mjs" > "$log" 2>&1; rc=$?
    sum=$(grep -oE '[0-9]+ OK, [0-9]+ FAIL' "$log" | tail -1)
    if [ $rc -eq 0 ] && echo "$sum" | grep -q ' 0 FAIL' && ! grep -qE '^\s*FAIL' "$log"; then pass "scenario $item $sum"; else fail "scenario $item rc=$rc ${sum:-no summary}: $(grep -E '^\s*FAIL' "$log" | head -3 | cut -c1-160 | tr '\n' ';')"; fi
  done
fi

echo "RESULT: $([ $FAILS -eq 0 ] && echo 'ALL GREEN' || echo "FAIL: $FAILS")"
exit $([ $FAILS -eq 0 ] && echo 0 || echo 1)
