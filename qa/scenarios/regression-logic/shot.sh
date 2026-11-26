#!/bin/bash
# usage: shot.sh <outdir> <args...>  prints a short summary of errors and overflow
out=$1; shift
$PWD/qa/shoot.sh --out "$out" "$@" > /tmp/shot_last.json 2>/tmp/shot_err.txt
python3 - <<'PY'
import json,sys,re
raw=open('/tmp/shot_last.json').read()
i=raw.find('{')
try: d=json.loads(raw[i:])
except Exception as e: print("PARSE FAIL", e, raw[:2000], open('/tmp/shot_err.txt').read()[-2000:]); sys.exit()
print("errors:", d.get("errors"))
for k,v in d.items():
  if isinstance(v,list):
    for r in v:
      if isinstance(r,dict) and 'overflow' in r:
        o=r['overflow']
        if o.get('sw') or o.get('docw') or o.get('wide'): print("OVERFLOW", r.get('route'), o)
    print(k, len(v), "items")
for k in d:
  if k not in ('errors',) and not isinstance(d[k],list): print(k, str(d[k])[:300])
PY
