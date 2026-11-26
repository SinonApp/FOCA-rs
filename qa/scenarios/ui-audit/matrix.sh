#!/bin/bash
# Runs every route in one configuration; prints errors and routes with overflow.
cd "$(dirname "$0")/../../.."
OUT=$1; shift
qa/shoot.sh --routes "$(cat qa/routes.txt)" --out $OUT "$@" > /tmp/m.json 2>/tmp/m.err
python3 - <<'PY'
import json
t=open('/tmp/m.json').read(); d=json.loads(t[t.rfind('{\n "errors"'):])
print('errors',d['errors'])
bad=[(r['route'],r['overflow']['sw'],r['overflow']['docw']) for r in d['report'] if r['overflow']['sw'] or r['overflow']['docw']]
print('overflow',bad or 'none', 'routes',len(d['report']))
PY
