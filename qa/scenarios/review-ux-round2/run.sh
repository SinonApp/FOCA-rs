#!/bin/bash
# run.sh <tag> <steps.mjs> [extra shoot args]; prints log of tag
tag=$1; st=$2; shift 2
cd $PWD && ./qa/shoot.sh --routes /welcome --out qa/scenarios/review-ux-round2 --w 393 --fs 1.3 --steps $PWD/qa/scenarios/review-ux-round2/$st "$@" > /tmp/$tag.out 2>&1
grep "^$tag " /tmp/$tag.out | python3 -c "
import json,sys
t=sys.stdin.read(); t=t[t.index(' ')+1:]
d=json.loads(t)
print(d.get('R'))
for l in d['log']: print(json.dumps(l,ensure_ascii=False)[:400])
"
python3 -c "
import json,re
t=open('/tmp/$tag.out').read(); i=t.rfind('{\n \"errors\"'); 
print('ERRORS', json.loads(t[i:])['errors'] if i>=0 else t[-500:])"
