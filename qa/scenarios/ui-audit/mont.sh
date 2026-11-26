#!/bin/bash
# mont.sh <dir> <prefix> [per]: builds a montage of screenshots in qa/routes.txt order.
D=$1; P=$2; N=${3:-4}; mkdir -p mont; rm -f mont/${P}_*.png
files=()
for r in $(tr ',' ' ' < $PWD/qa/routes.txt); do n=$(echo "$r" | sed -E 's/[^A-Za-z0-9_]+/_/g; s/^_|_$//g'); f=$(ls $D/${n}_*.png 2>/dev/null | head -1); [ -n "$f" ] && files+=("$f"); done
i=0; k=0
while [ $i -lt ${#files[@]} ]; do montage "${files[@]:$i:$N}" -tile ${N}x1 -geometry 393x+6+0 -background '#808080' mont/${P}_$(printf %02d $k).png; i=$((i+N)); k=$((k+1)); done
ls mont/${P}_* | wc -l
