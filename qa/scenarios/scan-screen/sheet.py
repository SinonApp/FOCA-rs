#!/usr/bin/env python3
# Splits a tall screenshot into columns for review: sheet.py in.png out.png [chunk_px] [y0] [y1]
import sys
from PIL import Image
im = Image.open(sys.argv[1]); out = sys.argv[2]
ch = int(sys.argv[3]) if len(sys.argv) > 3 else 1700
y0 = int(sys.argv[4]) if len(sys.argv) > 4 else 0
y1 = int(sys.argv[5]) if len(sys.argv) > 5 else im.height
im = im.crop((0, y0, im.width, y1))
n = (im.height + ch - 1) // ch
res = Image.new("RGB", (im.width * n + 20 * (n - 1), ch), (255, 0, 255))
for i in range(n):
    res.paste(im.crop((0, i * ch, im.width, min(im.height, (i + 1) * ch))), (i * (im.width + 20), 0))
res.save(out)
print(res.size)
