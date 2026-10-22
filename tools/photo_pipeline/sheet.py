#!/usr/bin/env python3
# PNG 여러 장을 가로로 붙여 한 장으로 — 미리보기 확인용 (docs/이미지작업_프로세스.md ⑤)
#   python3 sheet.py pv-1.png pv-2.png … sheet.png
import sys, re
from PIL import Image
if len(sys.argv) < 3:
    print('사용법: python3 sheet.py in1.png in2.png … out.png'); sys.exit(1)
ins, out = sys.argv[1:-1], sys.argv[-1]
ins = sorted(ins, key=lambda x: int(m.group(1)) if (m := re.search(r'(\d+)\.png$', x)) else 0)
ims = [Image.open(f) for f in ins]
w = sum(i.width for i in ims) + 10 * (len(ims) - 1); h = max(i.height for i in ims)
sheet = Image.new('RGB', (w, h), 'white'); x = 0
for im in ims:
    sheet.paste(im, (x, 0)); x += im.width + 10
sheet.save(out); print(out, sheet.size)
