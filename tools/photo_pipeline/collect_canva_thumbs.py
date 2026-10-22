#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Canva 편집 응답으로 로컬에 저장된 페이지 썸네일(PNG)을 이름 붙여 raw/ 로 복사
(docs/이미지작업_프로세스.md 3-B 7번)

사용법:
  python3 collect_canva_thumbs.py --since 15 jangtaesan oncheon samsam …
    --since N : 최근 N분 안에 저장된 것만 (기본 30)
    --out DIR : 복사할 폴더 (기본 raw)
    --list    : 복사하지 않고 후보만 보여 주기
  이름은 썸네일이 저장된 순서(파일 이름의 밀리초)대로 붙는다.
  이름 수보다 썸네일이 많으면 앞에서부터 맞추고 남는 것은 건너뛴다(목록으로 확인할 것).

썸네일 위치: ~/.claude/projects/<작업폴더>/<세션>/tool-results/mcp-Canva-blob-<밀리초>-xxxx.png
"""
import sys, os, glob, time, shutil, re, argparse
from PIL import Image

ap = argparse.ArgumentParser()
ap.add_argument('names', nargs='*')
ap.add_argument('--since', type=int, default=30)
ap.add_argument('--out', default='raw')
ap.add_argument('--list', action='store_true')
a = ap.parse_args()

roots = [os.path.expanduser('~/.claude/projects'), '/root/.claude/projects']
files = []
for r in roots:
    files += glob.glob(os.path.join(r, '**', 'tool-results', 'mcp-Canva-blob-*.png'), recursive=True)
files = sorted(set(files), key=lambda f: int(re.search(r'blob-(\d+)-', f).group(1)))
now = time.time()
files = [f for f in files if now - os.path.getmtime(f) <= a.since * 60]
if not files:
    print('최근 %d분 안에 저장된 Canva 썸네일이 없음' % a.since); sys.exit(1)

print('후보 %d개 (저장 순):' % len(files))
for i, f in enumerate(files):
    im = Image.open(f)
    print('  [%d] %s  %dx%d' % (i, os.path.basename(f), im.width, im.height))
if a.list or not a.names:
    sys.exit(0)

os.makedirs(a.out, exist_ok=True)
for name, f in zip(a.names, files):
    dst = os.path.join(a.out, name + '.png')
    shutil.copy(f, dst)
    im = Image.open(dst)
    print('→ %s  %dx%d' % (dst, im.width, im.height))
if len(files) > len(a.names):
    print('(남은 썸네일 %d개는 건너뜀)' % (len(files) - len(a.names)))
