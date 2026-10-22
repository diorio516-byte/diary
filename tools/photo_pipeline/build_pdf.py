#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
사진이 들어간 A4 PDF 만들기 (docs/이미지작업_프로세스.md ④~⑤)

사용법:
  python3 build_pdf.py job.json

job.json 보기: job.example.json
  html      : 글이 들어 있는 HTML (사진 자리는 <!--PHOTO:slot--> 한 줄, 또는
              <div class="placeholder"><span>…img/slot.jpg…</span></div>)
  out_pdf   : 결과 PDF 경로
  frames    : {"land": [64, 37], "port": [31, 37]}  (mm · 가로 사진 프레임 · 세로 사진 프레임)
  photos    : [{"slot": "...", "src": "raw/x.png", "caption": "..."},
               {"slot": "...", "pair": [{"src":..., "caption":...}, {"src":..., "caption":...}]}]
  footer    : (선택) 바닥글에서 바꿀 글 {"find": "...", "replace": "..."}

하는 일: 사진 센터 크롭(img/) → 자리 표시를 사진 블록으로 → _wk.html(zoom 보정) → wkhtmltopdf
         → pdfinfo 쪽 수 → pdftoppm 미리보기 → sheet.png(전 쪽 한 장)
"""
import sys, os, re, json, html, subprocess, glob
from PIL import Image

PF_CSS = '''
  .pf { position: relative; width: 100%; height: __H__mm; overflow: hidden; border-radius: 6px; margin-bottom: 4mm; background: #eee; }
  .pf img { width: 100%; height: 100%; display: block; border-radius: 6px; }
  .pl { position: absolute; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.58); color: #fff; font-size: 8.3pt; padding: 2px 7px 3px 7px; line-height: 1.3; border-radius: 0 0 6px 6px; }
  .pgrid { display: table; width: 100%; border-spacing: 0; }
  .pgrid .pc { display: table-cell; width: 50%; vertical-align: top; padding: 0; }
  .pgrid .pc + .pc { padding-left: 2mm; }
'''

def crop(src, dst, aspect, vshift=0.5):
    """src를 aspect(가로/세로)에 맞춰 가운데 잘라 dst(jpg)로 저장. vshift: 세로 자를 때 위에서부터 비율(0=위, 0.5=가운데)."""
    im = Image.open(src).convert('RGB')
    w, h = im.size
    if w / h > aspect:
        nw = int(round(h * aspect)); x0 = (w - nw) // 2
        box = (x0, 0, x0 + nw, h)
    else:
        nh = int(round(w / aspect)); y0 = int(round((h - nh) * vshift))
        box = (0, y0, w, y0 + nh)
    out = im.crop(box)
    out.save(dst, quality=90)
    return out.size

def pf(img_rel, cap):
    return '<div class="pf"><img src="%s"><span class="pl">%s</span></div>' % (img_rel, html.escape(cap))

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    job_path = os.path.abspath(sys.argv[1])
    base = os.path.dirname(job_path)
    job = json.load(open(job_path, encoding='utf-8'))
    os.chdir(base)
    frames = job.get('frames', {"land": [64, 37], "port": [31, 37]})
    land = frames['land'][0] / frames['land'][1]
    port = frames['port'][0] / frames['port'][1]
    os.makedirs('img', exist_ok=True)

    blocks = {}
    for p in job['photos']:
        slot = p['slot']
        if 'pair' in p:
            cells = []
            for i, q in enumerate(p['pair']):
                name = '%s_%d' % (slot, i + 1)
                size = crop(q['src'], 'img/%s.jpg' % name, port, q.get('vshift', 0.5))
                print('crop', name, size)
                cells.append('<div class="pc">' + pf('img/%s.jpg' % name, q['caption']) + '</div>')
            blocks[slot] = '<div class="pgrid">' + ''.join(cells) + '</div>'
        else:
            size = crop(p['src'], 'img/%s.jpg' % slot, land, p.get('vshift', 0.5))
            print('crop', slot, size)
            blocks[slot] = pf('img/%s.jpg' % slot, p['caption'])

    s = open(job['html'], encoding='utf-8').read()
    used = set()
    def repl_comment(m):
        slot = m.group(1).strip()
        if slot in blocks:
            used.add(slot); return blocks[slot]
        return m.group(0)
    s = re.sub(r'<!--\s*PHOTO:([^>]+?)\s*-->', repl_comment, s)
    def repl_old(m):
        block = m.group(0)
        for slot in blocks:
            if ('img/%s.jpg' % slot) in block or ('PHOTO:%s' % slot) in block:
                used.add(slot); return blocks[slot]
        return block
    s = re.sub(r'<div class="placeholder"><span>.*?</span></div>', repl_old, s, flags=re.S)
    missing = [k for k in blocks if k not in used]
    if missing:
        print('⚠️ 자리 표시를 못 찾은 slot:', missing)

    if '.pf {' not in s:
        s = s.replace('</style>', PF_CSS.replace('__H__', str(frames['land'][1])) + '</style>', 1)
    ft = job.get('footer')
    if ft:
        s = s.replace(ft['find'], ft['replace'])

    out_html = os.path.splitext(job['html'])[0] + '_out.html'
    open(out_html, 'w', encoding='utf-8').write(s)
    wk = s.replace('</style>', '  body { zoom: 1.282; }\n</style>', 1)   # wkhtmltopdf mm 보정
    open('_wk.html', 'w', encoding='utf-8').write(wk)

    out_pdf = job['out_pdf']
    cmd = ['wkhtmltopdf', '--quiet', '--page-size', 'A4', '--orientation', 'Portrait',
           '--margin-top', '0', '--margin-bottom', '0', '--margin-left', '0', '--margin-right', '0',
           '--encoding', 'utf-8', '--enable-local-file-access', '_wk.html', out_pdf]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if not os.path.exists(out_pdf):
        print('❌ wkhtmltopdf 실패\n', r.stderr); sys.exit(2)
    info = subprocess.run(['pdfinfo', out_pdf], capture_output=True, text=True).stdout
    pages = re.search(r'Pages:\s+(\d+)', info)
    print('PDF 쪽 수:', pages.group(1) if pages else '?', '→', out_pdf)

    for f in glob.glob('pv-*.png'):
        os.remove(f)
    subprocess.run(['pdftoppm', '-r', '40', '-png', out_pdf, 'pv'])
    pngs = sorted(glob.glob('pv-*.png'), key=lambda x: int(re.search(r'(\d+)\.png$', x).group(1)))
    ims = [Image.open(f) for f in pngs]
    if ims:
        w = sum(i.width for i in ims) + 10 * (len(ims) - 1); h = max(i.height for i in ims)
        sheet = Image.new('RGB', (w, h), 'white'); x = 0
        for im in ims:
            sheet.paste(im, (x, 0)); x += im.width + 10
        sheet.save('sheet.png')
        print('미리보기 한 장: %s/sheet.png (Read로 보고 넘침·겹침 확인)' % base)

if __name__ == '__main__':
    main()
