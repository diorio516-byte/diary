#!/usr/bin/env python3
"""우리 다이어리 독립 앱 동기화 도구 (GitHub Pages 저장소 + 암호화).

비밀값(토큰, 비밀번호)은 재준 드라이브의 '우리 다이어리 앱 설정 (재준만)' 문서에서 읽는다.
파일은 AES-GCM(키: PBKDF2-SHA256)으로 암호화해서 저장소에 올린다. 같은 내용이면 같은 암호문이
나오도록 IV를 내용의 HMAC으로 만든다(바뀐 파일만 커밋되게).

  settings --doc doc.txt --out s.json            드라이브 문서 글 → 설정 JSON
  clone    --settings s.json --dir repo           저장소 받기(얕게)
  open     --settings s.json --repo repo --out data.json         data.json.enc 풀기
  seal     --settings s.json --repo repo --data data.json [--photos dir]   data.json·새 사진 암호화해 넣기
  pages    --settings s.json --repo repo [--app app.html] [--page 이름=경로 ...]   화면 파일 암호화해 넣기
  keyfile  --settings s.json --repo repo          k.json 만들기(처음 한 번; 있으면 그대로)
  push     --settings s.json --repo repo --msg 메시지     커밋하고 올리기
  cfg      --settings s.json --repo repo          바로 공유 설정(cfg.json.enc: 토큰·공유 키) 만들기/갱신
  syncinit --settings s.json                      원격에 'sync' 가지가 없으면 만들기
  syncclone --settings s.json --dir syncdir       'sync' 가지 받기(얕게)
  syncpull --settings s.json --repo repo --sync syncdir --data data.json --out appdl   앱에서 올린 사진 → ingest용 파일
  syncclean --settings s.json --repo repo --sync syncdir --data data.json           합쳐진 사진 파일을 sync 가지에서 지우기
  newsopen --settings s.json --repo repo --out news.json   아침 소식(news.json.enc) 풀기, 없으면 빈 틀
  newsseal --settings s.json --repo repo --news news.json [--today YYYY-MM-DD]   검사·정리 후 암호화(바뀐 점 요약 출력)
  newswants --settings s.json --repo repo --sync syncdir   두 사람이 '가고 싶어/같이 볼래' 누른 소식 목록
  freshopen --settings s.json --repo repo --out fresh.json   매주 새 소재(fresh.json.enc) 풀기, 없으면 빈 틀
  freshseal --settings s.json --repo repo --fresh fresh.json   검사 후 암호화
  libopen  --settings s.json --repo repo --out lib.json     매주 쌓이는 책(lib.json.enc) 풀기, 없으면 빈 틀
  balinseal --in balin.json                                v43.1 밸런스 「우리 분석」 해석문(balin.json.enc) — 매달 점검 때 Claude 가 다시 씀
  reportcontext/repseal                                    v43 우리 리포트(rep.json.enc) — 두 폰 rep 기록 → Claude 리포트(plancontext/planseal 과 같은 꼴, DIARY_PW)
  mvwopen/mvwseal                                          매주 영화책(mvw.json.enc) — libopen/libseal 과 같은 꼴(--base content/movies_base.json)
  libseal  --settings s.json --repo repo --in lib.json [--base content/books.json] [--sync syncdir]   검사·정리 후 암호화(ok·errors·counts)
  plcopen/plcseal  매주 장소(v22) plc.json — --base content/places.json (먹을 곳·잘 곳 새 곳·재확인·순서표·출처 장부)
  worldopen --settings s.json --repo repo --out world.json  매주 쌓이는 해외여행(world.json.enc) 풀기, 없으면 빈 틀
  worldseal --settings s.json --repo repo --in world.json [--base content/trips.json] [--sync syncdir]  검사·정리 후 암호화
  packsrc  --settings s.json --repo repo --src 폴더           앱 소스(빌드 전 파일) 묶음을 암호화해 dev/src.tgz.enc로
  unpacksrc --settings s.json --repo repo --out 폴더          dev/src.tgz.enc 풀기
  fcv      --repo repo --sync syncdir --out fcv.json [--who j|h|both]   v62 미래 자금 「저장」 값(k 'fcv') + 계획 값 → 분석용(값은 파일에만)
"""
import argparse, base64, glob, hashlib, hmac, json, os, re, subprocess, sys, unicodedata

ITER = 600000
REPO = 'diary'
DEFAULT_USER = 'diorio516-byte'


def die(msg):
    print(json.dumps({'error': msg}, ensure_ascii=False)); sys.exit(1)


def load_settings(p):
    # v41.1: 설정 파일 없이 환경 변수 DIARY_PW 만으로(--settings env 또는 생략) — 비밀번호를 파일로 쓰지 않음
    if not p or p == 'env':
        pw = os.environ.get('DIARY_PW', '')
        if not pw:
            die('환경 변수 DIARY_PW 없음')
        return {'user': 'diorio516-byte', 'token': os.environ.get('GH_TOKEN', '-'), 'pw': pw}
    with open(p, encoding='utf-8') as f:
        s = json.load(f)
    for k in ('user', 'token', 'pw'):
        if not s.get(k):
            die(f'설정에 {k} 없음')
    return s


# ---------- 설정 문서 ----------
def unescape_md(v):
    return re.sub(r'\\([\\`*_{}\[\]()#+\-.!|~<>])', r'\1', v)


def cmd_settings(a):
    txt = open(a.doc, encoding='utf-8').read()
    try:  # read_file_content 결과(JSON) 그대로 저장한 경우
        j = json.loads(txt)
        if isinstance(j, dict) and 'fileContent' in j:
            txt = j['fileContent']
    except Exception:
        pass
    out = {}
    for line in txt.splitlines():
        line = unescape_md(line.strip())
        m = re.match(r'^(GitHub\s*아이디|토큰\s*만료|토큰|둘만의\s*비밀번호|이전\s*비밀번호)\s*[:：]\s*(.*)$', line)
        if not m:
            continue
        g = m.group(1)
        key = 'token_exp' if g.startswith('토큰') and '만료' in g else {'G': 'user', '토': 'token', '둘': 'pw', '이': 'old_pw'}[g[0]]
        val = m.group(2).strip()
        if key in ('user', 'token'):
            val = val.replace(' ', '')
        if key == 'token_exp':
            mm = re.search(r'(20\d{2})[-./년\s]+(\d{1,2})[-./월\s]+(\d{1,2})', val)
            val = f'{mm.group(1)}-{int(mm.group(2)):02d}-{int(mm.group(3)):02d}' if mm else ''
        if val:
            out[key] = val
    out['user'] = (out.get('user') or DEFAULT_USER).lower()
    out['repo'] = REPO
    missing = [k for k in ('user', 'token', 'pw') if not out.get(k)]
    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False)
    os.chmod(a.out, 0o600)
    print(json.dumps({'user': out['user'], 'token': bool(out.get('token')), 'tokenPrefix': (out.get('token') or '')[:11],
                      'pwLen': len(out.get('pw') or ''), 'missing': missing}, ensure_ascii=False))
    if missing:
        sys.exit(1)


# ---------- 암호 ----------
def derive(pw, salt, it=ITER):
    dk = hashlib.pbkdf2_hmac('sha256', unicodedata.normalize('NFC', pw).encode('utf-8'), salt, it, 64)
    return dk[:32], dk[32:]


def seal_bytes(aes, mac, data):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = hmac.new(mac, data, hashlib.sha256).digest()[:12]
    return iv + AESGCM(aes).encrypt(iv, data, None)


def open_bytes(aes, blob):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(aes).decrypt(blob[:12], blob[12:], None)


def try_keys(pw, k):
    aes, mac = derive(pw, base64.b64decode(k['salt']), k['iter'])
    try:
        return (aes, mac) if open_bytes(aes, base64.b64decode(k['check'])) == b'hj-diary-ok' else None
    except Exception:
        return None


def new_keyfile(pw):
    salt = os.urandom(16)
    aes, mac = derive(pw, salt)
    k = {'v': 1, 'iter': ITER, 'salt': base64.b64encode(salt).decode(), 'check': base64.b64encode(seal_bytes(aes, mac, b'hj-diary-ok')).decode()}
    return k, aes, mac


def keys_for(s, repo):
    kp = os.path.join(repo, 'k.json')
    if not os.path.exists(kp):
        die('k.json 없음(keyfile 먼저)')
    k = json.load(open(kp))
    got = try_keys(s['pw'], k)
    if got:
        return got
    old = try_keys(s['old_pw'], k) if s.get('old_pw') else None
    if not old:
        die('비밀번호가 k.json과 맞지 않음(설정 문서의 비밀번호를 바꿨다면 「이전 비밀번호:」 줄에 예전 것을 적어야 함)')
    k2, aes, mac = new_keyfile(s['pw'])
    n = 0
    for p in glob.glob(os.path.join(repo, '**', '*.enc'), recursive=True):
        with open(p, 'rb') as f:
            data = open_bytes(old[0], f.read())
        with open(p, 'wb') as f:
            f.write(seal_bytes(aes, mac, data))
        n += 1
    with open(kp, 'w') as f:
        json.dump(k2, f)
    print(json.dumps({'rekeyed': n, 'note': '새 비밀번호로 다시 잠금. 두 폰은 새 비밀번호를 한 번 넣어야 함'}, ensure_ascii=False))
    return aes, mac


def write_if_changed(path, data):
    if os.path.exists(path):
        with open(path, 'rb') as f:
            if f.read() == data:
                return False
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)
    return True


# ---------- git ----------
def git(repo, *args, s=None, check=True):
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0')
    if s:  # 처음 요청부터 토큰을 실어 보낸다(중간 프록시가 인증 요청 없이 막는 경우 대비). 명령줄에는 안 남김
        basic = base64.b64encode(('x-access-token:' + s['token']).encode()).decode()
        env.update({'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'http.https://github.com/.extraHeader',
                    'GIT_CONFIG_VALUE_0': 'Authorization: Basic ' + basic})
    r = subprocess.run(['git', *args], cwd=repo, env=env, capture_output=True, text=True)
    out = (r.stdout + r.stderr)
    if s:
        out = out.replace(s['token'], '***').replace(basic, '***')
    if check and r.returncode != 0:
        die('git ' + args[0] + ' 실패: ' + out.strip()[-400:])
    return out


def cmd_clone(a):
    s = load_settings(a.settings)
    url = a.url or f"https://github.com/{s['user']}/{s['repo']}.git"
    if os.path.exists(a.dir):
        die(f'{a.dir} 이미 있음')
    os.makedirs(a.dir)
    git(a.dir, 'init', '-q', '-b', 'main')
    git(a.dir, 'remote', 'add', 'origin', url)
    git(a.dir, 'fetch', '-q', '--depth', '1', 'origin', 'main', s=s)
    git(a.dir, 'checkout', '-q', '-B', 'main', 'FETCH_HEAD')
    git(a.dir, 'config', 'user.name', '우리 다이어리 밤 기록')
    git(a.dir, 'config', 'user.email', 'noreply@anthropic.com')
    print(json.dumps({'cloned': url, 'files': len(git(a.dir, 'ls-files').split())}, ensure_ascii=False))


def cmd_push(a):
    s = load_settings(a.settings)
    git(a.repo, 'add', '-A')
    st = git(a.repo, 'status', '--porcelain')
    if st.strip():
        git(a.repo, 'commit', '-q', '-m', a.msg)
    out = git(a.repo, 'push', 'origin', 'HEAD:main', s=s)
    print(json.dumps({'pushed': 'up-to-date' not in out, 'changed': len(st.strip().splitlines())}, ensure_ascii=False))


# ---------- 파일 ----------
def cmd_keyfile(a):
    s = load_settings(a.settings)
    kp = os.path.join(a.repo, 'k.json')
    if os.path.exists(kp):
        keys_for(s, a.repo)
        print(json.dumps({'keyfile': 'kept'})); return
    k, aes, mac = new_keyfile(s['pw'])
    with open(kp, 'w') as f:
        json.dump(k, f)
    print(json.dumps({'keyfile': 'new'}))


def cmd_open(a):
    s = load_settings(a.settings)
    aes, _ = keys_for(s, a.repo)
    with open(os.path.join(a.repo, 'data.json.enc'), 'rb') as f:
        data = open_bytes(aes, f.read())
    with open(a.out, 'wb') as f:
        f.write(data)
    d = json.loads(data)
    print(json.dumps({'opened': a.out, 'photos': len(d.get('photos', {})), 'days': len(d.get('days', {}))}, ensure_ascii=False))


def cmd_seal(a):
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    changed = []
    with open(a.data, 'rb') as f:
        raw = f.read()
    json.loads(raw)
    if write_if_changed(os.path.join(a.repo, 'data.json.enc'), seal_bytes(aes, mac, raw)):
        changed.append('data.json')
    for p in sorted(glob.glob(os.path.join(a.photos, '*.webp'))) if a.photos else []:
        name = os.path.basename(p)
        with open(p, 'rb') as f:
            b = f.read()
        if write_if_changed(os.path.join(a.repo, 'p', name + '.enc'), seal_bytes(aes, mac, b)):
            changed.append('p/' + name)
    print(json.dumps({'sealed': changed}, ensure_ascii=False))


def cmd_pages(a):
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    items = []
    if a.app:
        items.append(('app.html', a.app))
    for x in a.page or []:
        n, p = x.split('=', 1)
        items.append((n, p))
    changed = []
    for n, p in items:
        with open(p, 'rb') as f:
            b = f.read()
        if write_if_changed(os.path.join(a.repo, n + '.enc'), seal_bytes(aes, mac, b)):
            changed.append(n)
    print(json.dumps({'sealed': changed}, ensure_ascii=False))


# ---------- 바로 공유 ----------
def cfg_path(repo):
    return os.path.join(repo, 'cfg.json.enc')


def read_cfg(repo, aes):
    p = cfg_path(repo)
    if not os.path.exists(p):
        return None
    try:
        return json.loads(open_bytes(aes, open(p, 'rb').read()))
    except Exception:
        return None


def cmd_cfg(a):
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    old = read_cfg(a.repo, aes) or {}
    osync = old.get('sync') or {}
    key = osync.get('syncKey') or base64.b64encode(os.urandom(32)).decode()
    cfg = {'v': 1, 'sync': {'owner': s['user'], 'repo': s['repo'], 'branch': 'sync', 'token': s['token'], 'syncKey': key,
                            'tokenExp': s.get('token_exp') or osync.get('tokenExp') or ''}}
    if old.get('ntfy'):  # 알림 주제(ntfy)는 그대로 둔다
        cfg['ntfy'] = old['ntfy']
    raw = json.dumps(cfg, ensure_ascii=False, sort_keys=True).encode('utf-8')
    changed = write_if_changed(cfg_path(a.repo), seal_bytes(aes, mac, raw))
    print(json.dumps({'cfg': ('new' if not old else 'updated') if changed else 'same', 'tokenExp': cfg['sync']['tokenExp'],
                      'keyKept': bool(osync.get('syncKey'))}, ensure_ascii=False))


def cmd_notify(a):
    """두 폰(또는 한쪽)에 짧은 알림을 보낸다. 주제 이름은 cfg.json의 ntfy에서 읽는다. 내용은 짧게, 기록 본문은 넣지 않는다."""
    s = load_settings(a.settings)
    aes, _ = keys_for(s, a.repo)
    n = (read_cfg(a.repo, aes) or {}).get('ntfy') or {}
    if not (n.get('j') and n.get('h')):
        print(json.dumps({'sent': 0, 'note': '알림 주제가 아직 없음'}, ensure_ascii=False)); return
    import urllib.request
    who = ['j', 'h'] if a.to == 'both' else [a.to]
    sent = 0
    for w in who:
        body = json.dumps({'topic': n[w], 'title': a.title or '우리 다이어리', 'message': a.msg[:300], 'priority': 3, 'tags': ['sparkles']}, ensure_ascii=False).encode('utf-8')
        try:
            req = urllib.request.Request((n.get('server') or 'https://ntfy.sh').rstrip('/'), data=body, headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=20).read(); sent += 1
        except Exception as e:
            print(json.dumps({'warn': f'{w} 알림 실패: {type(e).__name__}'}, ensure_ascii=False))
    print(json.dumps({'sent': sent}, ensure_ascii=False))


# ---- 파이어 카드 (v35) — 항로도 DB card/current → fire.json.enc. 앱은 blocks 를 그리기만(읽기 전용, 두 폰 같은 화면) ----
FIRE_T = {'title', 'stat', 'text', 'bar', 'line', 'next', 'checklist', 'warn', 'calc', 'link'}   # v38: calc(숫자 바꿔 보기) · link(버튼)
FIRE_LINK = re.compile(r'^https://claude\.ai/artifact/[A-Za-z0-9_-]{6,64}(#[A-Za-z0-9_-]{1,30})?$')
FIRE_STATE = {'up', 'down', 'warn', 'start', 'none'}


def fire_check(f):
    """card/spec 그대로: 모르는 t 는 건너뛴다. 글 길이·개수 제한, 링크·태그 금지. (오류 목록, 다듬은 카드)"""
    errs = []
    if not isinstance(f, dict):
        return ['카드가 객체가 아님'], None
    f = f.get('data') if isinstance(f.get('data'), dict) and 'blocks' in f['data'] else f
    bad = re.compile(r'https?://|<\s*/?\s*[a-z]|javascript:', re.I)
    s_ = lambda v, n: v if isinstance(v, str) and len(v) <= n and not bad.search(v) else None
    num = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) < 1e7
    out = []
    for i, b in enumerate(f.get('blocks') if isinstance(f.get('blocks'), list) else []):
        w = f'blocks[{i}]'
        if not isinstance(b, dict) or b.get('t') not in FIRE_T:
            continue
        t = b['t']; nb = {'t': t}
        if t == 'title':
            nb['text'] = s_(b.get('text'), 40); nb['sub'] = s_(b.get('sub', ''), 60)
            if nb['text'] is None: errs.append(w + ': title.text 40자')
        elif t in ('text', 'warn'):
            nb['text'] = s_(b.get('text'), 200 if t == 'text' else 100)
            if not nb['text']: errs.append(w + f': {t}.text 글자 수')
        elif t == 'next':
            nb['label'] = s_(b.get('label', ''), 20); nb['text'] = s_(b.get('text'), 80)
            if not nb['text']: errs.append(w + ': next.text 80자')
        elif t == 'stat':
            its = b.get('items') if isinstance(b.get('items'), list) else []
            nb['items'] = [{'k': s_(x.get('k'), 20) or '', 'v': s_(str(x.get('v', '')), 20) or '', 's': s_(x.get('s', '') or '', 50) or '',
                            'state': x.get('state') if x.get('state') in FIRE_STATE else 'none'} for x in its[:4] if isinstance(x, dict)]
            if not nb['items']: errs.append(w + ': stat.items 1~4개')
        elif t == 'bar':
            its = b.get('items') if isinstance(b.get('items'), list) else []
            nb['items'] = [{'k': s_(x.get('k'), 20) or '', 'v': x['v']} for x in its[:8] if isinstance(x, dict) and num(x.get('v'))]
            nb['unit'] = s_(b.get('unit', ''), 6) or ''
            if not nb['items']: errs.append(w + ': bar.items 숫자 v')
        elif t == 'checklist':
            its = b.get('items') if isinstance(b.get('items'), list) else []
            nb['label'] = s_(b.get('label', ''), 20) or ''
            nb['items'] = [{'text': s_(x.get('text'), 80) or '', 'done': bool(x.get('done'))} for x in its[:8] if isinstance(x, dict) and s_(x.get('text'), 80)]
            if not nb['items']: errs.append(w + ': checklist.items 1~8개')
        elif t == 'line':
            ser = []
            for x in (b.get('series') if isinstance(b.get('series'), list) else [])[:4]:
                pts = [[p[0], p[1]] for p in (x.get('points') or [])[:400] if isinstance(p, list) and len(p) == 2 and num(p[0]) and num(p[1])] if isinstance(x, dict) else []
                if pts: ser.append({'name': s_(x.get('name', ''), 20) or '', 'key': s_(x.get('key', ''), 12) or '', 'points': pts})
            nb['series'] = ser; nb['unit'] = s_(b.get('unit', ''), 6) or ''
            nb['marks'] = [[m[0], s_(str(m[1]), 12) or ''] for m in (b.get('marks') or [])[:6] if isinstance(m, list) and len(m) == 2 and num(m[0])]
            if not ser: errs.append(w + ': line.series 점 있는 선 1~4개')
        elif t == 'calc':   # v38 숫자 바꿔 보기 — 계획 값은 따로(plan), 앱에서 움직인 값은 저장 안 함
            nb['label'] = s_(b.get('label', '') or '', 20) or ''
            nb['save'] = False
        elif t == 'link':   # v38 버튼 — claude.ai 아티팩트 링크만
            its = b.get('items') if isinstance(b.get('items'), list) else []
            nb['items'] = [{'label': s_(x.get('label'), 12), 'url': x['url']} for x in its[:3]
                           if isinstance(x, dict) and s_(x.get('label'), 12) and isinstance(x.get('url'), str) and FIRE_LINK.match(x['url'])]
            if not nb['items']: errs.append(w + ': link.items 1~3개(claude.ai 아티팩트 주소만)')
        out.append({k: v for k, v in nb.items() if v is not None})
    if not 1 <= len(out) <= 30:
        errs.append('그릴 블록 1~30개')
    return errs, {'v': 1, 'updated': s_(str(f.get('updated', '')), 20) or '', 'source': s_(f.get('source', '') or '', 60) or '', 'blocks': out}


def fire_plan_clean(v, depth=0):
    """기준서 DB plan/current 의 values — 숫자·짧은 글·참거짓·작은 목록/객체만 남긴다(태그·링크 금지). 이상하면 None."""
    bad = re.compile(r'https?://|<\s*/?\s*[a-z]|javascript:', re.I)
    if depth > 4: return None
    if isinstance(v, bool): return v
    if isinstance(v, (int, float)): return v if v == v and abs(v) < 1e9 else None
    if isinstance(v, str): return v if len(v) <= 40 and not bad.search(v) else None
    if isinstance(v, list):
        out = [fire_plan_clean(x, depth + 1) for x in v[:30]]
        return out if all(x is not None for x in out) else None
    if isinstance(v, dict):
        out = {}
        for k, x in list(v.items())[:40]:
            if not (isinstance(k, str) and re.match(r'^[A-Za-z][A-Za-z0-9_]{0,23}$', k)): return None
            c = fire_plan_clean(x, depth + 1)
            if c is None: return None
            out[k] = c
        return out
    return None


def fire_plan_read(path):
    """ArtifactData get plan/current 저장 파일 → {'values', 'updated'} 또는 None"""
    try:
        j = json.load(open(path, encoding='utf-8'))
    except Exception:
        return None
    d = j.get('data') if isinstance(j, dict) and isinstance(j.get('data'), dict) else j
    vals = fire_plan_clean(d.get('values')) if isinstance(d, dict) else None
    if not isinstance(vals, dict) or not vals: return None
    up = d.get('updated') if isinstance(d.get('updated'), str) and len(d['updated']) <= 20 else ''
    return {'values': vals, 'updated': up}


def cmd_fireseal(a):
    """밤 기록이 ArtifactData get card/current 결과를 --in 으로 준다. 못 읽었으면(파일 없음·형식 오류) 지난 fire.json 을 그대로 둔다."""
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    try:
        f = json.load(open(getattr(a, 'in'), encoding='utf-8'))
    except Exception as e:
        print(json.dumps({'ok': False, 'errors': [f'읽기 실패 {type(e).__name__} — 지난 카드 유지']}, ensure_ascii=False)); return
    errs, card = fire_check(f)
    if errs:
        print(json.dumps({'ok': False, 'errors': errs[:20], 'note': '지난 카드 유지'}, ensure_ascii=False)); return
    p = os.path.join(a.repo, 'fire.json.enc')
    old = None
    if os.path.exists(p):
        try: old = json.loads(open_bytes(aes, open(p, 'rb').read()))
        except Exception: old = None
    # v38 계획 값(기준서 DB plan/current) — 못 읽으면 지난 값 유지, 그것도 없으면 앱이 모델 기본값을 씀
    plan = fire_plan_read(a.plan) if getattr(a, 'plan', None) else None
    plan_note = 'new' if plan else ('kept' if (old or {}).get('plan') else 'none')
    if not plan and isinstance((old or {}).get('plan'), dict): plan = old['plan']
    if plan: card['plan'] = plan
    if old == card:
        print(json.dumps({'ok': True, 'changed': False, 'notify': False, 'plan': plan_note}, ensure_ascii=False)); return
    raw = json.dumps(card, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(raw) > 256 * 1024:
        print(json.dumps({'ok': False, 'errors': ['256KB 넘음 — 지난 카드 유지']}, ensure_ascii=False)); return
    write_if_changed(p, seal_bytes(aes, mac, raw))
    print(json.dumps({'ok': True, 'changed': True, 'notify': bool(old) and (old or {}).get('updated') != card['updated'], 'blocks': [b['t'] for b in card['blocks']], 'updated': card['updated'], 'plan': plan_note}, ensure_ascii=False))


# ---- 우리 집 (Cowork '신축 반전세 스코어보드' 아티팩트 → home.json.enc) ----
HOME_FINAL = ['S클래스더제니스', '더샵염주센트럴파크', '힐스테이트월산', '무등산자이앤어울림(1단지)', '계림아이파크SK뷰']
HOME_RESERVE = ['힐스테이트신용더리버']
HOME_PRESETS = {'equal': None,
                'commute': {'price': 12, 'age': 8, 'brand': 8, 'scale': 6, 'commute': 30, 'ktx': 8, 'subway': 6, 'mart': 8, 'parking': 6, 'stability': 8},
                'value': {'price': 30, 'age': 8, 'brand': 8, 'scale': 8, 'commute': 10, 'ktx': 6, 'subway': 6, 'mart': 8, 'parking': 6, 'stability': 10},
                'product': {'price': 8, 'age': 20, 'brand': 20, 'scale': 18, 'commute': 8, 'ktx': 4, 'subway': 4, 'mart': 6, 'parking': 8, 'stability': 4},
                'life': {'price': 8, 'age': 6, 'brand': 6, 'scale': 6, 'commute': 12, 'ktx': 16, 'subway': 18, 'mart': 18, 'parking': 6, 'stability': 4}}
HOME_TOL = 0.10   # KB 와 실거래가 10% 안이면 일치
HOME_AB = {'S클래스더제니스': 'S클', '더샵염주센트럴파크': '염주', '힐스테이트월산': '월산', '무등산자이앤어울림1단지': '무등', '계림아이파크SK뷰': '계림', '힐스테이트신용더리버': '신용'}


def _hkey(n):
    return re.sub(r'[\s()·]', '', str(n or ''))


def home_verify(r):
    """검증 표시: ok(실거래·KB 일치) · warn(불일치) · one(단일 출처). 월세(보증금 5천 기준)와 전세를 비교."""
    rep = r.get('rep') or {}; a = r.get('act') or {}
    kb = bool(rep.get('kb'))
    deals = (a.get('n_wolse') or 0) >= 2 and a.get('r5') is not None
    if not kb or not deals:
        return {'s': 'one', 'by': 'KB' if kb else ('실거래' if deals else '추정'),
                't': ('KB 시세만 있어요' if kb else (f"실거래 {a.get('n_wolse') or 0}건만 있어요(KB 시세 없음)" if a.get('n_wolse') else '매물 호가로 추정했어요'))}
    pairs = []
    kr = r.get('e5') if r.get('e5') is not None else rep.get('kbr')
    if kr: pairs.append(('월세', kr, a['r5'], '만'))
    if rep.get('jeonse_mid') and a.get('jeonse'): pairs.append(('전세', rep['jeonse_mid'], a['jeonse'], ''))
    worst = 0.0; parts = []
    for nm, k, x, u in pairs:
        d = (x - k) / k
        worst = max(worst, abs(d))
        fm = (lambda v: f'{v}만') if u else (lambda v: (f'{v // 10000}억 {v % 10000:,}' if v % 10000 else f'{v // 10000}억') if v >= 10000 else f'{v:,}만')
        parts.append(f"{nm} KB {fm(k)} · 실거래 {fm(x)} ({'+' if d >= 0 else ''}{round(d * 100)}%)")
    return {'s': 'ok' if worst <= HOME_TOL else 'warn', 'gap': round(worst * 100), 't': ' / '.join(parts)}


def home_build(d, final=None, reserve=None):
    keys = d['keys']
    pre = {k: (v or {x: 10 for x in keys}) for k, v in HOME_PRESETS.items()}
    final = d.get('final') or final or HOME_FINAL
    reserve = d.get('reserve') or reserve or HOME_RESERVE
    anchors = d.get('anchors') or []
    rows = []
    for r in d['rows']:
        a = r.get('act') or {}; rep = r.get('rep') or {}
        cma = r.get('cmA') or []
        o = {'id': r['id'], 'n': r['name'], 'z': r['zone'], 'rg': r['region'], 'dong': r.get('dong') or '',
             'addr': (r.get('addr') or '').replace('전남광주통합특별시', '광주'), 'lat': r.get('lat'), 'lng': r.get('lng'),
             'mv': r.get('movein') or '', 'hh': r.get('hh'), 'fl': r.get('fl'), 'brand': r.get('brand') or '',
             'bld': (r.get('builder') or '').split(',')[0].replace('(주)', '').replace('주식회사', '').strip(),
             'tier': r.get('tier'), 'park': r.get('park'), 'heat': r.get('heat') or '', 'jeonse': r.get('jeonse'),
             'r5': r.get('e5') if r.get('e5') is not None else r.get('r5'), 'r10': r.get('e10') if r.get('e10') is not None else r.get('r10'),
             'psrc': r.get('psrc') or '', 'src': r.get('src') or '', 'cm': r.get('cm'),
             'ktx': r.get('ktx') or '', 'ktxm': r.get('ktxm'), 'sub': r.get('sub') or '', 'subk': r.get('subk'),
             'mart': r.get('mart') or '', 'martk': r.get('martk'), 'naver': r.get('naver'), 'sp': rep.get('sp'), 'rooms': rep.get('rooms'), 'baths': rep.get('baths'),
             's': r['s'], 'g': r['g'], 'rank': r.get('rank'), 'total': r.get('total'), 'jr': r.get('jr'),
             'types': [{'nm': t.get('nm') or '', 'sp': t.get('sp'), 'hh': t.get('hh'), 'r5': t.get('r5'), 'r10': t.get('r10')} for t in (r.get('types') or [])[:4]],
             'act': {'n': a.get('n_wolse') or 0, 'r5': a.get('r5'), 'jeonse': a.get('jeonse'),
                     'recent': [[x.get('d'), x.get('ar'), x.get('fl'), x.get('dep'), x.get('rent')] for x in (a.get('recent') or [])[:5]]},
             'vf': home_verify(r)}
        if anchors and len(cma) == len(anchors) and len(set(cma)) > 1:
            o['cmA'] = [round(x, 1) if isinstance(x, (int, float)) else None for x in cma]
        rows.append(o)
    by = {_hkey(o['n']): o for o in rows}
    pick = []
    for i, n in enumerate(list(final) + list(reserve)):
        o = by.get(_hkey(n))
        if not o: continue
        o['pick'] = 'final' if i < len(final) else 'reserve'
        o['ab'] = HOME_AB.get(_hkey(o['n'])) or re.sub(r'^(힐스테이트|더샵|e편한세상|자이|아이파크|푸르지오|롯데캐슬|SK뷰)', '', o['n'])[:2] or o['n'][:2]
        pick.append(o['id'])
    ash = [re.sub(r'\s*\(동구 도심\)', '', x).replace('혁신도시(나주)', '(나주)') for x in anchors]
    return {'v': 2, 'generated': d.get('generated', ''), 'dest': d.get('dest', ''), 'anchors': anchors, 'ash': ash, 'keys': keys, 'labels': d['labels'], 'presets': pre,
            'pick': pick, 'tol': round(HOME_TOL * 100),
            'src': 'Cowork 신축 반전세 스코어보드 · KB부동산 단지·시세 · 국토부 전월세 실거래 · OSRM 자동차 소요시간(정체 미반영)',
            'rows': rows}


def home_src_from(path):
    """Artifact read 가 저장한 HTML(또는 <script id=data> 를 꺼낸 JSON) → 원본 dict"""
    raw = open(path, encoding='utf-8').read()
    if raw.lstrip().startswith('{'):
        return json.loads(raw)
    m = re.search(r'<script id="data" type="application/json">(.*?)</script>', raw, re.S)
    if not m:
        raise ValueError('스코어보드 자료(<script id="data">)를 못 찾음')
    return json.loads(m.group(1))


def home_check(h):
    errs = []
    if not isinstance(h.get('rows'), list) or len(h['rows']) < 20: errs.append('단지 수가 너무 적음')
    for k in ('keys', 'labels', 'presets'):
        if not h.get(k): errs.append(f'{k} 없음')
    for r in h.get('rows', [])[:400]:
        if not isinstance(r.get('id'), int) or not r.get('n') or not isinstance(r.get('s'), dict):
            errs.append(f"단지 형식 오류 {r.get('n')}"); break
    if len([i for i in h.get('pick', []) if i]) < 3: errs.append('최종 후보를 3곳도 못 찾음(이름이 바뀌었나?)')
    return errs


def cmd_homeseal(a):
    """밤 기록: Artifact read 로 받은 스코어보드 HTML 을 --in 으로. 못 읽거나 이상하면 지난 home.json.enc 그대로."""
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    try:
        h = home_build(home_src_from(getattr(a, 'in')))
    except Exception as e:
        print(json.dumps({'ok': False, 'errors': [f'읽기 실패 {type(e).__name__}: {str(e)[:80]} — 지난 우리 집 유지']}, ensure_ascii=False)); return
    errs = home_check(h)
    if errs:
        print(json.dumps({'ok': False, 'errors': errs, 'note': '지난 우리 집 유지'}, ensure_ascii=False)); return
    p = os.path.join(a.repo, 'home.json.enc')
    old = None
    if os.path.exists(p):
        try: old = json.loads(open_bytes(aes, open(p, 'rb').read()))
        except Exception: old = None
    pk = [next(r['n'] for r in h['rows'] if r['id'] == i) for i in h['pick']]
    vf = {r['n']: r['vf']['s'] for r in h['rows'] if r.get('pick')}
    if old == h:
        print(json.dumps({'ok': True, 'changed': False, 'rows': len(h['rows'])}, ensure_ascii=False)); return
    raw = json.dumps(h, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(raw) > 2 * 1024 * 1024:
        print(json.dumps({'ok': False, 'errors': ['2MB 넘음 — 지난 우리 집 유지']}, ensure_ascii=False)); return
    write_if_changed(p, seal_bytes(aes, mac, raw))
    print(json.dumps({'ok': True, 'changed': True, 'rows': len(h['rows']), 'generated': h['generated'], 'pick': pk, 'verify': vf,
                      'was': (old or {}).get('generated')}, ensure_ascii=False))


def remote_url(s):
    return f"https://github.com/{s['user']}/{s.get('repo') or REPO}.git"   # v62 --settings env 엔 repo 가 없음


def cmd_syncinit(a):
    s = load_settings(a.settings)
    import tempfile
    d = tempfile.mkdtemp(prefix='hjsync-')
    git(d, 'init', '-q', '-b', 'sync')
    git(d, 'remote', 'add', 'origin', remote_url(s))
    out = git(d, 'ls-remote', '--heads', 'origin', 'sync', s=s)
    if 'refs/heads/sync' in out:
        print(json.dumps({'sync': 'exists'})); return
    with open(os.path.join(d, 'README.md'), 'w', encoding='utf-8') as f:
        f.write('# 바로 공유\n\n두 폰이 암호를 걸어 올리는 기록이에요. 사람이 고치지 않아요.\n')
    git(d, 'config', 'user.name', '우리 다이어리 밤 기록')
    git(d, 'config', 'user.email', 'noreply@anthropic.com')
    git(d, 'add', '-A')
    git(d, 'commit', '-q', '-m', '바로 공유 시작')
    git(d, 'push', 'origin', 'HEAD:sync', s=s)
    print(json.dumps({'sync': 'created'}))


def cmd_syncclone(a):
    s = load_settings(a.settings)
    if os.path.exists(a.dir):
        die(f'{a.dir} 이미 있음')
    os.makedirs(a.dir)
    git(a.dir, 'init', '-q', '-b', 'sync')
    git(a.dir, 'remote', 'add', 'origin', remote_url(s))
    git(a.dir, 'fetch', '-q', '--depth', '1', 'origin', 'sync', s=s)
    git(a.dir, 'checkout', '-q', '-B', 'sync', 'FETCH_HEAD')
    git(a.dir, 'config', 'user.name', '우리 다이어리 밤 기록')
    git(a.dir, 'config', 'user.email', 'noreply@anthropic.com')
    n = len(glob.glob(os.path.join(a.dir, 'sync', '**', '*.enc'), recursive=True))
    print(json.dumps({'cloned': 'sync', 'files': n}, ensure_ascii=False))


def sync_key(s, repo):
    aes, _ = keys_for(s, repo)
    cfg = read_cfg(repo, aes)
    if not cfg:
        die('cfg.json.enc 없음(cfg 먼저)')
    return base64.b64decode(cfg['sync']['syncKey'])


def sync_open(key, blob):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


def sync_records(key, syncdir):
    recs = {}
    bad = []
    for p in sorted(glob.glob(os.path.join(syncdir, 'sync', '[jh]', '*.enc'))):
        if os.path.basename(p).startswith('me-'):
            continue  # 나만 보기 기록은 열지 않는다
        try:
            obj = json.loads(sync_open(key, open(p, 'rb').read()))
        except Exception:
            bad.append(os.path.relpath(p, syncdir)); continue
        for rid, r in (obj.get('recs') or {}).items():
            if not isinstance(r, dict):
                continue
            cur = recs.get(rid)
            if not cur or (r.get('t') or 0) > (cur.get('t') or 0):
                recs[rid] = r
    return recs, bad


def cmd_syncpull(a):
    s = load_settings(a.settings)
    key = sync_key(s, a.repo)
    data = json.load(open(a.data, encoding='utf-8')) if a.data else {}
    merged = data.get('merged') or {}
    recs, bad = sync_records(key, a.sync)
    os.makedirs(a.out, exist_ok=True)
    files, missing = [], []
    for rid, r in sorted(recs.items()):
        if r.get('k') != 'photo' or r.get('del') or rid in merged:
            continue
        fp = os.path.join(a.sync, r.get('f') or '')
        if not r.get('f') or not os.path.exists(fp):
            missing.append(rid); continue
        try:
            raw = sync_open(key, open(fp, 'rb').read())
        except Exception:
            bad.append(r.get('f')); continue
        d = r.get('d') if re.match(r'^20\d{2}-\d{2}-\d{2}$', str(r.get('d'))) else None
        if not d:
            missing.append(rid); continue
        o = {'id': 'app:' + rid, 'title': f'app-{rid}.jpg', 'content': base64.b64encode(raw).decode(),
             'app': {'rec': rid, 'who': r.get('w'), 'd': d, 't': r.get('tm') or '', 'cap': (r.get('cap') or '')[:60]}}
        out = os.path.join(a.out, f'app-{len(files) + 1:03d}.json')
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(o, f, ensure_ascii=False)
        files.append(out)
    kinds = {}
    for r in recs.values():
        if not r.get('del'):
            k = f"{r.get('w')}:{r.get('k')}"
            kinds[k] = kinds.get(k, 0) + 1
    # 연필 초안 참고용: 최근 이틀 두 사람이 남긴 한 줄·간 곳·먹은 것
    today = now_kst_date()
    recent = []
    for r in recs.values():
        if r.get('del') or r.get('p') or r.get('k') not in ('note', 'place', 'food', 'thx', 'dlog'):
            continue
        if str(r.get('d') or r.get('dd') or '') >= (today - __import__('datetime').timedelta(days=2)).isoformat():
            recent.append({'k': r['k'], 'w': r.get('w'), 'd': r.get('d') or r.get('dd'), 's': (r.get('s') or r.get('n') or r.get('ref') or '')[:80]})
    print(json.dumps({'appPhotos': len(files), 'files': files, 'missing': missing, 'badFiles': bad, 'records': kinds,
                      'recent': recent[:40]}, ensure_ascii=False, indent=1))


def cmd_fcv(a):
    """v62 미래 자금 계산기 「저장」 값: 폰이 남긴 기록 k 'fcv' {d, v:{t, vals:{칸 id: 값}, n}}(하루 한 장) → 사람마다 가장 새것 + 날마다 흐름,
    그리고 앱이 「계획 값」으로 쓰는 fire.json plan 을 같이 --out 에. 화면엔 날짜·칸 수만(값은 파일에만). 기본은 재준(j) 것만."""
    import datetime as _dt
    s = load_settings(a.settings)
    aes, _ = keys_for(s, a.repo)
    key = sync_key(s, a.repo)
    recs, bad = sync_records(key, a.sync)
    who = {}
    for r in recs.values():
        if not isinstance(r, dict) or r.get('del') or r.get('k') != 'fcv' or r.get('w') not in ('j', 'h'):
            continue
        if a.who != 'both' and r['w'] != a.who:
            continue
        v = r.get('v') if isinstance(r.get('v'), dict) else {}
        vals = v.get('vals')
        if not isinstance(vals, dict):
            continue
        who.setdefault(r['w'], []).append({'d': str(r.get('d') or ''), 't': int(v.get('t') or 0), 'n': len(vals), 'vals': vals})
    out = {'who': {}, 'badFiles': bad}
    for w, L in who.items():
        L.sort(key=lambda x: x['t'])
        out['who'][w] = {'latest': L[-1], 'history': L}
    plan = None
    p = os.path.join(a.repo, 'fire.json.enc')
    if os.path.exists(p):
        try: plan = (json.loads(open_bytes(aes, open(p, 'rb').read())) or {}).get('plan')
        except Exception: plan = None
    out['plan'] = plan
    json.dump(out, open(a.out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    kst = _dt.timezone(_dt.timedelta(hours=9))
    when = lambda t: _dt.datetime.fromtimestamp(t / 1000, kst).strftime('%m/%d %H:%M') if t else ''
    print(json.dumps({'ok': True, 'out': a.out, 'plan': bool(plan), 'badFiles': len(bad),
                      'who': {w: {'saved': when(x['latest']['t']), 'n': x['latest']['n'], 'days': [h['d'] for h in x['history']]} for w, x in out['who'].items()}}, ensure_ascii=False))


def now_kst_date():
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone(_dt.timedelta(hours=9))).date()


def cmd_syncclean(a):
    s = load_settings(a.settings)
    key = sync_key(s, a.repo)
    data = json.load(open(a.data, encoding='utf-8'))
    merged = data.get('merged') or {}
    recs, _ = sync_records(key, a.sync)
    gone = []
    for rid, r in recs.items():
        if r.get('k') == 'photo' and rid in merged and r.get('f'):
            fp = os.path.join(a.sync, r['f'])
            if os.path.exists(fp):
                git(a.sync, 'rm', '-q', r['f'])
                gone.append(r['f'])
    if not gone:
        print(json.dumps({'cleaned': 0})); return
    git(a.sync, 'commit', '-q', '-m', f'합친 사진 {len(gone)}장 정리')
    for i in range(3):
        r = subprocess.run(['git', 'push', 'origin', 'HEAD:sync'], cwd=a.sync, capture_output=True, text=True,
                           env=dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_CONFIG_COUNT='1',
                                    GIT_CONFIG_KEY_0='http.https://github.com/.extraHeader',
                                    GIT_CONFIG_VALUE_0='Authorization: Basic ' + base64.b64encode(('x-access-token:' + s['token']).encode()).decode()))
        if r.returncode == 0:
            print(json.dumps({'cleaned': len(gone)})); return
        git(a.sync, 'pull', '-q', '--rebase', 'origin', 'sync', s=s)
    die('sync 가지에 올리지 못함(나중에 다시)')


def cmd_packsrc(a):
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    import tarfile, io, gzip
    buf = io.BytesIO()
    # 같은 소스면 같은 묶음이 나오게(순서 고정, gzip 시각 0) — 바뀐 게 없으면 커밋도 없음
    with gzip.GzipFile(fileobj=buf, mode='wb', mtime=0) as gz, tarfile.open(fileobj=gz, mode='w') as t:
        for root, dirs, files in os.walk(a.src):
            dirs[:] = sorted(d for d in dirs if d not in ('node_modules', 'shots', '__pycache__', 'www', 'nightly', 'prodtest'))
            for f in sorted(files):
                p = os.path.join(root, f)
                if os.path.getsize(p) > 5 * 1024 * 1024 or f.endswith(('.jpg', '.png')):
                    continue
                t.add(p, arcname=os.path.relpath(p, a.src))
    raw = buf.getvalue()
    ch = write_if_changed(os.path.join(a.repo, 'dev', 'src.tgz.enc'), seal_bytes(aes, mac, raw))
    print(json.dumps({'packed': len(raw), 'changed': ch}))


def cmd_unpacksrc(a):
    s = load_settings(a.settings)
    aes, _ = keys_for(s, a.repo)
    import tarfile, io
    raw = open_bytes(aes, open(os.path.join(a.repo, 'dev', 'src.tgz.enc'), 'rb').read())
    os.makedirs(a.out, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as t:
        t.extractall(a.out, filter='data')
    print(json.dumps({'unpacked': a.out}))


# ---------- 아침 소식(공연·경기) ----------
NEWS_CAT = ('내한', '국내', '충청', '호남', '축제', '야구', '축구')
NEWS_ST = ('sold', 'on', 'soon', 'tba', 'free', 'cancel', 'done')
NEWS_FOLLOW = ('KIA', '롯데', '가을야구', '야구대표', '축구대표', '광주FC', '부산아이파크', '해외파')
NEWS_LIM = {'t': 60, 'lb': 8, 'v': 40, 'city': 12, 'note': 80, 'pre': 60, 'tk': 30, 'tv': 30, 'lg': 16, 'home': 20, 'away': 20, 'win': 20}


def _kst_today():
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone(_dt.timedelta(hours=9))).date().isoformat()


ECON_TAG = ('증시', '산업', '기업', '정책', '부동산', '글로벌', '생활', '금융')
ECON_KEEP = 30


def _dok(v):
    import datetime as _dt
    try:
        _dt.date.fromisoformat(v); return bool(re.match(r'^20\d{2}-\d{2}-\d{2}$', v))
    except Exception:
        return False


def econ_check(e, today):
    """오늘의 경제: {"days":[{"d","src","vid","mkd","mk":[{"n","v","c"}],"one","items":[{"t","s","url","tag"}]}]}"""
    import datetime as _dt
    if e is None:
        return None, []
    if not isinstance(e, dict) or not isinstance(e.get('days'), list):
        return None, ['econ 형식이 {"days":[...]}가 아님']
    errs, byd = [], {}
    cut = (_dt.date.fromisoformat(today) - _dt.timedelta(days=ECON_KEEP)).isoformat()
    for i, x in enumerate(e['days']):
        w = f"econ.days[{i}] {x.get('d') if isinstance(x, dict) else ''}"
        if not isinstance(x, dict):
            errs.append(w + ': 객체가 아님'); continue
        d = str(x.get('d', ''))
        if not _dok(d):
            errs.append(w + ': d 날짜'); continue
        if d > today:
            errs.append(w + ': 앞으로 올 날짜'); continue
        if d < cut:
            continue              # 30일 지난 건 정리
        if d in byd:
            errs.append(w + ': 같은 날짜가 두 번'); continue
        o = {'d': d}
        for k, lim in (('src', 40), ('one', 140)):
            v = x.get(k) or ''
            if not isinstance(v, str) or len(v) > lim:
                errs.append(w + f': {k} {lim}자 이내'); break
            if v.strip():
                o[k] = v.strip()
        else:
            vid = x.get('vid') or ''
            if vid and not str(vid).startswith('https://'):
                errs.append(w + ': vid는 https'); continue
            if vid:
                o['vid'] = vid
            mkd = x.get('mkd') or ''
            if mkd and (not _dok(str(mkd)) or mkd > d):
                errs.append(w + ': mkd 날짜'); continue
            if mkd:
                o['mkd'] = mkd
            mk = x.get('mk') or []
            if not isinstance(mk, list) or len(mk) > 6:
                errs.append(w + ': mk는 6칸 이하 목록'); continue
            mko, bad = [], False
            for m in mk:
                if not isinstance(m, dict) or not m.get('n') or not m.get('v') or len(str(m['n'])) > 10 or len(str(m['v'])) > 16 or len(str(m.get('c') or '')) > 12:
                    bad = True; break
                if m.get('c') and not re.match(r'^[+\-−▲▼]?\s?[\d.,]+\s?(%|원|p|bp)?$', str(m['c'])):
                    bad = True; break
                mko.append({k: str(m[k]) for k in ('n', 'v', 'c') if m.get(k)})
            if bad:
                errs.append(w + ': mk 칸 형식({"n":"코스피","v":"7,080.92","c":"+0.90%"})'); continue
            if mko:
                o['mk'] = mko
            its = x.get('items')
            if not isinstance(its, list) or not (1 <= len(its) <= 12):
                errs.append(w + ': items는 1~12개'); continue
            io, urls, bad = [], set(), ''
            for j, it in enumerate(its):
                if not isinstance(it, dict) or not isinstance(it.get('t'), str) or not it['t'].strip():
                    bad = f'items[{j}] 제목 없음'; break
                if len(it['t']) > 90 or len(str(it.get('s') or '')) > 160:
                    bad = f'items[{j}] 너무 긺(제목 90·요약 160)'; break
                u = str(it.get('url') or '')
                if not u.startswith('https://'):
                    bad = f'items[{j}] url은 https'; break
                if u in urls:
                    bad = f'items[{j}] url 겹침'; break
                urls.add(u)
                tg = it.get('tag') or ''
                if tg and tg not in ECON_TAG:
                    bad = f'items[{j}] tag는 ' + '|'.join(ECON_TAG); break
                q = {'t': it['t'].strip(), 'url': u}
                if (it.get('s') or '').strip():
                    q['s'] = it['s'].strip()
                if tg:
                    q['tag'] = tg
                io.append(q)
            if bad:
                errs.append(w + ': ' + bad); continue
            o['items'] = io
            byd[d] = o
    days = sorted(byd.values(), key=lambda x: x['d'], reverse=True)
    return ({'days': days} if days else None), errs


def news_check(n, today):
    import datetime as _dt
    errs = []
    if not isinstance(n, dict) or n.get('v') != 1 or not isinstance(n.get('items'), list):
        return None, ['맨 위 형식이 {"v":1,"items":[...]}가 아님']
    fol = n.get('follow') or list(NEWS_FOLLOW)
    if not isinstance(fol, list) or any(f not in NEWS_FOLLOW for f in fol):
        errs.append('follow 값이 이상함: ' + json.dumps(fol, ensure_ascii=False))
    ymd = re.compile(r'^20\d{2}-\d{2}-\d{2}$')
    def dok(v):
        try:
            _dt.date.fromisoformat(v); return bool(ymd.match(v))
        except Exception:
            return False
    keep, seen = {}, set()
    cut = (_dt.date.fromisoformat(today) - _dt.timedelta(days=45)).isoformat()
    for i, x in enumerate(n['items']):
        w = f"items[{i}] {x.get('id') if isinstance(x, dict) else ''}"
        if not isinstance(x, dict):
            errs.append(w + ': 객체가 아님'); continue
        if not re.match(r'^[a-z0-9-]{3,60}$', str(x.get('id', ''))):
            errs.append(w + ': id 형식'); continue
        if x.get('cat') not in NEWS_CAT:
            errs.append(w + ': cat'); continue
        if not isinstance(x.get('t'), str) or not x['t'].strip():
            errs.append(w + ': t 없음'); continue
        if not dok(str(x.get('s', ''))):
            errs.append(w + ': s 날짜'); continue
        if not x.get('e'):
            x['e'] = x['s']
        if not dok(str(x['e'])) or x['e'] < x['s']:
            errs.append(w + ': e 날짜'); continue
        if x.get('st') not in NEWS_ST:
            errs.append(w + ': st'); continue
        if x.get('tm') and not re.match(r'^([01]\d|2[0-3]):[0-5]\d$', str(x['tm'])):
            errs.append(w + ': tm'); continue
        if x.get('open') and not re.match(r'^20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}$', str(x['open'])):
            errs.append(w + ': open'); continue
        for k in ('url', 'src'):
            if x.get(k) and not str(x[k]).startswith('https://'):
                errs.append(w + f': {k}는 https'); break
        else:
            if x['cat'] in ('야구', '축구'):
                if not isinstance(x.get('team'), list) or not x['team'] or any(t not in NEWS_FOLLOW for t in x['team']):
                    errs.append(w + ': team'); continue
                if x.get('res') and not re.match(r'^\d{1,2}:\d{1,2}$', str(x['res'])):
                    errs.append(w + ': res'); continue
            bad = [k for k, lim in NEWS_LIM.items() if isinstance(x.get(k), str) and len(x[k]) > lim]
            if bad:
                errs.append(w + ': 너무 긺 ' + ','.join(bad)); continue
            if re.search(r'\d[\d,]*\s*원', json.dumps(x, ensure_ascii=False)):
                errs.append(w + ': 가격(원)은 넣지 않음'); continue
            if not x.get('lb'):
                x['lb'] = x['t'][:6]
            if not x.get('added') or not dok(str(x['added'])):
                x['added'] = today
            for k in list(x):
                if x[k] in ('', None):
                    del x[k]
            if x['e'] < cut:
                continue          # 45일 지난 건 정리
            if x['id'] in seen:
                errs.append(w + ': id 겹침'); continue
            seen.add(x['id'])
            keep[x['id']] = x
    items = sorted(keep.values(), key=lambda x: (x['s'], x.get('tm') or '99:99', x['id']))
    ctx = n.get('ctx') if isinstance(n.get('ctx'), dict) else {}
    out = {'v': 1, 'updated': n.get('updated') or '', 'follow': fol, 'ctx': ctx, 'items': items}
    ec, eerrs = econ_check(n.get('econ'), today)
    errs += eerrs
    if ec:
        out['econ'] = ec
    return out, errs


def cmd_newsopen(a):
    s = load_settings(a.settings)
    aes, _ = keys_for(s, a.repo)
    p = os.path.join(a.repo, 'news.json.enc')
    if os.path.exists(p):
        raw = open_bytes(aes, open(p, 'rb').read())
        n = json.loads(raw)
    else:
        n = {'v': 1, 'updated': '', 'follow': list(NEWS_FOLLOW), 'ctx': {}, 'items': []}
    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(n, f, ensure_ascii=False, indent=0)
    today = _kst_today()
    t1 = __import__('datetime').date.fromisoformat(today)
    y = (t1 - __import__('datetime').timedelta(days=1)).isoformat()
    it = n.get('items', [])
    print(json.dumps({'opened': a.out, 'items': len(it), 'updated': n.get('updated'), 'follow': n.get('follow'),
                      'todayGames': [f"{x.get('tm','')} {x['t']}" for x in it if x.get('cat') in ('야구', '축구') and x.get('s') == today],
                      'yesterdayNoResult': [x['id'] for x in it if x.get('cat') in ('야구', '축구') and x.get('s') == y and not x.get('res') and x.get('st') != 'cancel'],
                      'econDays': [d.get('d') for d in ((n.get('econ') or {}).get('days') or [])][:5]},
                     ensure_ascii=False, indent=1))


def cmd_newsseal(a):
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    today = a.today or _kst_today()
    n = json.load(open(a.news, encoding='utf-8'))
    out, errs = news_check(n, today)
    if out is None or errs:
        print(json.dumps({'ok': False, 'errors': errs[:40]}, ensure_ascii=False, indent=1)); sys.exit(1)
    import datetime as _dt
    out['updated'] = _dt.datetime.now(_dt.timezone(_dt.timedelta(hours=9))).replace(microsecond=0).isoformat()
    raw = json.dumps(out, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(raw) > 400 * 1024:
        print(json.dumps({'ok': False, 'errors': [f'너무 큼 {len(raw)//1024}KB (400KB 이하)']}, ensure_ascii=False)); sys.exit(1)
    p = os.path.join(a.repo, 'news.json.enc')
    old = {}
    if os.path.exists(p):
        try:
            old = {x['id']: x for x in json.loads(open_bytes(aes, open(p, 'rb').read())).get('items', [])}
        except Exception:
            old = {}
    new = [x for x in out['items'] if x['id'] not in old]
    chg = []
    for x in out['items']:
        o = old.get(x['id'])
        if o:
            d = [k for k in ('s', 'e', 'tm', 'st', 'open', 'res', 'v') if o.get(k) != x.get(k)]
            if d:
                chg.append({'id': x['id'], 't': x['t'], 'fields': d})
    gone = [k for k in old if k not in {x['id'] for x in out['items']}]
    with open(p, 'wb') as f:
        f.write(seal_bytes(aes, mac, raw))
    t1 = _dt.date.fromisoformat(today)
    tm = (t1 + _dt.timedelta(days=1)).isoformat()
    y = (t1 - _dt.timedelta(days=1)).isoformat()
    print(json.dumps({'ok': True, 'items': len(out['items']), 'kb': len(raw) // 1024,
                      'new': [f"{x['s']} {x['t']}" for x in new], 'changed': chg[:30], 'removed': len(gone),
                      'todayGames': [f"{x.get('tm','')} {x['t']}" for x in out['items'] if x['cat'] in ('야구', '축구') and x['s'] == today],
                      'yesterdayResults': [f"{x['t']} {x.get('res','?')}" for x in out['items'] if x['cat'] in ('야구', '축구') and x['s'] == y],
                      'opens': [f"{x['open']} {x['t']}" for x in out['items'] if x.get('open', '')[:10] in (today, tm)],
                      'econ': econ_brief(out.get('econ'), today)},
                     ensure_ascii=False, indent=1))


def econ_brief(ec, today):
    days = (ec or {}).get('days') or []
    if not days:
        return {'days': 0}
    x = days[0]
    mk = ' · '.join(f"{m['n']} {m['v']}{'(' + m['c'] + ')' if m.get('c') else ''}" for m in (x.get('mk') or [])[:3])
    return {'days': len(days), 'latest': x['d'], 'today': x['d'] == today, 'items': len(x['items']), 'mk': mk, 'one': x.get('one', '')}


def cmd_newswants(a):
    s = load_settings(a.settings)
    key = sync_key(s, a.repo)
    recs, _ = sync_records(key, a.sync)
    last = {}
    for r in recs.values():
        if r.get('k') != 'gw' or r.get('del') or not r.get('ref'):
            continue
        k = (r['ref'], r.get('w'))
        if k not in last or (r.get('t') or 0) > (last[k].get('t') or 0):
            last[k] = r
    out = {}
    for (ref, w), r in last.items():
        if r.get('v'):
            o = out.setdefault(ref, {'ref': ref, 't': r.get('tt'), 's': r.get('s'), 'who': []})
            o['who'].append({'j': '재준', 'h': '현지'}.get(w, w))
    print(json.dumps({'wants': sorted(out.values(), key=lambda x: x.get('s') or '')}, ensure_ascii=False, indent=1))


# ---------- v41 놀이 비서: AI 놀이 편지(plan.json.enc) ----------
# 매일 아침 예약 작업(Claude)이 plancontext 로 「둘의 지금」을 한 파일로 모아 읽고 → plan.json 을 쓰고 → planseal 로 검사·잠금.
# 앱(09zp)은 plan.json.enc 를 받아 맨 위에 편지 한 줄 + 고른 후보 가산점 + 아이디어를 후보로 넣는다. 나만 보기(p)·me-* 기록은 읽지 않는다.
PLAN_BAD = re.compile(r'(\d[\d,]*\s*원|https?://|010-\d|☎|@[a-z0-9.-]+\.[a-z]{2,})', re.I)
PLAN_RECENT_K = ('note', 'thx', 'mood', 'food', 'place', 'dlog', 'went', 'wish', 'miss', 'bal', 'pl', 'apx', 'wc', 'amen', 'fq', 'gthx', 'photo', 'prv', 'ans')
CITY_LL = {'청주': (36.642, 127.489), '광주': (35.160, 126.851)}


def _plan_weather(days=4):
    import urllib.request
    out = {}
    for city, (la, lo) in CITY_LL.items():
        u = (f'https://api.open-meteo.com/v1/forecast?latitude={la}&longitude={lo}&timezone=Asia%2FSeoul&forecast_days={days}'
             '&daily=weathercode,temperature_2m_max,temperature_2m_min,precipitation_probability_max,sunset')
        j = None
        for _ in range(2):
            try:
                j = json.loads(urllib.request.urlopen(u, timeout=15).read()); break
            except Exception:
                j = None
        try:
            dl = (j or {}).get('daily') or {}
            if not dl:
                raise ValueError('no daily')
            out[city] = [{'d': d, 'code': dl['weathercode'][i], 'tmax': dl['temperature_2m_max'][i], 'tmin': dl['temperature_2m_min'][i],
                          'pp': (dl.get('precipitation_probability_max') or [None] * 9)[i], 'sunset': str((dl.get('sunset') or [''] * 9)[i])[11:16]}
                         for i, d in enumerate(dl.get('time') or [])]
        except Exception as e:
            out[city] = None
    return out


def cmd_plancontext(a):
    import datetime as _dt
    s = load_settings(a.settings)
    aes, _ = keys_for(s, a.repo)
    key = sync_key(s, a.repo)
    recs, bad = sync_records(key, a.sync)
    today = _kst_today()
    t0 = _dt.date.fromisoformat(today)
    days = [(t0 + _dt.timedelta(days=i)).isoformat() for i in range(3)]
    since = (t0 - _dt.timedelta(days=7)).isoformat()
    live = [r for r in recs.values() if isinstance(r, dict) and not r.get('del') and not r.get('p')]
    plx = {}
    for w in ('j', 'h'):
        L = sorted([r for r in live if r.get('k') == 'plx' and r.get('w') == w and isinstance(r.get('v'), dict)], key=lambda r: r.get('t') or 0)
        if L:
            plx[w] = {'d': L[-1].get('d'), 'days': L[-1]['v'].get('days') or {}, 'tags': L[-1]['v'].get('tags') or []}
    recent = {'j': [], 'h': []}
    for r in sorted(live, key=lambda r: r.get('t') or 0):
        k = r.get('k')
        d = str(r.get('d') or r.get('dd') or '')
        if k not in PLAN_RECENT_K or r.get('w') not in recent or not (since <= d <= today):
            continue
        txt = r.get('s') or r.get('n') or r.get('tt') or r.get('ref') or r.get('v') or r.get('win') or ''
        if isinstance(txt, (dict, list)):
            txt = r.get('f') or k
        txt = re.sub(r'https?://\S+', '(링크)', str(txt))
        recent[r['w']].append({'d': d, 'k': k, 'x': txt[:60], **({'st': r.get('st')} if r.get('st') else {})})
    for w in recent:
        recent[w] = recent[w][-60:]
    meet = {}
    for r in live:
        if r.get('k') == 'mday' and re.match(r'^20\d{2}-\d{2}-\d{2}$', str(r.get('d'))) and str(r['d']) >= today:
            cur = meet.get(r['d'])
            if not cur or (r.get('t') or 0) > (cur.get('t') or 0):
                meet[r['d']] = r
    meet = [{'d': d, 'tm': r.get('tm') or '', 'pl': (r.get('pl') or '')[:40]} for d, r in sorted(meet.items()) if r.get('on')][:4]
    exams = {}
    for w in ('j', 'h'):
        L = sorted([r for r in live if r.get('k') == 'stexam' and r.get('w') == w], key=lambda r: r.get('t') or 0)
        if L and isinstance(L[-1].get('v'), list):
            exams[w] = [{'n': str(x.get('n') or '시험')[:20], 'd': x.get('d')} for x in L[-1]['v'] if isinstance(x, dict) and str(x.get('d') or '') >= today][:3]
    news = []
    p = os.path.join(a.repo, 'news.json.enc')
    if os.path.exists(p):
        try:
            n = json.loads(open_bytes(aes, open(p, 'rb').read()))
            wants = {}
            for r in live:
                if r.get('k') == 'gw' and r.get('ref'):
                    k2 = (r['ref'], r.get('w'))
                    if k2 not in wants or (r.get('t') or 0) > (wants[k2].get('t') or 0):
                        wants[k2] = r
            for x in n.get('items', []):
                s0, e0 = str(x.get('s') or ''), str(x.get('e') or x.get('s') or '')
                op = str(x.get('open') or '')[:10]
                if (s0 <= days[-1] and e0 >= today) or (today <= op <= days[-1]):
                    who = [w for w in ('j', 'h') if (wants.get((x.get('id'), w)) or {}).get('v')]
                    news.append({'id': x.get('id'), 'cat': x.get('cat'), 't': (x.get('t') or '')[:50], 's': s0, 'e': e0, 'tm': x.get('tm') or '', 'city': x.get('city') or '',
                                 'open': x.get('open') or '', 'want': who})
        except Exception:
            pass
    ctx = {'v': 1, 'today': today, 'days': days, 'people': {'j': {'n': '재준', 'city': '청주'}, 'h': {'n': '현지', 'city': '광주'}},
           'plx': plx, 'recent': recent, 'meet': meet, 'exams': exams, 'news': news[:24], 'weather': _plan_weather(4)}
    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(ctx, f, ensure_ascii=False, indent=1)
    print(json.dumps({'ok': True, 'out': a.out, 'plx': {w: v.get('d') for w, v in plx.items()}, 'recent': {w: len(v) for w, v in recent.items()},
                      'meet': meet[:1], 'news': len(news), 'weather': {c: bool(v) for c, v in ctx['weather'].items()}, 'badFiles': len(bad)}, ensure_ascii=False))


def _plan_txt(v, n, errs, where):
    v = str(v or '').strip()
    if PLAN_BAD.search(v):
        errs.append(f'{where}: 금지 흔적(가격·주소·전화·URL)')
    if len(v) > n:
        errs.append(f'{where}: {len(v)}자 > {n}')
    return v[:n]


def cmd_planseal(a):
    import datetime as _dt
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    raw = json.load(open(a.plan, encoding='utf-8'))
    today = _dt.date.fromisoformat(_kst_today())
    lo, hi = (today - _dt.timedelta(days=1)).isoformat(), (today + _dt.timedelta(days=6)).isoformat()
    errs, out = [], {}
    for d, x in sorted((raw.get('days') or {}).items()):
        if not re.match(r'^20\d{2}-\d{2}-\d{2}$', d) or not (lo <= d <= hi) or not isinstance(x, dict):
            errs.append(f'{d}: 날짜 범위 밖(어제~6일 뒤만)'); continue
        day = {}
        for who in ('both', 'j', 'h'):
            y = x.get(who)
            if not isinstance(y, dict):
                continue
            o = {}
            if y.get('t'): o['t'] = _plan_txt(y['t'], 40, errs, f'{d}.{who}.t')
            if y.get('m'): o['m'] = _plan_txt(y['m'], 240, errs, f'{d}.{who}.m')
            if isinstance(y.get('pick'), list) and who != 'both':
                o['pick'] = [str(p)[:80] for p in y['pick'] if p][:6]
            ideas = []
            for i, it in enumerate((y.get('ideas') or [])[:3]):
                if isinstance(it, dict) and it.get('t'):
                    ideas.append({'t': _plan_txt(it['t'], 24, errs, f'{d}.{who}.ideas{i}.t'), 'd': _plan_txt(it.get('d'), 90, errs, f'{d}.{who}.ideas{i}.d'),
                                  'slot': it.get('slot') if it.get('slot') in ('now', 'eve', 'heart') else 'eve'})
            if ideas: o['ideas'] = ideas
            if o: day[who] = o
        if day: out[d] = day
    if errs:
        print(json.dumps({'ok': False, 'errors': errs[:30]}, ensure_ascii=False, indent=1)); sys.exit(1)
    if not out:
        print(json.dumps({'ok': False, 'errors': ['days 가 비었음']}, ensure_ascii=False)); sys.exit(1)
    obj = {'v': 1, 'made': _dt.datetime.now(_dt.timezone(_dt.timedelta(hours=9))).strftime('%Y-%m-%dT%H:%M'), 'days': out}
    data = json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode()
    ch = write_if_changed(os.path.join(a.repo, 'plan.json.enc'), seal_bytes(aes, mac, data))
    print(json.dumps({'ok': True, 'changed': bool(ch), 'days': sorted(out), 'bytes': len(data)}, ensure_ascii=False))


# ---------- v43 우리 리포트 (rep.json.enc) — 두 폰의 「오늘 놀이 요약」 rep 기록 → 밤 예약 작업(Claude)이 리포트를 씀 ----------
REP_MAX_DELTA = 4000
def _rep_prev(prev):
    """지난 리포트: 제목·한 줄·질문 + v54 x(알아 가기 facts 는 이어서 쌓으려고 전부 · 에피소드는 제목·새로 안 것만 · 답 표는 뺌)"""
    if not isinstance(prev, dict): return None
    o = {k: prev.get(k) for k in ('d', 'title', 'one', 'ask')}
    x = prev.get('x')
    if isinstance(x, dict):
        o['x'] = {k: v for k, v in x.items() if k not in ('table', 'ep')}
        o['x']['ep'] = {w: {'id': e.get('id'), 't': e.get('t'), 'learn': e.get('learn') or []} for w, e in (x.get('ep') or {}).items() if isinstance(e, dict)}
    return o


def cmd_reportcontext(a):
    """두 폰 rep 기록(k 'rep': d, sig, v{delta, full}) 중 최근 것들과 지난 리포트를 모아 ctx 로. 이름·돈 없음(앱이 그렇게 만듦)."""
    import datetime as _dt
    s = load_settings(a.settings)
    aes, _ = keys_for(s, a.repo)
    key = sync_key(s, a.repo)
    recs, bad = sync_records(key, a.sync)
    today = _kst_today()
    t0 = _dt.date.fromisoformat(today)
    days = [(t0 - _dt.timedelta(days=i)).isoformat() for i in range(0, 8)]
    live = [r for r in recs.values() if isinstance(r, dict) and not r.get('del') and r.get('k') == 'rep' and isinstance(r.get('v'), dict) and str(r.get('d') or '') in days]
    by_day = {}
    for r in sorted(live, key=lambda r: r.get('t') or 0):
        d = str(r['d']); v = r['v']
        cur = by_day.get(d) or {'d': d, 'delta': '', 'full': '', 'w': []}
        if v.get('delta') and len(str(v['delta'])) >= len(cur['delta']): cur['delta'] = str(v['delta'])[:REP_MAX_DELTA]
        if v.get('full') and len(str(v['full'])) >= len(cur['full']): cur['full'] = str(v['full'])[:24000]
        if r.get('w') in ('j', 'h') and r['w'] not in cur['w']: cur['w'].append(r['w'])
        by_day[d] = cur
    prev = None
    p = os.path.join(a.repo, 'rep.json.enc')
    if os.path.exists(p):
        try: prev = json.loads(open_bytes(aes, open(p, 'rb').read()))
        except Exception: prev = None
    # v43.2 쓰임 기록(use): 최근 30일 두 폰 합산 — 누른 수·머문 초(이름·내용 없음)
    days30 = {(t0 - _dt.timedelta(days=i)).isoformat() for i in range(0, 30)}
    use = {'days': 0, 'acts': {}, 'pages': {}, 'tabs': {}}
    for r in recs.values():
        if not (isinstance(r, dict) and not r.get('del') and r.get('k') == 'use' and isinstance(r.get('v'), dict) and str(r.get('d') or '') in days30):
            continue
        v = r['v']; use['days'] += 1
        for k, n in (v.get('acts') or {}).items():
            if isinstance(n, (int, float)): use['acts'][k] = use['acts'].get(k, 0) + int(n)
        for box in ('pages', 'tabs'):
            for k, x in (v.get(box) or {}).items():
                if isinstance(x, dict):
                    cur = use[box].setdefault(k, {'n': 0, 's': 0}); cur['n'] += int(x.get('n') or 0); cur['s'] += int(x.get('s') or 0)
    use['acts'] = dict(sorted(use['acts'].items(), key=lambda kv: -kv[1])[:150])
    out = {'today': today, 'yesterday': days[1], 'days': [by_day[d] for d in days if d in by_day], 'use': use,
           'prev': _rep_prev(prev),
           'people': {'j': '재준(청주)', 'h': '현지(광주)'}, 'badFiles': len(bad)}
    json.dump(out, open(a.out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(json.dumps({'ok': True, 'days': [d['d'] for d in out['days']], 'hasYesterday': days[1] in by_day, 'hasToday': today in by_day, 'prev': (prev or {}).get('d')}, ensure_ascii=False))

REP_LENS = {'new': '🎢 같이 새로운 거 해 보기', 'val': '🧭 우리가 중요하게 여기는 것', 'map': '🗺 서로 얼마나 알까', 'near': '🤝 가까이 · 따로', 'talk': '💬 말 거는 법',
            'life': '🧺 생활 나누기', 'love': '💌 마음 표현', 'home': '🏡 함께 꾸릴 날', 'kid': '👶 아이 이야기'}
REP_KINDS = ('bal', 'day', 'month')
# 화면 글엔 학자·연구 이름·어려운 말·점수 말을 쓰지 않는다(재준 10/23 「공부하는 게 아니고 노는 거잖아」) — 출처(src)에만
REP_HARD = re.compile(r'가트맨|고트만|아론|슈워츠|에릭슨|오은영|자기\s?확장|사랑의\s?지도|사랑의\s?언어|애착\s?(이론|유형)|가설|확신\s?(높음|중간|낮음)|궁합|\d+\s*점(?![심검])|진단|생리')


def _rx(v, n, errs, where, need=False):
    """리포트 글 하나: 길이·금지 흔적(_plan_txt) + 어려운 말"""
    if v is None or v == '':
        if need: errs.append(f'{where}: 비어 있음')
        return ''
    if not isinstance(v, str):
        errs.append(f'{where}: 글이 아님'); return ''
    t = _plan_txt(v, n, errs, where)
    m = REP_HARD.search(t)
    if m: errs.append(f'{where}: 「{m.group(0)}」 — 화면 글엔 쉬운 말만(학자·연구 이름은 src 에만 · 점수·궁합·진단 X)')
    return t


def _rep_ep(e, w, errs):
    """애인 공략하기 에피소드 한 편(그 폰 사람이 상대를 공략) — lover.html 이 받는 모양"""
    if not isinstance(e, dict): errs.append(f'{w}: 객체가 아님'); return None
    out = {'id': str(e.get('id') or '')[:40], 't': _rx(e.get('t'), 30, errs, w + '.t', True), 'sub': _rx(e.get('sub'), 60, errs, w + '.sub')}
    if not re.match(r'^ep-\d{8}-[jh]$', out['id']): errs.append(f'{w}.id: ep-YYYYMMDD-j|h')
    sc = e.get('scenes')
    if not isinstance(sc, list) or not 3 <= len(sc) <= 6: errs.append(f'{w}.scenes: 3~6개'); return None
    out['scenes'] = []
    for i, s in enumerate(sc):
        ws = f'{w}.scenes[{i}]'
        if not isinstance(s, dict): errs.append(ws + ': 객체가 아님'); continue
        op = s.get('opts')
        if not isinstance(op, list) or len(op) != 3: errs.append(ws + '.opts: 보기 3개'); continue
        b = s.get('best'); x = s.get('worst')
        if not isinstance(b, int) or not 0 <= b <= 2: errs.append(ws + '.best: 0~2'); continue
        one = {'cap': _rx(s.get('cap'), 40, errs, ws + '.cap'), 'line': _rx(s.get('line'), 90, errs, ws + '.line', True),
               'opts': [_rx(o, 40, errs, f'{ws}.opts{j}', True) for j, o in enumerate(op)], 'best': b,
               'why': _rx(s.get('why'), 120, errs, ws + '.why', True), 'ev': _rx(s.get('ev'), 80, errs, ws + '.ev')}
        if isinstance(x, int) and 0 <= x <= 2 and x != b: one['worst'] = x
        out['scenes'].append(one)
    L = e.get('learn') or []
    if not isinstance(L, list) or len(L) > 5: errs.append(w + '.learn: 5개까지 글')
    else: out['learn'] = [_rx(t, 40, errs, f'{w}.learn{i}') for i, t in enumerate(L)]
    out['care'] = _rx(e.get('care'), 80, errs, w + '.care')
    return out


def rep_x_check(x, errs):
    """x = 새 리포트 화면(v54). 다 선택이지만 kind 는 꼭. 앱은 x 가 있으면 새 화면, 없으면 blocks 로 그린다."""
    if not isinstance(x, dict): errs.append('x 가 객체가 아님'); return None
    o = {'kind': x.get('kind') if x.get('kind') in REP_KINDS else ''}
    if not o['kind']: errs.append('x.kind 는 bal|day|month')
    # 10/24 재준 「사실 나열 말고 심리 분석 — 그래서 뭐 어떻다는 건지 · 어쩌자는 건지 · 왜 그런지」: 마음 읽기 칸(문서 13절)
    o['story'] = _rx(x.get('story'), 600, errs, 'x.story')
    me = x.get('me')
    if me is not None:
        if not isinstance(me, dict): errs.append('x.me 는 {j,h}')
        else: o['me'] = {w: _rx(me.get(w), 320, errs, f'x.me.{w}') for w in ('j', 'h') if me.get(w)}
    o['us'] = _rx(x.get('us'), 400, errs, 'x.us')
    th = x.get('three')
    if th is not None:
        if not isinstance(th, dict): errs.append('x.three 는 {g,o,b}')
        else: o['three'] = {k: _rx(th.get(k), 160, errs, f'x.three.{k}') for k in ('g', 'o', 'b') if th.get(k)}
    o['todo'] = _rx(x.get('todo'), 120, errs, 'x.todo')
    c = x.get('care')
    if isinstance(c, dict): o['care'] = {w: _rx(c.get(w), 80, errs, f'x.care.{w}') for w in ('j', 'h') if c.get(w)}
    elif c: o['care'] = _rx(c, 80, errs, 'x.care')
    mp = x.get('map')
    if mp is not None:
        rows, cols, dots = (mp or {}).get('rows'), (mp or {}).get('cols'), (mp or {}).get('dots')
        if not (isinstance(rows, list) and 1 <= len(rows) <= 8 and isinstance(cols, list) and 1 <= len(cols) <= 6 and isinstance(dots, list) and len(dots) <= 48):
            errs.append('x.map: rows 1~8 · cols 1~6(관점 키) · dots [[줄,칸]…]')
        else:
            bad = [c for c in cols if c not in REP_LENS]
            if bad: errs.append(f'x.map.cols: 모르는 관점 {bad[:3]} — {list(REP_LENS)}')
            dd = []
            for p in dots:
                if isinstance(p, list) and len(p) == 2 and all(isinstance(v, int) for v in p) and 0 <= p[0] < len(rows) and 0 <= p[1] < len(cols):
                    if p not in dd: dd.append(p)
                else: errs.append(f'x.map.dots: {p} 범위 밖'); break
            o['map'] = {'rows': [_rx(r, 16, errs, f'x.map.rows{i}', True) for i, r in enumerate(rows)], 'cols': cols, 'dots': dd}
    ls = x.get('lens')
    if ls is not None:
        if not isinstance(ls, list) or len(ls) > 5: errs.append('x.lens: 5개까지')
        else:
            o['lens'] = []
            for i, l in enumerate(ls):
                w = f'x.lens[{i}]'
                if not isinstance(l, dict) or l.get('k') not in REP_LENS: errs.append(f'{w}.k: {list(REP_LENS)} 중 하나'); continue
                one = {'k': l['k'], 'line': _rx(l.get('line'), 80, errs, w + '.line', True), 'us': _rx(l.get('us'), 160, errs, w + '.us'),
                       'may': _rx(l.get('may'), 160, errs, w + '.may'), 'try': _rx(l.get('try'), 160, errs, w + '.try'), 'ev': _rx(l.get('ev'), 220, errs, w + '.ev'),
                       'mean': _rx(l.get('mean'), 240, errs, w + '.mean'), 'why': _rx(l.get('why'), 240, errs, w + '.why'), 'do': _rx(l.get('do'), 200, errs, w + '.do')}
                o['lens'].append({k: v for k, v in one.items() if v})
    df = x.get('diff')
    if df is not None:
        if not isinstance(df, dict): errs.append('x.diff 는 {decide,talk,taste}')
        else: o['diff'] = {k: _rx(df.get(k), 200, errs, f'x.diff.{k}') for k in ('decide', 'talk', 'taste') if df.get(k)}
    mo = x.get('month')
    if mo is not None:
        if not isinstance(mo, dict): errs.append('x.month 는 {now,before,later,thx}')
        else: o['month'] = {k: _rx(mo.get(k), n, errs, f'x.month.{k}') for k, n in (('now', 120), ('before', 120), ('later', 120), ('thx', 240)) if mo.get(k)}
    tb = x.get('table')
    if tb is not None:
        if not isinstance(tb, list) or len(tb) > 80: errs.append('x.table: 80줄까지')
        else:
            o['table'] = []
            for i, r in enumerate(tb):
                if not isinstance(r, dict): errs.append(f'x.table[{i}]: 객체가 아님'); continue
                o['table'].append({k: _plan_txt(r.get(k), n, errs, f'x.table[{i}].{k}') for k, n in (('q', 60), ('j', 30), ('h', 30), ('rj', 40), ('rh', 40)) if r.get(k)})   # 문항·답은 그대로 옮긴 것이라 쉬운 말 검사 안 함
    sm = x.get('same')
    if sm is not None:
        if not (isinstance(sm, dict) and isinstance(sm.get('n'), int) and isinstance(sm.get('of'), int) and 0 <= sm['n'] <= sm['of'] <= 999): errs.append('x.same: {n,of} 정수(n ≤ of)')
        else: o['same'] = {'n': sm['n'], 'of': sm['of']}
    fc = x.get('facts')
    if fc is not None:
        if not isinstance(fc, dict): errs.append('x.facts 는 {j:[…],h:[…]}')
        else:
            o['facts'] = {}
            for w in ('j', 'h'):
                L = fc.get(w) or []
                if not isinstance(L, list) or len(L) > 40: errs.append(f'x.facts.{w}: 40개까지'); continue
                o['facts'][w] = []
                for i, f in enumerate(L):
                    if not isinstance(f, dict) or f.get('lv') not in ('sure', 'once'): errs.append(f'x.facts.{w}[{i}]: {{t,lv:sure|once,ev}}'); continue
                    o['facts'][w].append({'t': _rx(f.get('t'), 40, errs, f'x.facts.{w}[{i}].t', True), 'lv': f['lv'], 'ev': _rx(f.get('ev'), 40, errs, f'x.facts.{w}[{i}].ev')})
    ep = x.get('ep')
    if ep is not None:
        if not isinstance(ep, dict): errs.append('x.ep 는 {j:에피소드,h:에피소드}')
        else:
            o['ep'] = {}
            for w in ('j', 'h'):
                if ep.get(w) is None: continue
                e = _rep_ep(ep[w], f'x.ep.{w}', errs)
                if e:
                    if not e['id'].endswith('-' + w): errs.append(f'x.ep.{w}.id 끝은 -{w}')
                    o['ep'][w] = e
    sr = x.get('src')
    if sr is not None:
        if not isinstance(sr, list) or len(sr) > 8: errs.append('x.src: 8개까지 글')
        else: o['src'] = [_plan_txt(s, 100, errs, f'x.src{i}') for i, s in enumerate(sr) if isinstance(s, str) and s.strip()]
    return {k: v for k, v in o.items() if v not in ('', None, {}, [])}


def _cut(s, n):
    s = str(s or '').strip()
    return s if len(s) <= n else s[:n - 1] + '…'


def rep_blocks_from_x(o):
    """옛 앱(블록만 그림)을 위해 x 로 블록을 만든다 — 줄바꿈 대신 「 / 」"""
    B = []
    if o.get('story'): B.append({'h': '오늘의 마음 읽기', 'p': _cut(o['story'], 420)})
    me = o.get('me') or {}
    if me: B.append({'h': '재준 마음 · 현지 마음', 'p': _cut(' / '.join(f'{n}: {me[w]}' for w, n in (('j', '재준'), ('h', '현지')) if me.get(w)), 420)})
    if o.get('us'): B.append({'h': '둘이 만나면', 'p': _cut(o['us'], 420)})
    th = o.get('three') or {}
    if th: B.append({'h': '한눈에 셋', 'p': _cut(' / '.join(f'{e} {n}: {th[k]}' for k, e, n in (('g', '🟢', '잘 맞는 것'), ('o', '🟠', '다른 것'), ('b', '🔵', '같이 해 볼 것')) if th.get(k)), 420)})
    mo = o.get('month') or {}
    if mo.get('now') or mo.get('before') or mo.get('later'):
        B.append({'h': '이번 달 할 일 셋', 'p': _cut(' / '.join(f'{n}: {mo[k]}' for k, n in (('now', '이번 달'), ('before', '같이 살기 전'), ('later', '그다음')) if mo.get(k)), 420)})
    if o.get('todo'): B.append({'h': '오늘 해 볼 것', 'p': _cut(o['todo'], 420)})
    for l in (o.get('lens') or [])[:2]:
        parts = [l.get('line')] + [f'{n} {l[k]}' for k, n in (('mean', '그래서 뭐냐면 —'), ('why', '왜 그러냐면 —'), ('do', '그래서 이렇게 해 봐요 —'), ('us', '이런 우리예요 —'), ('may', '그래서 이럴 수 있어요 —'), ('try', '이렇게 해 볼까요? —'), ('ev', '우리가 고른 것 —')) if l.get(k)]
        B.append({'h': _cut(REP_LENS[l['k']], 24), 'p': _cut(' / '.join(p for p in parts if p), 420)})
    df = o.get('diff') or {}
    if df: B.append({'h': '다른 답 정리', 'p': _cut(' / '.join(f'{n}: {df[k]}' for k, n in (('decide', '같이 정할 것'), ('talk', '수다거리'), ('taste', '그냥 취향')) if df.get(k)), 420)})
    if mo.get('thx'): B.append({'h': '고마웠던 순간', 'p': _cut(mo['thx'], 420)})
    return B[:6]


def rep_check(raw, today):
    """rep.json — v1(제목·한 줄·블록·질문) + v54 새 화면 x(선택). x 만 있고 blocks 가 없으면 x 로 블록을 만든다(옛 앱도 보이게)."""
    import datetime as _dt
    errs = []
    if not isinstance(raw, dict): return ['rep 가 객체가 아님'], None
    d = str(raw.get('d') or '')
    t0 = _dt.date.fromisoformat(today)
    ok_days = {(t0 - _dt.timedelta(days=i)).isoformat() for i in range(0, 3)}
    if d not in ok_days: errs.append('d 는 오늘·어제·그제 중 하나(YYYY-MM-DD)')
    out = {'v': 1, 'd': d, 'title': _rx(raw.get('title'), 40, errs, 'title', True), 'one': _rx(raw.get('one'), 140, errs, 'one')}
    x = None
    if raw.get('x') is not None:
        x = rep_x_check(raw['x'], errs)
    bl = raw.get('blocks')
    if bl is None and x:
        bl = rep_blocks_from_x(x)
    if not isinstance(bl, list) or not (1 <= len(bl) <= 6): errs.append('blocks 는 1~6개(또는 x 를 채우면 저절로)')
    else:
        out['blocks'] = [{'h': _rx(b.get('h'), 24, errs, f'blocks{i}.h'), 'p': _rx(b.get('p'), 420, errs, f'blocks{i}.p')} for i, b in enumerate(bl) if isinstance(b, dict)]
    if raw.get('ask'): out['ask'] = _rx(raw['ask'], 120, errs, 'ask')
    if raw.get('notify'): out['notify'] = _rx(raw['notify'], 60, errs, 'notify')
    if x: out['x'] = x
    txt = json.dumps(out, ensure_ascii=False)
    if re.search(r'https?://|\d{2,3}-\d{3,4}-\d{4}|[0-9][0-9,]*\s*(원|만원|천원)', txt): errs.append('주소(URL)·전화·돈 숫자는 넣지 않는다')
    if len(txt.encode('utf-8')) > 60 * 1024: errs.append(f'너무 큼 {len(txt.encode("utf-8"))//1024}KB (60KB 이하)')
    return errs, out

def cmd_repseal(a):
    import datetime as _dt
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    raw = json.load(open(a.rep, encoding='utf-8'))
    errs, out = rep_check(raw, _kst_today())
    if errs:
        print(json.dumps({'ok': False, 'errors': errs[:30]}, ensure_ascii=False, indent=1)); sys.exit(1)
    out['made'] = _dt.datetime.now(_dt.timezone(_dt.timedelta(hours=9))).strftime('%Y-%m-%dT%H:%M')
    data = json.dumps(out, ensure_ascii=False, separators=(',', ':')).encode()
    ch = write_if_changed(os.path.join(a.repo, 'rep.json.enc'), seal_bytes(aes, mac, data))
    print(json.dumps({'ok': True, 'changed': bool(ch), 'd': out['d'], 'title': out['title'], 'notify': out.get('notify') or '', 'bytes': len(data)}, ensure_ascii=False))

def cmd_balinseal(a):
    """v43.1 밸런스 「우리 분석」 해석문(balin.json.enc) — 매달 점검 때 Claude 가 다시 쓴다. 앱은 빌드에 박힌 글 대신 이것을 보여 준다."""
    import datetime as _dt
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    raw = json.load(open(getattr(a, 'in'), encoding='utf-8'))
    errs = []
    out = {'v': 1, 'd': str(raw.get('d') or _kst_today()), 'src': _plan_txt(raw.get('src') or '밸런스 게임 · 월간 점검', 80, errs, 'src'), 'one': _plan_txt(raw.get('one'), 140, errs, 'one')}
    if not re.match(r'^20\d{2}-\d{2}-\d{2}$', out['d']): errs.append('d 는 YYYY-MM-DD')
    for k, n, mx in (('strengths', 'strengths', 160), ('actions', 'actions', 160)):
        L = raw.get(k)
        if not isinstance(L, list) or not (1 <= len(L) <= 8): errs.append(f'{n} 는 1~8개 글 목록')
        else: out[k] = [_plan_txt(x, mx, errs, f'{n}{i}') for i, x in enumerate(L)]
    L = raw.get('diffs')
    if not isinstance(L, list) or not (1 <= len(L) <= 8): errs.append('diffs 는 1~8개 {h,p}')
    else: out['diffs'] = [{'h': _plan_txt(x.get('h'), 40, errs, f'diffs{i}.h'), 'p': _plan_txt(x.get('p'), 300, errs, f'diffs{i}.p')} for i, x in enumerate(L) if isinstance(x, dict)]
    pr = raw.get('profiles') if isinstance(raw.get('profiles'), dict) else {}
    out['profiles'] = {w: _plan_txt(pr.get(w), 220, errs, f'profiles.{w}') for w in ('j', 'h') if pr.get(w)}
    txt = json.dumps(out, ensure_ascii=False)
    if re.search(r'https?://|\d{2,3}-\d{3,4}-\d{4}|[0-9][0-9,]*\s*(원|만원|천원)', txt): errs.append('주소(URL)·전화·돈 숫자는 넣지 않는다')
    if errs:
        print(json.dumps({'ok': False, 'errors': errs[:30]}, ensure_ascii=False, indent=1)); sys.exit(1)
    data = json.dumps(out, ensure_ascii=False, separators=(',', ':')).encode()
    ch = write_if_changed(os.path.join(a.repo, 'balin.json.enc'), seal_bytes(aes, mac, data))
    print(json.dumps({'ok': True, 'changed': bool(ch), 'd': out['d'], 'bytes': len(data)}, ensure_ascii=False))


# ---------- 매주 새 소재(fresh.json.enc) ----------
FRESH_MAX = {'balance': 1500, 'quiz': 600, 'imagine': 600, 'dates': 1000, 'courses': 200, 'books': 30, 'wed': 30}   # v22: 쌓이도록 크게(재준 요청 「데이터량 늘리기」)
FRESH_MAX_KB = 4 * 1024   # v54 밸런스 이유·떨어진 날 풀이 붙어 2MB → 4MB
# v54 떨어진 날 풀 자동 채우기(재준 10/24 「잔여의 60% 넘어가면 알아서 새로 찾아서 양 늘려」): fresh.apart = {풀: [{s: 항목, g: 시작 날}]} — 붙이기만(앞 것을 지우거나 바꾸지 않음)
FRESH_AP_STR = {'tele': (2, 20), 'deep': (6, 40), 'cq': (3, 24), 'wave': (2, 14), 'relay': (1, 14), 'body': (4, 22), 'cut': (2, 14), 'draw': (1, 8), 'par': (12, 60),
                'inv': (1, 8), 'fut': (6, 36), 'drw': (4, 28), 'emo': (1, 4), 'story': (12, 60), 'who': (8, 40), 'never': (8, 44), 'if': (8, 90)}   # if = 상상 놀이 「만약에」 질문
FRESH_AP_POOLS = tuple(FRESH_AP_STR) + ('sur', 'role', 'post')
FRESH_AP_SUR = ('q', 'mimic', 'emoji', 'draw')
FRESH_AP_WEEK = 300        # 풀마다 한 주에 붙일 수 있는 수
FRESH_AP_MAX = 3000        # 풀마다 fresh 로 붙인 전체
FRESH_BAL_R = 18           # 밸런스 「고른 이유」 보기 한 개 길이
COURSE_K = ('see', 'do', 'eat', 'cafe', 'stay', 'move')
DATE_ENUM = {'io': ('both', 'in', 'out'), 'time': ('1h', 'day', 'half', 'trip'), 'wx': ('any', 'clear', 'cold', 'hot', 'rain'), 'when': ('any', 'day', 'night', 'weekend'),
             'tag': ('계절', '공연', '만들기', '맛집', '바다', '산책', '액티비티', '야경', '여행', '장거리', '전시', '집데이트', '축제', '카페'), 'reg': ('', '청주', '광주', '충청', '호남', '중간')}


def fresh_check(f, today):
    errs = []
    if not isinstance(f, dict):
        return None, ['맨 위 형식이 {"v":1,...}가 아님']
    out = {'v': 1, 'updated': '', 'week': str(f.get('week') or ''), 'balance': [], 'quiz': [], 'imagine': [], 'dates': [], 'courses': [], 'books': [], 'wed': [], 'log': []}
    seen = set()
    for i, b in enumerate(f.get('balance') or []):
        w = f'balance[{i}]'
        if not isinstance(b, dict) or not re.match(r'^fb-[a-z0-9-]{2,30}$', str(b.get('id', ''))):
            errs.append(w + ': id는 fb-로 시작(영문 소문자·숫자·-)'); continue
        if b['id'] in seen:
            errs.append(w + ': id 겹침'); continue
        if not all(isinstance(b.get(k), str) and 1 <= len(b[k]) <= 40 for k in ('a', 'b')) or not isinstance(b.get('c'), str) or not 1 <= len(b['c']) <= 6:
            errs.append(w + ': a·b(40자)·c(6자) 확인'); continue
        r = b.get('r')   # v54 고른 이유 보기 {a:[2~4],b:[2~4]} (각 18자) — 없어도 됨(앱은 「직접 쓰기」만)
        if r is not None and not (isinstance(r, dict) and all(isinstance(r.get(k), list) and 2 <= len(r[k]) <= 4 and all(isinstance(x, str) and 1 <= len(x.strip()) <= FRESH_BAL_R for x in r[k]) for k in ('a', 'b'))):
            errs.append(w + f': r 는 {{"a":[2~4개],"b":[2~4개]}} (각 {FRESH_BAL_R}자 이내)'); continue
        seen.add(b['id']); out['balance'].append({'id': b['id'], 'a': b['a'], 'b': b['b'], 'c': b['c'], 'wk': str(b.get('wk') or out['week']), **({'area': str(b['area'])[:20]} if isinstance(b.get('area'), str) and b.get('area') else {}), **({'r': {k: [x.strip() for x in r[k]] for k in ('a', 'b')}} if r else {})})   # v43.1 영역 태그(우리 분석)
    # v43.3 연예인 월드컵 세트: {id wcs-…, t 40자, for j|h|both, items 8~32 {n 20자, sub 40자, img upload/thumb.wikimedia.org https, credit 90자, page}}
    out['wcsets'] = []
    for i, st in enumerate(f.get('wcsets') or []):
        w = f'wcsets[{i}]'
        if not isinstance(st, dict) or not re.match(r'^wcs-[a-z0-9-]{2,30}$', str(st.get('id', ''))):
            errs.append(w + ': id는 wcs-로 시작'); continue
        if st['id'] in seen:
            errs.append(w + ': id 겹침'); continue
        items = st.get('items')
        if not isinstance(st.get('t'), str) or not 1 <= len(st['t']) <= 40 or not isinstance(items, list) or not 8 <= len(items) <= 32:
            errs.append(w + ': t(40자)·items 8~32개 확인'); continue
        ok_items = []
        for j, x in enumerate(items):
            if not isinstance(x, dict) or not isinstance(x.get('n'), str) or not 1 <= len(x['n']) <= 20 or not re.match(r'^https://(upload|thumb)\.wikimedia\.org/[^\s"<>]+$', str(x.get('img', ''))):
                errs.append(f'{w}.items[{j}]: n(20자)·img(upload/thumb.wikimedia.org https) 확인'); break
            ok_items.append({'id': f"{st['id']}-{j+1}", 'n': x['n'], 'sub': str(x.get('sub') or '')[:40], 'img': x['img'], 'credit': str(x.get('credit') or '')[:90], 'page': str(x.get('page') or '')[:200]})
        if len(ok_items) != len(items):
            continue
        seen.add(st['id']); out['wcsets'].append({'id': st['id'], 't': st['t'], 'for': st.get('for') if st.get('for') in ('j', 'h', 'both') else 'both', 'items': ok_items, 'wk': str(st.get('wk') or out['week'])})
    for i, q in enumerate(f.get('quiz') or []):
        w = f'quiz[{i}]'
        if not isinstance(q, dict) or not re.match(r'^fz-[a-z0-9-]{2,30}$', str(q.get('id', ''))):
            errs.append(w + ': id는 fz-로 시작'); continue
        if q['id'] in seen:
            errs.append(w + ': id 겹침'); continue
        if not isinstance(q.get('q'), str) or not 1 <= len(q['q']) <= 70 or not isinstance(q.get('o'), list) or len(q['o']) != 4 or not all(isinstance(o, str) and 1 <= len(o) <= 16 for o in q['o']):
            errs.append(w + ': q(70자)·o 4개(16자) 확인'); continue
        seen.add(q['id']); out['quiz'].append({'id': q['id'], 'q': q['q'], 'o': q['o'], 'c': str(q.get('c') or '새로')[:6], 'wk': str(q.get('wk') or out['week'])})
    for i, sline in enumerate(f.get('imagine') or []):
        if not isinstance(sline, str) or not 5 <= len(sline) <= 90:
            errs.append(f'imagine[{i}]: 5~90자 문장'); continue
        if sline not in out['imagine']:
            out['imagine'].append(sline)
    for i, d in enumerate(f.get('dates') or []):
        w = f'dates[{i}]'
        if not isinstance(d, dict) or not re.match(r'^dtf-[a-z0-9-]{2,30}$', str(d.get('id', ''))):
            errs.append(w + ': id는 dtf-로 시작'); continue
        if d['id'] in seen:
            errs.append(w + ': id 겹침'); continue
        if not isinstance(d.get('t'), str) or not 2 <= len(d['t']) <= 16 or not isinstance(d.get('d'), str) or not 10 <= len(d['d']) <= 90:
            errs.append(w + ': t(16자)·d(10~90자) 확인'); continue
        bad = [k for k, vs in DATE_ENUM.items() if d.get(k, '' if k == 'reg' else None) not in vs]
        if bad or not isinstance(d.get('season'), list) or any(x not in ('봄', '여름', '가을', '겨울') for x in d['season']):
            errs.append(w + ': ' + ','.join(bad or ['season'])); continue
        if re.search(r'\d[\d,]*\s*원', json.dumps(d, ensure_ascii=False)):
            errs.append(w + ': 가격(원)은 넣지 않음'); continue
        seen.add(d['id']); out['dates'].append({k: d.get(k, '') for k in ('id', 't', 'd', 'io', 'time', 'season', 'wx', 'when', 'tag', 'reg', 'place', 'area')} | {'wk': str(d.get('wk') or out['week'])})
    for i, c in enumerate(f.get('courses') or []):
        w = f'courses[{i}]'
        if not isinstance(c, dict) or not re.match(r'^crf-[a-z0-9-]{2,30}$', str(c.get('id', ''))):
            errs.append(w + ': id는 crf-로 시작'); continue
        if c['id'] in seen:
            errs.append(w + ': id 겹침'); continue
        if not isinstance(c.get('t'), str) or not 2 <= len(c['t']) <= 14 or c.get('reg') not in ('충청', '호남', '중간', '전국') or c.get('days') not in (1, 2):
            errs.append(w + ': t(14자)·reg(충청|호남|중간|전국)·days(1|2) 확인'); continue
        st = c.get('steps')
        if not isinstance(st, list) or not 3 <= len(st) <= 12:
            errs.append(w + ': steps 3~12개'); continue
        bad = [j for j, x in enumerate(st) if not isinstance(x, dict) or x.get('k') not in COURSE_K or not isinstance(x.get('n'), str) or not 1 <= len(x['n']) <= 40
               or len(str(x.get('what') or '')) > 60 or (x.get('t100') and not re.match(r'^t\d{3}$', str(x['t100'])))]
        if bad:
            errs.append(w + f': steps{bad} k·n(40자)·what(60자)·t100 확인'); continue
        if re.search(r'\d[\d,]*\s*원', json.dumps(c, ensure_ascii=False)):
            errs.append(w + ': 가격(원)은 넣지 않음'); continue
        keep = ('id', 't', 'reg', 'area', 'days', 'theme', 'season', 'wx', 'io', 'from', 'one', 'steps', 'tips')
        seen.add(c['id']); out['courses'].append({k: c[k] for k in keep if k in c} | {'wk': str(c.get('wk') or out['week'])})
    for i, b in enumerate(f.get('books') or []):   # 책장(v14): 새 추천 책 bkf-…
        w = f'books[{i}]'
        if not isinstance(b, dict) or not re.match(r'^bkf-[a-z0-9-]{2,30}$', str(b.get('id', ''))):
            errs.append(w + ': id는 bkf-로 시작(영문 소문자·숫자·-)'); continue
        if b['id'] in seen:
            errs.append(w + ': id 겹침'); continue
        if not all(isinstance(b.get(k), str) and 1 <= len(b[k].strip()) <= n for k, n in (('t', 60), ('a', 40), ('cat', 12))):
            errs.append(w + ': t(60자)·a(40자)·cat(12자) 확인'); continue
        if len(str(b.get('one') or '')) > 80 or len(str(b.get('why') or '')) > 160 or len(str(b.get('pub') or '')) > 30:
            errs.append(w + ': one(80자)·why(160자)·pub(30자) 확인'); continue
        pg, yr = b.get('pages', 0), b.get('yr', 0)
        if not isinstance(pg, int) or not 0 <= pg <= 3000 or not isinstance(yr, int) or not (yr == 0 or 1000 <= yr <= 2100):
            errs.append(w + ': pages(0~3000 정수)·yr(연도 정수) 확인'); continue
        tags = b.get('tags') or []
        if not isinstance(tags, list) or len(tags) > 6 or not all(isinstance(t, str) and 1 <= len(t) <= 12 for t in tags):
            errs.append(w + ': tags 6개까지(각 12자)'); continue
        src = b.get('src') or []
        if not isinstance(src, list) or len(src) > 5 or not all(isinstance(x, (int, str)) or (isinstance(x, dict) and isinstance(x.get('n'), str)) for x in src):
            errs.append(w + ': src 5개까지(번호·이름·{n,u})'); continue
        if b.get('isbn') is not None and not re.match(r'^(\d{10}|\d{13})$', str(b['isbn'])):
            errs.append(w + ': isbn 은 숫자 10·13자리'); continue
        if re.search(r'\d[\d,]*\s*원', json.dumps(b, ensure_ascii=False)):
            errs.append(w + ': 가격(원)은 넣지 않음'); continue
        keep = ('id', 't', 'a', 'pub', 'yr', 'cat', 'tags', 'one', 'why', 'src', 'pages', 'couple', 'isbn')
        seen.add(b['id']); out['books'].append({k: b[k] for k in keep if k in b} | {'couple': bool(b.get('couple')), 'wk': str(b.get('wk') or out['week'])})
    out['wed'] = []   # v32.3 결혼 준비 소식(지원 제도·시세). 이 목록만 금액(원) 허용
    for i, x in enumerate(f.get('wed') or []):
        w = f'wed[{i}]'
        if not isinstance(x, dict) or not isinstance(x.get('t'), str) or not 2 <= len(x['t']) <= 40 or not isinstance(x.get('d'), str) or not 5 <= len(x['d']) <= 140:
            errs.append(w + ': t(40자)·d(5~140자) 확인'); continue
        u = str(x.get('url') or '')
        if u and not re.match(r'^https://[^\s"\'<>]+$', u):
            errs.append(w + ': url은 https://'); continue
        ver = str(x.get('ver') or '')
        if ver not in ('✓', '⚠', '단일'):
            errs.append(w + ': ver는 ✓/⚠/단일 중 하나'); continue
        out['wed'].append({'t': x['t'], 'd': x['d'], 'url': u, 'ver': ver, 'asof': str(x.get('asof') or '')[:10], 'wk': str(x.get('wk') or out['week'])})
    out['apart'] = {}
    ap = f.get('apart') or {}
    if not isinstance(ap, dict):
        errs.append('apart 는 {풀 이름: [{s, g}]}'); ap = {}
    for k, L in ap.items():
        w = f'apart.{k}'
        if k not in FRESH_AP_POOLS:
            errs.append(f'{w}: 모르는 풀 — {list(FRESH_AP_POOLS)}'); continue
        if not isinstance(L, list) or len(L) > FRESH_AP_MAX:
            errs.append(f'{w}: {FRESH_AP_MAX}개까지 목록'); continue
        ok, last_g, bad = [], '', 0
        for i, x in enumerate(L):
            it = x.get('s') if isinstance(x, dict) else None
            g = str(x.get('g') or '') if isinstance(x, dict) else ''
            if not re.match(r'^20\d{2}-\d{2}-\d{2}$', g) or g < last_g:
                errs.append(f'{w}[{i}]: g(시작 날 YYYY-MM-DD)가 없거나 앞 것보다 이름 — 붙이기만, 날짜 차례대로'); bad += 1; break
            if k in FRESH_AP_STR:
                lo, hi = FRESH_AP_STR[k]
                good = isinstance(it, str) and lo <= len(it.strip()) <= hi
            elif k == 'sur':
                good = isinstance(it, list) and len(it) == 2 and it[0] in FRESH_AP_SUR and isinstance(it[1], str) and 5 <= len(it[1]) <= 30
            elif k == 'role':
                good = isinstance(it, list) and len(it) == 2 and all(isinstance(v, str) and 1 <= len(v) <= 10 for v in it)
            else:   # post
                good = isinstance(it, dict) and isinstance(it.get('p'), str) and 2 <= len(it['p']) <= 30 and it.get('t') in ('real', 'fantasy')
            if not good:
                errs.append(f'{w}[{i}]: 모양·길이 확인(같은 풀 기본 항목과 같은 모양)'); bad += 1
                if bad > 5: break
                continue
            last_g = g
            ok.append({'s': it.strip() if isinstance(it, str) else ({'p': it['p'].strip(), 't': it['t']} if isinstance(it, dict) else [v.strip() for v in it]), 'g': g})
        if ok: out['apart'][k] = ok
    for k, lim in FRESH_MAX.items():
        if len(out[k]) > lim:
            out[k] = out[k][-lim:]        # 오래된 것부터 정리
    for l in (f.get('log') or [])[-30:]:
        if isinstance(l, str) and len(l) <= 120:
            out['log'].append(l)
    if re.search(r'\d[\d,]*\s*원', json.dumps({k: v for k, v in out.items() if k != 'wed'}, ensure_ascii=False)):
        errs.append('가격(원)은 넣지 않음 (결혼 소식 wed만 금액 허용)')
    return out, errs


def cmd_apuse(a):
    """v54 떨어진 날 풀 쓰임(앱이 매주 남기는 'apu' 기록: 풀마다 [나온 수, 오늘 풀 크기]) — 60% 넘은 풀과 붙일 수(크기의 절반 · 한 주 300 까지)를 알려 준다. 기록 내용은 수뿐."""
    s = load_settings(a.settings)
    key = sync_key(s, a.repo)
    recs, bad = sync_records(key, a.sync)
    L = sorted([r for r in recs.values() if isinstance(r, dict) and not r.get('del') and r.get('k') == 'apu' and isinstance(r.get('v'), dict)], key=lambda r: (str(r.get('d') or ''), r.get('t') or 0))
    if not L:
        print(json.dumps({'ok': True, 'd': None, 'note': '아직 apu 기록 없음(앱 v54 이후 매주 월요일 생김) — 붙일 것 없음', 'add': {}}, ensure_ascii=False)); return
    r = L[-1]; pools = {}
    for k, v in (r['v'].get('pools') or {}).items():
        if isinstance(v, list) and len(v) == 2 and all(isinstance(x, (int, float)) for x in v) and v[1] > 0:
            pools[k] = {'shown': int(v[0]), 'size': int(v[1]), 'pct': round(100 * v[0] / v[1])}
    over = sorted([k for k, v in pools.items() if v['pct'] >= 60], key=lambda k: -pools[k]['pct'])
    add = {k: min(FRESH_AP_WEEK, (pools[k]['size'] + 1) // 2) for k in over if k in FRESH_AP_POOLS}
    other = [k for k in over if k not in FRESH_AP_POOLS]   # balance·quiz·imagine 은 기존 목록(balance·quiz·imagine)에 붙인다
    print(json.dumps({'ok': True, 'd': r.get('d'), 'pools': pools, 'over60': over, 'add': add, 'addOther': {k: min(FRESH_AP_WEEK, (pools[k]['size'] + 1) // 2) for k in other}, 'badFiles': len(bad)}, ensure_ascii=False, indent=1))


def cmd_freshopen(a):
    s = load_settings(a.settings)
    aes, _ = keys_for(s, a.repo)
    p = os.path.join(a.repo, 'fresh.json.enc')
    f = json.loads(open_bytes(aes, open(p, 'rb').read())) if os.path.exists(p) else {'v': 1, 'updated': '', 'week': '', 'balance': [], 'quiz': [], 'imagine': [], 'dates': [], 'courses': [], 'books': [], 'wed': [], 'log': []}
    with open(a.out, 'w', encoding='utf-8') as fh:
        json.dump(f, fh, ensure_ascii=False, indent=0)
    print(json.dumps({'opened': a.out, 'week': f.get('week'), 'updated': f.get('updated'), 'counts': {k: len(f.get(k) or []) for k in ('balance', 'quiz', 'imagine', 'dates', 'courses', 'books', 'wed')},
                      'lastIds': {k: [x.get('id') for x in (f.get(k) or [])[-3:]] for k in ('balance', 'quiz', 'dates', 'courses', 'books')}, 'log': (f.get('log') or [])[-3:]}, ensure_ascii=False, indent=1))


def cmd_freshseal(a):
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    today = a.today or _kst_today()
    f = json.load(open(a.fresh, encoding='utf-8'))
    out, errs = fresh_check(f, today)
    if out is not None:   # v54 apart 는 붙이기만: 지난번 것은 그대로 앞에 · 새로 붙인 건 내일부터(g > 오늘) · 풀마다 한 주 300개까지
        oldp = os.path.join(a.repo, 'fresh.json.enc')
        try: old_ap = (json.loads(open_bytes(aes, open(oldp, 'rb').read())).get('apart') or {}) if os.path.exists(oldp) else {}
        except Exception: old_ap = {}
        for k in set(old_ap) | set(out.get('apart') or {}):
            O, N = old_ap.get(k) or [], (out.get('apart') or {}).get(k) or []
            if N[:len(O)] != O:
                errs.append(f'apart.{k}: 지난번 항목 {len(O)}개를 지우거나 바꾸면 안 돼요(앞에 그대로 두고 뒤에 붙이기)'); continue
            new = N[len(O):]
            if any(x['g'] <= today for x in new): errs.append(f'apart.{k}: 새 항목의 g 는 내일 이후(오늘 {today})')
            if len(new) > FRESH_AP_WEEK: errs.append(f'apart.{k}: 이번에 {len(new)}개 — 한 번에 {FRESH_AP_WEEK}개까지')
    if out is None or errs:
        print(json.dumps({'ok': False, 'errors': errs[:40]}, ensure_ascii=False, indent=1)); sys.exit(1)
    import datetime as _dt
    out['updated'] = _dt.datetime.now(_dt.timezone(_dt.timedelta(hours=9))).replace(microsecond=0).isoformat()
    raw = json.dumps(out, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    while len(raw) > FRESH_MAX_KB * 1024 and len(out['courses']) > 24:   # 넘치면 오래된 코스부터(코스가 가장 큼)
        out['courses'] = out['courses'][1:]
        raw = json.dumps(out, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(raw) > FRESH_MAX_KB * 1024:
        print(json.dumps({'ok': False, 'errors': [f'너무 큼 {len(raw)//1024}KB ({FRESH_MAX_KB}KB 이하)']}, ensure_ascii=False)); sys.exit(1)
    with open(os.path.join(a.repo, 'fresh.json.enc'), 'wb') as fh:
        fh.write(seal_bytes(aes, mac, raw))
    wk = out['week']
    print(json.dumps({'ok': True, 'week': wk, 'kb': len(raw) // 1024, 'thisWeek': {k: len([x for x in out[k] if isinstance(x, dict) and x.get('wk') == wk]) for k in ('balance', 'quiz', 'dates', 'courses', 'books')},
                      'imagine': len(out['imagine']), 'total': {k: len(out[k]) for k in ('balance', 'quiz', 'imagine', 'dates', 'courses', 'wed')},
                      'apart': {k: len(v) for k, v in (out.get('apart') or {}).items()}}, ensure_ascii=False, indent=1))


# ---------- 매주 쌓이는 자료(v18): 책 lib.json.enc · 해외여행 world.json.enc ----------
# 앱 빌드(app.html)에 박힌 책 150권·여행지 61곳에 매주 새로 조사한 것을 더해 가는 누적 파일.
# 앱은 책장·해외여행을 열 때(또는 시작 뒤 한가할 때) 받아 빌드 자료와 합친다(같은 id 면 누적 쪽이 이김).
# 새 id 는 접두로 빌드 자료와 구분: 책 bkw-<주>-NNN (예 bkw-2026w41-001), 여행지 trw-<주>-NNN.
LIB_MAX_KB = 3 * 1024          # lib.json 평문 3MB (책 1권 ≈ 0.5KB → 약 40주 치)
WORLD_MAX_KB = 8 * 1024        # world.json 평문 8MB (여행지 1곳 ≈ 10KB → 약 13주 치, 오래된 주는 기본 일정만 남겨 더 버팀)
LIB_WEEK_CAP = 200             # 한 주에 더할 수 있는 책
WORLD_WEEK_CAP = 80            # 한 주에 더할 수 있는 여행지
WORLD_SLIM_WEEKS = 8           # 크기가 넘치면 이 주 수보다 오래된 여행지는 기본 일정만 남김
WK_RE = re.compile(r'^(\d{4})-W(\d{2})$')
DOWS = ('일', '월', '화', '수', '목', '금', '토')
TR_REGIONS = ('일본', '동남아', '중화권', '아시아', '유럽', '북유럽', '북미', '대양주', '중동', '아프리카', '중남미')
TR_STEP_K = ('see', 'do', 'eat', 'cafe', 'stay', 'move', 'fly')
TR_FROM_K = ('청주', '광주/무안', '인천', '김포')
# robots.txt 로 자동 수집을 막은 곳(v9·v15 조사 원칙) — 출처·링크로 들어 있으면 거부
BLOCKED_SRC = re.compile(r'(?i)(?<![a-z0-9-])(?:[a-z0-9-]+\.)*(?:kakao\.com|kko\.to|kakaocdn\.net|brunch\.co\.kr|naver\.com|naver\.me|catchtable\.(?:co\.kr|net)|bluer\.co\.kr|'
                         r'klook\.com|kkday\.com|airport\.co\.kr|skyscanner\.[a-z.]+)(?![a-z0-9-])'
                         r'|(?<![a-z0-9-])(?:maps\.google\.[a-z.]+|(?:www\.)?google\.[a-z.]+/maps|goo\.gl/maps|maps\.app\.goo\.gl)')
SECRET_RE = re.compile(r'gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|\bsk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}'
                       r'|xox[abprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY'
                       r'|(?i:(?:password|passwd|비밀번호|토큰|token|secret|api[_-]?key)\s*[:=：]\s*\S{4,})')
PRICE_RE = re.compile(r'\d[\d,]*\s*원|₩\s*\d')


def _wk_ok(wk):
    m = WK_RE.match(str(wk or ''))
    return bool(m) and 1 <= int(m.group(2)) <= 53


def _wk_slug(wk):          # '2026-W41' → '2026w41'
    return str(wk).lower().replace('-', '')


def _strs(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for k, v in o.items():
            yield str(k)
            yield from _strs(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strs(v)


def _secret_vals(s, repo, aes):
    """설정·cfg 안의 비밀값(토큰·공유 키·알림 주제 등). 값은 비교에만 쓰고 어디에도 출력하지 않는다."""
    sub, word = set(), set()
    if s.get('token') and len(s['token']) >= 8:
        sub.add(s['token'])
    for k in ('pw', 'old_pw'):
        if s.get(k) and len(s[k]) >= 4:
            word.add(s[k])
    cfg = read_cfg(repo, aes) if aes else None
    for v in _strs(cfg or {}):
        if len(v) >= 12 and not v.startswith('http') and ' ' not in v:
            sub.add(v)
    return sub, word


def _leak(obj, sub, word):
    """비밀값처럼 보이는 문자열이 있으면 어디(첫 칸 이름)인지만 돌려준다. 값은 돌려주지 않는다."""
    for v in _strs(obj):
        if SECRET_RE.search(v):
            return True
        if any(x in v for x in sub):
            return True
        if any(re.search(r'(?<![0-9A-Za-z])' + re.escape(w) + r'(?![0-9A-Za-z])', v) for w in word):
            return True
    return False


def _blocked(obj):
    for v in _strs(obj):
        m = BLOCKED_SRC.search(v)
        if m:
            return m.group(0)
    return ''


def _txt(v, lo, hi):
    return isinstance(v, str) and lo <= len(v.strip()) <= hi


def _src_list(src, w, errs, need=0, lim=8):
    """출처: 이름(글) 또는 {n,u}. 번호는 파일마다 뜻이 달라 받지 않는다."""
    if not isinstance(src, list) or len(src) > lim:
        errs.append(f'{w}: src 는 {lim}개까지 목록'); return None
    out = []
    for x in src:
        if isinstance(x, str) and 1 <= len(x.strip()) <= 80:
            out.append(x.strip())
        elif isinstance(x, dict) and _txt(x.get('n'), 1, 80) and (x.get('u') in (None, '') or (isinstance(x.get('u'), str) and re.match(r'^https?://\S{3,300}$', x['u']))):
            out.append({'n': x['n'].strip()} | ({'u': x['u']} if x.get('u') else {}))
        else:
            errs.append(f'{w}: src 는 이름(80자) 또는 {{"n","u":"https://…"}}'); return None
    if len(out) < need:
        errs.append(f'{w}: 출처(src)가 {need}곳 이상 있어야 함'); return None
    return out


def _norm_key(*vals):
    return '|'.join(re.sub(r'[\s·.,:;\'"!?()〈〉《》「」\-]', '', str(v or '')).lower() for v in vals)


def _weeks_check(f, kind, errs):
    weeks, seen = [], set()
    for i, w in enumerate(f.get('weeks') or []):
        at = f'weeks[{i}]'
        if not isinstance(w, dict) or not _wk_ok(w.get('wk')):
            errs.append(at + ': wk 는 "2026-W41" 꼴'); continue
        if w['wk'] in seen:
            errs.append(at + ': 같은 주가 두 번'); continue
        src = _src_list(w.get('src') or [], at, errs, 0, 300)
        if src is None:
            continue
        if len(str(w.get('note') or '')) > 200:
            errs.append(at + ': note 200자까지'); continue
        seen.add(w['wk'])
        weeks.append({'wk': w['wk'], 'n': 0, 'src': src} | ({'note': w['note']} if w.get('note') else {}) | ({'np': 0} if kind == 'world' else {}))
    weeks.sort(key=lambda w: w['wk'])
    return weeks


def _load_base(path, key):
    """--base: 앱 소스의 content/books.json·trips.json(unpacksrc 로 푼 것). id·이름 겹침 검사용"""
    if not path:
        return None
    try:
        b = json.load(open(path, encoding='utf-8'))
        if key == 'places' and 'places' not in b:
            return (b.get('food') or []) + (b.get('stay') or [])   # content/places.json
        return b.get(key) or []
    except Exception as e:
        die(f'--base 읽기 실패: {type(e).__name__}')


def _keep_refs(s, repo, syncdir, pre):
    """--sync: 두 사람 기록(♥·읽는 중·우리 여행 등)이 가리키는 누적 id 는 정리하지 않는다"""
    if not syncdir:
        return set()
    try:
        key = sync_key(s, repo)
        recs, _ = sync_records(key, syncdir)
    except SystemExit:
        return set()
    return {str(r.get('ref')) for r in recs.values() if isinstance(r, dict) and str(r.get('ref') or '').startswith(pre)}


def _book_check(b, w, errs):
    if not all(_txt(b.get(k), 1, n) for k, n in (('t', 60), ('a', 40), ('cat', 12), ('one', 80), ('why', 160))):
        errs.append(w + ': t(60자)·a(40자)·cat(12자)·one(80자)·why(160자) 모두 필요'); return None
    if len(str(b.get('pub') or '')) > 30:
        errs.append(w + ': pub 30자까지'); return None
    pg, yr = b.get('pages', 0), b.get('yr', 0)
    if not isinstance(pg, int) or isinstance(pg, bool) or not 0 <= pg <= 3000 or not isinstance(yr, int) or isinstance(yr, bool) or not (yr == 0 or 1000 <= yr <= 2100):
        errs.append(w + ': pages(0~3000 정수)·yr(연도 정수) 확인'); return None
    tags = b.get('tags') or []
    if not isinstance(tags, list) or len(tags) > 6 or not all(_txt(t, 1, 12) for t in tags):
        errs.append(w + ': tags 6개까지(각 12자)'); return None
    src = _src_list(b.get('src') or [], w, errs, 1, 5)
    if src is None:
        return None
    if b.get('isbn') not in (None, '') and not re.match(r'^(\d{10}|\d{13})$', str(b['isbn'])):
        errs.append(w + ': isbn 은 숫자 10·13자리'); return None
    if any(k in b for k in ('price', 'pr', '가격', 'cost')) or PRICE_RE.search(json.dumps(b, ensure_ascii=False)):
        errs.append(w + ': 책에는 가격을 넣지 않음'); return None
    keep = ('id', 'wk', 't', 'a', 'pub', 'yr', 'cat', 'tags', 'one', 'why', 'pages', 'isbn')
    return {k: b[k] for k in keep if k in b and b[k] not in (None, '')} | {'src': src, 'couple': bool(b.get('couple'))}


def lib_check(f, base=None, keep=frozenset(), max_kb=LIB_MAX_KB):
    """lib.json 검사·정리. (정리된 것, 오류 목록, 정보) — 오류가 하나라도 있으면 올리지 않는다."""
    errs, info = [], {'pruned': 0, 'prunedWeeks': []}
    if not isinstance(f, dict) or f.get('v') != 1:
        return None, ['맨 위 형식이 {"v":1,"weeks":[],"books":[]} 가 아님'], info
    for k in f:
        if k not in ('v', 'updated', 'dow', 'weeks', 'books'):
            errs.append(f'모르는 칸 "{k}"')
    if f.get('dow') not in (None, '') and f.get('dow') not in DOWS:
        errs.append('dow 는 일·월·화·수·목·금·토 중 하나')
    weeks = _weeks_check(f, 'lib', errs)
    wkset = {w['wk'] for w in weeks}
    books, ids, names = [], set(), {}
    base_ids = {str(x.get('id')) for x in (base or [])}
    base_names = {_norm_key(x.get('t'), x.get('a')) for x in (base or [])}
    for i, b in enumerate(f.get('books') or []):
        w = f'books[{i}]'
        if not isinstance(b, dict):
            errs.append(w + ': 모양이 {…} 가 아님'); continue
        m = re.match(r'^bkw-(\d{4}w\d{2})-(\d{3})$', str(b.get('id', '')))
        if not m:
            errs.append(w + ': id 는 bkw-<주>-NNN (예 bkw-2026w41-001)'); continue
        wk = str(b.get('wk') or '')
        if not _wk_ok(wk) or _wk_slug(wk) != m.group(1):
            errs.append(w + f': wk 와 id 의 주가 다름({b["id"]})'); continue
        if wk not in wkset:
            errs.append(w + f': weeks 에 {wk} 가 없음'); continue
        if b['id'] in ids or b['id'] in base_ids:
            errs.append(w + f': id 겹침 {b["id"]}'); continue
        y = _book_check(b, w, errs)
        if not y:
            continue
        nk = _norm_key(y['t'], y['a'])
        if nk in names:
            errs.append(w + f': 같은 책(제목·저자)이 이미 있음 — {names[nk]}'); continue
        if nk in base_names:
            errs.append(w + ': 앱에 이미 있는 책(제목·저자)'); continue
        ids.add(y['id']); names[nk] = y['id']
        books.append(y)
    for wk in wkset:
        n = sum(1 for b in books if b['wk'] == wk)
        if n > LIB_WEEK_CAP:
            errs.append(f'{wk}: 한 주 책 {n}권 — {LIB_WEEK_CAP}권까지')
    out = {'v': 1, 'updated': str(f.get('updated') or ''), 'dow': f.get('dow') or '', 'weeks': weeks, 'books': books}
    _prune(out, 'books', keep, max_kb, info, slim=None)
    for w in out['weeks']:
        w['n'] = sum(1 for b in out['books'] if b['wk'] == w['wk'])
    return out, errs, info


def _pair(v, lo=0, hi=100_000_000):
    return isinstance(v, list) and len(v) == 2 and all(isinstance(x, int) and not isinstance(x, bool) and lo <= x <= hi for x in v) and v[0] <= v[1]


def _cost_check(c, w, errs, need=True):
    if not isinstance(c, dict):
        errs.append(w + ': cost 는 {…}'); return None
    req = ('air', 'stay', 'food', 'act', 'total2') if need else ()
    for k in req:
        if k not in c:
            errs.append(w + f': cost.{k} 필요([최소, 최대] 원, 1인 — total2 는 둘이)'); return None
    out = {}
    for k in ('air', 'stay', 'food', 'local', 'act', 'total2'):
        if k in c:
            if not _pair(c[k]):
                errs.append(w + f': cost.{k} 는 [최소, 최대] 정수(원)'); return None
            out[k] = c[k]
    if not out:
        errs.append(w + ': cost 에 바꿀 값이 없음'); return None
    if c.get('note') not in (None, '') and not _txt(c['note'], 1, 600):
        errs.append(w + ': cost.note 600자까지'); return None
    if c.get('asof') not in (None, '') and not re.match(r'^\d{4}-\d{2}(-\d{2})?$', str(c['asof'])):
        errs.append(w + ': cost.asof 는 2026-10 또는 2026-10-08'); return None
    return out | {k: c[k] for k in ('note', 'asof') if c.get(k)}


def _strlist(v, n, ln):
    return isinstance(v, list) and len(v) <= n and all(_txt(x, 1, ln) for x in v)


def _trip_check(t, w, errs):
    for k, n in (('country', 20), ('city', 30), ('flag', 8), ('one', 80)):
        if not _txt(t.get(k), 1, n):
            errs.append(w + f': {k}({n}자) 필요'); return None
    if t.get('region') not in TR_REGIONS:
        errs.append(w + ': region 은 ' + '·'.join(TR_REGIONS) + ' 중 하나'); return None
    if t.get('lv') not in (0, 1, 2) or isinstance(t.get('lv'), bool):
        errs.append(w + ': lv(이 도시의 외교부 여행경보 단계 0~2) 필요 — 3단계(출국권고) 이상은 넣지 않음'); return None
    if not _strlist(t.get('tags') or [], 8, 12):
        errs.append(w + ': tags 8개까지(각 12자)'); return None
    for k in ('best', 'avoid'):
        v = t.get(k) or []
        if not isinstance(v, list) or len(v) > 12 or not all((isinstance(x, int) and not isinstance(x, bool) and 1 <= x <= 12) or _txt(x, 1, 40) for x in v):
            errs.append(w + f': {k} 는 달(1~12) 또는 40자 글 목록'); return None
    if not t.get('best'):
        errs.append(w + ': best(가기 좋은 달) 필요'); return None
    fly = t.get('fly')
    if not isinstance(fly, dict) or not isinstance(fly.get('from'), dict) or not fly['from'] or any(k not in TR_FROM_K for k in fly['from']) \
            or not all(_txt(v, 1, 160) or (isinstance(v, dict) and len(json.dumps(v, ensure_ascii=False)) <= 300) for v in fly['from'].values()) \
            or not (_txt(fly.get('hours'), 1, 60) or isinstance(fly.get('hours'), (int, float))) or len(str(fly.get('airport') or '')) > 100:
        errs.append(w + ': fly {from{청주·광주/무안·인천·김포: 160자}, hours(60자), airport(100자)} 확인'); return None
    cost = _cost_check(t.get('cost'), w, errs, True)
    if not cost:
        return None
    prep = t.get('prep')
    if not isinstance(prep, dict) or not _txt(prep.get('visa'), 1, 400) or not _txt(prep.get('safety'), 1, 300):
        errs.append(w + ': prep.visa(400자)·prep.safety(300자) 필요'); return None
    for k, v in prep.items():
        if k == 'apps':
            if not _strlist(v, 8, 40):
                errs.append(w + ': prep.apps 8개까지(40자)'); return None
        elif k not in ('visa', 'plug', 'tip', 'sim', 'safety', 'health') or not _txt(v, 1, 400):
            errs.append(w + f': prep.{k} 확인(visa·plug·tip·sim·safety·health 400자, apps)'); return None
    plans = t.get('plans')
    if not isinstance(plans, list) or not 1 <= len(plans) <= 4:
        errs.append(w + ': plans 1~4개'); return None
    pids = set()
    for j, p in enumerate(plans):
        pw = f'{w}.plans[{j}]'
        if not isinstance(p, dict) or not _txt(p.get('id'), 3, 40) or p['id'] in pids or not _txt(p.get('t'), 1, 40):
            errs.append(pw + ': id(40자, 겹치지 않게)·t(40자)'); return None
        if not isinstance(p.get('nights'), int) or isinstance(p.get('nights'), bool) or not 0 <= p['nights'] <= 30 or not isinstance(p.get('basic', False), bool):
            errs.append(pw + ': nights(0~30 정수)·basic(true/false)'); return None
        days = p.get('days')
        if not isinstance(days, list) or not 1 <= len(days) <= 16:
            errs.append(pw + ': days 1~16일'); return None
        for d_, dy in enumerate(days):
            st = dy.get('steps') if isinstance(dy, dict) else None
            if not isinstance(st, list) or not 1 <= len(st) <= 14 or not isinstance(dy.get('day'), int):
                errs.append(pw + f'.days[{d_}]: day(정수)·steps 1~14개'); return None
            for s_, x in enumerate(st):
                if not isinstance(x, dict) or x.get('k') not in TR_STEP_K or not _txt(x.get('n'), 1, 40) \
                        or any(len(str(x.get(k) or '')) > n for k, n in (('tm', 11), ('what', 90), ('area', 30), ('cost', 60), ('book', 30), ('tip', 80))):
                    errs.append(pw + f'.days[{d_}].steps[{s_}]: k(see·do·eat·cafe·stay·move·fly)·n(40자)·what(90자)·tm·area·cost·book·tip 길이'); return None
        for k in ('rain', 'couple'):
            if k in p and not _strlist(p[k], 6, 80):
                errs.append(pw + f': {k} 6개까지(80자)'); return None
        pids.add(p['id'])
    if sum(1 for p in plans if p.get('basic')) != 1:
        errs.append(w + ': basic 일정은 꼭 하나'); return None
    if 'souvenir' in t and not _strlist(t['souvenir'], 8, 40):
        errs.append(w + ': souvenir 8개까지(40자)'); return None
    if t.get('cur') not in (None, '') and not re.match(r'^[A-Z]{3}$', str(t['cur'])):
        errs.append(w + ': cur 는 통화 코드 3자(예 NOK)'); return None
    au = t.get('aurora')
    if au is not None:
        if not isinstance(au, dict) or not au.get('months') or not isinstance(au['months'], list) or not all(k in ('months', 'best', 'spot', 'odds', 'tour', 'moon', 'stay', 'wear', 'photo', 'couple') for k in au) \
                or not all(_txt(v, 1, 240) for k, v in au.items() if k != 'months'):
            errs.append(w + ': aurora {months[], best·spot·odds·tour·moon·stay·wear·photo·couple 240자}'); return None
    keep = ('id', 'wk', 'country', 'city', 'flag', 'region', 'lv', 'fly', 'best', 'avoid', 'one', 'tags', 'prep', 'plans', 'souvenir', 'cur', 'aurora')
    return {k: t[k] for k in keep if k in t} | {'cost': cost}


def _fx_check(fx, errs):
    if fx in (None, {}):
        return {}
    if not isinstance(fx, dict) or not re.match(r'^\d{4}-\d{2}-\d{2}$', str(fx.get('기준일', ''))):
        errs.append('fx: {"기준일":"2026-10-08","출처":…,"단위":"외화 1단위당 원","JPY":8.6,…}'); return {}
    out = {}
    for k, v in fx.items():
        if k in ('기준일',):
            out[k] = v
        elif k in ('출처', '단위'):
            if not _txt(v, 1, 200):
                errs.append(f'fx.{k}: 200자까지'); return {}
            out[k] = v
        elif re.match(r'^[A-Z]{3}$', k) and isinstance(v, (int, float)) and not isinstance(v, bool) and 0 < v < 100000:
            out[k] = v
        else:
            errs.append(f'fx.{k}: 통화 코드 3자 → 1단위당 원(0보다 큰 수)'); return {}
    return out


def world_check(f, base=None, keep=frozenset(), max_kb=WORLD_MAX_KB):
    errs, info = [], {'pruned': 0, 'prunedWeeks': [], 'slimmed': 0}
    if not isinstance(f, dict) or f.get('v') != 1:
        return None, ['맨 위 형식이 {"v":1,"fx":{},"weeks":[],"trips":[],"patch":{}} 가 아님'], info
    for k in f:
        if k not in ('v', 'updated', 'dow', 'fx', 'weeks', 'trips', 'patch'):
            errs.append(f'모르는 칸 "{k}"')
    if f.get('dow') not in (None, '') and f.get('dow') not in DOWS:
        errs.append('dow 는 일·월·화·수·목·금·토 중 하나')
    weeks = _weeks_check(f, 'world', errs)
    wkset = {w['wk'] for w in weeks}
    fx = _fx_check(f.get('fx'), errs)
    trips, ids, names = [], set(), {}
    base_ids = {str(x.get('id')) for x in (base or [])}
    base_names = {_norm_key(x.get('country'), x.get('city')) for x in (base or [])}
    for i, t in enumerate(f.get('trips') or []):
        w = f'trips[{i}]'
        if not isinstance(t, dict):
            errs.append(w + ': 모양이 {…} 가 아님'); continue
        m = re.match(r'^trw-(\d{4}w\d{2})-(\d{3})$', str(t.get('id', '')))
        if not m:
            errs.append(w + ': id 는 trw-<주>-NNN (예 trw-2026w41-001)'); continue
        wk = str(t.get('wk') or '')
        if not _wk_ok(wk) or _wk_slug(wk) != m.group(1):
            errs.append(w + f': wk 와 id 의 주가 다름({t["id"]})'); continue
        if wk not in wkset:
            errs.append(w + f': weeks 에 {wk} 가 없음'); continue
        if t['id'] in ids or t['id'] in base_ids:
            errs.append(w + f': id 겹침 {t["id"]}'); continue
        y = _trip_check(t, w + f'({t["id"]})', errs)
        if not y:
            continue
        nk = _norm_key(y['country'], y['city'])
        if nk in names:
            errs.append(w + f': 같은 여행지(나라·도시)가 이미 있음 — {names[nk]}'); continue
        if nk in base_names:
            errs.append(w + ': 앱에 이미 있는 여행지(나라·도시) — 비용 갱신은 patch 로'); continue
        ids.add(y['id']); names[nk] = y['id']
        trips.append(y)
    for wk in wkset:
        n = sum(1 for t in trips if t['wk'] == wk)
        if n > WORLD_WEEK_CAP:
            errs.append(f'{wk}: 한 주 여행지 {n}곳 — {WORLD_WEEK_CAP}곳까지')
    patch = {}
    P = f.get('patch') or {}
    if not isinstance(P, dict):
        errs.append('patch 는 {"여행지 id": {"cost":{…},"asof":"2026-10","wk":"2026-W41"}}')
        P = {}
    for pid, p in P.items():
        w = f'patch[{pid}]'
        if not re.match(r'^(tr-[a-z0-9-]{2,40}|trw-\d{4}w\d{2}-\d{3})$', str(pid)):
            errs.append(w + ': 키는 여행지 id(tr-… 또는 trw-…)'); continue
        if base is not None and pid.startswith('tr-') and pid not in base_ids:
            errs.append(w + ': 앱에 없는 여행지 id'); continue
        if pid.startswith('trw-') and pid not in ids:
            errs.append(w + ': 누적 여행지(trw-)는 trips 에서 바로 고치기'); continue
        if not isinstance(p, dict) or not isinstance(p.get('cost'), dict):
            errs.append(w + ': {"cost":{…},"asof":…,"wk":…}'); continue
        c = _cost_check(p['cost'], w, errs, False)
        if not c:
            continue
        asof = str(p.get('asof') or c.get('asof') or '')
        if not re.match(r'^\d{4}-\d{2}(-\d{2})?$', asof):
            errs.append(w + ': asof(조사 시점 2026-10 또는 2026-10-08) 필요'); continue
        wk = str(p.get('wk') or '')
        if wk and not _wk_ok(wk):
            errs.append(w + ': wk 는 "2026-W41" 꼴'); continue
        patch[pid] = {'cost': c, 'asof': asof} | ({'wk': wk} if wk else {})
    out = {'v': 1, 'updated': str(f.get('updated') or ''), 'dow': f.get('dow') or '', 'fx': fx, 'weeks': weeks, 'trips': trips, 'patch': patch}
    _prune(out, 'trips', keep, max_kb, info, slim=WORLD_SLIM_WEEKS)
    for w in out['weeks']:
        w['n'] = sum(1 for t in out['trips'] if t['wk'] == w['wk'])
        w['np'] = sum(1 for p in out['patch'].values() if p.get('wk') == w['wk'])
    return out, errs, info


def _size_kb(o):
    return len(json.dumps(o, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) / 1024



# ---------- 매주 장소(v22): plc.json.enc — 먹을 곳·잘 곳 새 곳 + 재확인(폐업·이전) + 증거 보강 + 순서표 + 출처 장부 ----------
PLC_MAX_KB = 3 * 1024
PLC_WEEK_CAP = 200
PLC_FCATS = ('한식', '고기', '국밥·탕', '면', '중식', '일식', '양식', '분식', '카페', '브런치')
PLC_SCATS = ('호텔', '모텔', '독채')
PLC_PATCH_K = {'vf', 'st', 'wk', 'note', 'addr', 'url', 'open', 'vsrc', 'sc', 'badge', 'plat', 'bluer', 'src'}
DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
PLC_CLAUDE_BLOCK = re.compile(r'(?i)diningcode\.com|tripadvisor\.|yna\.co\.kr|tripinfo\.co\.kr|daangn\.com|tabling\.co\.kr|redtable\.|localmap\.co\.kr|jidoro\.com|skweb\.cjsmarttour')   # 2026-W40 robots 확인


def plc_check(f, base=None, keep=frozenset(), max_kb=PLC_MAX_KB):
    errs, info = [], {'pruned': 0, 'prunedWeeks': []}
    if not isinstance(f, dict) or f.get('v') != 1:
        return None, ['맨 위 형식이 {"v":1,"weeks":[],"places":[],"patch":{},"rank":{},"ledger":{}} 가 아님'], info
    for k in f:
        if k not in ('v', 'updated', 'dow', 'weeks', 'places', 'patch', 'rank', 'ledger'):
            errs.append(f'모르는 칸 "{k}"')
    weeks = _weeks_check(f, 'plc', errs)
    wkset = {w['wk'] for w in weeks}
    base_ids = {str(x.get('id')) for x in (base or [])}
    places, ids = [], set()
    for i, x in enumerate(f.get('places') or []):
        w = f'places[{i}]'
        m = re.match(r'^plw-(\d{4}w\d{2})-(\d{3})$', str((x or {}).get('id', '')))
        if not isinstance(x, dict) or not m:
            errs.append(w + ': id 는 plw-<주>-NNN'); continue
        if _wk_slug(x.get('wk')) != m.group(1) or x['wk'] not in wkset:
            errs.append(w + ': wk 가 id·weeks 와 안 맞음'); continue
        if x['id'] in ids or x['id'] in base_ids:
            errs.append(w + f': id 겹침 {x["id"]}'); continue
        if x.get('city') not in ('청주', '광주') or x.get('kind') not in ('food', 'stay') or x.get('cat') not in (PLC_FCATS if x.get('kind') == 'food' else PLC_SCATS):
            errs.append(w + ': city(청주·광주)·kind(food·stay)·cat 확인'); continue
        if not _txt(x.get('n'), 1, 40) or not _txt(x.get('addr'), 4, 80) or not isinstance(x.get('km'), (int, float)) or not 0 <= x['km'] <= 20.5:
            errs.append(w + ': n(40자)·addr(80자)·km(0~20) 확인'); continue
        src = _src_list(x.get('src') or [], w, errs, 2, 6)
        if src is None:
            continue
        if PRICE_RE.search(json.dumps(x, ensure_ascii=False)) or any(k in x for k in ('price', 'cost', '가격')):
            errs.append(w + ': 장소에는 가격을 넣지 않음'); continue
        if not isinstance(x.get('sc'), (int, float)) or not DATE_RE.match(str(x.get('vf') or '')):
            errs.append(w + ': sc(숫자)·vf(날짜) 필요'); continue
        ids.add(x['id'])
        places.append(dict(x) | {'src': src})
    for wk in wkset:
        n = sum(1 for x in places if x['wk'] == wk)
        if n > PLC_WEEK_CAP:
            errs.append(f'{wk}: 한 주 새 곳 {n} — {PLC_WEEK_CAP}곳까지')
    known = base_ids | ids
    patch = {}
    for i, p in (f.get('patch') or {}).items():
        w = f'patch[{i}]'
        if base is not None and i not in known:
            errs.append(w + ': 없는 장소 id'); continue
        if not isinstance(p, dict) or set(p) - PLC_PATCH_K:
            errs.append(w + f': 칸은 {sorted(PLC_PATCH_K)} 만'); continue
        if p.get('st') not in (None, 'ok', 'closed', 'moved', 'unsure') or (p.get('vf') and not DATE_RE.match(str(p['vf']))):
            errs.append(w + ': st(ok·closed·moved·unsure)·vf(날짜) 확인'); continue
        if PRICE_RE.search(json.dumps(p, ensure_ascii=False)):
            errs.append(w + ': 가격 글자'); continue
        patch[i] = p
    rank = {}
    for i, r in (f.get('rank') or {}).items():
        if not (isinstance(r, list) and len(r) == 2 and isinstance(r[0], int) and r[1] in (0, 1)):
            errs.append(f'rank[{i}]: [순서, 0|1]'); break
        rank[i] = r
    led = f.get('ledger') or {}
    if not isinstance(led, dict) or len(json.dumps(led, ensure_ascii=False)) > 200 * 1024:
        errs.append('ledger 는 200KB 이하 {…}')
    bad = PLC_CLAUDE_BLOCK.search(json.dumps({'p': places, 'x': patch}, ensure_ascii=False))
    if bad:
        errs.append(f'robots 가 Claude 봇을 막는 출처가 들어 있음: {bad.group(0)}')
    out = {'v': 1, 'updated': str(f.get('updated') or ''), 'dow': f.get('dow') or '수', 'weeks': weeks, 'places': places, 'patch': patch, 'rank': rank, 'ledger': led}
    for w in out['weeks']:
        w['n'] = sum(1 for x in places if x['wk'] == w['wk'])
    return out, errs, info

def _prune(out, key, keep, max_kb, info, slim=None):
    """크기 한도를 넘으면 오래된 주부터 정리. ①(여행지) 오래된 주는 기본 일정만 남김 ②그래도 넘으면 오래된 주를 통째로 뺌.
    두 사람 기록이 가리키는 id(keep)와 가장 새 주는 남긴다."""
    if _size_kb(out) <= max_kb:
        return
    wks = [w['wk'] for w in out['weeks']]
    if slim is not None:
        for wk in wks[:-slim] if len(wks) > slim else []:
            for t in out[key]:
                if t['wk'] == wk and len(t['plans']) > 1:
                    t['plans'] = [p for p in t['plans'] if p.get('basic')]
                    info['slimmed'] += 1
            if _size_kb(out) <= max_kb:
                return
    for wk in wks[:-1]:
        before = len(out[key])
        out[key] = [x for x in out[key] if x['wk'] != wk or x['id'] in keep]
        info['pruned'] += before - len(out[key])
        if not any(x['wk'] == wk for x in out[key]):
            out['weeks'] = [w for w in out['weeks'] if w['wk'] != wk]
        info['prunedWeeks'].append(wk)
        if _size_kb(out) <= max_kb:
            return


MVW_MAX_KB = 2 * 1024          # mvw.json 평문 2MB (영화 1편 ≈ 1KB → 약 1년 치)
MVW_WEEK_CAP = 40              # 한 주에 더할 수 있는 영화
MV_CATS = ('romance', 'comedy', 'thriller', 'horror', 'action', 'sf', 'drama', 'animation')
MV_ORG = ('N', 'L', 'G', 'Y', 'T', 'D', 'V', 'C', 'W', 'A')   # 넷플릭스 오리지널·라이선스·지브리·유튜브·극장·디즈니+·티빙·쿠팡플레이·왓챠·애플TV+


def _film_check(b, w, errs):
    if not all(_txt(b.get(k), 1, n) for k, n in (('ko', 60), ('country', 20), ('director', 40), ('tag', 80), ('syn', 320), ('talk', 80))):
        errs.append(w + ': ko(60자)·country(20)·director(40)·tag(80)·syn(320)·talk(80) 모두 필요'); return None
    if b.get('cat') not in MV_CATS:
        errs.append(w + ': cat 은 ' + '·'.join(MV_CATS) + ' 중 하나'); return None
    if b.get('origin') not in MV_ORG:
        errs.append(w + ': origin 은 ' + '·'.join(MV_ORG) + ' 중 하나'); return None
    yr, rt = b.get('year'), b.get('rt')
    if not isinstance(yr, int) or isinstance(yr, bool) or not 1900 <= yr <= 2100:
        errs.append(w + ': year 는 연도 정수'); return None
    if rt is not None and (not isinstance(rt, int) or isinstance(rt, bool) or not 20 <= rt <= 400):
        errs.append(w + ': rt 는 분(정수) 또는 null'); return None
    m = b.get('m')
    if not (isinstance(m, list) and len(m) == 3 and all(isinstance(x, int) and not isinstance(x, bool) and 1 <= x <= 5 for x in m)):
        errs.append(w + ': m 은 [가볍게, 몰입, 여운] 1~5 정수 3개'); return None
    cast = b.get('cast') or []
    if not isinstance(cast, list) or len(cast) > 6 or not all(_txt(c, 1, 24) for c in cast):
        errs.append(w + ': cast 6명까지(각 24자)'); return None
    if b.get('orig') not in (None, '') and not _txt(b.get('orig'), 1, 90):
        errs.append(w + ': orig 90자까지'); return None
    src = _src_list(b.get('src') or [], w, errs, 2, 5)
    if src is None:
        return None
    if any(k in b for k in ('price', 'pr', '가격', 'cost')) or PRICE_RE.search(json.dumps(b, ensure_ascii=False)):
        errs.append(w + ': 영화에는 가격을 넣지 않음'); return None
    keep = ('id', 'wk', 'cat', 'ko', 'orig', 'year', 'country', 'rt', 'director', 'origin', 'tag', 'syn', 'talk', 'm')
    return {k: b[k] for k in keep if k in b and b[k] not in (None, '')} | {'rt': rt, 'cast': cast, 'r19': bool(b.get('r19')), 'src': src}


def mvw_check(f, base=None, keep=frozenset(), max_kb=MVW_MAX_KB):
    """mvw.json(매주 영화책) 검사·정리. 오류가 하나라도 있으면 올리지 않는다."""
    errs, info = [], {'pruned': 0, 'prunedWeeks': []}
    if not isinstance(f, dict) or f.get('v') != 1:
        return None, ['맨 위 형식이 {"v":1,"weeks":[],"films":[]} 가 아님'], info
    for k in f:
        if k not in ('v', 'updated', 'dow', 'weeks', 'films'):
            errs.append(f'모르는 칸 "{k}"')
    weeks = _weeks_check(f, 'mvw', errs)
    wkset = {w['wk'] for w in weeks}
    films, ids, names = [], set(), {}
    base_names = set()
    for x in (base or []):
        for v in (x.get('ko'), x.get('orig')):
            if v:
                base_names.add(_norm_key(v))
    for i, b in enumerate(f.get('films') or []):
        w = f'films[{i}]'
        if not isinstance(b, dict):
            errs.append(w + ': 모양이 {…} 가 아님'); continue
        m = re.match(r'^mvw-(\d{4}w\d{2})-(\d{3})$', str(b.get('id', '')))
        if not m:
            errs.append(w + ': id 는 mvw-<주>-NNN (예 mvw-2026w42-001)'); continue
        wk = str(b.get('wk') or '')
        if not _wk_ok(wk) or _wk_slug(wk) != m.group(1):
            errs.append(w + f': wk 와 id 의 주가 다름({b["id"]})'); continue
        if wk not in wkset:
            errs.append(w + f': weeks 에 {wk} 가 없음'); continue
        if b['id'] in ids:
            errs.append(w + f': id 겹침 {b["id"]}'); continue
        y = _film_check(b, w, errs)
        if not y:
            continue
        nk = _norm_key(y['ko'])
        if nk in names:
            errs.append(w + f': 같은 영화가 이미 있음 — {names[nk]}'); continue
        if nk in base_names or (y.get('orig') and _norm_key(y['orig']) in base_names):
            errs.append(w + ': 영화책에 이미 있는 영화'); continue
        ids.add(y['id']); names[nk] = y['id']
        films.append(y)
    for wk in wkset:
        n = sum(1 for b in films if b['wk'] == wk)
        if n > MVW_WEEK_CAP:
            errs.append(f'{wk}: 한 주 영화 {n}편 — {MVW_WEEK_CAP}편까지')
    out = {'v': 1, 'updated': str(f.get('updated') or ''), 'dow': f.get('dow') or '금', 'weeks': weeks, 'films': films}
    _prune(out, 'films', keep, max_kb, info, slim=None)
    for w in out['weeks']:
        w['n'] = sum(1 for b in out['films'] if b['wk'] == w['wk'])
    return out, errs, info


def _kst_now_iso():
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone(_dt.timedelta(hours=9))).replace(microsecond=0).isoformat()


WEEKLY = {
    'lib': {'file': 'lib.json.enc', 'items': 'books', 'check': lib_check, 'max': LIB_MAX_KB, 'pre': 'bkw-', 'base': 'books',
            'empty': lambda: {'v': 1, 'updated': '', 'dow': '', 'weeks': [], 'books': []}},
    'world': {'file': 'world.json.enc', 'items': 'trips', 'check': world_check, 'max': WORLD_MAX_KB, 'pre': 'trw-', 'base': 'trips',
              'empty': lambda: {'v': 1, 'updated': '', 'dow': '', 'fx': {}, 'weeks': [], 'trips': [], 'patch': {}}},
    'mvw': {'file': 'mvw.json.enc', 'items': 'films', 'check': mvw_check, 'max': MVW_MAX_KB, 'pre': 'mvw-', 'base': 'movies',
            'empty': lambda: {'v': 1, 'updated': '', 'dow': '금', 'weeks': [], 'films': []}},
    'plc': {'file': 'plc.json.enc', 'items': 'places', 'check': plc_check, 'max': PLC_MAX_KB, 'pre': 'plw-', 'base': 'places',
            'empty': lambda: {'v': 1, 'updated': '', 'dow': '수', 'weeks': [], 'places': [], 'patch': {}, 'rank': {}, 'ledger': {'dom': {}, 'rot': 0, 'cand': []}}},
}


def weekly_open(kind, a):
    W = WEEKLY[kind]
    s = load_settings(a.settings)
    aes, _ = keys_for(s, a.repo)
    p = os.path.join(a.repo, W['file'])
    f = json.loads(open_bytes(aes, open(p, 'rb').read())) if os.path.exists(p) else W['empty']()
    with open(a.out, 'w', encoding='utf-8') as fh:
        json.dump(f, fh, ensure_ascii=False, indent=0)
    os.chmod(a.out, 0o600)
    L = f.get(W['items']) or []
    rep = {'opened': a.out, 'updated': f.get('updated'), 'kb': round(_size_kb(f)), 'maxKb': W['max'], 'counts': {W['items']: len(L), 'weeks': len(f.get('weeks') or [])},
           'weeks': [{'wk': w.get('wk'), 'n': w.get('n')} for w in (f.get('weeks') or [])[-4:]], 'lastIds': [x.get('id') for x in L[-3:]]}
    if kind == 'world':
        rep['counts']['patch'] = len(f.get('patch') or {})
        rep['fx'] = (f.get('fx') or {}).get('기준일')
    print(json.dumps(rep, ensure_ascii=False, indent=1))


def weekly_seal(kind, a):
    W = WEEKLY[kind]
    s = load_settings(a.settings)
    aes, mac = keys_for(s, a.repo)
    try:
        f = json.load(open(getattr(a, 'in'), encoding='utf-8'))
    except Exception as e:
        print(json.dumps({'ok': False, 'errors': [f'JSON 형식 오류: {e}'], 'counts': {}}, ensure_ascii=False, indent=1)); sys.exit(1)
    base = _load_base(a.base, W['base'])
    keep = _keep_refs(s, a.repo, a.sync, W['pre'])
    out, errs, info = W['check'](f, base, keep, W['max'])
    if out is not None:
        bad = _blocked(out) or _blocked(f.get('weeks') or [])
        if bad:
            errs.append(f'자동 수집 금지 출처(robots.txt)가 들어 있음: {bad}')
        sub, word = _secret_vals(s, a.repo, aes)
        if _leak(f, sub, word):
            errs.append('비밀값처럼 보이는 문자열이 있음(토큰·비밀번호·키 모양) — 지우고 다시')
    counts = {}
    if out is not None:
        L = out[W['items']]
        last = out['weeks'][-1]['wk'] if out['weeks'] else ''
        counts = {W['items']: len(L), 'weeks': len(out['weeks']), 'lastWeek': last, 'thisWeek': sum(1 for x in L if x['wk'] == last),
                  'kept': len(keep), 'pruned': info['pruned'], 'prunedWeeks': info['prunedWeeks'], 'kb': round(_size_kb(out))}
        if kind == 'world':
            counts |= {'patch': len(out['patch']), 'slimmed': info['slimmed'], 'fx': (out['fx'] or {}).get('기준일', '')}
    if out is None or errs:
        print(json.dumps({'ok': False, 'errors': errs[:40], 'counts': counts}, ensure_ascii=False, indent=1)); sys.exit(1)
    out['updated'] = _kst_now_iso()
    raw = json.dumps(out, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(raw) > W['max'] * 1024:
        print(json.dumps({'ok': False, 'errors': [f'너무 큼 {len(raw)//1024}KB ({W["max"]}KB 이하) — 이번 주 것을 줄여야 함'], 'counts': counts}, ensure_ascii=False, indent=1)); sys.exit(1)
    ch = write_if_changed(os.path.join(a.repo, W['file']), seal_bytes(aes, mac, raw))
    counts['kb'] = len(raw) // 1024
    print(json.dumps({'ok': True, 'errors': [], 'counts': counts, 'changed': ch, 'file': W['file']}, ensure_ascii=False, indent=1))


def cmd_libopen(a): weekly_open('lib', a)
def cmd_libseal(a): weekly_seal('lib', a)
def cmd_worldopen(a): weekly_open('world', a)
def cmd_worldseal(a): weekly_seal('world', a)
def cmd_mvwopen(a): weekly_open('mvw', a)
def cmd_mvwseal(a): weekly_seal('mvw', a)
def cmd_plcopen(a): weekly_open('plc', a)
def cmd_plcseal(a): weekly_seal('plc', a)


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('settings'); p.add_argument('--doc', required=True); p.add_argument('--out', required=True)
    p = sp.add_parser('clone'); p.add_argument('--settings', required=True); p.add_argument('--dir', required=True); p.add_argument('--url', help='시험용 원격 주소')
    p = sp.add_parser('open'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--out', required=True)
    p = sp.add_parser('seal'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--data', required=True); p.add_argument('--photos')
    p = sp.add_parser('pages'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--app'); p.add_argument('--page', action='append')
    p = sp.add_parser('keyfile'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True)
    p = sp.add_parser('push'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--msg', required=True)
    p = sp.add_parser('cfg'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True)
    p = sp.add_parser('syncinit'); p.add_argument('--settings', required=True)
    p = sp.add_parser('syncclone'); p.add_argument('--settings', required=True); p.add_argument('--dir', required=True)
    p = sp.add_parser('syncpull'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--sync', required=True); p.add_argument('--data'); p.add_argument('--out', required=True)
    p = sp.add_parser('syncclean'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--sync', required=True); p.add_argument('--data', required=True)
    p = sp.add_parser('newsopen'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--out', required=True)
    p = sp.add_parser('newsseal'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--news', required=True); p.add_argument('--today')
    p = sp.add_parser('plancontext'); p.add_argument('--settings', default='env'); p.add_argument('--repo', required=True); p.add_argument('--sync', required=True); p.add_argument('--out', required=True)
    p = sp.add_parser('planseal'); p.add_argument('--settings', default='env'); p.add_argument('--repo', required=True); p.add_argument('--plan', required=True)
    p = sp.add_parser('reportcontext'); p.add_argument('--settings', default='env'); p.add_argument('--repo', required=True); p.add_argument('--sync', required=True); p.add_argument('--out', required=True)
    p = sp.add_parser('balinseal'); p.add_argument('--settings', default='env'); p.add_argument('--repo', required=True); p.add_argument('--in', required=True)
    p = sp.add_parser('repseal'); p.add_argument('--settings', default='env'); p.add_argument('--repo', required=True); p.add_argument('--rep', required=True)
    p = sp.add_parser('newswants'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--sync', required=True)
    p = sp.add_parser('apuse'); p.add_argument('--settings', default='env'); p.add_argument('--repo', required=True); p.add_argument('--sync', required=True)
    p = sp.add_parser('freshopen'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--out', required=True)
    p = sp.add_parser('freshseal'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--fresh', required=True); p.add_argument('--today')
    for nm in ('libopen', 'worldopen', 'plcopen', 'mvwopen'):
        p = sp.add_parser(nm); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--out', required=True)
    for nm in ('libseal', 'worldseal', 'plcseal', 'mvwseal'):
        p = sp.add_parser(nm); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--in', required=True)
        p.add_argument('--base', help='앱 소스 content/books.json·trips.json (unpacksrc 로 푼 것) — id·이름 겹침 검사'); p.add_argument('--sync', help='syncclone 한 폴더 — 두 사람 기록이 가리키는 것은 정리하지 않음')
    p = sp.add_parser('homeseal'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--in', required=True)
    p = sp.add_parser('fcv'); p.add_argument('--settings', default='env'); p.add_argument('--repo', required=True); p.add_argument('--sync', required=True); p.add_argument('--out', required=True); p.add_argument('--who', choices=('j', 'h', 'both'), default='j')
    p = sp.add_parser('fireseal'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--in', required=True); p.add_argument('--plan')
    p = sp.add_parser('notify'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--to', choices=('j', 'h', 'both'), default='both'); p.add_argument('--title'); p.add_argument('--msg', required=True)
    p = sp.add_parser('packsrc'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--src', required=True)
    p = sp.add_parser('unpacksrc'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--out', required=True)
    a = ap.parse_args()
    {'plancontext': cmd_plancontext, 'planseal': cmd_planseal, 'reportcontext': cmd_reportcontext, 'repseal': cmd_repseal, 'balinseal': cmd_balinseal, 'homeseal': cmd_homeseal, 'fireseal': cmd_fireseal, 'fcv': cmd_fcv, 'libopen': cmd_libopen, 'libseal': cmd_libseal, 'worldopen': cmd_worldopen, 'worldseal': cmd_worldseal, 'plcopen': cmd_plcopen, 'plcseal': cmd_plcseal, 'mvwopen': cmd_mvwopen, 'mvwseal': cmd_mvwseal, 'notify': cmd_notify, 'newsopen': cmd_newsopen, 'newsseal': cmd_newsseal, 'newswants': cmd_newswants, 'freshopen': cmd_freshopen, 'freshseal': cmd_freshseal, 'apuse': cmd_apuse, 'packsrc': cmd_packsrc, 'unpacksrc': cmd_unpacksrc, 'settings': cmd_settings, 'clone': cmd_clone, 'open': cmd_open, 'seal': cmd_seal, 'pages': cmd_pages,
     'keyfile': cmd_keyfile, 'push': cmd_push, 'cfg': cmd_cfg, 'syncinit': cmd_syncinit, 'syncclone': cmd_syncclone,
     'syncpull': cmd_syncpull, 'syncclean': cmd_syncclean}[a.cmd](a)


if __name__ == '__main__':
    main()
