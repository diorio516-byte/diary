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
  libseal  --settings s.json --repo repo --in lib.json [--base content/books.json] [--sync syncdir]   검사·정리 후 암호화(ok·errors·counts)
  plcopen/plcseal  매주 장소(v22) plc.json — --base content/places.json (먹을 곳·잘 곳 새 곳·재확인·순서표·출처 장부)
  worldopen --settings s.json --repo repo --out world.json  매주 쌓이는 해외여행(world.json.enc) 풀기, 없으면 빈 틀
  worldseal --settings s.json --repo repo --in world.json [--base content/trips.json] [--sync syncdir]  검사·정리 후 암호화
  packsrc  --settings s.json --repo repo --src 폴더           앱 소스(빌드 전 파일) 묶음을 암호화해 dev/src.tgz.enc로
  unpacksrc --settings s.json --repo repo --out 폴더          dev/src.tgz.enc 풀기
"""
import argparse, base64, glob, hashlib, hmac, json, os, re, subprocess, sys, unicodedata

ITER = 600000
REPO = 'diary'
DEFAULT_USER = 'diorio516-byte'


def die(msg):
    print(json.dumps({'error': msg}, ensure_ascii=False)); sys.exit(1)


def load_settings(p):
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


def remote_url(s):
    return f"https://github.com/{s['user']}/{s['repo']}.git"


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


# ---------- 매주 새 소재(fresh.json.enc) ----------
FRESH_MAX = {'balance': 1500, 'quiz': 600, 'imagine': 600, 'dates': 1000, 'courses': 200, 'books': 30, 'wed': 30}   # v22: 쌓이도록 크게(재준 요청 「데이터량 늘리기」)
FRESH_MAX_KB = 2 * 1024
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
        seen.add(b['id']); out['balance'].append({'id': b['id'], 'a': b['a'], 'b': b['b'], 'c': b['c'], 'wk': str(b.get('wk') or out['week'])})
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
    for k, lim in FRESH_MAX.items():
        if len(out[k]) > lim:
            out[k] = out[k][-lim:]        # 오래된 것부터 정리
    for l in (f.get('log') or [])[-30:]:
        if isinstance(l, str) and len(l) <= 120:
            out['log'].append(l)
    if re.search(r'\d[\d,]*\s*원', json.dumps({k: v for k, v in out.items() if k != 'wed'}, ensure_ascii=False)):
        errs.append('가격(원)은 넣지 않음 (결혼 소식 wed만 금액 허용)')
    return out, errs


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
                      'imagine': len(out['imagine']), 'total': {k: len(out[k]) for k in ('balance', 'quiz', 'imagine', 'dates', 'courses', 'wed')}}, ensure_ascii=False, indent=1))


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


def _kst_now_iso():
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone(_dt.timedelta(hours=9))).replace(microsecond=0).isoformat()


WEEKLY = {
    'lib': {'file': 'lib.json.enc', 'items': 'books', 'check': lib_check, 'max': LIB_MAX_KB, 'pre': 'bkw-', 'base': 'books',
            'empty': lambda: {'v': 1, 'updated': '', 'dow': '', 'weeks': [], 'books': []}},
    'world': {'file': 'world.json.enc', 'items': 'trips', 'check': world_check, 'max': WORLD_MAX_KB, 'pre': 'trw-', 'base': 'trips',
              'empty': lambda: {'v': 1, 'updated': '', 'dow': '', 'fx': {}, 'weeks': [], 'trips': [], 'patch': {}}},
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
    p = sp.add_parser('newswants'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--sync', required=True)
    p = sp.add_parser('freshopen'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--out', required=True)
    p = sp.add_parser('freshseal'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--fresh', required=True); p.add_argument('--today')
    for nm in ('libopen', 'worldopen', 'plcopen'):
        p = sp.add_parser(nm); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--out', required=True)
    for nm in ('libseal', 'worldseal', 'plcseal'):
        p = sp.add_parser(nm); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--in', required=True)
        p.add_argument('--base', help='앱 소스 content/books.json·trips.json (unpacksrc 로 푼 것) — id·이름 겹침 검사'); p.add_argument('--sync', help='syncclone 한 폴더 — 두 사람 기록이 가리키는 것은 정리하지 않음')
    p = sp.add_parser('notify'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--to', choices=('j', 'h', 'both'), default='both'); p.add_argument('--title'); p.add_argument('--msg', required=True)
    p = sp.add_parser('packsrc'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--src', required=True)
    p = sp.add_parser('unpacksrc'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--out', required=True)
    a = ap.parse_args()
    {'libopen': cmd_libopen, 'libseal': cmd_libseal, 'worldopen': cmd_worldopen, 'worldseal': cmd_worldseal, 'plcopen': cmd_plcopen, 'plcseal': cmd_plcseal, 'notify': cmd_notify, 'newsopen': cmd_newsopen, 'newsseal': cmd_newsseal, 'newswants': cmd_newswants, 'freshopen': cmd_freshopen, 'freshseal': cmd_freshseal, 'packsrc': cmd_packsrc, 'unpacksrc': cmd_unpacksrc, 'settings': cmd_settings, 'clone': cmd_clone, 'open': cmd_open, 'seal': cmd_seal, 'pages': cmd_pages,
     'keyfile': cmd_keyfile, 'push': cmd_push, 'cfg': cmd_cfg, 'syncinit': cmd_syncinit, 'syncclone': cmd_syncclone,
     'syncpull': cmd_syncpull, 'syncclean': cmd_syncclean}[a.cmd](a)


if __name__ == '__main__':
    main()
