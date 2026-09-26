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
    raw = json.dumps(cfg, ensure_ascii=False, sort_keys=True).encode('utf-8')
    changed = write_if_changed(cfg_path(a.repo), seal_bytes(aes, mac, raw))
    print(json.dumps({'cfg': ('new' if not old else 'updated') if changed else 'same', 'tokenExp': cfg['sync']['tokenExp'],
                      'keyKept': bool(osync.get('syncKey'))}, ensure_ascii=False))


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
    import tarfile, io
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as t:
        for root, dirs, files in os.walk(a.src):
            dirs[:] = [d for d in dirs if d not in ('node_modules', 'shots', '__pycache__', 'www', 'nightly', 'prodtest')]
            for f in files:
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
FRESH_MAX = {'balance': 400, 'quiz': 200, 'imagine': 200, 'dates': 120}
DATE_ENUM = {'io': ('both', 'in', 'out'), 'time': ('1h', 'day', 'half', 'trip'), 'wx': ('any', 'clear', 'cold', 'hot', 'rain'), 'when': ('any', 'day', 'night', 'weekend'),
             'tag': ('계절', '공연', '만들기', '맛집', '바다', '산책', '액티비티', '야경', '여행', '장거리', '전시', '집데이트', '축제', '카페'), 'reg': ('', '청주', '광주', '충청', '호남', '중간')}


def fresh_check(f, today):
    errs = []
    if not isinstance(f, dict):
        return None, ['맨 위 형식이 {"v":1,...}가 아님']
    out = {'v': 1, 'updated': '', 'week': str(f.get('week') or ''), 'balance': [], 'quiz': [], 'imagine': [], 'dates': [], 'log': []}
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
    for k, lim in FRESH_MAX.items():
        if len(out[k]) > lim:
            out[k] = out[k][-lim:]        # 오래된 것부터 정리
    for l in (f.get('log') or [])[-30:]:
        if isinstance(l, str) and len(l) <= 120:
            out['log'].append(l)
    if re.search(r'\d[\d,]*\s*원', json.dumps(out, ensure_ascii=False)):
        errs.append('가격(원)은 넣지 않음')
    return out, errs


def cmd_freshopen(a):
    s = load_settings(a.settings)
    aes, _ = keys_for(s, a.repo)
    p = os.path.join(a.repo, 'fresh.json.enc')
    f = json.loads(open_bytes(aes, open(p, 'rb').read())) if os.path.exists(p) else {'v': 1, 'updated': '', 'week': '', 'balance': [], 'quiz': [], 'imagine': [], 'dates': [], 'log': []}
    with open(a.out, 'w', encoding='utf-8') as fh:
        json.dump(f, fh, ensure_ascii=False, indent=0)
    print(json.dumps({'opened': a.out, 'week': f.get('week'), 'updated': f.get('updated'), 'counts': {k: len(f.get(k) or []) for k in ('balance', 'quiz', 'imagine', 'dates')},
                      'lastIds': {k: [x.get('id') for x in (f.get(k) or [])[-3:]] for k in ('balance', 'quiz', 'dates')}, 'log': (f.get('log') or [])[-3:]}, ensure_ascii=False, indent=1))


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
    if len(raw) > 300 * 1024:
        print(json.dumps({'ok': False, 'errors': [f'너무 큼 {len(raw)//1024}KB (300KB 이하)']}, ensure_ascii=False)); sys.exit(1)
    with open(os.path.join(a.repo, 'fresh.json.enc'), 'wb') as fh:
        fh.write(seal_bytes(aes, mac, raw))
    wk = out['week']
    print(json.dumps({'ok': True, 'week': wk, 'kb': len(raw) // 1024, 'thisWeek': {k: len([x for x in out[k] if isinstance(x, dict) and x.get('wk') == wk]) for k in ('balance', 'quiz', 'dates')},
                      'imagine': len(out['imagine']), 'total': {k: len(out[k]) for k in ('balance', 'quiz', 'imagine', 'dates')}}, ensure_ascii=False, indent=1))


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
    p = sp.add_parser('packsrc'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--src', required=True)
    p = sp.add_parser('unpacksrc'); p.add_argument('--settings', required=True); p.add_argument('--repo', required=True); p.add_argument('--out', required=True)
    a = ap.parse_args()
    {'newsopen': cmd_newsopen, 'newsseal': cmd_newsseal, 'newswants': cmd_newswants, 'freshopen': cmd_freshopen, 'freshseal': cmd_freshseal, 'packsrc': cmd_packsrc, 'unpacksrc': cmd_unpacksrc, 'settings': cmd_settings, 'clone': cmd_clone, 'open': cmd_open, 'seal': cmd_seal, 'pages': cmd_pages,
     'keyfile': cmd_keyfile, 'push': cmd_push, 'cfg': cmd_cfg, 'syncinit': cmd_syncinit, 'syncclone': cmd_syncclone,
     'syncpull': cmd_syncpull, 'syncclean': cmd_syncclean}[a.cmd](a)


if __name__ == '__main__':
    main()
