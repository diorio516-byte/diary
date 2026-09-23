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
        m = re.match(r'^(GitHub\s*아이디|토큰|둘만의\s*비밀번호|이전\s*비밀번호)\s*[:：]\s*(.*)$', line)
        if not m:
            continue
        key = {'G': 'user', '토': 'token', '둘': 'pw', '이': 'old_pw'}[m.group(1)[0]]
        val = m.group(2).strip()
        if key in ('user', 'token'):
            val = val.replace(' ', '')
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
    a = ap.parse_args()
    {'settings': cmd_settings, 'clone': cmd_clone, 'open': cmd_open, 'seal': cmd_seal, 'pages': cmd_pages,
     'keyfile': cmd_keyfile, 'push': cmd_push}[a.cmd](a)


if __name__ == '__main__':
    main()
