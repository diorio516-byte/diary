#!/usr/bin/env python3
"""작업본 묶음 잠그기 · 풀기 — 다이어리 비밀번호와 따로인 새 열쇠(AES-256-GCM)
  열쇠 파일: 한 줄 'hjbox1:<base64 32바이트>' — 재준 구글 드라이브에만 둔다(저장소 · 채팅 · 커밋에 적지 않음).
  python3 dev/bundlebox.py newkey <열쇠 파일>                    새 열쇠(이미 있으면 덮어쓰지 않음 · 권한 600)
  python3 dev/bundlebox.py seal <열쇠 파일> <평문> <잠긴 파일>
  python3 dev/bundlebox.py open <열쇠 파일> <잠긴 파일> <평문>
잠긴 파일 = b'HJBOX1' + nonce 12바이트 + 암호문(태그 포함). 화면에는 열쇠 · 내용을 찍지 않고 sha256 만 찍는다."""
import base64, hashlib, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'HJBOX1'


def key_of(p):
    s = open(p, encoding='utf-8').read().strip()
    if not s.startswith('hjbox1:'):
        sys.exit('열쇠 파일 모양이 아님')
    k = base64.b64decode(s[7:])
    if len(k) != 32:
        sys.exit('열쇠 길이가 틀림')
    return k


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == 'newkey':
        fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write('hjbox1:' + base64.b64encode(os.urandom(32)).decode() + '\n')
        print('newkey ok')
    elif cmd == 'seal':
        k = key_of(sys.argv[2]); raw = open(sys.argv[3], 'rb').read(); n = os.urandom(12)
        with open(sys.argv[4], 'wb') as f:
            f.write(MAGIC + n + AESGCM(k).encrypt(n, raw, MAGIC))
        print('sealed', hashlib.sha256(raw).hexdigest())
    elif cmd == 'open':
        k = key_of(sys.argv[2]); b = open(sys.argv[3], 'rb').read()
        if not b.startswith(MAGIC):
            sys.exit('잠긴 파일 모양이 아님')
        raw = AESGCM(k).decrypt(b[6:18], b[18:], MAGIC)
        fd = os.open(sys.argv[4], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(raw)
        print('opened', hashlib.sha256(raw).hexdigest())
    else:
        sys.exit(__doc__)


main()
