#!/usr/bin/env python3
"""Claude Code 작업용: 앱 소스 묶음(dev/src.tgz.enc) 풀기·다시 잠그기.

비밀번호는 환경 변수 DIARY_PW에서만 읽는다(명령줄·파일에 적지 않음). 토큰은 필요 없다.
풀린 소스는 work/src/ 에 두며, 이 폴더는 .gitignore로 막혀 있다. 저장소는 공개라서
평문 소스를 절대 커밋하지 않는다.

  DIARY_PW=... python3 dev/srcbox.py open            dev/src.tgz.enc → work/src/
  DIARY_PW=... python3 dev/srcbox.py seal            work/src/ → dev/src.tgz.enc (바뀐 경우만)
  DIARY_PW=... python3 dev/srcbox.py check           비밀번호가 k.json과 맞는지만 확인

--repo(기본: 이 파일의 상위 폴더), --dir(기본: <repo>/work/src)로 위치를 바꿀 수 있다.
"""
import argparse, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'sync'))
import ghsync  # noqa: E402


def settings():
    pw = os.environ.get('DIARY_PW', '')
    if not pw:
        ghsync.die('환경 변수 DIARY_PW가 없음(Claude Code 환경 설정의 비밀값에 넣어 주세요)')
    return {'pw': pw}


def keys(repo):
    k = json.load(open(os.path.join(repo, 'k.json')))
    got = ghsync.try_keys(settings()['pw'], k)
    if not got:
        ghsync.die('DIARY_PW가 k.json과 맞지 않음')
    return got


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('cmd', choices=('open', 'seal', 'check'))
    ap.add_argument('--repo', default=os.path.normpath(os.path.join(HERE, '..')))
    ap.add_argument('--dir')
    a = ap.parse_args()
    d = a.dir or os.path.join(a.repo, 'work', 'src')
    keys(a.repo)  # 비밀번호가 틀리면 여기서 멈춤(k.json을 새 키로 바꾸는 일 없음)
    a.settings = None
    ghsync.load_settings = lambda _p: settings()
    if a.cmd == 'check':
        print(json.dumps({'ok': True}))
    elif a.cmd == 'open':
        a.out = d
        ghsync.cmd_unpacksrc(a)
    else:
        if not os.path.isdir(d):
            ghsync.die(f'{d} 없음(먼저 open)')
        a.src = d
        ghsync.cmd_packsrc(a)


if __name__ == '__main__':
    main()
