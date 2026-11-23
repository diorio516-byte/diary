# 프로젝트 인계서: 우리 다이어리

> 이 저장소는 **공개(public)** 다. 이 문서와 커밋에는 비밀번호 · 토큰 · 개인 기록 · 짝의 이름 · 사는 곳 · 생일을 적지 않는다.
> 비밀값은 Claude Code 환경 변수(`DIARY_PW` · `DIARY_GH_TOKEN` · `DIARY_GH_TOKEN_EXP`)나 재준 구글 드라이브(재준만 보는 파일)에만 둔다.
> **다음 채팅은 먼저**: `python3 dev/srcbox.py open` → 잠긴 소스 `work/src/claude/00_시작_여기부터.md`(읽는 순서 · 저장 루틴 · 남은 일) · `work/src/claude/수당_기준.md` · `work/src/HANDOFF.md`(구조 · 파일마다 하는 일 · 시험 · 배포).

## 1. 지금 상태 (2026-11-23 · v72)
- 두 사람이 함께 쓰는 사진 다이어리 PWA(GitHub Pages). 화면 · 기록 · 사진 · 설정은 전부 AES-GCM 암호문(`*.enc`)으로 올리고, 폰에서 비밀번호를 한 번 넣으면 서비스 워커가 폰 안에서만 풀어 보여 준다.
- 2026-11-23 새로 시작: 비밀번호 · `k.json` · 모든 `*.enc` 새로 잠금 · 저장소 히스토리 한 줄 · 바로 공유 가지 `share`(새 동기화 열쇠 · 새 알림 주제).
- **`srcbox.py open` 이 「비밀번호가 k.json과 맞지 않음」이면**: Claude 환경 변수 `DIARY_PW` 가 아직 예전 값이다. 재준에게 드라이브 「다이어리 새 비밀번호 (재준만).txt」의 값으로 `DIARY_PW` 를 바꾸고 새 채팅을 열어 달라고 한다(채팅에 비밀번호를 붙여 넣게 하지 않는다).
- 앱 공유 토큰은 2026-12-23 에 끝난다 → 그 전에 새 토큰을 환경 변수 `DIARY_GH_TOKEN`(+ `DIARY_GH_TOKEN_EXP`)에 넣고 `python3 sync/ghsync.py cfg --settings env --repo .`(토큰만 바뀌고 동기화 열쇠 · 알림 주제는 그대로).

## 2. 구조
| 경로 | 역할 | 평문? |
|---|---|---|
| `index.html` · `sw.js` · `manifest.webmanifest` · `icons/` | 잠금 화면 · 서비스 워커(`PROT` 목록의 `*.enc` 를 폰 안에서 풀어 응답) · PWA 설치 정보 | 예 |
| `k.json` | PBKDF2 salt · 반복 수 · 확인값(비밀번호 검사용) | 예 |
| `lib/leaflet.*` | 지도 라이브러리 | 예 |
| `app.html.enc` · `*.html.enc` · `data.json.enc` · `cfg.json.enc` · `news.json.enc` 등 | 앱 · 부속 화면 · 기록 · 설정 · 소식 | 아니오 |
| `dev/src.tgz.enc` | 앱 소스 묶음(빌드 전 파일 · 설명서 · 시험 · 인계 노트) | 아니오 |
| `dev/srcbox.py` | 소스 묶음 풀기/잠그기(`DIARY_PW` 사용) | 예 |
| `dev/bundlebox.py` | 비밀번호와 따로인 열쇠로 묶음 잠그기/풀기(옮길 때만) | 예 |
| `sync/ghsync.py` | 암호화 · 저장소 · 바로 공유 명령 모음 | 예 |
| `sync/pipeline.py` | 사진 날짜 · 누구 폰 판별 · 중복 제거 | 예 |
| `tools/photo_pipeline/` · `docs/` | 사진이 들어가는 안내서 만들기 순서 · 도구 | 예 |

암호 방식: 비밀번호 → PBKDF2-SHA256(600,000회) → AES-GCM 열쇠 + HMAC 열쇠. IV 는 내용의 HMAC(같은 내용이면 같은 암호문 → 바뀐 파일만 커밋). 형식 `IV(12) + 암호문`.

## 3. 실행 · 배포
```bash
python3 dev/srcbox.py open      # → work/src/ (git 이 무시함)
# work/src 에서 고치고 시험 (빌드 · 시험 방법은 work/src/HANDOFF.md)
python3 dev/srcbox.py seal      # → dev/src.tgz.enc (바뀐 경우만)
python3 sync/ghsync.py pages --settings env --repo . --app work/src/app/app.html
```
- `main` 가지에 올리면 GitHub Pages 가 그대로 배포한다(빌드 단계 없음).
- `sw.js` 나 `index.html` 을 바꾸면 캐시 이름(`hj-shell-v*`)을 올려야 폰에 새 파일이 간다.
- 필요 패키지: `cryptography` · `Pillow`(사진 파이프라인) · 선택 `pillow-heif`.

## 4. 절대 지우거나 깨면 안 되는 것
- `k.json` 을 새로 만들면 두 폰 모두 잠긴다(비밀번호를 바꿀 때만 도구가 바꾼다).
- `*.enc` 형식과 IV 규칙 · `sw.js` 의 `PROT` 목록 · IndexedDB 이름(`hj-diary` · `hj-sync` · `hj-move`).
- 사진 id · 기존 기록 · 기존 기능은 임의로 지우지 않는다.
- **평문 소스 · 기록 · 설정 파일을 커밋하지 않는다**(`.gitignore` 로 막아 둠).
