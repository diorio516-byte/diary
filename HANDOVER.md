# 프로젝트 인계서: 우리 다이어리 (Cowork → Claude Code)

> 이 저장소는 **공개(public)** 다. 이 문서와 커밋에는 비밀번호·토큰·개인 기록을 적지 않는다.
> 비밀값은 Claude Code 환경의 비밀값(`DIARY_PW`)이나 재준 드라이브의 설정 문서에만 둔다.

## 1. 프로젝트 목적
두 사람이 함께 쓰는 사진 다이어리 PWA. 폰 홈 화면에 설치해 쓰고, 매일 밤 예약 작업이
드라이브에 올라온 사진과 펜 기록을 모아 다이어리를 갱신한다. 아침에는 공연·경기·경제 소식을 채운다.

## 2. 현재 상태 (2026-09-26 기준, 앱 v2)
- Claude 아티팩트 + 드라이브 방식에서 **GitHub Pages 정적 사이트**로 옮김(2026-09-24).
- 공개 저장소 위에서 사생활을 지키려고 화면·기록·사진을 전부 **AES-GCM 암호문(`*.enc`)** 으로 올린다.
  폰에서 비밀번호를 한 번 넣으면 서비스 워커가 폰 안에서만 풀어 보여 준다.
- 실제 앱 소스(빌드 전 파일, 설명서, 시험 스크립트, 인계 노트)는 `dev/src.tgz.enc` 에 암호화돼 있다.
- 최근 작업: 달력·모아 보기 중심 v2, 바로 공유, 오늘의 소식/경제 카드, 잠·집중 타이머 제거.
- 09-26 Cowork: 청주·광주로 지역 전환, 먹을 곳·잘 곳, 내기·놀이·활동 기록, 오늘 할 거, 영상 게시, 매주 새 소재(`fresh.json`).
- Cowork와 Claude Code가 같은 저장소를 함께 쓴다. 작업 전에 `main` 을 먼저 받아 합친다.

## 3. 주요 기능
- 잠금 화면(`index.html`): 비밀번호 → PBKDF2로 열쇠 만들기 → IndexedDB에 보관, 설치 안내
- 앱(`app.html`): 달력, 날짜별 사진·연필(Claude 초안)·펜(두 사람 기록), 모아 보기, 바로 공유
- 부속 화면: `season1.html`, `movies.html`, `tarot.html`, `lover.html`
- 아침 소식(`news.json`): 공연·축제·야구·축구 일정, 오늘의 경제 지표·기사
- 매주 새 소재(`fresh.json`): `ghsync.py freshopen`/`freshseal` 로 풀고 잠근다
- 앱에서 올린 사진은 원격 `sync` 가지로 올라가고, 밤 작업이 합친다.

## 4. 기술과 구조
| 경로 | 역할 | 평문? |
|---|---|---|
| `index.html` | 잠금 화면 + 서비스 워커 등록 | 예 |
| `sw.js` | `*.enc` 를 받아 폰 안에서 풀어 응답(`PROT` 목록) | 예 |
| `k.json` | PBKDF2 salt·반복 수·확인값(비밀번호 검사용) | 예 |
| `manifest.webmanifest`, `icons/` | PWA 설치 정보 | 예 |
| `lib/leaflet.*` | 지도 라이브러리 | 예 |
| `*.html.enc`, `data.json.enc`, `cfg.json.enc`, `news.json.enc`, `fresh.json.enc`, `p/*.webp.enc` | 화면·기록·설정·사진 | 아니오 |
| `dev/src.tgz.enc` | 앱 소스 묶음 | 아니오 |
| `dev/srcbox.py` | 소스 묶음 풀기/잠그기(Claude Code용, `DIARY_PW` 사용) | 예 |
| `sync/ghsync.py` | 암호화·저장소 동기화 명령 모음 | 예 |
| `sync/pipeline.py` | 사진 날짜·누구 폰 판별, 중복 제거, 연필/펜 합치기 | 예 |

암호 방식: 비밀번호 → PBKDF2-SHA256(600,000회) → 앞 32바이트 AES-GCM 열쇠, 뒤 32바이트 HMAC 열쇠.
IV는 내용의 HMAC이라 같은 내용이면 같은 암호문이 나온다(바뀐 파일만 커밋됨). 형식: `IV(12) + 암호문`.

## 5. 데이터 구조
- `data.json`: 날짜별 사진(id, 찍은 시각, 누구 폰, 썸네일), 연필 초안, 펜 기록. 사진 id는 절대 바꾸지 않는다.
- `news.json`: 소식 목록(분류·상태·장소 등, 글자 수 제한은 `ghsync.py` 의 `NEWS_LIM`), 경제 카드.
- `cfg.json`: 바로 공유에 쓰는 토큰·공유 키(암호화 필수).

## 6. 실행 · 배포
```bash
# 소스 풀기 (비밀번호는 환경 변수로만)
python3 dev/srcbox.py open      # → work/src/  (git이 무시함)
# ... work/src 에서 수정·시험 (빌드 방법은 work/src 안 설명서 참고) ...
python3 dev/srcbox.py seal      # → dev/src.tgz.enc (바뀐 경우만)
# 화면 반영: 빌드한 app.html 등을 암호화해 넣기 (토큰·비밀번호가 든 설정 JSON 필요)
python3 sync/ghsync.py pages --settings <설정.json> --repo . --app <빌드된 app.html>
```
- `main` 가지에 올리면 GitHub Pages가 그대로 배포한다(빌드 단계 없음).
- `sw.js` 나 `index.html` 을 바꾸면 캐시 이름(`hj-shell-v*`)을 올려야 폰에 새 파일이 간다.
- 필요 패키지: `cryptography`, `Pillow`(사진 파이프라인), 선택 `pillow-heif`.

## 7. 절대 지우거나 깨면 안 되는 것
- `k.json` 을 새로 만들면 두 폰 모두 잠긴다(비밀번호 교체 시에만 `ghsync.py` 가 자동으로 다시 잠금).
- `*.enc` 형식과 IV 규칙, `sw.js` 의 `PROT` 목록과 IndexedDB 이름(`hj-diary`).
- 사진 id, 기존 기록. 기존 기능은 임의로 삭제하지 않는다.
- **평문 소스·기록·설정 파일을 커밋하지 않는다**(`.gitignore` 로 막아 둠).

## 8. 알려진 문제 · 주의
- 비밀번호가 짧은 숫자면, 공개된 `k.json` 과 암호문을 가진 누구나 오프라인으로 대입해 볼 수 있다.
  긴 문장형 비밀번호로 바꾸는 것을 권한다(설정 문서에 새 비밀번호 + 「이전 비밀번호:」 적고 한 번 동기화).
- 드라이브 「우리 다이어리 쓰는 법」 문서가 아직 예전 아티팩트 링크를 안내한다.
- 원래 `packsrc` 는 내용이 같아도 묶음이 매번 달라졌다 → 2026-09-26 고정 순서·gzip 시각 0으로 고침.

## 9. 다음 작업
1. Claude Code 환경에 비밀값 `DIARY_PW` 등록 → `srcbox.py open` 으로 소스 확보, `work/src` 의 인계 노트와 이 문서 합치기
2. 소스 전체 분석(기술·구조·기능·데이터·실행·배포·주의 파일·문제) — 코드 수정 전 정리
3. 비밀번호 강화, 쓰는 법 문서 링크 갱신
4. 밤 기록·아침 소식 예약 작업을 Claude Code 쪽에서 돌릴지 결정
