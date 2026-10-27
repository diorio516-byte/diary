# 개편 전 전체 앱 백업 (2026-10-27)

2026-10-27 재준 요청(「미래 자금 · 부탁하기 · 놀이 · 내 이동만 남기고 전부 삭제」)으로 앱을 줄이기 전,
그때까지의 **앱 전체(v55)** 를 통째로 남겨 둔 것이에요. 기록·사진은 지우지 않았고(저장소 그대로), 여기엔 그 시점의 복사본이 있어요.

## 무엇이 들어 있나
- app.html.enc — 개편 전 앱 화면 전체(암호문)
- lover/tarot/movies/season1.html.enc — 작은 앱 4개(암호문)
- src.tgz.enc — 앱 소스 전체(암호문 · dev/srcbox.py 로 풀기)
- index.html · sw.js · manifest.webmanifest — 앱을 여는 껍데기
- data/*.json.enc — 그 시점의 기록·설정·소재·리포트 등 전부(암호문)
- 사진(p/)·두 폰 기록(sync 가지)은 복사하지 않고 git 가지로 묶어 두었어요(GitHub › Branches 에서 보여요): `claude/backup-2026-10-27-full-app`(개편 전 main 전체 = cd9161d) · `claude/backup-2026-10-27-sync`(개편 전 두 폰 기록 = 2c363c9)

## 되돌리는 법 (재준은 이 한 줄만)
코드 창에 **「백업 2026-10-27 전체 앱으로 되돌려 줘」** 라고 보내면 돼요.
(Claude 가 하는 일: `git checkout claude/backup-2026-10-27-full-app -- app.html.enc lover.html.enc tarot.html.enc movies.html.enc season1.html.enc dev/src.tgz.enc` → 커밋 → main 에 올리기. 기록은 그대로라 따로 손댈 게 없어요.)
