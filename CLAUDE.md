# 우리 다이어리 — Claude Code 작업 규칙

먼저 `HANDOVER.md` 를 읽는다.

- 이 저장소는 공개다. 평문 소스·기록(`data.json`, `news.json`, `cfg.json`)·설정 JSON·비밀번호·토큰을 커밋하거나 커밋 메시지에 적지 않는다.
- 소스는 `python3 dev/srcbox.py open` 으로 `work/src/` 에 풀고, 끝나면 `seal` 로 다시 잠근다. 비밀번호는 환경 변수 `DIARY_PW` 에서만 읽는다.
- `k.json` 은 새로 만들지 않는다. 기존 기능·사진 id는 지우거나 바꾸지 않는다.
- 변경 전 관련 코드를 먼저 분석하고, 변경 후 시험한다. 답과 설명은 한국어로.
