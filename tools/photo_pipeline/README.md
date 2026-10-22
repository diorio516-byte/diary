# photo_pipeline — 사진 들어간 A4 PDF 만들기 도구

순서와 규칙은 `docs/이미지작업_프로세스.md`. 여기는 명령만.

| 파일 | 하는 일 | 명령 |
|---|---|---|
| `template_a4.html` | A4 표지 + 컨셉 쪽 템플릿(CSS 포함) · 사진 자리 `<!--PHOTO:slot-->` | 복사해서 글 채우기 |
| `job.example.json` | 사진 ↔ 자리 ↔ 캡션 목록 보기 | 복사해 `job.json` |
| `build_pdf.py` | 크롭 → 자리 채움 → wkhtmltopdf(zoom 보정) → 쪽 수 · 미리보기 `sheet.png` | `python3 build_pdf.py job.json` |
| `collect_canva_thumbs.py` | Canva 응답 썸네일(PNG)을 이름 붙여 `raw/`로 | `python3 collect_canva_thumbs.py --since 15 이름1 이름2 …` |
| `grab_frames.sh` | 영상에서 컨택트시트 · 장면 한 장 | `bash grab_frames.sh in.mp4` → `bash grab_frames.sh in.mp4 12.5 이름` |
| `sheet.py` | PNG 여러 장을 한 장으로 | `python3 sheet.py pv-*.png sheet.png` |

필요한 것: `wkhtmltopdf` · `pdfinfo`/`pdftoppm`(poppler-utils) · `ffmpeg` · 파이썬 `Pillow` · 글꼴 `fonts-noto-cjk`.
```bash
apt-get install -y wkhtmltopdf poppler-utils ffmpeg fonts-noto-cjk && pip install pillow --break-system-packages
```

가장 짧은 사용 예
```bash
cp tools/photo_pipeline/template_a4.html work/안내서.html      # 글 채우기
cp tools/photo_pipeline/job.example.json work/job.json         # html · out_pdf · photos 고치기
python3 tools/photo_pipeline/build_pdf.py work/job.json        # → PDF + work/sheet.png
```
`sheet.png`를 Read로 보고 넘침 · 겹침 · 캡션 두 줄이 없으면 PDF를 보낸다.
