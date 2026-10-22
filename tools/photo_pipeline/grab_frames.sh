#!/usr/bin/env bash
# 영상(릴스 화면 녹화)에서 장면 고르기 — docs/이미지작업_프로세스.md 3-C
#
#  1) 컨택트시트:  bash grab_frames.sh in.mp4            → frames/sheet_000.png … (1초 간격 · 3×4 · 초 번호 표시)
#  2) 한 장 뽑기:  bash grab_frames.sh in.mp4 12.5 scene  → raw/scene.jpg (12.5초 장면)
#
# 인스타 화면 녹화(1080×2400)는 위 265px · 아래 UI를 잘라 낸다(crop=1080:1700:0:265). 다른 비율이면 crop 값을 바꾼다.
set -e
IN="$1"; T="$2"; NAME="$3"
CROP="crop=1080:1700:0:265"
if [ -z "$IN" ]; then echo "사용법: bash grab_frames.sh in.mp4 [초 이름]"; exit 1; fi
if [ -z "$T" ]; then
  mkdir -p frames
  ffmpeg -v error -y -i "$IN" -vf "fps=1,${CROP},scale=270:-1,drawtext=text='%{n}s':x=8:y=8:fontsize=28:fontcolor=yellow:box=1:boxcolor=black@0.5,tile=3x4" frames/sheet_%03d.png
  echo "frames/sheet_*.png 를 Read로 보고 장면(초)을 고른 뒤: bash grab_frames.sh $IN <초> <이름>"
else
  mkdir -p raw
  ffmpeg -v error -y -ss "$T" -i "$IN" -frames:v 1 -vf "${CROP},scale=800:-1" "raw/${NAME:-scene_$T}.jpg"
  echo "raw/${NAME:-scene_$T}.jpg"
fi
