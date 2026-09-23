#!/usr/bin/env python3
"""우리 둘의 다이어리 — 사진·펜 연동 파이프라인.

매일 밤 예약 작업이 이 스크립트로 드라이브에서 받은 사진을 날짜별로 붙이고,
Claude가 쓴 연필 초안(review.json)과 두 사람의 펜 문서를 data.json에 합친다.

  python3 pipeline.py plan    --data data.json --list list.json
  python3 pipeline.py ingest  --data data.json --out build [downloads...]
  python3 pipeline.py apply   --data data.json --pending build/pending.json --review review.json --out build/data.json
  python3 pipeline.py pens    --data build/data.json --j pen_j.txt --h pen_h.txt --today 2026-09-24 --out build/data.json
  python3 pipeline.py check   --data build/data.json --build build

규칙
- 날짜: 사진 안의 찍은 시각(EXIF) > 파일 이름의 날짜_시각(재준 갤럭시 원본, 스크린샷)
        > 13자리 숫자·KakaoTalk_ 이름(카톡으로 받은 날) > 드라이브에 올린 날.
- 누구 폰: 카메라 모델(Galaxy=재준, iPhone=현지). 찍은 시각이 없으면 올린 사람의 반대편
        (재준이 올린 카톡 사진은 현지가 보낸 것).
- 같은 사진(해시 거리 5 이하)은 새로 넣지 않고, 새 쪽에 찍은 시각이 있으면 기존 사진의
  시각·화질만 올린다. 기존 사진 id는 절대 바꾸지 않는다.
"""
import argparse, base64, datetime as dt, glob, hashlib, io, json, os, re, sys

from PIL import Image, ImageDraw, ImageOps

try:
    import pillow_heif  # HEIC(아이폰) 대비
    pillow_heif.register_heif_opener()
except Exception:
    pass

KST = dt.timezone(dt.timedelta(hours=9))
LONG, QUAL, TH = 1280, 72, 128
FILE_CAP = 2000         # GitHub 저장소로 옮김(2026-09-24). 사진 칸은 넉넉함, 1GB 저장소 한도 안에서 시즌마다 책으로 묶기
DUP_DIST = 5
JAEJUN_EMAIL = "diorio516@gmail.com"


# ---------- 공통 ----------
def load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def dump(o, p):
    os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(o, f, ensure_ascii=False, separators=(",", ":"))


def now_kst():
    return dt.datetime.now(KST).replace(microsecond=0)


def dhash(im, n=8):
    g = im.convert("L").resize((n + 1, n), Image.LANCZOS)
    px = list(g.tobytes())
    bits = 0
    for r in range(n):
        for c in range(n):
            bits = (bits << 1) | (px[r * (n + 1) + c] > px[r * (n + 1) + c + 1])
    return f"{bits:016x}"


def hdist(a, b):
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def webp_bytes(im, long=LONG, q=QUAL):
    im = im.convert("RGB")
    im.thumbnail((long, long), Image.LANCZOS)
    b = io.BytesIO()
    im.save(b, "WEBP", quality=q, method=6)
    return b.getvalue(), im.size


def thumb_uri(im, size=TH):
    im = im.convert("RGB")
    w, h = im.size
    m = min(w, h)
    im = im.crop(((w - m) // 2, (h - m) // 2, (w - m) // 2 + m, (h - m) // 2 + m)).resize((size, size), Image.LANCZOS)
    b = io.BytesIO()
    im.save(b, "WEBP", quality=55, method=6)
    return "data:image/webp;base64," + base64.b64encode(b.getvalue()).decode()


def exif_info(raw_im):
    """(datetime|None, 카메라 모델) — 원본(회전 전) 이미지에서 읽는다."""
    try:
        ex = raw_im.getexif()
    except Exception:
        return None, ""
    model = str(ex.get(272) or "") + " " + str(ex.get(271) or "")
    sub = {}
    try:
        sub = ex.get_ifd(0x8769)
    except Exception:
        pass
    s = sub.get(36867) or sub.get(36868) or ex.get(306)
    t = None
    if s:
        try:
            t = dt.datetime.strptime(str(s).strip()[:19], "%Y:%m:%d %H:%M:%S")
        except Exception:
            t = None
    return t, model.strip()


def name_time(title):
    """파일 이름에서 (종류, datetime). 종류: shot(스크린샷), name(날짜_시각 원본), recv(카톡 받은 날)."""
    t = title or ""
    m = re.search(r"(20\d{2})(\d{2})(\d{2})[_-](\d{2})(\d{2})(\d{2})", t)
    if m and not re.search(r"KakaoTalk_", t):
        y, mo, d, hh, mi, ss = map(int, m.groups())
        try:
            return ("shot" if "screenshot" in t.lower() else "name"), dt.datetime(y, mo, d, hh, mi, ss)
        except ValueError:
            pass
    m = re.search(r"KakaoTalk_(20\d{2})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})", t)
    if m:
        y, mo, d, hh, mi, ss = map(int, m.groups())
        try:
            return "recv", dt.datetime(y, mo, d, hh, mi, ss)
        except ValueError:
            pass
    m = re.search(r"(?<!\d)(1[6-9]\d{11})(?!\d)", t)
    if m:
        return "recv", dt.datetime.fromtimestamp(int(m.group(1)) / 1000, KST).replace(tzinfo=None)
    return None, None


def who_of(model, title, owner, cfg):
    cams = cfg.get("cams") or {"galaxy": "j", "sm-": "j", "iphone": "h"}
    ml = (model or "").lower()
    for k, v in cams.items():
        if k.lower() in ml:
            return v
    if "screenshot" in (title or "").lower():
        return "h" if owner and owner != cfg.get("jEmail", JAEJUN_EMAIL) else "j"
    # 찍은 시각·카메라가 없으면 받은 사진: 올린 사람의 반대편
    if owner and owner != cfg.get("jEmail", JAEJUN_EMAIL):
        return "j"
    return "h"


def upload_time(created):
    try:
        return dt.datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone(KST).replace(tzinfo=None)
    except Exception:
        return now_kst().replace(tzinfo=None)


def new_id(d, t, who, taken):
    base = "n" + d.replace("-", "") + "_" + (t.replace(":", "") if t else "x") + "_" + who
    i, pid = 2, base
    while pid in taken:
        pid = f"{base}_{i}"
        i += 1
    return pid


def sort_key(photos, pid):
    p = photos.get(pid) or {}
    return (p.get("t") or "99:99", pid)


# ---------- plan ----------
def cmd_plan(a):
    data = load(a.data)
    done = (data.get("sync") or {}).get("processed") or {}
    lst = load(a.list)
    items = lst if isinstance(lst, list) else lst.get("files", [])
    todo, skip = [], []
    for f in items:
        fid = f.get("id")
        mt = (f.get("mimeType") or "").lower()
        if not fid or fid in done:
            continue
        if not (mt.startswith("image/") or re.search(r"\.(jpe?g|png|heic|heif|webp)$", (f.get("title") or "").lower())):
            skip.append({"id": fid, "title": f.get("title"), "why": "사진이 아님(" + (mt or "?") + ")"})
            continue
        todo.append({"id": fid, "title": f.get("title"), "size": f.get("fileSize")})
    print(json.dumps({"download": todo, "skip": skip}, ensure_ascii=False, indent=1))


# ---------- ingest ----------
def read_download(path):
    with open(path, encoding="utf-8") as f:
        txt = f.read()
    try:
        o = json.loads(txt)
    except Exception:
        return None
    if isinstance(o, dict) and "content" in o:
        return o
    return None


def cmd_ingest(a):
    data = load(a.data)
    cfg = data.get("cfg") or {}
    photos = data.get("photos") or {}
    processed = (data.get("sync") or {}).get("processed") or {}
    meta = {}
    if a.list and os.path.exists(a.list):
        lst = load(a.list)
        for f in (lst if isinstance(lst, list) else lst.get("files", [])):
            meta[f.get("id")] = f
    paths = list(a.downloads)
    if a.glob:
        paths += sorted(glob.glob(os.path.expanduser("~/.claude/projects/*/*/tool-results/mcp-Google_Drive-download_file_content-*.txt")))
        paths += sorted(glob.glob(os.path.expanduser("~/.claude/projects/*/tool-results/mcp-Google_Drive-download_file_content-*.txt")))
    os.makedirs(os.path.join(a.out, "p"), exist_ok=True)
    os.makedirs(os.path.join(a.out, "sheets"), exist_ok=True)
    pend = {"photos": {}, "dups": [], "upgrades": [], "skipped": []}
    seen_ids = set()
    batch_hash = {}
    taken = set(photos)
    for path in paths:
        o = read_download(path)
        if not o:
            pend["skipped"].append({"file": path, "why": "다운로드 파일을 읽지 못함"})
            continue
        fid = o.get("id")
        if not fid or fid in seen_ids or fid in processed:
            continue
        seen_ids.add(fid)
        title = o.get("title") or (meta.get(fid) or {}).get("title") or ""
        try:
            raw = Image.open(io.BytesIO(base64.b64decode(o["content"])))
            raw.load()
        except Exception as e:
            pend["skipped"].append({"id": fid, "title": title, "why": "이미지를 열지 못함: " + str(e)[:80]})
            continue
        et, model = exif_info(raw)
        im = ImageOps.exif_transpose(raw)
        h = dhash(im)
        owner = (meta.get(fid) or {}).get("owner") or ""
        who = who_of(model, title, owner, cfg)
        if et:
            tk, when = "exif", et
        else:
            kind, when = name_time(title)
            if when:
                tk = kind
            else:
                tk, when = "upload", upload_time((meta.get(fid) or {}).get("createdTime") or "")
        d = when.strftime("%Y-%m-%d")
        t = when.strftime("%H:%M") if tk in ("exif", "name", "shot") else ""
        # 같은 사진인지
        best, bd = None, 99
        for pid, p in photos.items():
            if p.get("hash"):
                x = hdist(h, p["hash"])
                if x < bd:
                    best, bd = pid, x
        for pid, ph in batch_hash.items():
            x = hdist(h, ph)
            if x < bd:
                best, bd = pid, x
        if best is not None and bd <= DUP_DIST:
            rec = {"id": fid, "title": title, "same": best, "dist": bd}
            old = photos.get(best)
            if old and tk == "exif" and old.get("tk") != "exif":
                wb, (w, hh) = webp_bytes(im)
                with open(os.path.join(a.out, "p", best + ".webp"), "wb") as f:
                    f.write(wb)
                rec["upgrade"] = {"d": d, "t": t, "tk": tk, "who": who, "w": w, "h": hh}
                pend["upgrades"].append(rec)
            else:
                pend["dups"].append(rec)
            continue
        pid = new_id(d, t, who, taken)
        taken.add(pid)
        wb, (w, hh) = webp_bytes(im)
        with open(os.path.join(a.out, "p", pid + ".webp"), "wb") as f:
            f.write(wb)
        batch_hash[pid] = h
        pend["photos"][pid] = {"d": d, "t": t, "tk": tk, "who": who, "cap": "", "w": w, "h": hh,
                               "th": thumb_uri(im), "hash": h, "f": "p/" + pid + ".webp",
                               "src": fid, "title": title, "model": model}
    # 접촉 시트 (Claude가 보고 쓰기 위한 것)
    ids = sorted(pend["photos"], key=lambda k: (pend["photos"][k]["d"], pend["photos"][k]["t"] or "99", k))
    sheets = []
    for n in range(0, len(ids), 9):
        chunk = ids[n:n + 9]
        cell = 360
        sheet = Image.new("RGB", (cell * 3, (cell + 26) * ((len(chunk) + 2) // 3)), "white")
        dr = ImageDraw.Draw(sheet)
        for i, pid in enumerate(chunk):
            im = Image.open(os.path.join(a.out, "p", pid + ".webp")).convert("RGB")
            im.thumbnail((cell - 8, cell - 8))
            x, y = (i % 3) * cell, (i // 3) * (cell + 26)
            sheet.paste(im, (x + 4, y + 26))
            p = pend["photos"][pid]
            dr.text((x + 6, y + 6), f"{pid}  {p['d'][5:]} {p['t'] or p['tk']}  {'J' if p['who'] == 'j' else 'H'}", fill="black")
        sp = os.path.join(a.out, "sheets", f"sheet_{n // 9 + 1}.jpg")
        sheet.save(sp, quality=82)
        sheets.append(sp)
    pend["sheets"] = sheets
    pend["order"] = ids
    dump(pend, os.path.join(a.out, "pending.json"))
    out = {k: (len(v) if isinstance(v, (list, dict)) else v) for k, v in pend.items() if k != "order"}
    out["sheets"] = sheets
    out["new"] = [{"id": k, "d": pend["photos"][k]["d"], "t": pend["photos"][k]["t"], "tk": pend["photos"][k]["tk"],
                   "who": pend["photos"][k]["who"], "title": pend["photos"][k]["title"]} for k in ids]
    out["dups"] = pend["dups"]
    out["upgrades"] = [{"id": u["id"], "same": u["same"], **u["upgrade"]} for u in pend["upgrades"]]
    out["skipped"] = pend["skipped"]
    print(json.dumps(out, ensure_ascii=False, indent=1))


# ---------- apply ----------
def ensure_day(data, d):
    days = data.setdefault("days", {})
    if d not in days:
        days[d] = {"photos": [], "pencil": {"line": "", "where": [], "ate": [], "saw": []}, "firsts": [], "pairs": []}
    days[d].setdefault("photos", [])
    days[d].setdefault("pencil", {"line": "", "where": [], "ate": [], "saw": []})
    return days[d]


def next_id(prefix, existing):
    n = 1
    nums = [int(k[len(prefix):]) for k in existing if k.startswith(prefix) and k[len(prefix):].isdigit()]
    if nums:
        n = max(nums) + 1
    return f"{prefix}{n}"


def cmd_apply(a):
    data = load(a.data)
    pend = load(a.pending)
    rev = load(a.review) if a.review and os.path.exists(a.review) else {}
    photos = data.setdefault("photos", {})
    sync = data.setdefault("sync", {})
    processed = sync.setdefault("processed", {})
    rp = rev.get("photos") or {}
    kept, dropped = [], []
    for pid, p in pend.get("photos", {}).items():
        r = rp.get(pid)
        if r is None:
            r = {"keep": True}
        if not r.get("keep", True):
            processed[p["src"]] = "excluded:" + (r.get("why") or "")
            dropped.append(pid)
            continue
        rec = {k: p[k] for k in ("d", "t", "tk", "who", "w", "h", "th", "hash", "f")}
        rec["cap"] = (r.get("cap") or "").strip()[:60]
        if r.get("d") and re.match(r"^20\d{2}-\d{2}-\d{2}$", r["d"]) and p["tk"] not in ("exif", "name", "shot"):
            rec["d"] = r["d"]  # 받은 날 사진은 Claude가 근거 있을 때만 옮길 수 있다
        photos[pid] = rec
        processed[p["src"]] = "kept:" + pid
        day = ensure_day(data, rec["d"])
        if pid not in day["photos"]:
            day["photos"].append(pid)
        kept.append(pid)
    for u in pend.get("upgrades", []):
        old = photos.get(u["same"])
        processed[u["id"]] = "dup:" + u["same"]
        if not old:
            continue
        up = u["upgrade"]
        if old.get("d") != up["d"]:
            od = data.get("days", {}).get(old["d"])
            if od and u["same"] in od.get("photos", []):
                od["photos"].remove(u["same"])
            nd = ensure_day(data, up["d"])
            nd["photos"].append(u["same"])
        old.update({k: up[k] for k in ("d", "t", "tk", "who", "w", "h")})
        old["f"] = "p/" + u["same"] + ".webp"
    for u in pend.get("dups", []):
        processed[u["id"]] = "dup:" + u["same"]
    # 날짜별 연필 초안
    foods = data.setdefault("foods", {})
    firsts = data.setdefault("firsts", {})
    for d, r in (rev.get("days") or {}).items():
        if not re.match(r"^20\d{2}-\d{2}-\d{2}$", d):
            continue
        day = ensure_day(data, d)
        for k in ("title", "place"):
            if r.get(k):
                day[k] = r[k].strip()[:40]
        pen = day["pencil"]
        if r.get("line"):
            pen["line"] = r["line"].strip()[:240]
        for k in ("where", "saw"):
            if isinstance(r.get(k), list):
                pen[k] = [str(x).strip()[:40] for x in r[k] if str(x).strip()][:8]
        if isinstance(r.get("ate"), list):
            ids = []
            for x in r["ate"]:
                if isinstance(x, str):
                    x = {"n": x}
                nm = (x.get("n") or "").strip()[:40]
                if not nm:
                    continue
                fid = next((k for k, v in foods.items() if v.get("d") == d and v.get("n") == nm), None)
                if not fid:
                    fid = next_id("f", foods)
                    foods[fid] = {"n": nm, "d": d, "p": x.get("p") if x.get("p") in photos else None, "w": (x.get("w") or "").strip()[:40]}
                ids.append(fid)
            pen["ate"] = ids
        if r.get("cover") in photos:
            day["cover"] = r["cover"]
        if isinstance(r.get("pairs"), list):
            day["pairs"] = [pp for pp in r["pairs"] if pp.get("a") in photos and pp.get("b") in photos][:3]
        if isinstance(r.get("firsts"), list):
            ids = list(day.get("firsts") or [])
            for x in r["firsts"]:
                t = (x.get("t") if isinstance(x, dict) else str(x)).strip()[:30]
                if not t or any(firsts.get(i, {}).get("t") == t for i in ids):
                    continue
                nid = next_id("fx", firsts)
                firsts[nid] = {"t": t, "d": d, "p": (x.get("p") if isinstance(x, dict) and x.get("p") in photos else None)}
                ids.append(nid)
            day["firsts"] = ids
        day["auto"] = True
    for d, day in data.get("days", {}).items():
        day["photos"] = sorted(dict.fromkeys(day["photos"]), key=lambda k: sort_key(photos, k))
        if day["photos"] and day.get("cover") not in day["photos"]:
            day["cover"] = day["photos"][0]
    stamp = now_kst()
    sync["last"] = stamp.isoformat()
    note = []
    if kept:
        note.append(f"새 사진 {len(kept)}장")
    if pend.get("upgrades"):
        note.append(f"원본 시각으로 바꾼 사진 {len(pend['upgrades'])}장")
    if dropped:
        note.append(f"뺀 사진 {len(dropped)}장")
    sync["lastNote"] = ", ".join(note) or "새 사진 없음"
    data["updated"] = stamp.isoformat()
    dump(data, a.out)
    print(json.dumps({"kept": kept, "dropped": dropped, "upgrades": [u["same"] for u in pend.get("upgrades", [])],
                      "note": sync["lastNote"]}, ensure_ascii=False, indent=1))


# ---------- pens ----------
MARK = "이 줄 아래에 쓰기"
S1_DAYS = {"c1": "2026-08-13", "c2": "2026-08-28", "c3": "2026-09-01", "c4": "2026-09-06",
           "c5": "2026-09-15", "c6": "2026-09-22", "c7": "2026-09-23"}


def decode_code(s):
    s = s.strip()
    m = re.match(r"^(S[12])-([A-Za-z0-9+/=\s]+)$", s)
    if not m:
        return None, None
    try:
        return m.group(1), json.loads(base64.b64decode(re.sub(r"\s+", "", m.group(2))).decode("utf-8"))
    except Exception:
        return m.group(1), None


def parse_date(line, today):
    m = re.match(r"^\s*(?:(20\d{2})[./-])?(\d{1,2})\s*(?:[./-]|월\s*)(\d{1,2})\s*일?\s*[:·,.)\-]?\s*(.*)$", line)
    if m:
        y = int(m.group(1) or today.year)
        try:
            d = dt.date(y, int(m.group(2)), int(m.group(3)))
            if not m.group(1) and d > today + dt.timedelta(days=1):
                d = d.replace(year=y - 1)
            return d.isoformat(), m.group(4).strip()
        except ValueError:
            pass
    return today.isoformat(), line.strip()


def merge_payload(pen, kind, o, seen):
    w = o.get("w")
    if w not in ("j", "h"):
        return 0
    n = 0
    notes = pen.setdefault("notes", [])
    have = {x["id"] for x in notes}
    if kind == "S1":
        d = o.get("d") or {}
        for cid, arr in (d.get("notes") or {}).items():
            for x in arr if isinstance(arr, list) else []:
                nid = f"s1-{w}-{x.get('t')}"
                if nid in have or not isinstance(x.get("s"), str) or cid not in S1_DAYS:
                    continue
                notes.append({"id": nid, "who": w, "d": S1_DAYS[cid], "s": x["s"][:140], "t": int(x.get("t") or 0), "src": "code"})
                have.add(nid)
                n += 1
        body = {"stars": d.get("stars"), "firsts": {k: 1 for k, v in (d.get("firsts") or {}).items() if v}, "wish": d.get("wish")}
    else:
        for x in o.get("notes") or []:
            if not isinstance(x, dict) or x.get("id") in have or not isinstance(x.get("s"), str):
                continue
            if not re.match(r"^20\d{2}-\d{2}-\d{2}$", str(x.get("d"))):
                continue
            nn = {"id": str(x["id"])[:40], "who": w, "d": x["d"], "s": x["s"][:140], "t": int(x.get("t") or 0), "src": "code"}
            if isinstance(x.get("q"), str) and re.match(r"^[a-z0-9-]{1,12}$", x["q"]):
                nn["q"] = x["q"]  # 질문 답(오늘의 질문 d01~, 36가지 a1~)
            notes.append(nn)
            have.add(x["id"])
            n += 1
        body = o
    for k in ("stars", "firsts"):
        v = body.get(k)
        if isinstance(v, dict):
            pen.setdefault(k, {}).setdefault(w, {}).update({str(a)[:20]: b for a, b in v.items()})
            n += len(v)
    wl = pen.setdefault("wish", [])
    wmap = {x["id"]: x for x in wl}
    for x in body.get("wish") or []:
        if not isinstance(x, dict) or not isinstance(x.get("s"), str):
            continue
        xid = str(x.get("id"))[:40]
        due = x.get("due") if re.match(r"^20\d{2}-\d{2}-\d{2}$", str(x.get("due") or "")) else None
        cur = wmap.get(xid)
        if cur is not None:  # 이미 있는 것: 했어요 표시와(쓴 사람이면) 날짜만 고친다
            ch = False
            if bool(x.get("done")) != bool(cur.get("done")):
                cur["done"] = bool(x.get("done")); ch = True
            if cur.get("who") == w and due and due != cur.get("due"):
                cur["due"] = due; ch = True
            n += 1 if ch else 0
            continue
        item = {"id": xid, "who": w, "s": x["s"][:80], "t": int(x.get("t") or 0), "done": bool(x.get("done"))}
        if due:
            item["due"] = due
        wl.append(item)
        wmap[xid] = item
        n += 1
    return n


def cmd_pens(a):
    data = load(a.data)
    pen = data.setdefault("pen", {"notes": [], "stars": {}, "firsts": {}, "wish": []})
    sync = data.setdefault("sync", {})
    seen = set(sync.get("seenLines") or [])
    today = dt.date.fromisoformat(a.today) if a.today else now_kst().date()
    added = []
    for who, path in (("j", a.j), ("h", a.h)):
        if not path or not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            txt = f.read()
        body = txt.split(MARK, 1)[1] if MARK in txt else txt
        for line in body.splitlines():
            line = line.strip().strip("─").strip()
            if not line:
                continue
            hsh = hashlib.sha1((who + "|" + line).encode("utf-8")).hexdigest()[:12]
            if hsh in seen:
                continue
            seen.add(hsh)
            kind, o = decode_code(line)
            if kind:
                if o:
                    o = dict(o)
                    o["w"] = o.get("w") if o.get("w") in ("j", "h") else who
                    added.append({"who": who, "code": kind, "items": merge_payload(pen, kind, o, seen)})
                    if re.match(r"^20\d{2}-\d{2}-\d{2}$", str(o.get("since") or "")):
                        data["since"] = o["since"]
                continue
            m = re.match(r"^함께\s*시작일?\s*[:：]?\s*(20\d{2})[./-](\d{1,2})[./-](\d{1,2})", line)
            if m:
                try:
                    data["since"] = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat()
                    added.append({"who": who, "since": data["since"]})
                except ValueError:
                    pass
                continue
            d, s = parse_date(line, today)
            if not s:
                continue
            nid = "doc-" + hsh
            pen.setdefault("notes", []).append({"id": nid, "who": who, "d": d, "s": s[:140],
                                                 "t": int(now_kst().timestamp() * 1000), "src": "doc"})
            added.append({"who": who, "d": d, "s": s[:60]})
    sync["seenLines"] = sorted(seen)[-4000:]
    dump(data, a.out)
    print(json.dumps({"added": added}, ensure_ascii=False, indent=1))


# ---------- check ----------
def cmd_check(a):
    data = load(a.data)
    photos = data.get("photos", {})
    probs = []
    for d, day in data.get("days", {}).items():
        for pid in day.get("photos", []):
            if pid not in photos:
                probs.append(f"{d}: 없는 사진 {pid}")
            elif photos[pid].get("d") != d:
                probs.append(f"{d}: {pid} 날짜가 {photos[pid].get('d')}")
    for fid, f in data.get("foods", {}).items():
        if f.get("p") and f["p"] not in photos:
            probs.append(f"음식 {fid}: 없는 사진 {f['p']}")
    n = len(photos)
    size = os.path.getsize(a.data)
    built = glob.glob(os.path.join(a.build or ".", "p", "*.webp")) if a.build else []
    print(json.dumps({"photos": n, "days": len(data.get("days", {})), "dataKB": round(size / 1024),
                      "newFiles": len(built), "fileCap": FILE_CAP, "roomLeft": FILE_CAP - n,
                      "problems": probs[:30]}, ensure_ascii=False, indent=1))
    if probs:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("plan"); p.add_argument("--data", required=True); p.add_argument("--list", required=True)
    p = sp.add_parser("ingest"); p.add_argument("--data", required=True); p.add_argument("--out", required=True)
    p.add_argument("--list"); p.add_argument("--glob", action="store_true"); p.add_argument("downloads", nargs="*")
    p = sp.add_parser("apply"); p.add_argument("--data", required=True); p.add_argument("--pending", required=True)
    p.add_argument("--review"); p.add_argument("--out", required=True)
    p = sp.add_parser("pens"); p.add_argument("--data", required=True); p.add_argument("--j"); p.add_argument("--h")
    p.add_argument("--today"); p.add_argument("--out", required=True)
    p = sp.add_parser("check"); p.add_argument("--data", required=True); p.add_argument("--build")
    a = ap.parse_args()
    {"plan": cmd_plan, "ingest": cmd_ingest, "apply": cmd_apply, "pens": cmd_pens, "check": cmd_check}[a.cmd](a)


if __name__ == "__main__":
    main()
