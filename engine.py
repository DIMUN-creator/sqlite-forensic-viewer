# -*- coding: utf-8 -*-
"""
SQLite 포렌식 분석 엔진 (GUI 비의존 순수 로직)
================================================
이 모듈은 화면 표시와 완전히 분리된 '분석 코어'입니다.
GUI(viewer.py)는 이 엔진을 호출해서 결과만 그려줍니다.
이렇게 분리하면: (1) 로직을 단독 테스트할 수 있고,
(2) 나중에 CLI나 웹으로도 재사용할 수 있습니다.

포렌식 3대 원칙을 코드로 지킵니다:
  1) 원본 불변성 : 원본 파일을 절대 열지 않고, 읽기 전용 사본으로만 작업
  2) 재현 가능성 : 모든 분석은 결정적(deterministic)이며 로그로 남김
  3) 무결성 검증 : 원본/사본의 해시를 비교해 훼손 여부를 증명
"""

import os
import shutil
import struct
import hashlib
import sqlite3
import tempfile
import datetime
from dataclasses import dataclass, field


# ─────────────────────────────────────────────────────────────
# 1. 타임스탬프 변환기
#    포렌식에서 시간 해석은 핵심 작업입니다. 앱마다 기준 시각과
#    단위가 달라서, 같은 숫자라도 전혀 다른 날짜가 됩니다.
# ─────────────────────────────────────────────────────────────

# 각 시간 체계의 기준점(epoch)
_UNIX_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
_WIN_EPOCH  = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)  # Windows FILETIME
_MAC_EPOCH  = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)  # Apple/Cocoa


def _fmt(dt):
    """datetime을 사람이 읽는 문자열로. 범위를 벗어나면 None."""
    try:
        return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return None


def interpret_timestamp(value):
    """
    숫자 하나를 받아 '있을 법한 모든 시간 해석'을 돌려줍니다.
    포렌식에서는 어떤 체계인지 모를 때가 많아서, 후보를 나열하고
    분석가가 문맥(대략 언제쯤 사건이 일어났는지)으로 고릅니다.

    반환: [(체계이름, 변환결과문자열), ...]
    """
    results = []
    try:
        n = float(value)
    except (TypeError, ValueError):
        return results

    candidates = [
        ("Unix 초",              lambda: _UNIX_EPOCH + datetime.timedelta(seconds=n)),
        ("Unix 밀리초",          lambda: _UNIX_EPOCH + datetime.timedelta(milliseconds=n)),
        ("Unix 마이크로초",      lambda: _UNIX_EPOCH + datetime.timedelta(microseconds=n)),
        ("Windows FILETIME",     lambda: _WIN_EPOCH  + datetime.timedelta(microseconds=n / 10)),
        ("WebKit/Chrome",        lambda: _WIN_EPOCH  + datetime.timedelta(microseconds=n)),
        ("Apple(Cocoa) 초",      lambda: _MAC_EPOCH  + datetime.timedelta(seconds=n)),
        ("Apple 마이크로초",     lambda: _MAC_EPOCH  + datetime.timedelta(microseconds=n)),
    ]

    # 합리적 범위(1990~2100년)로 거른 뒤 후보를 채택
    lo = datetime.datetime(1990, 1, 1, tzinfo=datetime.timezone.utc)
    hi = datetime.datetime(2100, 1, 1, tzinfo=datetime.timezone.utc)
    for name, fn in candidates:
        try:
            dt = fn()
            if lo <= dt <= hi:
                s = _fmt(dt)
                if s:
                    results.append((name, s))
        except (OverflowError, OSError, ValueError):
            continue

    # SQLite Julian day (예: 2451545.0 = 2000-01-01) 도 체크
    try:
        if 2400000 <= n <= 2500000:
            jd_unix = (n - 2440587.5) * 86400.0
            dt = _UNIX_EPOCH + datetime.timedelta(seconds=jd_unix)
            if lo <= dt <= hi:
                results.append(("SQLite Julian day", _fmt(dt)))
    except (OverflowError, OSError, ValueError):
        pass

    return results


# ─────────────────────────────────────────────────────────────
# 2. 원본 보호 + 무결성
# ─────────────────────────────────────────────────────────────

def sha256_of(path, chunk=1 << 20):
    """파일의 SHA-256 해시. 원본과 사본이 같음을 증명하는 데 씀."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


@dataclass
class CaseFile:
    """분석 대상 하나에 대한 메타정보(증거 기록)."""
    original_path: str
    working_copy: str
    original_hash: str
    copy_hash: str
    size_bytes: int
    opened_at: str

    @property
    def integrity_ok(self):
        return self.original_hash == self.copy_hash


def open_evidence(path):
    """
    원본을 건드리지 않고 읽기 전용 사본을 만들어 CaseFile을 반환.
    이후 모든 분석은 사본(working_copy)에 대해서만 수행합니다.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(path)

    original_hash = sha256_of(path)

    tmpdir = tempfile.mkdtemp(prefix="forensic_")
    copy_path = os.path.join(tmpdir, "evidence_copy.sqlite")
    shutil.copy2(path, copy_path)
    copy_hash = sha256_of(copy_path)

    return CaseFile(
        original_path=path,
        working_copy=copy_path,
        original_hash=original_hash,
        copy_hash=copy_hash,
        size_bytes=os.path.getsize(path),
        opened_at=datetime.datetime.now(datetime.timezone.utc)
                          .strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


# ─────────────────────────────────────────────────────────────
# 3. 스키마 / 데이터 조회 (읽기 전용 연결)
# ─────────────────────────────────────────────────────────────

def _connect_ro(copy_path):
    """읽기 전용 모드로 연결. 사본이라도 실수로 쓰지 않도록 이중 안전장치."""
    uri = f"file:{copy_path}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def list_tables(copy_path):
    """(테이블명, 행수, CREATE문) 목록."""
    out = []
    with _connect_ro(copy_path) as con:
        cur = con.cursor()
        cur.execute(
            "SELECT name, sql FROM sqlite_master "
            "WHERE type='table' ORDER BY name"
        )
        rows = cur.fetchall()
        for name, sql in rows:
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{name}"')
                count = cur.fetchone()[0]
            except sqlite3.DatabaseError:
                count = -1
            out.append({"name": name, "rows": count, "sql": sql or ""})
    return out


def read_table(copy_path, table, limit=200, offset=0):
    """테이블 내용을 페이지 단위로. 반환: (컬럼목록, 행리스트)."""
    with _connect_ro(copy_path) as con:
        cur = con.cursor()
        cur.execute(f'SELECT * FROM "{table}" LIMIT ? OFFSET ?', (limit, offset))
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
    return cols, rows


# ─────────────────────────────────────────────────────────────
# 4. 삭제 흔적 스캔  ── 포렌식의 꽃
#    SQLite는 행을 지워도 바이트를 즉시 지우지 않습니다.
#    - freeblock : 페이지 안에서 삭제되어 재사용 대기 중인 공간
#    - unallocated : 셀 영역과 헤더 사이의 미사용 공간
#    여기에 지워진 문자열이 그대로 남아있는 경우가 많습니다.
#    v1에서는 이 영역들에서 '읽을 수 있는 문자열'을 추출합니다.
#    (완전한 레코드 복원은 v2의 과제)
# ─────────────────────────────────────────────────────────────

@dataclass
class CarveHit:
    page: int
    region: str          # 'freeblock' | 'unallocated'
    offset: int
    text: str


def _read_header(data):
    """DB 헤더에서 페이지 크기와 페이지 수를 읽음."""
    if len(data) < 100 or data[:16] != b"SQLite format 3\x00":
        raise ValueError("유효한 SQLite 파일이 아닙니다.")
    page_size = struct.unpack(">H", data[16:18])[0]
    if page_size == 1:            # 특수값 1 = 65536
        page_size = 65536
    page_count = struct.unpack(">I", data[28:32])[0]
    return page_size, page_count


def _extract_strings(chunk, min_len=4):
    """바이트 조각에서 인쇄 가능한 ASCII/UTF-8 문자열을 뽑음."""
    hits = []
    cur = bytearray()
    start = 0
    for i, b in enumerate(chunk):
        # 인쇄 가능 ASCII 또는 UTF-8 연속 바이트로 취급
        if 0x20 <= b <= 0x7E or b >= 0x80:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                try:
                    hits.append((start, cur.decode("utf-8", errors="ignore")))
                except Exception:
                    pass
            cur = bytearray()
    if len(cur) >= min_len:
        hits.append((start, cur.decode("utf-8", errors="ignore")))
    # 너무 짧거나 의미 없는 것 정리
    cleaned = []
    for off, s in hits:
        s = s.strip()
        if len(s) >= min_len and any(c.isalnum() for c in s):
            cleaned.append((off, s))
    return cleaned


def scan_deleted(copy_path, min_len=4, max_hits=5000):
    """
    사본을 페이지 단위로 훑어 삭제 흔적(문자열)을 추출.
    반환: CarveHit 리스트
    """
    with open(copy_path, "rb") as f:
        data = f.read()

    page_size, page_count = _read_header(data)
    hits = []

    # b-tree 리프 페이지(타입 0x0D)만 대상으로 함
    for pg in range(page_count):
        base = pg * page_size
        page = data[base: base + page_size]
        if len(page) < 8:
            break

        # 첫 페이지는 100바이트 헤더 뒤부터 b-tree 헤더가 시작
        hdr = 100 if pg == 0 else 0
        if hdr >= len(page):
            continue
        ptype = page[hdr]
        if ptype != 0x0D:   # 0x0D = 테이블 b-tree 리프
            continue

        num_cells = struct.unpack(">H", page[hdr + 3: hdr + 5])[0]
        cell_content_start = struct.unpack(">H", page[hdr + 5: hdr + 7])[0]
        if cell_content_start == 0:
            cell_content_start = 65536

        # (a) freeblock 체인: 헤더 오프셋 1~2 바이트가 첫 freeblock 위치
        fb = struct.unpack(">H", page[hdr + 1: hdr + 3])[0]
        seen = set()
        while fb != 0 and fb not in seen and fb + 4 <= len(page):
            seen.add(fb)
            nxt = struct.unpack(">H", page[fb: fb + 2])[0]
            size = struct.unpack(">H", page[fb + 2: fb + 4])[0]
            region = page[fb: fb + max(size, 4)]
            for off, s in _extract_strings(region, min_len):
                hits.append(CarveHit(pg, "freeblock", base + fb + off, s))
                if len(hits) >= max_hits:
                    return hits
            fb = nxt

        # (b) unallocated 영역: 셀 포인터 배열 끝 ~ cell_content_start 사이
        ptr_array_end = hdr + 8 + num_cells * 2
        if ptr_array_end < cell_content_start <= len(page):
            gap = page[ptr_array_end: cell_content_start]
            for off, s in _extract_strings(gap, min_len):
                hits.append(CarveHit(pg, "unallocated", base + ptr_array_end + off, s))
                if len(hits) >= max_hits:
                    return hits

    return hits


# ─────────────────────────────────────────────────────────────
# 5. WAL(Write-Ahead Log) 존재 확인
#    -wal 파일에는 아직 본체에 반영 안 된 최신 변경이 들어있어
#    포렌식에서 매우 중요합니다. 존재 여부를 알려줍니다.
# ─────────────────────────────────────────────────────────────

def check_side_files(original_path):
    notes = []
    for suffix in ("-wal", "-journal", "-shm"):
        p = original_path + suffix
        if os.path.isfile(p):
            notes.append({
                "file": os.path.basename(p),
                "size": os.path.getsize(p),
                "note": {
                    "-wal": "미반영 최신 변경 포함 가능 — 반드시 함께 보존",
                    "-journal": "롤백 저널 — 직전 트랜잭션 흔적",
                    "-shm": "WAL 공유 메모리 인덱스",
                }[suffix],
            })
    return notes


# ─────────────────────────────────────────────────────────────
# 6. SQLite 파일 찾기 (수집/트리아지)
#    확장자를 믿지 않고 매직 넘버로 판별합니다.
#    (예전 finder.py 내용을 엔진으로 통합 — viewer가 단일 의존)
# ─────────────────────────────────────────────────────────────

SQLITE_MAGIC = b"SQLite format 3\x00"


def is_sqlite(path):
    """파일 앞 16바이트 매직 넘버로 SQLite 여부 판별."""
    try:
        with open(path, "rb") as f:
            return f.read(16) == SQLITE_MAGIC
    except (OSError, PermissionError):
        return False


def default_search_roots():
    """윈도우에서 SQLite가 잘 모여 있는 대표 위치들."""
    home = os.path.expanduser("~")
    local = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    roaming = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    roots = [
        os.path.join(local, "Google", "Chrome", "User Data"),
        os.path.join(local, "Microsoft", "Edge", "User Data"),
        os.path.join(roaming, "Mozilla", "Firefox", "Profiles"),
        os.path.join(roaming, "discord"),
        os.path.join(local, "Programs", "Microsoft VS Code"),
        os.path.join(home, "Desktop"),
        os.path.join(home, "Documents"),
        os.path.join(home, "Downloads"),
    ]
    return [r for r in roots if os.path.isdir(r)]


def find_sqlite(roots, max_depth=6, skip_bigger_than=500 * 1024 * 1024):
    """
    roots 아래를 재귀적으로 훑어 SQLite 파일 목록을 반환.
    반환: [(경로, 크기bytes), ...]  크기 내림차순
    """
    found = []
    for root in roots:
        root_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root):
            if dirpath.count(os.sep) - root_depth >= max_depth:
                dirnames[:] = []
                continue
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    size = os.path.getsize(p)
                except OSError:
                    continue
                if size < 16 or size > skip_bigger_than:
                    continue
                if is_sqlite(p):
                    found.append((p, size))
    found.sort(key=lambda x: -x[1])
    return found


def human(n):
    """바이트 수를 사람이 읽는 크기로."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


# ─────────────────────────────────────────────────────────────
# 7. 대화(메시지) 해석
#    (a) 평문 SQLite 메시지 테이블을 '대화 형태'로 정규화
#    (b) 카카오톡 내보내기 .txt 파싱
#    ※ 암호화된 메신저 DB 복호화는 다루지 않습니다.
#       본인 데이터의 정식 내보내기/평문 저장소만 대상으로 합니다.
# ─────────────────────────────────────────────────────────────

import re as _re

# 컬럼 이름으로 sender/body/time 역할을 추측하기 위한 힌트
_SENDER_HINTS = ("sender", "from", "author", "user", "nick", "name",
                 "보낸", "발신", "이름")
_BODY_HINTS   = ("body", "text", "message", "content", "msg", "content",
                 "내용", "메시지", "본문")
_TIME_HINTS   = ("time", "date", "ts", "created", "sent", "at",
                 "시각", "시간", "날짜")


def guess_message_columns(cols):
    """
    컬럼 목록에서 sender/body/time 역할을 추측.
    반환: {"sender": 컬럼명|None, "body": ..., "time": ...}
    확실치 않으면 None을 주고, 사용자가 UI에서 고르게 합니다.
    """
    lower = {c: c.lower() for c in cols}

    def pick(hints, exclude=()):
        for c in cols:
            if c in exclude:
                continue
            lc = lower[c]
            if any(h in lc for h in hints):
                return c
        return None

    sender = pick(_SENDER_HINTS)
    body = pick(_BODY_HINTS, exclude={sender})
    time_ = pick(_TIME_HINTS, exclude={sender, body})
    return {"sender": sender, "body": body, "time": time_}


def _best_time(value):
    """타임스탬프 후보 중 가장 그럴듯한 하나를 문자열로. 없으면 원값."""
    res = interpret_timestamp(value)
    if res:
        # WebKit/Unix 계열을 우선
        for pref in ("WebKit/Chrome", "Unix 초", "Unix 밀리초"):
            for name, s in res:
                if name == pref:
                    return s
        return res[0][1]
    return str(value)


def load_conversation(copy_path, table, sender_col, body_col, time_col,
                      limit=1000, offset=0):
    """
    메시지 테이블을 대화 형태로 읽어옵니다.
    반환: [{"sender":..., "body":..., "time":..., "raw_time":...}, ...]
    time_col이 숫자면 자동으로 사람이 읽는 시각으로 변환합니다.
    """
    sel_cols = [c for c in (sender_col, body_col, time_col) if c]
    if not sel_cols:
        return []
    quoted = ", ".join(f'"{c}"' for c in sel_cols)
    order = f' ORDER BY "{time_col}"' if time_col else ""
    with _connect_ro(copy_path) as con:
        cur = con.cursor()
        cur.execute(f'SELECT {quoted} FROM "{table}"{order} LIMIT ? OFFSET ?',
                    (limit, offset))
        rows = cur.fetchall()
        names = [d[0] for d in cur.description]

    idx = {name: i for i, name in enumerate(names)}
    out = []
    for r in rows:
        sender = r[idx[sender_col]] if sender_col else ""
        body   = r[idx[body_col]] if body_col else ""
        rawt   = r[idx[time_col]] if time_col else ""
        out.append({
            "sender": "" if sender is None else str(sender),
            "body":   "" if body is None else str(body),
            "time":   _best_time(rawt) if time_col and rawt not in (None, "") else "",
            "raw_time": "" if rawt is None else str(rawt),
        })
    return out


# 카카오톡 내보내기 형식들 -----------------------------------------

# PC 내보내기:  [홍길동] [오후 3:24] 메시지
_KAKAO_PC = _re.compile(
    r'^\[(?P<sender>.+?)\]\s*\[(?P<ampm>오전|오후)\s*(?P<h>\d{1,2}):(?P<m>\d{2})\]\s*(?P<body>.*)$')

# PC 날짜 구분선: --------------- 2024년 9월 30일 월요일 ---------------
_KAKAO_DATE = _re.compile(
    r'-{3,}\s*(?P<y>\d{4})년\s*(?P<mo>\d{1,2})월\s*(?P<d>\d{1,2})일')

# 모바일 내보내기:  2024. 9. 30. 15:24, 홍길동 : 메시지
_KAKAO_MOBILE = _re.compile(
    r'^(?P<y>\d{4})\.\s*(?P<mo>\d{1,2})\.\s*(?P<d>\d{1,2})\.\s*'
    r'(?P<h>\d{1,2}):(?P<m>\d{2}),\s*(?P<sender>.+?)\s*:\s*(?P<body>.*)$')


def parse_kakao_export(path):
    """
    카카오톡이 내보낸 .txt 대화 파일을 파싱.
    PC/모바일 두 형식을 모두 지원하며, 실패한 줄은 직전 메시지에
    이어붙입니다(여러 줄 메시지 처리).
    반환: [{"sender":..., "body":..., "time":...}, ...]
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()

    out = []
    cur_date = ""   # "2024-09-30"
    for line in lines:
        # 날짜 구분선 갱신
        md = _KAKAO_DATE.search(line)
        if md:
            cur_date = f"{int(md['y']):04d}-{int(md['mo']):02d}-{int(md['d']):02d}"
            continue

        # 모바일 형식(날짜가 줄 안에 포함)
        mm = _KAKAO_MOBILE.match(line)
        if mm:
            h = int(mm['h']); m = int(mm['m'])
            t = f"{int(mm['y']):04d}-{int(mm['mo']):02d}-{int(mm['d']):02d} {h:02d}:{m:02d}"
            out.append({"sender": mm['sender'].strip(),
                        "body": mm['body'].strip(), "time": t})
            continue

        # PC 형식
        mp = _KAKAO_PC.match(line)
        if mp:
            h = int(mp['h']) % 12
            if mp['ampm'] == '오후':
                h += 12
            t = f"{cur_date} {h:02d}:{int(mp['m']):02d}".strip()
            out.append({"sender": mp['sender'].strip(),
                        "body": mp['body'].strip(), "time": t})
            continue

        # 어느 형식도 아니면 → 직전 메시지의 다음 줄(여러 줄 메시지)
        if out and line.strip():
            out[-1]["body"] += "\n" + line
    return out


# ─────────────────────────────────────────────────────────────
# 8. 삭제 레코드 '구조' 복원  ── 이 도구에서 가장 어려운 부분
#    7번(문자열 추출)을 넘어, 삭제된 셀의 SQLite 레코드 포맷을
#    직접 파싱해 컬럼 값(보낸이/내용/시간)까지 되살립니다.
#    스키마의 컬럼 개수를 검증기로 써서 오탐을 걸러냅니다.
#    한계: 헤더가 덮인 셀, VACUUM/secure_delete된 DB는 복원 불가.
# ─────────────────────────────────────────────────────────────

def _read_varint(data, off):
    """SQLite varint(가변길이 정수) 파싱. 반환 (값, 소비바이트수)."""
    result = 0
    for i in range(9):
        if off + i >= len(data):
            return None, 0
        b = data[off + i]
        if i == 8:
            result = (result << 8) | b
            return result, 9
        result = (result << 7) | (b & 0x7F)
        if not (b & 0x80):
            return result, i + 1
    return result, 9


def _serial_size(t):
    """serial type 코드 → 값이 차지하는 바이트 수 (None이면 잘못된 타입)."""
    if t in (0, 8, 9):
        return 0
    if t in (1, 2, 3, 4):
        return t
    if t == 5:
        return 6
    if t in (6, 7):
        return 8
    if t in (10, 11):
        return None            # 예약값 → 유효한 레코드 아님
    return (t - 12) // 2 if t % 2 == 0 else (t - 13) // 2


def _decode_value(data, off, t):
    """serial type에 맞춰 값 하나를 디코드."""
    size = _serial_size(t)
    if size is None or off + size > len(data):
        return None
    if t == 0:
        return None
    if t == 8:
        return 0
    if t == 9:
        return 1
    chunk = data[off:off + size]
    if 1 <= t <= 6:
        return int.from_bytes(chunk, "big", signed=True)
    if t == 7:
        return struct.unpack(">d", chunk)[0]
    if t >= 12 and t % 2 == 0:
        return chunk                         # BLOB
    try:
        return chunk.decode("utf-8", errors="replace")   # TEXT
    except Exception:
        return chunk


def _serial_category(t):
    """serial type을 대분류로: NULL/INT/REAL/TEXT/BLOB/None(무효)."""
    if t == 0:
        return "NULL"
    if t in (1, 2, 3, 4, 5, 6, 8, 9):
        return "INT"
    if t == 7:
        return "REAL"
    if t in (10, 11):
        return None
    return "BLOB" if t % 2 == 0 else "TEXT"


def _affinity(decl):
    """선언 자료형 문자열 → 컬럼 애피니티(SQLite 규칙)."""
    d = (decl or "").upper()
    if "INT" in d:
        return "INT"
    if any(k in d for k in ("CHAR", "CLOB", "TEXT")):
        return "TEXT"
    if "BLOB" in d or d == "":
        return "BLOB"
    if any(k in d for k in ("REAL", "FLOA", "DOUB")):
        return "REAL"
    return "NUMERIC"


def _cat_ok(cat, aff):
    """복원된 값의 분류(cat)가 컬럼 애피니티(aff)에 맞는지."""
    if cat == "NULL":
        return True
    if aff == "TEXT":
        return cat == "TEXT"
    if aff == "INT":
        return cat in ("INT", "REAL")
    if aff == "REAL":
        return cat in ("REAL", "INT")
    if aff == "BLOB":
        return True
    return cat in ("INT", "REAL", "TEXT")


def _clean_text(s):
    """텍스트가 충분히 '읽을 수 있는' 상태인지(제어/깨진 문자 비율)."""
    if not s:
        return True
    bad = sum(1 for c in s if c == "\ufffd" or (ord(c) < 32 and c not in "\t\n"))
    return bad / len(s) <= 0.15


def _try_record(data, off, affs):
    """
    off에서 레코드 헤더가 시작한다고 가정하고 파싱 + 스키마 검증.
    affs: 컬럼별 애피니티 리스트. 컬럼 수/자료형이 다 맞아야 채택.
    """
    ncols = len(affs)
    hlen, n = _read_varint(data, off)
    if hlen is None or n == 0 or hlen < 2 or hlen > 0x0FFFFFFF:
        return None
    header_end = off + hlen
    if header_end > len(data):
        return None
    types = []
    p = off + n
    while p < header_end:
        t, m = _read_varint(data, p)
        if t is None or m == 0 or _serial_size(t) is None:
            return None
        types.append(t)
        p += m
    if p != header_end or len(types) != ncols:
        return None
    # 자료형 애피니티 검증 (오탐 제거의 핵심)
    for t, aff in zip(types, affs):
        if not _cat_ok(_serial_category(t), aff):
            return None
    # 값 해석
    values = []
    vp = header_end
    for t in types:
        size = _serial_size(t)
        if size is None or vp + size > len(data):
            return None
        val = _decode_value(data, vp, t)
        if isinstance(val, str) and not _clean_text(val):
            return None
        values.append(val)
        vp += size
    return values


def _freelist_pages(data, page_size):
    """DB 헤더에서 프리리스트(비워진 페이지) 번호들을 열거."""
    if len(data) < 40:
        return set()
    first_trunk = struct.unpack(">I", data[32:36])[0]
    free = set()
    trunk = first_trunk
    guard = 0
    while trunk != 0 and guard < 100000:
        guard += 1
        base = (trunk - 1) * page_size
        if base < 0 or base + 8 > len(data):
            break
        nxt = struct.unpack(">I", data[base:base + 4])[0]
        nleaf = struct.unpack(">I", data[base + 4:base + 8])[0]
        free.add(trunk - 1)                      # 트렁크 페이지도 옛 데이터 포함 가능
        for i in range(nleaf):
            off = base + 8 + i * 4
            if off + 4 > len(data):
                break
            leaf = struct.unpack(">I", data[off:off + 4])[0]
            if leaf > 0:
                free.add(leaf - 1)
        trunk = nxt
    return free


def _carve_region(data, lo, hi, affs, live, seen, out, page_idx):
    """[lo,hi) 구간의 모든 오프셋에서 레코드 파싱 시도, 유효한 것만 out에 추가."""
    ncols = len(affs)
    off = lo
    while off < hi:
        vals = _try_record(data, off, affs)
        if vals:
            key = tuple("" if v is None else str(v) for v in vals)
            if key not in live and key not in seen and \
               any(isinstance(v, str) and len(v.strip()) >= 2 for v in vals):
                seen.add(key)
                out.append({"values": vals, "page": page_idx, "offset": off})
        off += 1


def recover_deleted_records(copy_path, table):
    """
    삭제된 레코드를 구조까지 복원(스키마 검증 + 프리리스트/전체페이지 카빙).
    반환: {"columns":[...], "records":[{"values":[...],"page":n,"offset":n}]}
    best-effort — VACUUM/secure_delete 시 복원 불가.
    """
    with _connect_ro(copy_path) as con:
        cur = con.cursor()
        cur.execute(f'PRAGMA table_info("{table}")')
        info = cur.fetchall()
    cols = [r[1] for r in info]
    affs = [_affinity(r[2]) for r in info]
    if not cols:
        return {"columns": [], "records": []}

    live = set()
    with _connect_ro(copy_path) as con:
        cur = con.cursor()
        cur.execute(f'SELECT * FROM "{table}"')
        for r in cur.fetchall():
            live.add(tuple("" if v is None else str(v) for v in r))

    with open(copy_path, "rb") as f:
        data = f.read()
    page_size, page_count = _read_header(data)
    freelist = _freelist_pages(data, page_size)

    seen = set()
    records = []
    for pg in range(page_count):
        base = pg * page_size
        page = data[base: base + page_size]
        if len(page) < 8:
            break
        hdr = 100 if pg == 0 else 0

        if pg in freelist:
            # 통째로 비워진 페이지 → 페이지 전체를 카빙
            _carve_region(data, base + hdr, base + len(page), affs,
                          live, seen, records, pg)
            continue

        if hdr >= len(page) or page[hdr] != 0x0D:
            continue

        # 살아있는 리프 페이지 → freeblock + unallocated만 카빙
        num_cells = struct.unpack(">H", page[hdr + 3: hdr + 5])[0]
        cell_start = struct.unpack(">H", page[hdr + 5: hdr + 7])[0] or 65536
        ptr_end = hdr + 8 + num_cells * 2

        if ptr_end < cell_start <= len(page):
            _carve_region(data, base + ptr_end, base + cell_start, affs,
                          live, seen, records, pg)
        fb = struct.unpack(">H", page[hdr + 1: hdr + 3])[0]
        fseen = set()
        while fb != 0 and fb not in fseen and fb + 4 <= len(page):
            fseen.add(fb)
            nxt = struct.unpack(">H", page[fb: fb + 2])[0]
            size = struct.unpack(">H", page[fb + 2: fb + 4])[0]
            _carve_region(data, base + fb, base + min(fb + max(size, 4), len(page)),
                          affs, live, seen, records, pg)
            fb = nxt

    return {"columns": cols, "records": records}


def load_conversation_with_deleted(copy_path, table, sender_col, body_col,
                                   time_col, limit=2000):
    """
    살아있는 메시지 + 복원된 삭제 메시지를 시간순으로 병합.
    반환: [{"sender","body","time","raw_time","deleted"(bool)}, ...]
    삭제 메시지는 deleted=True로 표시되고, 시간값 기준 제자리에 삽입됩니다.
    """
    live = load_conversation(copy_path, table, sender_col, body_col,
                             time_col, limit=limit)
    for m in live:
        m["deleted"] = False

    rec = recover_deleted_records(copy_path, table)
    cols = rec["columns"]
    deleted = []
    if cols:
        si = cols.index(sender_col) if sender_col in cols else None
        bi = cols.index(body_col) if body_col in cols else None
        ti = cols.index(time_col) if time_col in cols else None
        for r in rec["records"]:
            v = r["values"]
            rawt = v[ti] if ti is not None else ""
            deleted.append({
                "sender": "" if si is None or v[si] is None else str(v[si]),
                "body":   "" if bi is None or v[bi] is None else str(v[bi]),
                "time":   _best_time(rawt) if ti is not None and rawt not in (None, "") else "",
                "raw_time": "" if rawt in (None, "") else str(rawt),
                "deleted": True,
            })

    merged = live + deleted

    # 시간(raw_time)이 숫자면 그 값으로, 아니면 뒤로 보내 원순서 유지
    def _key(m):
        try:
            return (0, float(m["raw_time"]))
        except (ValueError, TypeError):
            return (1, 0.0)
    merged.sort(key=_key)
    return merged, len(deleted)


# ─────────────────────────────────────────────────────────────
# 9. 대화 통계
#    "보여주기"를 넘어 "분석하기". 누가·언제·삭제가 언제 일어났나.
# ─────────────────────────────────────────────────────────────

def conversation_stats(messages):
    """
    병합된 대화 리스트를 받아 통계를 계산.
    messages: [{"sender","body","time","raw_time","deleted"}, ...]
    반환: dict (전체수, 삭제수, 보낸이별, 시간대별, 삭제 보낸이별 등)
    """
    from collections import Counter

    total = len(messages)
    deleted = [m for m in messages if m.get("deleted")]
    by_sender = Counter()
    by_sender_deleted = Counter()
    by_hour = Counter()
    first_time = None
    last_time = None

    for m in messages:
        s = m.get("sender") or "(알수없음)"
        by_sender[s] += 1
        if m.get("deleted"):
            by_sender_deleted[s] += 1
        # 시간대(시) 추출: "YYYY-MM-DD HH:MM..." 또는 변환된 "... HH:MM:SS UTC"
        t = m.get("time") or ""
        mobj = _re.search(r'(\d{1,2}):\d{2}', t)
        if mobj:
            by_hour[int(mobj.group(1))] += 1
        if t:
            if first_time is None:
                first_time = t
            last_time = t

    return {
        "total": total,
        "deleted_count": len(deleted),
        "live_count": total - len(deleted),
        "by_sender": by_sender.most_common(),
        "by_sender_deleted": by_sender_deleted.most_common(),
        "by_hour": [(h, by_hour.get(h, 0)) for h in range(24)],
        "top_sender": by_sender.most_common(1)[0] if by_sender else None,
        "first_time": first_time,
        "last_time": last_time,
        "sender_count": len(by_sender),
    }


# ─────────────────────────────────────────────────────────────
# 10. HTML 리포트 생성
#     자체 완결(외부 CDN/네트워크 없음). 막대그래프는 CSS로 그림.
# ─────────────────────────────────────────────────────────────

def _esc(s):
    """HTML 이스케이프."""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _bar_rows(pairs, max_items=12):
    """(라벨, 값) 목록을 CSS 막대 행 HTML로."""
    if not pairs:
        return "<p class='muted'>데이터 없음</p>"
    mx = max((v for _, v in pairs), default=1) or 1
    rows = []
    for label, v in pairs[:max_items]:
        pct = int(v / mx * 100)
        rows.append(
            f"<div class='bar-row'><div class='bar-label'>{_esc(label)}</div>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{pct}%'></div></div>"
            f"<div class='bar-val'>{v}</div></div>")
    return "\n".join(rows)


def build_html_report(case, tables, conv_messages=None, stats=None,
                      deleted_records=None, deleted_cols=None):
    """
    분석 결과를 자체 완결 HTML 문서로 생성해 문자열로 반환.
    """
    gen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    integrity = "확인됨 (원본과 동일)" if case.integrity_ok else "불일치 — 사본 손상"
    integ_cls = "ok" if case.integrity_ok else "bad"

    # 테이블 목록
    trows = "".join(
        f"<tr><td>{_esc(t['name'])}</td><td class='num'>{t['rows']}</td></tr>"
        for t in tables)

    # 통계 섹션
    stats_html = ""
    if stats:
        top = stats["top_sender"]
        top_str = f"{top[0]} ({top[1]}건)" if top else "-"
        stats_html = f"""
        <h2>대화 통계</h2>
        <div class="cards">
          <div class="card"><div class="big">{stats['total']}</div><div>전체 메시지</div></div>
          <div class="card"><div class="big del">{stats['deleted_count']}</div><div>삭제 복원</div></div>
          <div class="card"><div class="big">{stats['sender_count']}</div><div>참여자</div></div>
          <div class="card"><div class="big">{_esc(top_str)}</div><div>가장 활발</div></div>
        </div>
        <p class="muted">기간: {_esc(stats['first_time'] or '-')} ~ {_esc(stats['last_time'] or '-')}</p>
        <h3>보낸이별 메시지 수</h3>
        {_bar_rows(stats['by_sender'])}
        <h3>삭제된 메시지가 많은 보낸이</h3>
        {_bar_rows(stats['by_sender_deleted'])}
        <h3>시간대별 분포 (0~23시)</h3>
        {_bar_rows([(f"{h}시", v) for h, v in stats['by_hour']], max_items=24)}
        """

    # 삭제 복원 레코드 섹션
    del_html = ""
    if deleted_records and deleted_cols:
        head = "".join(f"<th>{_esc(c)}</th>" for c in deleted_cols)
        body_rows = []
        for r in deleted_records[:500]:
            cells = "".join(f"<td>{_esc('' if v is None else v)}</td>"
                            for v in r["values"])
            body_rows.append(f"<tr>{cells}</tr>")
        more = (f"<p class='muted'>… 외 {len(deleted_records)-500}건</p>"
                if len(deleted_records) > 500 else "")
        del_html = f"""
        <h2>삭제 복원 레코드 ({len(deleted_records)}건)</h2>
        <p class="muted">스키마 검증을 통과한 삭제 레코드입니다. best-effort 복원.</p>
        <div class="scroll"><table class="grid"><thead><tr>{head}</tr></thead>
        <tbody>{''.join(body_rows)}</tbody></table></div>{more}
        """

    # 대화 섹션 (삭제 표시)
    conv_html = ""
    if conv_messages:
        items = []
        for m in conv_messages[:2000]:
            d = m.get("deleted")
            cls = " deleted" if d else ""
            mark = "<span class='delmark'>[삭제됨]</span> " if d else ""
            items.append(
                f"<div class='msg{cls}'><span class='time'>{_esc(m.get('time',''))}</span> "
                f"{mark}<span class='who'>{_esc(m.get('sender',''))}</span>"
                f"<div class='body'>{_esc(m.get('body',''))}</div></div>")
        conv_html = f"""
        <h2>대화 내역 (삭제 메시지 포함)</h2>
        <div class="conv">{''.join(items)}</div>
        """

    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8">
<title>포렌식 분석 리포트</title>
<style>
  body {{ font-family: -apple-system, 'Malgun Gothic', sans-serif; margin: 0;
         background:#f5f6f8; color:#222; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 24px; }}
  header {{ background:#1a2233; color:#fff; padding:24px; }}
  header h1 {{ margin:0; font-size:20px; }}
  header .sub {{ color:#9fb0c9; font-size:13px; margin-top:4px; }}
  h2 {{ margin-top:32px; border-bottom:2px solid #1a2233; padding-bottom:6px; }}
  h3 {{ margin-top:20px; font-size:14px; color:#444; }}
  table {{ border-collapse:collapse; width:100%; background:#fff; }}
  th,td {{ border:1px solid #dde; padding:6px 10px; font-size:13px; text-align:left; }}
  th {{ background:#eef1f6; }}
  td.num {{ text-align:right; }}
  .kv {{ background:#fff; border:1px solid #dde; border-radius:6px; padding:14px; }}
  .kv div {{ margin:4px 0; font-size:13px; }}
  .kv .mono {{ font-family:monospace; font-size:12px; color:#555; word-break:break-all; }}
  .ok {{ color:#1a7f37; font-weight:bold; }}
  .bad {{ color:#c01c28; font-weight:bold; }}
  .muted {{ color:#888; font-size:12px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; }}
  .card {{ background:#fff; border:1px solid #dde; border-radius:8px; padding:16px;
          flex:1; min-width:120px; text-align:center; }}
  .card .big {{ font-size:24px; font-weight:bold; }}
  .card .big.del {{ color:#c01c28; }}
  .bar-row {{ display:flex; align-items:center; gap:8px; margin:3px 0; }}
  .bar-label {{ width:120px; font-size:12px; text-align:right; color:#444; }}
  .bar-track {{ flex:1; background:#eef1f6; border-radius:4px; height:16px; }}
  .bar-fill {{ background:#3b6ea5; height:16px; border-radius:4px; }}
  .bar-val {{ width:44px; font-size:12px; color:#555; }}
  .scroll {{ max-height:420px; overflow:auto; border:1px solid #dde; }}
  .conv {{ background:#fff; border:1px solid #dde; border-radius:6px; padding:12px;
          max-height:600px; overflow:auto; }}
  .msg {{ padding:6px 8px; border-bottom:1px solid #f0f0f0; }}
  .msg.deleted {{ background:#fdf0f0; }}
  .msg .time {{ color:#999; font-size:11px; }}
  .msg .who {{ font-weight:bold; color:#1a5fb4; }}
  .msg.deleted .who {{ color:#c01c28; }}
  .msg .body {{ margin-top:2px; font-size:13px; white-space:pre-wrap; }}
  .msg.deleted .body {{ color:#c01c28; }}
  .delmark {{ color:#c01c28; font-weight:bold; font-size:11px; }}
</style></head>
<body>
<header>
  <h1>SQLite 포렌식 분석 리포트</h1>
  <div class="sub">생성 {gen}</div>
</header>
<div class="wrap">
  <h2>증거 개요</h2>
  <div class="kv">
    <div>원본 경로: <span class="mono">{_esc(case.original_path)}</span></div>
    <div>파일 크기: {case.size_bytes:,} bytes</div>
    <div>열람 시각: {_esc(case.opened_at)}</div>
    <div>무결성: <span class="{integ_cls}">{integrity}</span></div>
    <div>원본 SHA-256: <span class="mono">{_esc(case.original_hash)}</span></div>
    <div>사본 SHA-256: <span class="mono">{_esc(case.copy_hash)}</span></div>
  </div>
  <h2>테이블</h2>
  <table><thead><tr><th>테이블</th><th class="num">행 수</th></tr></thead>
  <tbody>{trows}</tbody></table>
  {stats_html}
  {del_html}
  {conv_html}
  <p class="muted" style="margin-top:40px">
    본 리포트는 로컬에서 생성되었으며 어떤 데이터도 외부로 전송하지 않았습니다.
    삭제 복원은 best-effort이며, 원본을 수정하지 않고 사본에서 분석했습니다.
  </p>
</div></body></html>"""
