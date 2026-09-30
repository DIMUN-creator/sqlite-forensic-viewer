# -*- coding: utf-8 -*-
"""
삭제 복원 정확도 검증 하니스
============================
정답을 아는 상태에서 도구의 복원 성능을 자동 측정합니다.

원리:
  1) 알려진 데이터를 DB에 넣는다 (정답 확보)
  2) 특정 조건으로 일부를 삭제한다 (VACUUM 유무 등)
  3) 도구로 복원을 시도한다
  4) '지운 것 중 몇 개를 정확히 되살렸나'를 센다

측정 지표:
  - 복원율(Recall)   : 지운 것 중 복원한 비율  = 되살린수 / 지운수
  - 정밀도(Precision): 복원한 것 중 진짜 비율  = 진짜수 / 복원한수
  (정밀도가 낮으면 오탐(쓰레기)이 많다는 뜻)

실행:  python validate.py
결과:  콘솔 표 + validation_report.csv 저장
"""

import os
import csv
import sqlite3
import tempfile

import engine


def make_db(path, n_rows, delete_ids, *, vacuum=False, secure_delete=False,
            auto_vacuum=False):
    """
    알려진 데이터로 DB를 만들고 지정 조건으로 삭제.
    반환: 삭제한 행들의 '정답' 집합 (sender, body, sent_unix) 튜플
    """
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    c = con.cursor()
    c.execute(f"PRAGMA secure_delete = {'ON' if secure_delete else 'OFF'}")
    c.execute(f"PRAGMA auto_vacuum = {'FULL' if auto_vacuum else 'NONE'}")
    c.execute("""CREATE TABLE messages(
        id INTEGER PRIMARY KEY, room TEXT, sender TEXT, body TEXT,
        sent_unix INTEGER, sent_chrome INTEGER)""")

    base = 1727654400
    rows = []
    for i in range(1, n_rows + 1):
        rows.append((i, f"room_{i%4}", f"user_{i%9}",
                     f"메시지본문_{i:05d}_테스트데이터", base + i * 37,
                     0))
    c.executemany("INSERT INTO messages VALUES(?,?,?,?,?,?)", rows)
    con.commit()

    # 정답: 삭제할 행들의 (sender, body, sent_unix)
    truth = set()
    for i in delete_ids:
        r = rows[i - 1]
        truth.add((r[2], r[3], r[4]))

    id_list = ",".join(str(i) for i in delete_ids)
    c.execute(f"DELETE FROM messages WHERE id IN ({id_list})")
    con.commit()
    if vacuum:
        c.execute("VACUUM")
        con.commit()
    con.close()
    return truth


def measure(path, truth):
    """도구로 복원해 복원율/정밀도 계산."""
    case = engine.open_evidence(path)
    rec = engine.recover_deleted_records(case.working_copy, "messages")
    cols = rec["columns"]
    si, bi, ti = cols.index("sender"), cols.index("body"), cols.index("sent_unix")

    recovered = set()
    for r in rec["records"]:
        v = r["values"]
        s = "" if v[si] is None else str(v[si])
        b = "" if v[bi] is None else str(v[bi])
        t = v[ti]
        recovered.add((s, b, t))

    # 정답과 대조
    truth_norm = {(s, b, int(t)) for (s, b, t) in truth}
    rec_norm = {(s, b, int(t)) for (s, b, t) in recovered
                if isinstance(t, int) or (isinstance(t, str) and t.isdigit())
                for t in [int(t)]}
    # 위 컴프리헨션이 복잡하니 안전하게 재계산
    rec_norm = set()
    for (s, b, t) in recovered:
        try:
            rec_norm.add((s, b, int(t)))
        except (ValueError, TypeError):
            pass

    hit = len(truth_norm & rec_norm)           # 정답을 맞춘 수
    recall = hit / len(truth_norm) if truth_norm else 0.0
    precision = hit / len(rec_norm) if rec_norm else 0.0
    return {
        "deleted": len(truth_norm),
        "recovered": len(rec_norm),
        "correct": hit,
        "recall": recall,
        "precision": precision,
    }


def run_all():
    tmp = tempfile.mkdtemp(prefix="validate_")
    # 시나리오: (이름, 행수, 삭제개수, 조건)
    scenarios = [
        ("기본 삭제 (VACUUM 안 함)",     2000, 400, {}),
        ("소량 삭제",                    2000, 50,  {}),
        ("대량 삭제 (절반)",             2000, 1000, {}),
        ("VACUUM 실행 후",               2000, 400, {"vacuum": True}),
        ("secure_delete 켜짐",           2000, 400, {"secure_delete": True}),
        ("auto_vacuum 켜짐",             2000, 400, {"auto_vacuum": True}),
        ("작은 DB (defrag 영향)",         200, 40,  {}),
    ]

    results = []
    for name, nrows, ndel, opts in scenarios:
        # 삭제 대상: 가운데 연속 구간
        start = (nrows - ndel) // 2
        del_ids = list(range(start, start + ndel))
        db = os.path.join(tmp, f"case_{len(results)}.sqlite")
        truth = make_db(db, nrows, del_ids, **opts)
        m = measure(db, truth)
        m["scenario"] = name
        results.append(m)

    # 콘솔 표
    print("=" * 78)
    print(" 삭제 복원 정확도 검증 결과")
    print("=" * 78)
    print(f"{'시나리오':<26}{'삭제':>6}{'복원':>6}{'정확':>6}"
          f"{'복원율':>9}{'정밀도':>9}")
    print("-" * 78)
    for r in results:
        print(f"{r['scenario']:<26}{r['deleted']:>6}{r['recovered']:>6}"
              f"{r['correct']:>6}{r['recall']*100:>8.1f}%{r['precision']*100:>8.1f}%")
    print("-" * 78)
    print("복원율 = 지운 것 중 되살린 비율 · 정밀도 = 복원한 것 중 진짜 비율")

    # CSV 저장
    out = os.path.join(os.getcwd(), "validation_report.csv")
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["시나리오", "삭제수", "복원수", "정확수",
                    "복원율(%)", "정밀도(%)"])
        for r in results:
            w.writerow([r["scenario"], r["deleted"], r["recovered"],
                        r["correct"], f"{r['recall']*100:.1f}",
                        f"{r['precision']*100:.1f}"])
    print(f"\nCSV 저장: {out}")
    return results


if __name__ == "__main__":
    run_all()
