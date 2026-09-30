# -*- coding: utf-8 -*-
import os, sqlite3, engine

# 1) 샘플 증거 DB 생성: 채팅 비슷한 테이블
db = "/home/claude/forensic/sample_evidence.sqlite"
if os.path.exists(db): os.remove(db)
con = sqlite3.connect(db)
c = con.cursor()
c.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, body TEXT, sent_at INTEGER)")
rows = [
    (1, "김철수", "안녕하세요 프로젝트 잘 되나요", 1727654400),
    (2, "이영희", "네 순조롭습니다 SECRET_TOKEN_ABC123 참고", 1727654460),
    (3, "김철수", "삭제될 비밀 메시지입니다 DELETEME_XYZ", 1727654520),
    (4, "박민수", "회의는 내일 오후 세시", 1727654580),
    (5, "이영희", "이것도 곧 지워질 예정 CONFIDENTIAL_9999", 1727654640),
]
c.executemany("INSERT INTO messages VALUES(?,?,?,?)", rows)
con.commit()

# 2) 일부 행 삭제 → freeblock/unallocated에 흔적이 남음
c.execute("DELETE FROM messages WHERE id IN (3,5)")
con.commit()
# VACUUM은 일부러 안 함(VACUUM하면 흔적이 지워짐 → 그게 포인트)
con.close()

print("="*60)
print("TEST 1: 타임스탬프 변환")
print("="*60)
for name, s in engine.interpret_timestamp(1727654400):
    print(f"  {name:22} -> {s}")

print()
print("="*60)
print("TEST 2: 원본 보호 + 무결성")
print("="*60)
case = engine.open_evidence(db)
print(f"  원본 해시 : {case.original_hash[:32]}...")
print(f"  사본 해시 : {case.copy_hash[:32]}...")
print(f"  무결성 OK : {case.integrity_ok}")
print(f"  크기      : {case.size_bytes} bytes")

print()
print("="*60)
print("TEST 3: 테이블 목록")
print("="*60)
for t in engine.list_tables(case.working_copy):
    print(f"  {t['name']:12} 행수={t['rows']}")

print()
print("="*60)
print("TEST 4: 현재 살아있는 데이터")
print("="*60)
cols, data = engine.read_table(case.working_copy, "messages")
print("  컬럼:", cols)
for r in data:
    print("  ", r)

print()
print("="*60)
print("TEST 5: 삭제 흔적 스캔 (핵심!)")
print("="*60)
hits = engine.scan_deleted(case.working_copy, min_len=4)
found_secrets = []
for h in hits:
    print(f"  page{h.page} {h.region:12} off={h.offset:6} : {h.text!r}")
    if "DELETEME" in h.text or "CONFIDENTIAL" in h.text:
        found_secrets.append(h.text)

print()
print("  >>> 삭제된 메시지 흔적 발견:", found_secrets if found_secrets else "없음")
