# -*- coding: utf-8 -*-
"""
SQLite 포렌식 뷰어 (GUI)
========================
engine.py의 분석 기능을 화면으로 감싼 데스크톱 앱입니다.
윈도우/맥/리눅스 어디서든 파이썬만 있으면 돌아갑니다.

실행:  python viewer.py

구성 탭:
  [증거]      원본 보호 · 무결성 해시 · WAL 등 부속 파일 확인
  [탐색]      테이블 목록 · 스키마 · 데이터(페이지 넘김)
  [시간변환]  숫자 하나를 넣으면 가능한 모든 시간 해석
  [삭제흔적]  freeblock/unallocated에서 지워진 데이터 복원
  [리포트]    발견 내용을 문서로 저장

의존성: 표준 라이브러리만 사용 (tkinter, sqlite3, ...)
"""

import os
import datetime
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

import engine


APP_TITLE = "SQLite 포렌식 뷰어 v1.0"


class ForensicApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1000x680")
        self.minsize(820, 560)

        self.case = None          # 현재 열린 CaseFile
        self.current_table = None
        self.page_offset = 0
        self.page_size = 200
        self.scan_hits = []       # 마지막 스캔 결과

        self._build_ui()

    # ── UI 뼈대 ────────────────────────────────────────────
    def _build_ui(self):
        # 상단 툴바
        bar = ttk.Frame(self, padding=(8, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="증거 파일 열기…", command=self.on_open).pack(side="left")
        self.lbl_file = ttk.Label(bar, text="열린 파일 없음", foreground="#666")
        self.lbl_file.pack(side="left", padx=12)

        # 탭
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._build_tab_case()
        self._build_tab_finder()
        self._build_tab_explore()
        self._build_tab_time()
        self._build_tab_conversation()
        self._build_tab_stats()
        self._build_tab_carve()
        self._build_tab_report()

        # 상태바
        self.status = ttk.Label(self, text="준비됨", relief="sunken", anchor="w")
        self.status.pack(fill="x", side="bottom")

    def _build_tab_case(self):
        f = ttk.Frame(self.nb, padding=12)
        self.nb.add(f, text="증거")
        self.txt_case = scrolledtext.ScrolledText(f, wrap="word", height=20)
        self.txt_case.pack(fill="both", expand=True)
        self.txt_case.insert("1.0",
            "왼쪽 위 '증거 파일 열기'로 .sqlite / .db 파일을 선택하세요.\n\n"
            "이 도구는 원본을 절대 수정하지 않습니다. 열면 즉시\n"
            "읽기 전용 사본을 만들고, 원본과 사본의 SHA-256 해시를\n"
            "비교해 훼손이 없음을 증명합니다.")
        self.txt_case.config(state="disabled")

    def _build_tab_finder(self):
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text="파일 찾기")

        top = ttk.Frame(f)
        top.pack(fill="x")
        self.btn_find = ttk.Button(top, text="이 PC에서 SQLite 파일 찾기",
                                   command=self.do_find)
        self.btn_find.pack(side="left")
        ttk.Button(top, text="폴더 지정해서 찾기…",
                   command=self.do_find_folder).pack(side="left", padx=6)
        self.lbl_find = ttk.Label(top, text="", foreground="#666")
        self.lbl_find.pack(side="left", padx=10)

        ttk.Label(f, text="확장자가 아니라 파일 내용(매직 넘버)으로 판별합니다. "
                          "결과를 더블클릭하면 바로 엽니다.",
                  foreground="#666").pack(anchor="w", pady=(6, 2))

        cols = ("size", "name", "path")
        self.find_tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, w, t in zip(cols, (90, 200, 620),
                           ("크기", "파일명", "경로")):
            self.find_tree.heading(c, text=t)
            self.find_tree.column(c, width=w, anchor="w")
        self.find_tree.pack(fill="both", expand=True, pady=6)
        self.find_tree.bind("<Double-1>", self.on_find_dblclick)

        ys = ttk.Scrollbar(f, orient="vertical", command=self.find_tree.yview)
        self.find_tree.configure(yscroll=ys.set)

    def _build_tab_explore(self):
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text="탐색")

        paned = ttk.Panedwindow(f, orient="horizontal")
        paned.pack(fill="both", expand=True)

        # 좌: 테이블 목록
        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        ttk.Label(left, text="테이블").pack(anchor="w")
        self.tbl_list = tk.Listbox(left, exportselection=False)
        self.tbl_list.pack(fill="both", expand=True)
        self.tbl_list.bind("<<ListboxSelect>>", self.on_pick_table)

        # 우: 스키마 + 데이터
        right = ttk.Frame(paned)
        paned.add(right, weight=4)

        ttk.Label(right, text="스키마(CREATE 문)").pack(anchor="w")
        self.txt_schema = scrolledtext.ScrolledText(right, height=5, wrap="none")
        self.txt_schema.pack(fill="x")

        nav = ttk.Frame(right)
        nav.pack(fill="x", pady=4)
        ttk.Button(nav, text="◀ 이전", command=self.prev_page).pack(side="left")
        ttk.Button(nav, text="다음 ▶", command=self.next_page).pack(side="left", padx=4)
        self.lbl_page = ttk.Label(nav, text="")
        self.lbl_page.pack(side="left", padx=8)
        ttk.Label(nav, text="(셀 더블클릭 → 시간 해석)").pack(side="right")

        self.tree = ttk.Treeview(right, show="headings")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self.on_cell_dblclick)
        yscroll = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=yscroll.set)

    def _build_tab_time(self):
        f = ttk.Frame(self.nb, padding=12)
        self.tab_time = f          # 탭 위치가 바뀌어도 참조로 선택
        self.nb.add(f, text="시간변환")
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Label(row, text="타임스탬프 숫자:").pack(side="left")
        self.ent_ts = ttk.Entry(row, width=28)
        self.ent_ts.pack(side="left", padx=6)
        self.ent_ts.bind("<Return>", lambda e: self.do_convert())
        ttk.Button(row, text="변환", command=self.do_convert).pack(side="left")
        ttk.Label(f, text="가능한 해석(1990~2100년 범위만 표시):",
                  foreground="#666").pack(anchor="w", pady=(10, 2))
        self.txt_time = scrolledtext.ScrolledText(f, height=16, wrap="word")
        self.txt_time.pack(fill="both", expand=True)

    def _build_tab_conversation(self):
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text="대화보기")

        # 출처 1: 현재 SQLite 테이블에서 불러오기
        box1 = ttk.LabelFrame(f, text="SQLite 테이블에서 불러오기", padding=6)
        box1.pack(fill="x")
        r1 = ttk.Frame(box1); r1.pack(fill="x")
        ttk.Label(r1, text="테이블:").pack(side="left")
        self.cmb_conv_table = ttk.Combobox(r1, width=22, state="readonly")
        self.cmb_conv_table.pack(side="left", padx=4)
        self.cmb_conv_table.bind("<<ComboboxSelected>>", self.on_conv_table_pick)
        r2 = ttk.Frame(box1); r2.pack(fill="x", pady=4)
        ttk.Label(r2, text="보낸이:").pack(side="left")
        self.cmb_sender = ttk.Combobox(r2, width=14, state="readonly")
        self.cmb_sender.pack(side="left", padx=(2, 8))
        ttk.Label(r2, text="내용:").pack(side="left")
        self.cmb_body = ttk.Combobox(r2, width=14, state="readonly")
        self.cmb_body.pack(side="left", padx=(2, 8))
        ttk.Label(r2, text="시간:").pack(side="left")
        self.cmb_time = ttk.Combobox(r2, width=14, state="readonly")
        self.cmb_time.pack(side="left", padx=(2, 8))
        ttk.Button(r2, text="대화 불러오기",
                   command=self.do_load_conversation).pack(side="left", padx=6)
        self.var_incl_deleted = tk.BooleanVar(value=True)
        ttk.Checkbutton(box1, text="삭제된 메시지 복원해서 함께 표시",
                        variable=self.var_incl_deleted).pack(anchor="w", pady=(4, 0))

        # 출처 2: 카카오톡 내보내기 .txt
        box2 = ttk.LabelFrame(f, text="카카오톡 내보내기(.txt) 열기", padding=6)
        box2.pack(fill="x", pady=6)
        ttk.Button(box2, text="카카오톡 .txt 파일 열기…",
                   command=self.do_import_kakao).pack(side="left")
        ttk.Label(box2, text="(카카오톡 → 대화방 → 대화 내보내기로 저장한 본인 대화)",
                  foreground="#666").pack(side="left", padx=8)

        # 필터 + 대화 표시
        r3 = ttk.Frame(f); r3.pack(fill="x")
        ttk.Label(r3, text="필터:").pack(side="left")
        self.ent_conv_filter = ttk.Entry(r3, width=24)
        self.ent_conv_filter.pack(side="left", padx=4)
        self.ent_conv_filter.bind("<KeyRelease>", lambda e: self._render_conversation())
        self.lbl_conv = ttk.Label(r3, text="", foreground="#666")
        self.lbl_conv.pack(side="left", padx=8)

        self.txt_conv = scrolledtext.ScrolledText(f, wrap="word", height=20,
                                                  state="disabled")
        self.txt_conv.pack(fill="both", expand=True, pady=6)
        # 스타일 태그
        self.txt_conv.tag_config("sender", foreground="#1a5fb4",
                                 font=("TkDefaultFont", 10, "bold"))
        self.txt_conv.tag_config("time", foreground="#888")
        self.txt_conv.tag_config("del_mark", foreground="#c01c28",
                                 font=("TkDefaultFont", 10, "bold"))
        self.txt_conv.tag_config("del_body", foreground="#c01c28")
        self.conv_messages = []

    def _refresh_conv_tables(self):
        """증거가 열리면 대화보기의 테이블 목록을 갱신."""
        names = [t["name"] for t in getattr(self, "tables", [])]
        self.cmb_conv_table["values"] = names
        self.cmb_conv_table.set("")
        for cmb in (self.cmb_sender, self.cmb_body, self.cmb_time):
            cmb["values"] = []
            cmb.set("")

    def on_conv_table_pick(self, _evt):
        table = self.cmb_conv_table.get()
        if not table:
            return
        cols, _ = engine.read_table(self.case.working_copy, table, limit=1)
        opts = [""] + cols
        for cmb in (self.cmb_sender, self.cmb_body, self.cmb_time):
            cmb["values"] = opts
        guess = engine.guess_message_columns(cols)
        self.cmb_sender.set(guess["sender"] or "")
        self.cmb_body.set(guess["body"] or "")
        self.cmb_time.set(guess["time"] or "")

    def do_load_conversation(self):
        if not self.case:
            messagebox.showinfo("안내", "먼저 증거 파일을 여세요.")
            return
        table = self.cmb_conv_table.get()
        if not table:
            messagebox.showinfo("안내", "테이블을 고르세요.")
            return
        sender = self.cmb_sender.get() or None
        body = self.cmb_body.get() or None
        time_ = self.cmb_time.get() or None
        try:
            if self.var_incl_deleted.get():
                self.set_status("삭제 메시지 복원 중…")
                self.conv_messages, ndel = engine.load_conversation_with_deleted(
                    self.case.working_copy, table, sender, body, time_, limit=2000)
                self._render_conversation()
                self.set_status(f"대화 {len(self.conv_messages)}건 "
                                f"(삭제 복원 {ndel}건 포함)")
            else:
                self.conv_messages = engine.load_conversation(
                    self.case.working_copy, table, sender, body, time_, limit=2000)
                for m in self.conv_messages:
                    m["deleted"] = False
                self._render_conversation()
                self.set_status(f"대화 {len(self.conv_messages)}건 불러옴")
        except Exception as e:
            messagebox.showerror("불러오기 실패", str(e))
            return

    def do_import_kakao(self):
        path = filedialog.askopenfilename(
            title="카카오톡 내보내기 .txt 선택",
            filetypes=[("텍스트", "*.txt"), ("모든 파일", "*.*")])
        if not path:
            return
        try:
            self.conv_messages = engine.parse_kakao_export(path)
        except Exception as e:
            messagebox.showerror("파싱 실패", str(e))
            return
        if not self.conv_messages:
            messagebox.showinfo("안내", "대화를 인식하지 못했습니다. "
                                        "카카오톡 내보내기 형식이 맞는지 확인하세요.")
            return
        self._render_conversation()
        self.set_status(f"카카오톡 대화 {len(self.conv_messages)}건 불러옴")

    def _render_conversation(self):
        flt = self.ent_conv_filter.get().strip().lower()
        self.txt_conv.config(state="normal")
        self.txt_conv.delete("1.0", "end")
        shown = 0
        ndel = 0
        for m in self.conv_messages:
            line = f"{m.get('sender','')} {m.get('body','')}".lower()
            if flt and flt not in line:
                continue
            shown += 1
            is_del = m.get("deleted", False)
            t = m.get("time", "")
            if t:
                self.txt_conv.insert("end", f"[{t}] ", "time")
            if is_del:
                ndel += 1
                self.txt_conv.insert("end", "[삭제됨] ", "del_mark")
            self.txt_conv.insert("end", f"{m.get('sender','')}\n", "sender")
            body_tag = "del_body" if is_del else ""
            self.txt_conv.insert("end", f"{m.get('body','')}\n\n", body_tag)
        self.txt_conv.config(state="disabled")
        total = len(self.conv_messages)
        if flt:
            self.lbl_conv.config(text=f"{shown}/{total}건 표시 · 삭제 {ndel}건")
        else:
            self.lbl_conv.config(text=f"총 {total}건 · 삭제 복원 {ndel}건")

    def _build_tab_stats(self):
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text="통계")
        ttk.Button(f, text="현재 대화 통계 계산",
                   command=self.do_compute_stats).pack(anchor="w")
        ttk.Label(f, text="대화보기에서 대화를 먼저 불러온 뒤 계산하세요.",
                  foreground="#666").pack(anchor="w", pady=(4, 6))
        self.txt_stats = scrolledtext.ScrolledText(f, wrap="word", height=22,
                                                   state="disabled",
                                                   font=("Consolas", 10))
        self.txt_stats.pack(fill="both", expand=True)
        self.last_stats = None

    def do_compute_stats(self):
        if not getattr(self, "conv_messages", None):
            messagebox.showinfo("안내", "먼저 대화보기에서 대화를 불러오세요.")
            return
        st = engine.conversation_stats(self.conv_messages)
        self.last_stats = st

        def bars(pairs, width=30, n=15):
            if not pairs:
                return "  (없음)\n"
            mx = max((v for _, v in pairs), default=1) or 1
            out = []
            for label, v in pairs[:n]:
                fill = "█" * int(v / mx * width)
                out.append(f"  {str(label):12} {fill} {v}")
            return "\n".join(out) + "\n"

        top = st["top_sender"]
        lines = [
            "═" * 50,
            " 대화 통계",
            "═" * 50,
            f"전체 메시지 : {st['total']}",
            f"삭제 복원   : {st['deleted_count']}",
            f"살아있음    : {st['live_count']}",
            f"참여자 수   : {st['sender_count']}",
            f"가장 활발   : {top[0]} ({top[1]}건)" if top else "가장 활발   : -",
            f"기간        : {st['first_time'] or '-'}  ~  {st['last_time'] or '-'}",
            "",
            "── 보낸이별 메시지 수 ──",
            bars(st["by_sender"]),
            "── 삭제된 메시지가 많은 보낸이 ──",
            bars(st["by_sender_deleted"]),
            "── 시간대별 분포 (0~23시) ──",
            bars([(f"{h:02d}시", v) for h, v in st["by_hour"]], n=24),
        ]
        self.txt_stats.config(state="normal")
        self.txt_stats.delete("1.0", "end")
        self.txt_stats.insert("1.0", "\n".join(lines))
        self.txt_stats.config(state="disabled")
        self.set_status("통계 계산 완료")

    def _build_tab_carve(self):
        f = ttk.Frame(self.nb, padding=8)
        self.nb.add(f, text="삭제흔적")
        top = ttk.Frame(f)
        top.pack(fill="x")
        ttk.Button(top, text="삭제 흔적 스캔 실행", command=self.do_scan).pack(side="left")
        ttk.Label(top, text="최소 길이:").pack(side="left", padx=(12, 2))
        self.spin_len = ttk.Spinbox(top, from_=3, to=40, width=5)
        self.spin_len.set(6)
        self.spin_len.pack(side="left")
        ttk.Label(top, text="필터:").pack(side="left", padx=(12, 2))
        self.ent_filter = ttk.Entry(top, width=20)
        self.ent_filter.pack(side="left")
        self.ent_filter.bind("<KeyRelease>", lambda e: self._refresh_carve())

        cols = ("page", "region", "offset", "text")
        self.carve_tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, w in zip(cols, (60, 110, 90, 620)):
            self.carve_tree.heading(c, text=c)
            self.carve_tree.column(c, width=w, anchor="w")
        self.carve_tree.pack(fill="both", expand=True, pady=6)

    def _build_tab_report(self):
        f = ttk.Frame(self.nb, padding=12)
        self.nb.add(f, text="리포트")
        row = ttk.Frame(f)
        row.pack(anchor="w", fill="x")
        ttk.Button(row, text="텍스트 리포트 저장…",
                   command=self.save_report).pack(side="left")
        ttk.Button(row, text="HTML 리포트 저장… (통계·삭제복원·대화 포함)",
                   command=self.save_html_report).pack(side="left", padx=6)
        ttk.Label(f, text="HTML 리포트는 대화·통계를 계산해둔 경우 함께 담습니다.",
                  foreground="#666").pack(anchor="w", pady=(6, 2))
        ttk.Label(f, text="현재까지의 분석 요약:", foreground="#666").pack(anchor="w", pady=(6, 2))
        self.txt_report = scrolledtext.ScrolledText(f, height=18, wrap="word")
        self.txt_report.pack(fill="both", expand=True)

    def save_html_report(self):
        if not self.case:
            messagebox.showinfo("안내", "먼저 증거 파일을 여세요.")
            return
        path = filedialog.asksaveasfilename(
            title="HTML 리포트 저장", defaultextension=".html",
            filetypes=[("HTML", "*.html")])
        if not path:
            return
        self.set_status("HTML 리포트 생성 중…")
        # 대화가 로드돼 있으면 통계/삭제복원도 함께 담음
        conv = getattr(self, "conv_messages", None) or None
        stats = getattr(self, "last_stats", None)
        if conv and not stats:
            stats = engine.conversation_stats(conv)
        del_records, del_cols = None, None
        table = self.cmb_conv_table.get() if hasattr(self, "cmb_conv_table") else ""
        if table:
            try:
                rec = engine.recover_deleted_records(self.case.working_copy, table)
                del_records, del_cols = rec["records"], rec["columns"]
            except Exception:
                pass
        try:
            html = engine.build_html_report(
                self.case, getattr(self, "tables", []),
                conv_messages=conv, stats=stats,
                deleted_records=del_records, deleted_cols=del_cols)
            with open(path, "w", encoding="utf-8") as fp:
                fp.write(html)
        except Exception as e:
            messagebox.showerror("저장 실패", str(e))
            self.set_status("HTML 저장 실패")
            return
        messagebox.showinfo("저장 완료", f"HTML 리포트 저장됨:\n{path}")
        self.set_status("HTML 리포트 저장 완료")

    # ── 동작 ──────────────────────────────────────────────
    def set_status(self, msg):
        self.status.config(text=msg)
        self.update_idletasks()

    def on_open(self):
        path = filedialog.askopenfilename(
            title="증거 SQLite 파일 선택",
            filetypes=[("SQLite/DB", "*.sqlite *.db *.sqlite3 *.db3"), ("모든 파일", "*.*")])
        if not path:
            return
        self._open_path(path)

    def _open_path(self, path):
        """경로 하나를 증거로 열고 모든 탭을 갱신. 파일찾기/툴바 공용."""
        try:
            self.set_status("사본 생성 및 해시 계산 중…")
            self.case = engine.open_evidence(path)
        except Exception as e:
            messagebox.showerror("열기 실패", str(e))
            self.set_status("열기 실패")
            return
        self.scan_hits = []           # 새 증거 → 이전 스캔 결과 비움
        self.current_table = None
        self.lbl_file.config(text=os.path.basename(path))
        self._show_case_info()
        self._load_tables()
        self.nb.select(0)             # 증거 탭으로 이동해 요약 보여주기
        self.set_status("증거 열림 · 원본 보호 적용됨")

    # ── 파일 찾기 ──────────────────────────────────────────
    def do_find(self):
        """기본 위치(브라우저/문서/다운로드 등)에서 검색."""
        roots = engine.default_search_roots()
        if not roots:
            messagebox.showinfo("안내", "검색할 기본 위치를 찾지 못했습니다. "
                                        "'폴더 지정해서 찾기'를 써보세요.")
            return
        self._start_find(roots)

    def do_find_folder(self):
        """사용자가 고른 폴더에서 검색."""
        d = filedialog.askdirectory(title="검색할 폴더 선택")
        if not d:
            return
        self._start_find([d])

    def _start_find(self, roots):
        """검색을 백그라운드 스레드로 실행(화면 멈춤 방지)."""
        self.find_tree.delete(*self.find_tree.get_children())
        self.btn_find.config(state="disabled")
        self.lbl_find.config(text="검색 중…")
        self.set_status("SQLite 파일 검색 중…")

        def worker():
            try:
                hits = engine.find_sqlite(roots)
            except Exception as e:
                hits = e
            # 결과를 메인 스레드에서 반영
            self.after(0, lambda: self._find_done(hits))

        threading.Thread(target=worker, daemon=True).start()

    def _find_done(self, hits):
        self.btn_find.config(state="normal")
        if isinstance(hits, Exception):
            self.lbl_find.config(text="")
            messagebox.showerror("검색 실패", str(hits))
            self.set_status("검색 실패")
            return
        for path, size in hits:
            name = os.path.basename(path) or "(이름없음)"
            self.find_tree.insert("", "end",
                                  values=(engine.human(size), name, path))
        self.lbl_find.config(text=f"{len(hits)}개 발견")
        self.set_status(f"검색 완료 · {len(hits)}개")

    def on_find_dblclick(self, _evt):
        sel = self.find_tree.selection()
        if not sel:
            return
        path = self.find_tree.item(sel[0], "values")[2]
        self._open_path(path)

    def _show_case_info(self):
        c = self.case
        side = engine.check_side_files(c.original_path)
        lines = [
            "═" * 52,
            " 증거 개요",
            "═" * 52,
            f"원본 경로   : {c.original_path}",
            f"작업 사본   : {c.working_copy}",
            f"파일 크기   : {c.size_bytes:,} bytes",
            f"열람 시각   : {c.opened_at}",
            "",
            "─ 무결성 검증 ─",
            f"원본 SHA-256: {c.original_hash}",
            f"사본 SHA-256: {c.copy_hash}",
            f"일치 여부   : {'[OK] 무결성 확인됨 (원본과 동일)' if c.integrity_ok else '[!] 불일치! 사본 손상'}",
            "",
            "─ 부속 파일 ─",
        ]
        if side:
            for s in side:
                lines.append(f"• {s['file']} ({s['size']:,} B) — {s['note']}")
        else:
            lines.append("(WAL / journal 등 부속 파일 없음)")

        self.txt_case.config(state="normal")
        self.txt_case.delete("1.0", "end")
        self.txt_case.insert("1.0", "\n".join(lines))
        self.txt_case.config(state="disabled")
        self._update_report()

    def _load_tables(self):
        self.tbl_list.delete(0, "end")
        try:
            self.tables = engine.list_tables(self.case.working_copy)
        except Exception as e:
            messagebox.showerror("읽기 실패", str(e))
            self.tables = []
        for t in self.tables:
            self.tbl_list.insert("end", f"{t['name']}  ({t['rows']})")
        self._refresh_conv_tables()

    def on_pick_table(self, _evt):
        sel = self.tbl_list.curselection()
        if not sel:
            return
        self.current_table = self.tables[sel[0]]["name"]
        self.page_offset = 0
        # 스키마 표시
        self.txt_schema.delete("1.0", "end")
        self.txt_schema.insert("1.0", self.tables[sel[0]]["sql"])
        self._load_page()

    def _load_page(self):
        if not self.current_table:
            return
        cols, rows = engine.read_table(
            self.case.working_copy, self.current_table,
            limit=self.page_size, offset=self.page_offset)
        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = cols
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=140, anchor="w")
        for r in rows:
            vals = ["" if v is None else str(v) for v in r]
            self.tree.insert("", "end", values=vals)
        start = self.page_offset + 1 if rows else 0
        self.lbl_page.config(text=f"{start}–{self.page_offset + len(rows)} 행")

    def next_page(self):
        if not self.current_table:
            return
        self.page_offset += self.page_size
        self._load_page()

    def prev_page(self):
        if not self.current_table:
            return
        self.page_offset = max(0, self.page_offset - self.page_size)
        self._load_page()

    def on_cell_dblclick(self, event):
        """셀을 더블클릭하면 그 값을 시간으로 해석해 시간변환 탭으로."""
        item = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        if not item or not col:
            return
        idx = int(col.replace("#", "")) - 1
        vals = self.tree.item(item, "values")
        if 0 <= idx < len(vals):
            self.ent_ts.delete(0, "end")
            self.ent_ts.insert(0, vals[idx])
            self.nb.select(self.tab_time)  # 시간변환 탭(참조로 안전하게)
            self.do_convert()

    def do_convert(self):
        raw = self.ent_ts.get().strip()
        self.txt_time.delete("1.0", "end")
        if not raw:
            return
        results = engine.interpret_timestamp(raw)
        if not results:
            self.txt_time.insert("1.0",
                f"'{raw}' 은(는) 1990~2100년 범위의 알려진 시간 체계로\n"
                "해석되지 않았습니다. (시간값이 아닐 수 있음)")
            return
        out = [f"입력값: {raw}", ""]
        for name, s in results:
            out.append(f"  {name:22} → {s}")
        out.append("")
        out.append("※ 문맥(사건 추정 시기)에 맞는 해석을 고르세요.")
        self.txt_time.insert("1.0", "\n".join(out))

    def do_scan(self):
        if not self.case:
            messagebox.showinfo("안내", "먼저 증거 파일을 여세요.")
            return
        try:
            min_len = int(self.spin_len.get())
        except ValueError:
            min_len = 6
        self.set_status("삭제 흔적 스캔 중…")
        try:
            self.scan_hits = engine.scan_deleted(self.case.working_copy, min_len=min_len)
        except Exception as e:
            messagebox.showerror("스캔 실패", str(e))
            self.set_status("스캔 실패")
            return
        self._refresh_carve()
        self.set_status(f"스캔 완료 · {len(self.scan_hits)}건 발견")
        self._update_report()

    def _refresh_carve(self):
        flt = self.ent_filter.get().strip().lower()
        self.carve_tree.delete(*self.carve_tree.get_children())
        for h in self.scan_hits:
            if flt and flt not in h.text.lower():
                continue
            self.carve_tree.insert("", "end",
                                   values=(h.page, h.region, h.offset, h.text))

    def _report_text(self):
        if not self.case:
            return "분석된 증거가 없습니다."
        c = self.case
        lines = [
            APP_TITLE + " — 분석 리포트",
            "생성: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "=" * 56, "",
            "[증거]",
            f"  원본       : {c.original_path}",
            f"  크기       : {c.size_bytes:,} bytes",
            f"  원본 SHA256: {c.original_hash}",
            f"  사본 SHA256: {c.copy_hash}",
            f"  무결성     : {'확인됨' if c.integrity_ok else '불일치'}",
            f"  열람 시각  : {c.opened_at}", "",
            "[테이블]",
        ]
        for t in getattr(self, "tables", []):
            lines.append(f"  - {t['name']} : {t['rows']} 행")
        lines += ["", "[삭제 흔적 스캔]",
                  f"  총 {len(self.scan_hits)}건 발견"]
        for h in self.scan_hits[:200]:
            lines.append(f"  page{h.page} {h.region} off={h.offset}: {h.text}")
        if len(self.scan_hits) > 200:
            lines.append(f"  … 외 {len(self.scan_hits) - 200}건 (전체는 저장 파일 참조)")
        return "\n".join(lines)

    def _update_report(self):
        self.txt_report.delete("1.0", "end")
        self.txt_report.insert("1.0", self._report_text())

    def save_report(self):
        if not self.case:
            messagebox.showinfo("안내", "먼저 증거 파일을 여세요.")
            return
        path = filedialog.asksaveasfilename(
            title="리포트 저장", defaultextension=".txt",
            filetypes=[("텍스트", "*.txt")])
        if not path:
            return
        # 저장본에는 흔적 전체를 담음
        full = self._report_text()
        if len(self.scan_hits) > 200:
            extra = ["", "[삭제 흔적 — 전체]"]
            for h in self.scan_hits:
                extra.append(f"  page{h.page} {h.region} off={h.offset}: {h.text}")
            full += "\n" + "\n".join(extra)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(full)
        messagebox.showinfo("저장 완료", f"저장됨:\n{path}")


if __name__ == "__main__":
    ForensicApp().mainloop()
