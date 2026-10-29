"""
giao_dien_gia_mao.py - Giao dien mo phong Kich ban 2 (muc 3.3.2): tan cong gia mao tam thuong.

Cach chay (trong thu muc chua schnorr_lib.py):   python giao_dien_gia_mao.py

Hai tab:
  1. Nan nhan : chi tao khoa; ke tan cong chi can khoa cong khai Y.
  2. Ke tan cong : chon luoc do (a) chuan, (b) khong gian thach thuc thu nho, (c) ham bam yeu;
     chon s, e*; tinh R* = sG - e*Y; tim thong diep m*; nop chu ky gia cho ham xac minh.
"""
import secrets
import tkinter as tk
from tkinter import ttk

import schnorr_lib as lib
import attack_trivial_forgery as atf
from gui_chung import KhungChung, Nhat_ky, hex_sach, doc_hex, hx, FONT, MONO, XANH, DO, TIM


class App(KhungChung):
    def __init__(self):
        super().__init__("Mô phỏng giả mạo tầm thường – EC-Schnorr", "1120x820")
        self.v_sk, self.v_pk = tk.StringVar(), tk.StringVar()
        self.a_pk, self.a_s, self.a_e = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.a_m = tk.StringVar(value="Chuyen toan bo tai san cho Eve")
        self.kieu = tk.StringVar(value="a")
        self.bits = tk.IntVar(value=12)
        self.ngan_sach = tk.StringVar(value=str(atf.NGAN_SACH))
        self.m_star = None
        self.dang_tim, self.dung = False, False
        self.v_sk.trace_add("write", lambda *_: self._cap_nhat_pk())

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tab_nn, self.tab_tc = ttk.Frame(nb), ttk.Frame(nb)
        nb.add(self.tab_nn, text="1. Nạn nhân")
        nb.add(self.tab_tc, text="2. Kẻ tấn công")
        self._dung_nan_nhan()
        self._dung_tan_cong()

    # ---------------- tab 1 ----------------
    def _dung_nan_nhan(self):
        f = ttk.LabelFrame(self.tab_nn, text=" Tạo khóa ")
        f.pack(fill="x", padx=10, pady=10)
        self._dong(f, 0, "Khóa bí mật x (64 hex)", self.v_sk,
                   nut=[("Sinh ngẫu nhiên", self._sinh_khoa), ("Sao chép", lambda: self._chep(self.v_sk))])
        self._dong(f, 1, "Khóa công khai Y (x-only)", self.v_pk, readonly=True,
                   nut=[("Sao chép", lambda: self._chep(self.v_pk))])
        self._sinh_khoa()

    def _sinh_khoa(self):
        while True:
            sk = secrets.token_bytes(32)
            if 1 <= lib.bytes_to_int(sk) <= lib.q - 1:
                break
        self.v_sk.set(sk.hex())

    def _cap_nhat_pk(self):
        try:
            self.v_pk.set(lib.pubkey_gen(doc_hex(self.v_sk.get(), 32, "khóa bí mật")).hex())
        except Exception:
            self.v_pk.set("")

    # ---------------- tab 2 ----------------
    def _dung_tan_cong(self):
        t, self.log = self._khung(self.tab_tc, height=14)
        f = ttk.LabelFrame(t, text=" Dữ liệu công khai ")
        f.pack(fill="x", padx=10, pady=6)
        self._dong(f, 0, "Khóa công khai Y (64 hex)", self.a_pk,
                   nut=[("Điền nhanh từ tab Nạn nhân", lambda: self.a_pk.set(self.v_pk.get()))])

        g = ttk.LabelFrame(t, text=" Lược đồ bị tấn công ")
        g.pack(fill="x", padx=10, pady=6)
        ttk.Radiobutton(g, text="(a) Lược đồ chuẩn: thách thức e cỡ 2²⁵⁶", variable=self.kieu, value="a"
                        ).grid(row=0, column=0, sticky="w", padx=6, pady=2)
        h = ttk.Frame(g)
        h.grid(row=1, column=0, sticky="w", padx=6, pady=2)
        ttk.Radiobutton(h, text="(b) Không gian thách thức thu nhỏ còn 2^b với b =", variable=self.kieu, value="b"
                        ).pack(side="left")
        ttk.Spinbox(h, from_=4, to=20, width=4, textvariable=self.bits).pack(side="left", padx=6)
        ttk.Radiobutton(g, text="(c) Hàm băm yếu e = H(m), bỏ qua R", variable=self.kieu, value="c"
                        ).grid(row=2, column=0, sticky="w", padx=6, pady=2)

        p = ttk.LabelFrame(t, text=" Tham số của kẻ tấn công ")
        p.pack(fill="x", padx=10, pady=6)
        self._dong(p, 0, "s (64 hex)", self.a_s, nut=[("Sinh s, e* ngẫu nhiên", self._sinh_se)])
        self._dong(p, 1, "e* (64 hex)", self.a_e)
        self._dong(p, 2, "Số thông điệp thử tối đa (a)", self.ngan_sach, rong=20)
        self._dong(p, 3, "Thông điệp m (dùng cho c)", self.a_m)

        b = ttk.LabelFrame(t, text=" Các bước tấn công ")
        b.pack(fill="x", padx=10, pady=6)
        for i, (ten, cmd) in enumerate([
                ("Bước 1. Tính R* = sG − e*·Y (không cần khóa bí mật)", self._b1),
                ("Bước 2. Tìm thông điệp m* sao cho H(R*, Y, m*) = e*", self._b2),
                ("Bước 3. Nộp chữ ký giả (e*, s) cho hàm xác minh", self._b3)]):
            ttk.Button(b, text=ten, style="Big.TButton", command=cmd).grid(
                row=i, column=0, sticky="we", padx=6, pady=3)
        b.columnconfigure(0, weight=1)
        h2 = ttk.Frame(b)
        h2.grid(row=3, column=0, sticky="w", padx=6, pady=(0, 4))
        ttk.Button(h2, text="Dừng tìm kiếm", command=self._dung_tim).pack(side="left")
        ttk.Button(h2, text="Xóa nhật ký", command=self.log.xoa).pack(side="left", padx=6)

    # ---------------- ham ho tro ----------------
    def _sinh_se(self):
        self.a_s.set(hx(secrets.randbelow(lib.q - 1) + 1))
        k = self.kieu.get()
        if k == "a":
            self.a_e.set(hx(secrets.randbelow(lib.q - 1) + 1))
        elif k == "b":
            self.a_e.set(hx(secrets.randbelow(2 ** self.bits.get() - 1) + 1))
        else:
            self.a_e.set(hx(atf.H_yeu(self.a_m.get().encode("utf-8"))))

    def _tham_so(self):
        pk = doc_hex(self.a_pk.get(), 32, "khóa công khai")
        Y = lib.lift_x(pk)
        if Y is None:
            raise ValueError("khóa công khai không nằm trên đường cong")
        s = lib.bytes_to_int(doc_hex(self.a_s.get(), 32, "s"))
        e = lib.bytes_to_int(doc_hex(self.a_e.get(), 32, "e*"))
        if self.kieu.get() == "b":
            atf.TOY = 2 ** self.bits.get()
            if not 1 <= e < atf.TOY:
                raise ValueError(f"với b = {self.bits.get()}, e* phải trong [1, {atf.TOY - 1}]")
        return Y, s, e

    def _dung_tim(self):
        self.dung = True

    # ---------------- cac buoc ----------------
    def _b1(self):
        log = self.log
        log.ghi("")
        try:
            Y, s, e = self._tham_so()
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        log.ghi("Bước 1. Chọn s, e* tùy ý rồi tính ngược R* = sG − e*·Y", "head")
        if self.kieu.get() == "c":
            log.ghi("  Hàm băm yếu e = H(m) không dùng R nên không cần R*. Sang Bước 2.", "info")
            return
        R = atf.diem_cuoi(s, e, Y)
        if R is None:
            log.ghi("  R* là điểm vô cực, hãy chọn s, e* khác.", "bad")
            return
        log.ghi(f"  s  = {hx(s)}")
        log.ghi(f"  e* = {hx(e)}")
        log.ghi(f"  x_R* = {lib.x_only(R).hex()}")

    def _b2(self):
        log = self.log
        if self.dang_tim:
            return
        log.ghi("")
        try:
            Y, s, e = self._tham_so()
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        k = self.kieu.get()
        self.m_star = None
        if k == "c":
            m = self.a_m.get().encode("utf-8")
            e = atf.H_yeu(m)
            self.a_e.set(hx(e))
            self.m_star = m
            log.ghi("Bước 2. Hàm băm yếu: chọn m rồi đặt e* = H(m), không cần tìm kiếm", "head")
            log.ghi(f"  m  = {self.a_m.get()}")
            log.ghi(f"  e* = H(m) = {hx(e)}")
            return
        R = atf.diem_cuoi(s, e, Y)
        if R is None:
            log.ghi("R* là điểm vô cực, hãy chọn s, e* khác.", "bad")
            return
        if k == "a":
            H = atf.H_day_du
            try:
                gioi_han = int(self.ngan_sach.get())
            except ValueError:
                log.ghi("Lỗi: số thông điệp thử tối đa phải là số nguyên", "bad")
                return
            log.ghi(f"Bước 2. Lược đồ chuẩn: thử {gioi_han} thông điệp tìm m* với H(R*, Y, m*) = e*", "head")
        else:
            H = atf.H_toy
            gioi_han = 20 * atf.TOY
            log.ghi(f"Bước 2. Không gian thu nhỏ 2^{self.bits.get()} = {atf.TOY}: tìm m* với H(R*, Y, m*) = e* "
                    f"(kỳ vọng cỡ {atf.TOY} lần thử)", "head")
        tim, da_thu = None, 0
        self.dang_tim, self.dung = True, False
        try:
            for t in range(1, gioi_han + 1):
                da_thu = t
                if H(R, Y, t.to_bytes(8, "big")) == e:
                    tim = t
                    break
                if t % 2000 == 0:
                    self.update()
                    if self.dung:
                        break
        finally:
            self.dang_tim = False
        if tim is None and self.dung:
            log.ghi(f"  Đã dừng sau {da_thu} lần thử: chưa tìm được m*.", "chan")
        elif tim is None:
            log.ghi(f"  Đã thử {gioi_han} thông điệp: KHÔNG tìm được m*.", "chan")
        else:
            self.m_star = tim.to_bytes(8, "big")
            log.ghi(f"  Tìm được m* sau {tim} lần thử:  m* = {self.m_star.hex()}", "ok")

    def _b3(self):
        log = self.log
        log.ghi("")
        if self.m_star is None:
            log.ghi("Chưa có m*. Chạy Bước 2 và tìm được m* trước.", "bad")
            return
        try:
            Y, s, e = self._tham_so()
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        k, m = self.kieu.get(), self.m_star
        if k == "a":
            R = atf.diem_cuoi(s, e, Y)
            ok = R is not None and atf.H_day_du(R, Y, m) == e
        elif k == "b":
            ok = atf.verify_toy(m, (e, s), Y)
        else:
            ok = atf.verify_yeu(m, (e, s), Y)
        log.ghi("Bước 3. Nộp chữ ký giả (e*, s) cho hàm xác minh đầy đủ của lược đồ", "head")
        log.ghi(f"  Thông điệp m* = {m.hex() if k != 'c' else self.a_m.get()}")
        if ok:
            log.ghi("  Hàm xác minh CHẤP NHẬN chữ ký giả: True → giả mạo thành công mà không cần khóa bí mật.", "ok")
        else:
            log.ghi("  Hàm xác minh TỪ CHỐI chữ ký giả: False.", "chan")


if __name__ == "__main__":
    App().mainloop()
