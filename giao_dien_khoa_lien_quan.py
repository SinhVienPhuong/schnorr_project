"""
giao_dien_khoa_lien_quan.py - Giao dien mo phong Kich ban 3 (muc 3.3.3): tan cong khoa lien quan.

Cach chay (trong thu muc chua schnorr_lib.py):   python giao_dien_khoa_lien_quan.py

Bon tab:
  Phan A (dich khoa Y' = Y - aG):
    1. Nan nhan (ky)       : tao khoa, chon dang thach thuc (co ban hoac key-prefixing BIP-340), ky.
    2. Ke tan cong (dich khoa): tu nhap du lieu cong khai, chon a, bien doi chu ky sang khoa Y'.
  Phan B (phat sinh khoa phan cap kieu BIP-32, rut gon):
    3. Nan nhan (khoa con) : sinh khoa cha, phat sinh 3 khoa con (khong cung hoa hoac cung hoa).
    4. Ke tan cong (khoa cha): tu mot khoa con bi lo suy ra khoa cha va khoa con khac.
"""
import hashlib
import hmac
import secrets
import tkinter as tk
from tkinter import ttk

import schnorr_lib as lib
import attack_related_key as ark
from gui_chung import KhungChung, hex_sach, doc_hex, hx


def diem_tu_33(b33):
    """Khoi phuc diem tu khoa cong khai nen 33 byte (02/03 || x)."""
    if len(b33) != 33 or b33[0] not in (2, 3):
        raise ValueError("khóa công khai cha phải gồm 33 byte, bắt đầu bằng 02 hoặc 03")
    P = lib.lift_x(b33[1:])
    if P is None:
        raise ValueError("khóa công khai cha không nằm trên đường cong")
    return P if b33[0] == 2 else lib.point_neg(P)


def offset_tu_P(P, chain, i):
    """I_L cua phat sinh KHONG cung hoa: chi can khoa cong khai cha, chain code, chi so."""
    return lib.bytes_to_int(hmac.new(chain, ark.ser33(P) + i.to_bytes(4, "big"), hashlib.sha512).digest()[:32])


class App(KhungChung):
    def __init__(self):
        super().__init__("Mô phỏng tấn công khóa liên quan – EC-Schnorr", "1120x840")
        S = tk.StringVar
        # --- phan A: nan nhan ---
        self.v_sk, self.v_pk, self.v_sig = S(), S(), S()
        self.v_m = S(value="Chuyen 100 USD cho Bob")
        self.v_kieu = S(value="co_ban")
        # --- phan A: ke tan cong ---
        self.a_pk, self.a_sig, self.a_a = S(), S(), S()
        self.a_m = S(value="Chuyen 100 USD cho Bob")
        self.a_kieu = S(value="co_ban")
        self.A = {}
        # --- phan B: nan nhan ---
        self.b_par, self.b_chain, self.b_P = S(), S(), S()
        self.b_loai = S(value="cong_khai")
        self.b_con = [S() for _ in range(3)]
        self.b_pkcon = [S() for _ in range(3)]
        self.b_lo = tk.IntVar(value=1)
        # --- phan B: ke tan cong ---
        self.c_P, self.c_chain, self.c_xcon, self.c_pkj = S(), S(), S(), S()
        self.c_i, self.c_j = tk.IntVar(value=1), tk.IntVar(value=2)
        self.c_m = S(value="Chuyen toan bo tai san cho Eve")
        self.B = {}
        self.v_sk.trace_add("write", lambda *_: self._pk_A())

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tabs = [ttk.Frame(nb) for _ in range(4)]
        for tab, ten in zip(self.tabs, ("1. Nạn nhân (ký)", "2. Kẻ tấn công (dịch khóa)",
                                        "3. Nạn nhân (khóa con)", "4. Kẻ tấn công (khóa cha)")):
            nb.add(tab, text=ten)
        self._tab1()
        self._tab2()
        self._tab3()
        self._tab4()

    # ================== PHAN A ==================
    def _tab1(self):
        t, self.log1 = self._khung(self.tabs[0], height=8)
        f = ttk.LabelFrame(t, text=" Khóa và thông điệp ")
        f.pack(fill="x", padx=10, pady=6)
        self._dong(f, 0, "Khóa bí mật x (64 hex)", self.v_sk,
                   nut=[("Sinh ngẫu nhiên", self._sinh_khoa_A), ("Sao chép", lambda: self._chep(self.v_sk))])
        self._dong(f, 1, "Khóa công khai Y (x-only)", self.v_pk, readonly=True,
                   nut=[("Sao chép", lambda: self._chep(self.v_pk))])
        self._dong(f, 2, "Thông điệp m", self.v_m)
        g = ttk.LabelFrame(t, text=" Dạng thách thức nạn nhân dùng ")
        g.pack(fill="x", padx=10, pady=6)
        ttk.Radiobutton(g, text="Dạng cơ bản  e = H(x_R ‖ m)   (Chương 1, không chứa khóa công khai)",
                        variable=self.v_kieu, value="co_ban").pack(anchor="w", padx=6, pady=2)
        ttk.Radiobutton(g, text="Key-prefixing  e = H(x_R ‖ x_Y ‖ m)   (BIP-340)",
                        variable=self.v_kieu, value="kp").pack(anchor="w", padx=6, pady=2)
        h = ttk.LabelFrame(t, text=" Ký ")
        h.pack(fill="x", padx=10, pady=6)
        ttk.Button(h, text="Ký thông điệp", style="Big.TButton", command=self._ky_A
                   ).grid(row=0, column=0, columnspan=3, sticky="w", padx=6, pady=6)
        self._dong(h, 1, "Chữ ký σ = x_R ‖ s (128 hex)", self.v_sig, readonly=True,
                   nut=[("Sao chép", lambda: self._chep(self.v_sig))])
        self._sinh_khoa_A()

    def _sinh_khoa_A(self):
        while True:
            sk = secrets.token_bytes(32)
            if 1 <= lib.bytes_to_int(sk) <= lib.q - 1:
                break
        self.v_sk.set(sk.hex())
        self.v_sig.set("")

    def _pk_A(self):
        try:
            self.v_pk.set(lib.pubkey_gen(doc_hex(self.v_sk.get(), 32, "khóa bí mật")).hex())
        except Exception:
            self.v_pk.set("")

    def _ky_A(self):
        log = self.log1
        log.xoa()
        try:
            sk = doc_hex(self.v_sk.get(), 32, "khóa bí mật")
            kp = self.v_kieu.get() == "kp"
            sig = lib.schnorr_sign(self.v_m.get().encode("utf-8"), sk, secrets.token_bytes(32), key_prefix=kp)
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        self.v_sig.set(sig.hex())
        log.ghi("Đã ký. Dữ liệu công khai (gửi sang tab Kẻ tấn công):", "head")
        log.ghi(f"  Khóa công khai : {self.v_pk.get()}")
        log.ghi(f"  Thông điệp     : {self.v_m.get()}")
        log.ghi(f"  Chữ ký σ       : {sig.hex()}")
        log.ghi("  Dạng thách thức: " + ("key-prefixing e = H(x_R‖x_Y‖m)" if kp else "cơ bản e = H(x_R‖m)"), "info")

    def _tab2(self):
        t, self.log2 = self._khung(self.tabs[1], height=14)
        f = ttk.LabelFrame(t, text=" Dữ liệu công khai kẻ tấn công thu được ")
        f.pack(fill="x", padx=10, pady=6)
        self._dong(f, 0, "Khóa công khai Y (64 hex)", self.a_pk)
        self._dong(f, 1, "Thông điệp m", self.a_m)
        self._dong(f, 2, "Chữ ký σ (128 hex)", self.a_sig)
        bar = ttk.Frame(f)
        bar.grid(row=3, column=1, sticky="w", pady=(4, 6))
        ttk.Button(bar, text="Điền nhanh từ tab Nạn nhân", command=self._dien_A).pack(side="left")
        ttk.Button(bar, text="Xóa nhật ký", command=self.log2.xoa).pack(side="left", padx=6)
        g = ttk.LabelFrame(t, text=" Hàm xác minh nhắm tới (dạng thách thức) ")
        g.pack(fill="x", padx=10, pady=6)
        ttk.Radiobutton(g, text="Dạng cơ bản  e = H(x_R ‖ m)", variable=self.a_kieu, value="co_ban"
                        ).pack(side="left", padx=6, pady=2)
        ttk.Radiobutton(g, text="Key-prefixing  e = H(x_R ‖ x_Y ‖ m)  (BIP-340)", variable=self.a_kieu, value="kp"
                        ).pack(side="left", padx=6, pady=2)
        p = ttk.LabelFrame(t, text=" Tham số kẻ tấn công chọn ")
        p.pack(fill="x", padx=10, pady=6)
        self._dong(p, 0, "a (64 hex)", self.a_a,
                   nut=[("Sinh a ngẫu nhiên", self._sinh_a)])
        b = ttk.LabelFrame(t, text=" Các bước tấn công ")
        b.pack(fill="x", padx=10, pady=6)
        for i, (ten, cmd) in enumerate([
                ("Bước 1. Tính e từ dữ liệu công khai", self._a1),
                ("Bước 2. Tính khóa mới Y′ = Y − aG", self._a2),
                ("Bước 3. Tính s′ = s − a·e", self._a3),
                ("Bước 4. Nộp (x_R, s′) cho người xác minh với khóa Y′", self._a4)]):
            ttk.Button(b, text=ten, style="Big.TButton", command=cmd).grid(
                row=i, column=0, sticky="we", padx=6, pady=3)
        b.columnconfigure(0, weight=1)

    def _dien_A(self):
        self.a_pk.set(self.v_pk.get())
        self.a_m.set(self.v_m.get())
        self.a_sig.set(self.v_sig.get())

    def _sinh_a(self):
        try:
            Y = lib.lift_x(doc_hex(self.a_pk.get(), 32, "khóa công khai"))
        except Exception as ex:
            self.log2.ghi(f"Lỗi: {ex}", "bad")
            return
        while True:
            a = secrets.randbelow(lib.q - 1) + 1
            if lib.has_even_y(lib.point_add(Y, lib.point_neg(lib.point_mul(lib.G, a)))):
                break
        self.a_a.set(hx(a))

    def _doc_A(self):
        pk = doc_hex(self.a_pk.get(), 32, "khóa công khai")
        sig = doc_hex(self.a_sig.get(), 64, "chữ ký")
        return pk, sig, self.a_m.get().encode("utf-8"), self.a_kieu.get() == "kp"

    def _a1(self):
        log = self.log2
        log.ghi("")
        try:
            pk, sig, m, kp = self._doc_A()
            e = lib.challenge(sig[:32], pk, m, key_prefix=kp)
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        self.A = {"e": e}
        log.ghi("Bước 1. Tính lại thách thức e từ x_R, khóa công khai và thông điệp (đều công khai)", "head")
        log.ghi(f"  e = {hx(e)}")

    def _a2(self):
        log = self.log2
        log.ghi("")
        try:
            pk, sig, m, kp = self._doc_A()
            Y = lib.lift_x(pk)
            a = lib.bytes_to_int(doc_hex(self.a_a.get(), 32, "a"))
            if not 1 <= a <= lib.q - 1:
                raise ValueError("a phải nằm trong [1, q−1]")
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        Y2 = lib.point_add(Y, lib.point_neg(lib.point_mul(lib.G, a)))
        log.ghi("Bước 2. Khóa mới Y′ = Y − aG (kẻ tấn công không dùng khóa bí mật)", "head")
        log.ghi(f"  Y′ (x-only) = {lib.x_only(Y2).hex()}")
        if lib.has_even_y(Y2):
            self.A.update({"a": a, "Y2": Y2})
            log.ghi("  Y′ có tung độ chẵn: hợp lệ với khóa x-only.", "info")
        else:
            self.A.pop("Y2", None)
            log.ghi("  Y′ có tung độ lẻ: khóa x-only sẽ thành −Y′. Hãy chọn a khác (nút Sinh a ngẫu nhiên).", "bad")

    def _a3(self):
        log = self.log2
        log.ghi("")
        if "e" not in self.A or "Y2" not in self.A:
            log.ghi("Hãy chạy Bước 1 và Bước 2 (với Y′ có tung độ chẵn) trước.", "bad")
            return
        try:
            pk, sig, m, kp = self._doc_A()
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        s = lib.bytes_to_int(sig[32:])
        s2 = (s - self.A["a"] * self.A["e"]) % lib.q
        self.A["s2"] = s2
        log.ghi("Bước 3. s′ = s − a·e mod q", "head")
        log.ghi(f"  s  = {hx(s)}")
        log.ghi(f"  s′ = {hx(s2)}")

    def _a4(self):
        log = self.log2
        log.ghi("")
        if "s2" not in self.A:
            log.ghi("Hãy chạy Bước 3 trước.", "bad")
            return
        try:
            pk, sig, m, kp = self._doc_A()
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        sig2 = sig[:32] + lib.int_to_bytes(self.A["s2"])
        ok = lib.schnorr_verify(m, lib.x_only(self.A["Y2"]), sig2, key_prefix=kp)
        log.ghi("Bước 4. Nộp (x_R, s′) cho người xác minh, khóa công khai là Y′, cùng thông điệp", "head")
        log.ghi(f"  Chữ ký biến đổi : {sig2.hex()}")
        if ok:
            log.ghi("  Người xác minh CHẤP NHẬN: True → chữ ký được chuyển sang khóa Y′ mà không cần khóa bí mật.", "ok")
        else:
            log.ghi("  Người xác minh TỪ CHỐI: False → phép biến đổi bị chặn.", "chan")

    # ================== PHAN B ==================
    def _tab3(self):
        t, self.log3 = self._khung(self.tabs[2], height=8)
        f = ttk.LabelFrame(t, text=" Khóa cha ")
        f.pack(fill="x", padx=10, pady=6)
        self._dong(f, 0, "Khóa bí mật cha x_cha (64 hex)", self.b_par,
                   nut=[("Sinh ngẫu nhiên", self._sinh_cha)])
        self._dong(f, 1, "Chain code (64 hex)", self.b_chain,
                   nut=[("Sao chép", lambda: self._chep(self.b_chain))])
        self._dong(f, 2, "Khóa công khai cha (33 byte)", self.b_P, readonly=True,
                   nut=[("Sao chép", lambda: self._chep(self.b_P))])
        g = ttk.LabelFrame(t, text=" Kiểu phát sinh khóa con ")
        g.pack(fill="x", padx=10, pady=6)
        ttk.Radiobutton(g, text="Không cứng hóa:  x_con = x_cha + I_L,  I_L = HMAC(chain, khóa công khai cha ‖ i)",
                        variable=self.b_loai, value="cong_khai").pack(anchor="w", padx=6, pady=2)
        ttk.Radiobutton(g, text="Cứng hóa (hardened):  I_L = HMAC(chain, 0x00 ‖ khóa bí mật cha ‖ i)",
                        variable=self.b_loai, value="cung_hoa").pack(anchor="w", padx=6, pady=2)
        ttk.Button(g, text="Phát sinh 3 khóa con", style="Big.TButton", command=self._phat_sinh
                   ).pack(anchor="w", padx=6, pady=6)
        c = ttk.LabelFrame(t, text=" Các khóa con ")
        c.pack(fill="x", padx=10, pady=6)
        for i in range(3):
            self._dong(c, 2 * i, f"Khóa bí mật con {i}", self.b_con[i], readonly=True,
                       nut=[("Sao chép", lambda v=self.b_con[i]: self._chep(v))])
            self._dong(c, 2 * i + 1, f"Khóa công khai con {i}", self.b_pkcon[i], readonly=True,
                       nut=[("Sao chép", lambda v=self.b_pkcon[i]: self._chep(v))])
        h = ttk.Frame(t)
        h.pack(fill="x", padx=10, pady=4)
        ttk.Label(h, text="Sự cố: lộ khóa bí mật của khóa con số").pack(side="left")
        ttk.Spinbox(h, from_=0, to=2, width=4, textvariable=self.b_lo).pack(side="left", padx=6)
        self._sinh_cha()

    def _sinh_cha(self):
        self.b_par.set(hx(secrets.randbelow(lib.q - 1) + 1))
        self.b_chain.set(secrets.token_bytes(32).hex())
        for v in self.b_con + self.b_pkcon:
            v.set("")
        try:
            self.b_P.set(ark.ser33(lib.point_mul(lib.G, lib.bytes_to_int(doc_hex(self.b_par.get(), 32, "x")))).hex())
        except Exception:
            self.b_P.set("")

    def _phat_sinh(self):
        log = self.log3
        log.xoa()
        try:
            x = lib.bytes_to_int(doc_hex(self.b_par.get(), 32, "khóa cha"))
            chain = doc_hex(self.b_chain.get(), 32, "chain code")
            if not 1 <= x <= lib.q - 1:
                raise ValueError("khóa cha phải nằm trong [1, q−1]")
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        self.b_P.set(ark.ser33(lib.point_mul(lib.G, x)).hex())
        off = ark.offset_cong_khai if self.b_loai.get() == "cong_khai" else ark.offset_cung_hoa
        for i in range(3):
            xc = (x + off(x, chain, i)) % lib.q
            self.b_con[i].set(hx(xc))
            self.b_pkcon[i].set(lib.pubkey_gen(lib.int_to_bytes(xc)).hex())
        i = self.b_lo.get()
        log.ghi("Đã phát sinh 3 khóa con (" + ("không cứng hóa" if self.b_loai.get() == "cong_khai" else "cứng hóa") + ").", "head")
        log.ghi("Dữ liệu công khai (có trong khóa công khai mở rộng xpub):", "head")
        log.ghi(f"  Khóa công khai cha : {self.b_P.get()}")
        log.ghi(f"  Chain code         : {self.b_chain.get()}")
        for j in range(3):
            log.ghi(f"  Khóa công khai con {j}: {self.b_pkcon[j].get()}")
        log.ghi(f"Sự cố: khóa bí mật con số {i} bị lộ:", "head")
        log.ghi(f"  {self.b_con[i].get()}")

    # ---------------- tab 4: ke tan cong ----------------
    def _tab4(self):
        t, self.log4 = self._khung(self.tabs[3], height=14)
        f = ttk.LabelFrame(t, text=" Dữ liệu công khai và khóa con bị lộ ")
        f.pack(fill="x", padx=10, pady=6)
        self._dong(f, 0, "Khóa công khai cha (66 hex)", self.c_P)
        self._dong(f, 1, "Chain code (64 hex)", self.c_chain)
        self._dong(f, 2, "Khóa bí mật con bị lộ (64 hex)", self.c_xcon)
        self._dong(f, 3, "Khóa công khai con cần giả mạo (64 hex)", self.c_pkj)
        r = ttk.Frame(f)
        r.grid(row=4, column=1, sticky="w", pady=3)
        ttk.Label(r, text="Chỉ số khóa con bị lộ i =").pack(side="left")
        ttk.Spinbox(r, from_=0, to=2, width=4, textvariable=self.c_i).pack(side="left", padx=6)
        ttk.Label(r, text="   Chỉ số khóa con cần giả mạo j =").pack(side="left")
        ttk.Spinbox(r, from_=0, to=2, width=4, textvariable=self.c_j).pack(side="left", padx=6)
        self._dong(f, 5, "Thông điệp giả", self.c_m)
        bar = ttk.Frame(f)
        bar.grid(row=6, column=1, sticky="w", pady=(4, 6))
        ttk.Button(bar, text="Điền nhanh từ tab Nạn nhân", command=self._dien_B).pack(side="left")
        ttk.Button(bar, text="Xóa nhật ký", command=self.log4.xoa).pack(side="left", padx=6)
        b = ttk.LabelFrame(t, text=" Các bước tấn công ")
        b.pack(fill="x", padx=10, pady=6)
        for i, (ten, cmd) in enumerate([
                ("Bước 1. Tính I_L của khóa con bị lộ, chỉ từ dữ liệu công khai", self._b1),
                ("Bước 2. Khôi phục khóa cha  x_cha = x_con − I_L", self._b2),
                ("Bước 3. Suy ra khóa con j  x_j = x_cha + I_L(j)", self._b3),
                ("Bước 4. Ký giả bằng khóa con j, xác minh bằng khóa công khai thật", self._b4),
                ("Bước 5. Đối chiếu với khóa cha thật (chỉ để kiểm chứng)", self._b5)]):
            ttk.Button(b, text=ten, style="Big.TButton", command=cmd).grid(
                row=i, column=0, sticky="we", padx=6, pady=3)
        b.columnconfigure(0, weight=1)

    def _dien_B(self):
        self.c_P.set(self.b_P.get())
        self.c_chain.set(self.b_chain.get())
        i, j = self.b_lo.get(), 2 if self.b_lo.get() != 2 else 0
        self.c_i.set(i)
        self.c_j.set(j)
        self.c_xcon.set(self.b_con[i].get())
        self.c_pkj.set(self.b_pkcon[j].get())

    def _doc_B(self):
        P = diem_tu_33(doc_hex(self.c_P.get(), 33, "khóa công khai cha"))
        chain = doc_hex(self.c_chain.get(), 32, "chain code")
        xcon = lib.bytes_to_int(doc_hex(self.c_xcon.get(), 32, "khóa con bị lộ"))
        return P, chain, xcon

    def _b1(self):
        log = self.log4
        log.ghi("")
        try:
            P, chain, xcon = self._doc_B()
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        i = self.c_i.get()
        IL = offset_tu_P(P, chain, i)
        self.B = {"IL": IL}
        log.ghi(f"Bước 1. I_L = HMAC-SHA512(chain, khóa công khai cha ‖ {i})[:32]  (mọi đầu vào đều công khai)", "head")
        log.ghi(f"  I_L = {hx(IL)}")

    def _b2(self):
        log = self.log4
        log.ghi("")
        if "IL" not in self.B:
            log.ghi("Hãy chạy Bước 1 trước.", "bad")
            return
        try:
            P, chain, xcon = self._doc_B()
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        xcha = (xcon - self.B["IL"]) % lib.q
        self.B["xcha"] = xcha
        log.ghi("Bước 2. x_cha = x_con − I_L mod q", "head")
        log.ghi(f"  x_cha tìm được = {hx(xcha)}", "ok")
        kt = ark.ser33(lib.point_mul(lib.G, xcha)) == ark.ser33(P)
        log.ghi(f"  Kiểm tra bằng dữ liệu công khai: x_cha·G có trùng khóa công khai cha: {kt}", "ok" if kt else "chan")

    def _b3(self):
        log = self.log4
        log.ghi("")
        if "xcha" not in self.B:
            log.ghi("Hãy chạy Bước 2 trước.", "bad")
            return
        try:
            P, chain, xcon = self._doc_B()
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        j = self.c_j.get()
        xj = (self.B["xcha"] + offset_tu_P(P, chain, j)) % lib.q
        self.B["xj"] = xj
        log.ghi(f"Bước 3. x_{j} = x_cha + I_L({j}) mod q", "head")
        log.ghi(f"  x_{j} tính được = {hx(xj)}", "ok")

    def _b4(self):
        log = self.log4
        log.ghi("")
        if "xj" not in self.B:
            log.ghi("Hãy chạy Bước 3 trước.", "bad")
            return
        try:
            pkj = doc_hex(self.c_pkj.get(), 32, "khóa công khai con cần giả mạo")
            msg = self.c_m.get().encode("utf-8")
            sig = lib.schnorr_sign(msg, lib.int_to_bytes(self.B["xj"]), bytes(32))
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        ok = lib.schnorr_verify(msg, pkj, sig)
        log.ghi(f"Bước 4. Ký giả bằng x_{self.c_j.get()} vừa tính, xác minh bằng khóa công khai thật của khóa con {self.c_j.get()}", "head")
        log.ghi(f"  Thông điệp giả : {self.c_m.get()}")
        log.ghi(f"  Chữ ký giả     : {sig.hex()}")
        if ok:
            log.ghi("  Khóa công khai thật CHẤP NHẬN chữ ký giả: True → kẻ tấn công ký thay được khóa con chưa từng bị lộ.", "ok")
        else:
            log.ghi("  Khóa công khai thật TỪ CHỐI chữ ký giả: False → x_j tính được không phải khóa con thật.", "chan")

    def _b5(self):
        log = self.log4
        log.ghi("")
        if "xcha" not in self.B:
            log.ghi("Hãy chạy Bước 2 trước.", "bad")
            return
        try:
            x = lib.bytes_to_int(doc_hex(self.b_par.get(), 32, "khóa cha (tab Nạn nhân)"))
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        log.ghi("Bước 5. Đối chiếu (phép kiểm chứng của người làm thí nghiệm; kẻ tấn công thật không có khóa này)", "head")
        log.ghi(f"  Khóa cha thật       : {hx(x)}")
        log.ghi(f"  Khóa cha tìm được   : {hx(self.B['xcha'])}")
        if x == self.B["xcha"]:
            log.ghi("  → TRÙNG: khóa cha đã bị lộ.", "ok")
        else:
            log.ghi("  → KHÔNG TRÙNG: tấn công không lấy được khóa cha.", "chan")


if __name__ == "__main__":
    App().mainloop()
