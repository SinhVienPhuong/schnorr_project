"""
giao_dien_nonce.py - Giao dien mo phong Kich ban 1 (muc 3.3.1): tan cong tai su dung nonce.

Cach chay (trong thu muc chua schnorr_lib.py):   python giao_dien_nonce.py
Chi dung thu vien chuan cua Python (tkinter co san khi cai Python tren Windows).

Ba tab:
  1. Nan nhan : tao khoa, nhap thong diep va nonce, ky hai thong diep voi CUNG nonce.
  2. Ke tan cong : tu nhap (hoac dan) DU LIEU CONG KHAI; khong co khoa bi mat; tinh ra khoa bi mat.
  3. Phong thu : nan nhan ky bang BIP-340 (nonce dan xuat tu khoa + thong diep); tan cong that bai.
"""
import secrets
import tkinter as tk
from tkinter import ttk

import schnorr_lib as lib
from gui_chung import (KhungChung, Nhat_ky, hex_sach, doc_hex, chuan_hoa, hx,
                       FONT, MONO, XANH, DO, TIM)


class App(KhungChung):
    def __init__(self):
        super().__init__("Mô phỏng tấn công tái sử dụng nonce – EC-Schnorr (BIP-340)", "1120x800")
        # --- bien trang thai cua nan nhan ---
        self.v_sk, self.v_pk = tk.StringVar(), tk.StringVar()
        self.v_m1 = tk.StringVar(value="Chuyen 100 USD cho Bob")
        self.v_m2 = tk.StringVar(value="Chuyen 200 USD cho Eve")
        self.v_k = tk.StringVar()
        self.v_sg1, self.v_sg2 = tk.StringVar(), tk.StringVar()
        # --- bien cua ke tan cong ---
        self.a_pk, self.a_sg1, self.a_sg2 = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.a_m1 = tk.StringVar(value="Chuyen 100 USD cho Bob")
        self.a_m2 = tk.StringVar(value="Chuyen 200 USD cho Eve")
        self.a_moi = tk.StringVar(value="Chuyen toan bo tai san cho Eve")
        self.v_sk.trace_add("write", lambda *_: self._cap_nhat_pk())

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.tab_nn, self.tab_tc, self.tab_pt = ttk.Frame(nb), ttk.Frame(nb), ttk.Frame(nb)
        nb.add(self.tab_nn, text="1. Nạn nhân")
        nb.add(self.tab_tc, text="2. Kẻ tấn công")
        nb.add(self.tab_pt, text="3. Phòng thủ (BIP-340)")
        self._dung_nan_nhan()
        self._dung_tan_cong()
        self._dung_phong_thu()

    # =====================================================================
    # TAB 1: NAN NHAN
    # =====================================================================
    def _dung_nan_nhan(self):
        t, self.nn_log = self._khung(self.tab_nn, height=8)

        f1 = ttk.LabelFrame(t, text=" Bước 1. Tạo khóa ")
        f1.pack(fill="x", padx=10, pady=6)
        self._dong(f1, 0, "Khóa bí mật x (64 hex)", self.v_sk,
                   nut=[("Sinh ngẫu nhiên", self._sinh_khoa), ("Sao chép", lambda: self._chep(self.v_sk))])
        self._dong(f1, 1, "Khóa công khai Y (x-only)", self.v_pk, readonly=True,
                   nut=[("Sao chép", lambda: self._chep(self.v_pk))])

        f2 = ttk.LabelFrame(t, text=" Bước 2. Nhập thông điệp và chọn nonce ")
        f2.pack(fill="x", padx=10, pady=6)
        self._dong(f2, 0, "Thông điệp m₁", self.v_m1)
        self._dong(f2, 1, "Thông điệp m₂", self.v_m2)
        self._dong(f2, 2, "Nonce k (64 hex)", self.v_k,
                   nut=[("Sinh ngẫu nhiên", self._sinh_nonce)])

        f3 = ttk.LabelFrame(t, text=" Bước 3. Ký hai thông điệp với cùng nonce k ")
        f3.pack(fill="x", padx=10, pady=6)
        ttk.Button(f3, text="Ký cả hai thông điệp", style="Big.TButton", command=self._ky
                   ).grid(row=0, column=0, columnspan=3, sticky="w", padx=6, pady=6)
        self._dong(f3, 1, "Chữ ký σ₁ = x_R ‖ s₁ (128 hex)", self.v_sg1, readonly=True,
                   nut=[("Sao chép", lambda: self._chep(self.v_sg1))])
        self._dong(f3, 2, "Chữ ký σ₂ = x_R ‖ s₂ (128 hex)", self.v_sg2, readonly=True,
                   nut=[("Sao chép", lambda: self._chep(self.v_sg2))])
        self._sinh_khoa()
        self._sinh_nonce()

    def _sinh_khoa(self):
        while True:
            sk = secrets.token_bytes(32)
            if 1 <= lib.bytes_to_int(sk) <= lib.q - 1:
                break
        self.v_sk.set(sk.hex())
        self.v_sg1.set("")
        self.v_sg2.set("")

    def _cap_nhat_pk(self):
        try:
            sk = doc_hex(self.v_sk.get(), 32, "khóa bí mật")
            self.v_pk.set(lib.pubkey_gen(sk).hex())
        except Exception:
            self.v_pk.set("")

    def _sinh_nonce(self):
        self.v_k.set(hx(secrets.randbelow(lib.q - 1) + 1))

    def _ky(self):
        log = self.nn_log
        log.xoa()
        try:
            sk = doc_hex(self.v_sk.get(), 32, "khóa bí mật")
            x0 = lib.bytes_to_int(sk)
            if not 1 <= x0 <= lib.q - 1:
                raise ValueError("khóa bí mật phải nằm trong [1, q−1]")
            k = lib.bytes_to_int(doc_hex(self.v_k.get(), 32, "nonce k"))
            if not 1 <= k <= lib.q - 1:
                raise ValueError("nonce k phải nằm trong [1, q−1]")
            m1, m2 = self.v_m1.get().encode("utf-8"), self.v_m2.get().encode("utf-8")
            if m1 == m2:
                log.ghi("Lưu ý: hai thông điệp giống nhau nên hai chữ ký giống hệt nhau và kẻ tấn công "
                        "không thu được gì. Hãy nhập hai thông điệp KHÁC nhau.", "bad")
            sg1 = lib.schnorr_sign_with_nonce(m1, x0, k)
            sg2 = lib.schnorr_sign_with_nonce(m2, x0, k)
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        self.v_sg1.set(sg1.hex())
        self.v_sg2.set(sg2.hex())
        log.ghi("Đã ký xong. Dữ liệu công khai (gửi sang tab Kẻ tấn công):", "head")
        log.ghi(f"  Khóa công khai : {self.v_pk.get()}")
        log.ghi(f"  Chữ ký σ₁      : {sg1.hex()}")
        log.ghi(f"  Chữ ký σ₂      : {sg2.hex()}")
        log.ghi(f"  x_R của σ₁ và σ₂ giống nhau: {sg1[:32] == sg2[:32]}  (vì R = kG cùng một k)", "info")

    # =====================================================================
    # TAB 2: KE TAN CONG
    # =====================================================================
    def _dung_tan_cong(self):
        t, self.tc_log = self._khung(self.tab_tc)
        f = ttk.LabelFrame(t, text=" Dữ liệu công khai kẻ tấn công thu được ")
        f.pack(fill="x", padx=10, pady=6)
        self._dong(f, 0, "Khóa công khai Y (64 hex)", self.a_pk)
        self._dong(f, 1, "Thông điệp m₁", self.a_m1)
        self._dong(f, 2, "Thông điệp m₂", self.a_m2)
        self._dong(f, 3, "Chữ ký σ₁ (128 hex)", self.a_sg1)
        self._dong(f, 4, "Chữ ký σ₂ (128 hex)", self.a_sg2)
        bar = ttk.Frame(f)
        bar.grid(row=5, column=1, sticky="w", pady=(4, 6))
        ttk.Button(bar, text="Điền nhanh từ tab Nạn nhân", command=self._dien_nhanh).pack(side="left")
        ttk.Button(bar, text="Xóa các ô", command=self._xoa_o).pack(side="left", padx=6)
        ttk.Button(bar, text="Xóa nhật ký", command=lambda: self.tc_log.xoa()).pack(side="left")

        b = ttk.LabelFrame(t, text=" Các bước tấn công ")
        b.pack(fill="x", padx=10, pady=6)
        ttk.Button(b, text="Bước 1. Kiểm tra dữ liệu và dấu hiệu dùng lại nonce", style="Big.TButton",
                   command=self._b1).grid(row=0, column=0, sticky="we", padx=6, pady=3)
        ttk.Button(b, text="Bước 2. Tính e₁, e₂, s₁, s₂ từ chữ ký công khai", style="Big.TButton",
                   command=self._b2).grid(row=0, column=1, sticky="we", padx=6, pady=3)
        ttk.Button(b, text="Bước 3. Tính khóa bí mật  x = (s₁ − s₂)/(e₁ − e₂)", style="Big.TButton",
                   command=self._b3).grid(row=1, column=0, columnspan=2, sticky="we", padx=6, pady=3)
        ttk.Button(b, text="Bước 5. Đối chiếu với khóa thật (chỉ để kiểm chứng)", style="Big.TButton",
                   command=self._b5).grid(row=3, column=0, columnspan=2, sticky="we", padx=6, pady=3)
        b.columnconfigure(0, weight=1)
        b.columnconfigure(1, weight=1)
        g = ttk.Frame(b)
        g.grid(row=2, column=0, columnspan=2, sticky="we", pady=3)
        ttk.Label(g, text="Bước 4. Ký giả thông điệp:").pack(side="left", padx=(6, 6))
        ttk.Entry(g, textvariable=self.a_moi, font=MONO).pack(side="left", fill="x", expand=True)
        ttk.Button(g, text="Ký giả và xác minh", style="Big.TButton", command=self._b4).pack(side="left", padx=6)
        self.x_tim = None

    def _dien_nhanh(self):
        self.a_pk.set(self.v_pk.get())
        self.a_m1.set(self.v_m1.get())
        self.a_m2.set(self.v_m2.get())
        self.a_sg1.set(self.v_sg1.get())
        self.a_sg2.set(self.v_sg2.get())

    def _xoa_o(self):
        for v in (self.a_pk, self.a_sg1, self.a_sg2):
            v.set("")
        self.tc_log.xoa()

    def _doc_du_lieu(self):
        pk = doc_hex(self.a_pk.get(), 32, "khóa công khai")
        sg1 = doc_hex(self.a_sg1.get(), 64, "chữ ký σ₁")
        sg2 = doc_hex(self.a_sg2.get(), 64, "chữ ký σ₂")
        return pk, self.a_m1.get().encode("utf-8"), self.a_m2.get().encode("utf-8"), sg1, sg2

    def _tinh_es(self):
        pk, m1, m2, sg1, sg2 = self._doc_du_lieu()
        e1 = lib.challenge(sg1[:32], pk, m1)
        e2 = lib.challenge(sg2[:32], pk, m2)
        s1, s2 = lib.bytes_to_int(sg1[32:]), lib.bytes_to_int(sg2[32:])
        return pk, sg1, sg2, e1, e2, s1, s2

    def _b1(self):
        log = self.tc_log
        log.ghi('')
        try:
            pk, m1, m2, sg1, sg2 = self._doc_du_lieu()
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        log.ghi("Bước 1. Kiểm tra dữ liệu", "head")
        log.ghi(f"  Độ dài khóa công khai: {len(pk)} byte; chữ ký σ₁: {len(sg1)} byte; chữ ký σ₂: {len(sg2)} byte", "info")
        log.ghi(f"  x_R của σ₁: {sg1[:32].hex()}")
        log.ghi(f"  x_R của σ₂: {sg2[:32].hex()}")
        if sg1[:32] == sg2[:32]:
            log.ghi("  → Hai x_R GIỐNG NHAU: nonce bị dùng lại. Có thể tấn công.", "ok")
        else:
            log.ghi("  → Hai x_R KHÁC NHAU: không dùng chung nonce, công thức tấn công sẽ không cho ra khóa.", "chan")
        if m1 == m2:
            log.ghi("  Cảnh báo: hai thông điệp giống nhau, e₁ = e₂ nên không chia được.", "bad")

    def _b2(self):
        log = self.tc_log
        log.ghi('')
        try:
            pk, sg1, sg2, e1, e2, s1, s2 = self._tinh_es()
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        log.ghi("Bước 2. Tính lại thách thức e từ dữ liệu công khai: e = H(x_R ‖ x_Y ‖ m); s lấy từ nửa sau chữ ký", "head")
        log.ghi(f"  e₁ = {hx(e1)}")
        log.ghi(f"  e₂ = {hx(e2)}")
        log.ghi(f"  s₁ = {hx(s1)}")
        log.ghi(f"  s₂ = {hx(s2)}")

    def _b3(self):
        log = self.tc_log
        log.ghi('')
        try:
            pk, sg1, sg2, e1, e2, s1, s2 = self._tinh_es()
            log.ghi("Bước 3. s₁ = k + x·e₁,  s₂ = k + x·e₂  ⇒  s₁ − s₂ = x·(e₁ − e₂)  ⇒  x = (s₁ − s₂)·(e₁ − e₂)⁻¹ mod q", "head")
            x = (s1 - s2) * pow(e1 - e2, -1, lib.q) % lib.q
        except ValueError as ex:
            if "not invertible" in str(ex):
                log.ghi("Lỗi: e₁ − e₂ = 0 (hai thông điệp giống nhau) nên không có nghịch đảo.", "bad")
            else:
                log.ghi(f"Lỗi: {ex}", "bad")
            return
        self.x_tim = x
        log.ghi(f"  x tìm được = {hx(x)}", "ok")
        if sg1[:32] != sg2[:32]:
            log.ghi("  Lưu ý: hai x_R khác nhau, đây là số vô nghĩa chứ không phải khóa bí mật.", "chan")
        else:
            log.ghi("  Hai x_R giống nhau nên giá trị này là khóa bí mật (đã chuẩn hóa tung độ chẵn). Bước 4 sẽ chứng minh.", "info")

    def _b4(self):
        log = self.tc_log
        log.ghi('')
        if self.x_tim is None:
            log.ghi("Hãy chạy Bước 3 trước để có khóa x.", "bad")
            return
        try:
            pk = doc_hex(self.a_pk.get(), 32, "khóa công khai")
            msg = self.a_moi.get().encode("utf-8")
            gia = lib.schnorr_sign(msg, lib.int_to_bytes(self.x_tim), bytes(32))
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        ok = lib.schnorr_verify(msg, pk, gia)
        log.ghi("Bước 4. Dùng x vừa tìm để ký thông điệp mới, rồi xác minh bằng KHÓA CÔNG KHAI THẬT", "head")
        log.ghi(f"  Thông điệp giả : {self.a_moi.get()}")
        log.ghi(f"  Chữ ký giả     : {gia.hex()}")
        if ok:
            log.ghi("  Khóa công khai thật CHẤP NHẬN chữ ký giả: True → kẻ tấn công ký thay được chủ khóa.", "ok")
        else:
            log.ghi("  Chữ ký giả bị từ chối: False → x tìm được không phải khóa thật.", "chan")

    def _b5(self):
        log = self.tc_log
        log.ghi('')
        if self.x_tim is None:
            log.ghi("Hãy chạy Bước 3 trước.", "bad")
            return
        try:
            x0 = lib.bytes_to_int(doc_hex(self.v_sk.get(), 32, "khóa bí mật (tab Nạn nhân)"))
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        xc = chuan_hoa(x0)
        log.ghi("Bước 5. Đối chiếu (đây là phép kiểm chứng của người làm thí nghiệm; kẻ tấn công thật không có khóa này)", "head")
        log.ghi(f"  Khóa bí mật thật của nạn nhân  : {hx(x0)}")
        log.ghi(f"  Khóa thật đã chuẩn hóa y chẵn  : {hx(xc)}")
        log.ghi(f"  Khóa kẻ tấn công tìm được      : {hx(self.x_tim)}")
        if self.x_tim == xc:
            kieu = "bằng khóa thật" if xc == x0 else "bằng q − khóa thật (do khóa công khai có tung độ lẻ, BIP-340 lưu dạng q − x)"
            log.ghi(f"  → TRÙNG: khóa bí mật đã bị lộ ({kieu}).", "ok")
        else:
            log.ghi("  → KHÔNG TRÙNG: tấn công không lấy được khóa.", "chan")

    # =====================================================================
    # TAB 3: PHONG THU
    # =====================================================================
    def _dung_phong_thu(self):
        t, self.pt_log = self._khung(self.tab_pt, height=20)
        bar = ttk.Frame(t)
        bar.pack(fill="x", padx=10, pady=4)
        ttk.Button(bar, text="Bước 1. Nạn nhân ký m₁, m₂ bằng BIP-340", style="Big.TButton",
                   command=self._pt1).pack(side="left")
        ttk.Button(bar, text="Bước 2. Kẻ tấn công áp công thức cũ", style="Big.TButton",
                   command=self._pt2).pack(side="left", padx=8)
        self.pt_sig = None

    def _pt1(self):
        log = self.pt_log
        log.xoa()
        self.pt_sig = None
        try:
            sk = doc_hex(self.v_sk.get(), 32, "khóa bí mật (tab Nạn nhân)")
            m1, m2 = self.v_m1.get().encode("utf-8"), self.v_m2.get().encode("utf-8")
            aux = secrets.token_bytes(32)
            pk = lib.pubkey_gen(sk)
            t1 = lib.schnorr_sign(m1, sk, aux)
            t2 = lib.schnorr_sign(m2, sk, aux)
        except Exception as ex:
            log.ghi(f"Lỗi: {ex}", "bad")
            return
        self.pt_sig = (pk, m1, m2, t1, t2, sk)
        log.ghi("Bước 1. Nạn nhân ký bằng BIP-340 (cùng khóa, cùng aux_rand, nonce tự dẫn xuất)", "head")
        log.ghi(f"  x_R của σ₁: {t1[:32].hex()}")
        log.ghi(f"  x_R của σ₂: {t2[:32].hex()}")
        if t1[:32] != t2[:32]:
            log.ghi("  → Hai x_R KHÁC NHAU: không còn dùng chung nonce.", "chan")
        else:
            log.ghi("  → Hai x_R giống nhau (xảy ra khi hai thông điệp giống nhau).", "bad")

    def _pt2(self):
        log = self.pt_log
        if self.pt_sig is None:
            log.ghi("Hãy chạy Bước 1 trước.", "bad")
            return
        pk, m1, m2, t1, t2, sk = self.pt_sig
        e1, e2 = lib.challenge(t1[:32], pk, m1), lib.challenge(t2[:32], pk, m2)
        s1, s2 = lib.bytes_to_int(t1[32:]), lib.bytes_to_int(t2[32:])
        log.ghi("")
        log.ghi("Bước 2. Kẻ tấn công vẫn áp công thức x = (s₁ − s₂)/(e₁ − e₂) mod q", "head")
        try:
            x = (s1 - s2) * pow(e1 - e2, -1, lib.q) % lib.q
        except ValueError:
            log.ghi("  e₁ = e₂ nên không tính được.", "bad")
            return
        xc = chuan_hoa(lib.bytes_to_int(sk))
        log.ghi(f"  Kết quả công thức : {hx(x)}")
        log.ghi(f"  Khóa thật (chuẩn) : {hx(xc)}")
        if x != xc:
            log.ghi("  → KHÔNG TRÙNG: công thức cho ra một số không liên quan, khóa bí mật không bị lộ. Phòng thủ có tác dụng.", "chan")
        else:
            log.ghi("  → Trùng khóa thật (không mong đợi).", "ok")


if __name__ == "__main__":
    App().mainloop()
