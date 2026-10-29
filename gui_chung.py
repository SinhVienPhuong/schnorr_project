"""
gui_chung.py - Thanh phan dung chung cho cac giao dien mo phong (giao_dien_*.py):
chuoi hex, khung nhat ky co mau, cua so goc co thanh keo va nut an khung nhap.
Khong chay truc tiep.
"""
import re
import secrets
import tkinter as tk
from tkinter import ttk, scrolledtext

import schnorr_lib as lib

FONT = ("Segoe UI", 10)
MONO = ("Consolas", 9)
XANH, DO, TIM = "#1a7f37", "#c62828", "#1f4e9c"


# ---------- tien ich ----------
def hex_sach(s):
    """Bo khoang trang, xuong dong, dau ':' - de dan chuoi hex bi ngat dong van dung."""
    return re.sub(r"[\s:]", "", s)


def doc_hex(s, n_byte, ten):
    """Doc chuoi hex thanh bytes, kiem tra dung do dai; bao loi bang tieng Viet."""
    h = hex_sach(s)
    if not h:
        raise ValueError(f"{ten}: chưa nhập")
    if len(h) != 2 * n_byte:
        raise ValueError(f"{ten}: cần {2 * n_byte} ký tự hex nhưng đang có {len(h)} "
                         f"({'thiếu' if len(h) < 2 * n_byte else 'thừa'} {abs(2 * n_byte - len(h))} ký tự)")
    try:
        return bytes.fromhex(h)
    except ValueError:
        raise ValueError(f"{ten}: có ký tự không phải hex (0-9, a-f)")


def chuan_hoa(x0):
    """Khoa bi mat da chuan hoa (Y co tung do chan) - gia tri BIP-340 thuc su dung de ky."""
    return x0 if lib.has_even_y(lib.point_mul(lib.G, x0)) else lib.q - x0


def hx(v):
    return format(v, "064x")


class Nhat_ky(scrolledtext.ScrolledText):
    """Khung in ket qua co mau."""

    def __init__(self, master, height=14, **kw):
        super().__init__(master, font=MONO, wrap="char", height=height, state="disabled", **kw)
        self.tag_config("ok", foreground=XANH, font=("Consolas", 9, "bold"))
        self.tag_config("bad", foreground=DO, font=("Consolas", 9, "bold"))
        self.tag_config("info", foreground=TIM)
        self.tag_config("chan", foreground=TIM, font=("Consolas", 9, "bold"))
        self.tag_config("head", font=("Consolas", 9, "bold"))

    def ghi(self, text, tag=None):
        self.config(state="normal")
        self.insert("end", text + "\n", tag)
        self.see("end")
        self.config(state="disabled")

    def xoa(self):
        self.config(state="normal")
        self.delete("1.0", "end")
        self.config(state="disabled")



class KhungChung(tk.Tk):
    """Cua so goc: dat tieu de, kieu chu, va cac ham dung khung (_dong, _khung, _chep)."""

    def __init__(self, tieu_de, kich_thuoc="1120x800"):
        super().__init__()
        self.title(tieu_de)
        self.geometry(kich_thuoc)
        self.minsize(980, 700)
        style = ttk.Style(self)
        style.configure(".", font=FONT)
        style.configure("TNotebook.Tab", padding=(14, 6), font=("Segoe UI", 10, "bold"))
        style.configure("Big.TButton", font=("Segoe UI", 10, "bold"), padding=6)

    # ---------- khung dung chung ----------
    def _dong(self, parent, row, nhan, var, rong=100, readonly=False, nut=()):
        ttk.Label(parent, text=nhan).grid(row=row, column=0, sticky="w", padx=(6, 8), pady=3)
        e = ttk.Entry(parent, textvariable=var, width=rong, font=MONO,
                      state="readonly" if readonly else "normal")
        e.grid(row=row, column=1, sticky="we", pady=3)
        for i, (ten, cmd) in enumerate(nut):
            ttk.Button(parent, text=ten, command=cmd).grid(row=row, column=2 + i, padx=(6, 0), pady=3)
        parent.columnconfigure(1, weight=1)
        return e

    def _khung(self, tab, height=14):
        """Chia tab thanh 2 khung (tren: nhap lieu, duoi: nhat ky) co thanh keo de doi kich thuoc.
        Nut 'An khung nhap' cho nhat ky chiem toan bo tab - tien de chup hinh."""
        pw = ttk.PanedWindow(tab, orient="vertical")
        pw.pack(fill="both", expand=True)
        top, bot = ttk.Frame(pw), ttk.Frame(pw)
        pw.add(top, weight=0)
        pw.add(bot, weight=1)
        thanh = ttk.Frame(bot)
        thanh.pack(fill="x", padx=10, pady=(4, 0))
        nut = ttk.Button(thanh)
        nut.pack(side="left")
        log = Nhat_ky(bot, height=height)
        log.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        trang_thai = {"an": False}

        def doi():
            if trang_thai["an"]:
                pw.insert(0, top, weight=0)
                nut.config(text="Ẩn khung nhập (để chụp nhật ký)")
            else:
                pw.forget(top)
                nut.config(text="Hiện lại khung nhập")
            trang_thai["an"] = not trang_thai["an"]
        nut.config(text="Ẩn khung nhập (để chụp nhật ký)", command=doi)
        return top, log

    def _chep(self, var):
        self.clipboard_clear()
        self.clipboard_append(hex_sach(var.get()))
