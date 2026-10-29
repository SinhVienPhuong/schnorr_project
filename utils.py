"""utils.py - Tien ich dung chung: in mau, doc/ghi file JSON luu khoa va chu ky."""
import json
import os

import sys
if sys.platform == "win32":
    os.system("")          # bat ma mau ANSI tren cmd Windows

KEYS_FILE = "keys.json"
SIGS_FILE = "signatures.json"


class mau:
    XANH = "\033[92m"
    DO = "\033[91m"
    VANG = "\033[93m"
    DAM = "\033[1m"
    HET = "\033[0m"


def thanh_cong(*a):
    print(mau.XANH + " ".join(str(x) for x in a) + mau.HET)


def that_bai(*a):
    print(mau.DO + " ".join(str(x) for x in a) + mau.HET)


def tieu_de(s):
    print("\n" + mau.DAM + "=" * 70 + "\n" + s + "\n" + "=" * 70 + mau.HET)


def buoc(n, s):
    print(f"\n{mau.VANG}--- Buoc {n}: {s}{mau.HET}")


def doc_json(ten, mac_dinh):
    if not os.path.exists(ten):
        return mac_dinh
    with open(ten, encoding="utf-8") as f:
        return json.load(f)


def ghi_json(ten, du_lieu):
    with open(ten, "w", encoding="utf-8") as f:
        json.dump(du_lieu, f, indent=2, ensure_ascii=False)


def in_trace(ten, gia_tri):
    """Ham 'trace' truyen vao thu vien de in tung buoc trung gian."""
    if isinstance(gia_tri, bytes):
        gia_tri = gia_tri.hex()
    elif isinstance(gia_tri, int):
        gia_tri = format(gia_tri, "064x")
    print(f"  {ten:<28} = {gia_tri}")
