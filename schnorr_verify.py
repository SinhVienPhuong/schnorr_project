"""
schnorr_verify.py - Xac minh chu ky

Cach dung:
  python schnorr_verify.py                       xac minh tat ca chu ky trong signatures.json
  python schnorr_verify.py <user> "<tn>" <sig>   xac minh mot chu ky cu the (sig dang hex)
Chi dung KHOA CONG KHAI; khong can khoa bi mat.
"""
import sys

import schnorr_lib as lib
from utils import KEYS_FILE, SIGS_FILE, doc_json, in_trace, tieu_de, buoc, thanh_cong, that_bai


def kiem_tra(pk_hex, thong_diep, sig_hex, chi_tiet=True):
    msg = thong_diep.encode("utf-8")
    trace = in_trace if chi_tiet else (lambda *a: None)
    return lib.schnorr_verify(msg, bytes.fromhex(pk_hex), bytes.fromhex(sig_hex), trace=trace)


def main():
    keys = {u["name"]: u["public_key"] for u in doc_json(KEYS_FILE, {"users": []})["users"]}
    if len(sys.argv) >= 4:
        muc = [{"user": sys.argv[1], "message": sys.argv[2], "signature": sys.argv[3]}]
    else:
        muc = doc_json(SIGS_FILE, {"signatures": []})["signatures"]
    if not muc:
        that_bai("Chua co chu ky nao. Hay chay schnorr_sign.py truoc.")
        sys.exit(1)

    tieu_de("XAC MINH CHU KY")
    for i, m in enumerate(muc, 1):
        buoc(i, f"Chu ky cua {m['user']} tren \"{m['message']}\"")
        ok = kiem_tra(keys[m["user"]], m["message"], m["signature"])
        (thanh_cong if ok else that_bai)("  KET QUA:", "HOP LE" if ok else "KHONG HOP LE")
        # Phep thu sai de thay xac minh co tac dung
        sai = kiem_tra(keys[m["user"]], m["message"] + "!", m["signature"], chi_tiet=False)
        print(f"  (thu sua thong diep them dau '!'  -> {'van hop le (LOI!)' if sai else 'bi tu choi dung'})")
        khac = [k for k in keys if k != m["user"]]
        if khac:
            sai2 = kiem_tra(keys[khac[0]], m["message"], m["signature"], chi_tiet=False)
            print(f"  (thu dung khoa cong khai cua {khac[0]} -> {'van hop le (LOI!)' if sai2 else 'bi tu choi dung'})")


if __name__ == "__main__":
    main()
