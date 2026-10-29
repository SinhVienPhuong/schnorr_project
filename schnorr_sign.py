"""
schnorr_sign.py - Ky mot thong diep bang khoa bi mat cua nguoi dung (doc tu keys.json)

Cach dung:   python schnorr_sign.py <ten_nguoi_dung> "<thong diep>"
Ket qua in ra tung buoc va luu chu ky vao signatures.json.
"""
import secrets
import sys

import schnorr_lib as lib
from utils import (KEYS_FILE, SIGS_FILE, doc_json, ghi_json, in_trace, tieu_de, buoc, thanh_cong,
                   that_bai)


def main():
    if len(sys.argv) < 3:
        that_bai('Cach dung: python schnorr_sign.py <user> "<thong diep>"')
        sys.exit(1)
    ten, thong_diep = sys.argv[1], sys.argv[2]
    keys = doc_json(KEYS_FILE, {"users": []})["users"]
    u = next((x for x in keys if x["name"] == ten), None)
    if u is None:
        that_bai(f"Khong thay '{ten}' trong {KEYS_FILE}. Hay chay create_keypair.py truoc.")
        sys.exit(1)

    tieu_de(f"KY THONG DIEP CUA {ten}")
    msg = thong_diep.encode("utf-8")
    print("  thong diep m =", thong_diep)
    print("  khoa cong khai =", u["public_key"])
    buoc(1, "Cac gia tri trung gian khi ky (BIP-340)")
    sig = lib.schnorr_sign(msg, bytes.fromhex(u["private_key"]), secrets.token_bytes(32), trace=in_trace)
    buoc(2, "Chu ky = R.x (32 byte) || s (32 byte) = 64 byte")
    print("  chu ky =", sig.hex())
    sigs = doc_json(SIGS_FILE, {"signatures": []})
    sigs["signatures"].append({"user": ten, "message": thong_diep, "signature": sig.hex()})
    ghi_json(SIGS_FILE, sigs)
    thanh_cong(f"Da luu vao {SIGS_FILE}. Tiep theo: python schnorr_verify.py")


if __name__ == "__main__":
    main()
