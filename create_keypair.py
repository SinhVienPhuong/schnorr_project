"""
create_keypair.py - Tao cap khoa cho n nguoi dung va luu vao keys.json

Cach dung:   python create_keypair.py [so_nguoi]        (mac dinh 2)
Moi nguoi: khoa bi mat 32 byte ngau nhien (hex), khoa cong khai x-only 32 byte (hex).
LUU Y: keys.json chua khoa bi mat dang ro - chi dung cho thuc hanh, KHONG dung that.
"""
import sys
import secrets

import schnorr_lib as lib
from utils import KEYS_FILE, ghi_json, tieu_de, buoc, thanh_cong


def tao_khoa(so_nguoi):
    ds = []
    for i in range(1, so_nguoi + 1):
        while True:
            sk = secrets.token_bytes(32)
            if 1 <= lib.bytes_to_int(sk) <= lib.q - 1:      # khoa phai nam trong [1, n-1]
                break
        ds.append({"name": f"user{i}", "private_key": sk.hex(),
                   "public_key": lib.pubkey_gen(sk).hex()})
    return ds


def main():
    so_nguoi = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    tieu_de(f"TAO {so_nguoi} CAP KHOA  (Y = x*G tren secp256k1)")
    buoc(1, "Sinh khoa bi mat ngau nhien x trong [1, n-1] va tinh khoa cong khai")
    ds = tao_khoa(so_nguoi)
    for u in ds:
        print(f"  {u['name']}:")
        print(f"     khoa bi mat  = {u['private_key']}")
        print(f"     khoa cong khai (x-only) = {u['public_key']}")
    buoc(2, f"Luu vao {KEYS_FILE}")
    ghi_json(KEYS_FILE, {"users": ds})
    thanh_cong(f"Da tao {so_nguoi} cap khoa. Tiep theo: python schnorr_sign.py user1 \"noi dung\"")


if __name__ == "__main__":
    main()
