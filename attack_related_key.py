"""
attack_related_key.py - Kich ban 3 (muc 3.3.3): tan cong khoa lien quan (related-key).
  Phan A: khoa cong khai bi dich them aG; chu ky cu bien doi thanh chu ky hop le cho khoa moi
          khi thach thuc KHONG chua khoa cong khai, e = H(x_R||m) (bat bang key_prefix=False).
          Phong thu: key-prefixing e = H(x_R||x_Y||m), chinh la BIP-340 (key_prefix=True).
  Phan B: phat sinh khoa phan cap kieu BIP-32 (rut gon): lo 1 khoa con -> lo khoa cha.
          Phong thu: phat sinh cung hoa (hardened).
Cach dung:
  python attack_related_key.py              chay 1 lan, in tung buoc
  python attack_related_key.py --thong-ke   lap 200 lan
"""
import hashlib
import hmac
import secrets
import sys

import schnorr_lib as lib
from utils import tieu_de, buoc, thanh_cong, that_bai

MSG = b"Chuyen 100 USD cho Bob"


# ---------- Phan A: bien doi chu ky khi khoa dich them aG ----------
def tan_cong_A(co_tien_to):
    """Co chu ky (x_R, s) cho Y tren thong diep MSG. Ke tan cong chon a, tao Y' = Y - aG va s' = s - a*e.
    co_tien_to=False: thach thuc khong chua khoa cong khai,  e = H(x_R || m)
    co_tien_to=True : dang BIP-340 (key-prefixing),           e = H(x_R || x_Y || m)
    Tra ve True neu (x_R, s') duoc chap nhan voi Y' (tren cung thong diep)."""
    sk = secrets.token_bytes(32)
    pk = lib.pubkey_gen(sk)
    Y = lib.lift_x(pk)                                       # khoa cong khai that (tung do chan)
    sig = lib.schnorr_sign(MSG, sk, secrets.token_bytes(32), key_prefix=co_tien_to)
    x_R, s = sig[:32], lib.bytes_to_int(sig[32:])
    e = lib.challenge(x_R, pk, MSG, key_prefix=co_tien_to)   # ke tan cong tinh duoc e tu du lieu cong khai
    while True:                                              # chon a sao cho Y' co tung do chan (de x-only khong doi dau)
        a = secrets.randbelow(lib.q - 1) + 1
        Y2 = lib.point_add(Y, lib.point_neg(lib.point_mul(lib.G, a)))        # Y' = Y - aG
        if lib.has_even_y(Y2):
            break
    s2 = (s - a * e) % lib.q
    return lib.schnorr_verify(MSG, lib.x_only(Y2), x_R + lib.int_to_bytes(s2), key_prefix=co_tien_to)


# ---------- Phan B: phat sinh khoa phan cap ----------
def ser33(P):
    return (b"\x02" if P[1] % 2 == 0 else b"\x03") + lib.int_to_bytes(P[0])


def offset_cong_khai(x_par, chain, i):          # I_L chi phu thuoc KHOA CONG KHAI cha
    P = lib.point_mul(lib.G, x_par)
    return lib.bytes_to_int(hmac.new(chain, ser33(P) + i.to_bytes(4, "big"), hashlib.sha512).digest()[:32])


def offset_cung_hoa(x_par, chain, i):           # I_L phu thuoc KHOA BI MAT cha
    return lib.bytes_to_int(hmac.new(chain, b"\x00" + lib.int_to_bytes(x_par) + i.to_bytes(4, "big"),
                                     hashlib.sha512).digest()[:32])


def tan_cong_B():
    """Tra ve (khoi phuc duoc khoa cha, tinh dung khoa con 2, chu ky gia duoc chap nhan, tan cong len khoa cung hoa)."""
    x_par = secrets.randbelow(lib.q - 1) + 1
    chain = secrets.token_bytes(32)
    con = [(x_par + offset_cong_khai(x_par, chain, i)) % lib.q for i in range(3)]
    I_L = offset_cong_khai(x_par, chain, 1)      # ke tan cong tinh lai tu du lieu CONG KHAI
    x_tim = (con[1] - I_L) % lib.q               # khoa con 1 bi lo
    con2 = (x_tim + offset_cong_khai(x_tim, chain, 2)) % lib.q
    sig = lib.schnorr_sign(b"gia mao", lib.int_to_bytes(con2), secrets.token_bytes(32))
    gia_ok = lib.schnorr_verify(b"gia mao", lib.x_only(lib.point_mul(lib.G, con[2])), sig)
    con_h = (x_par + offset_cung_hoa(x_par, chain, 1)) % lib.q
    return x_tim == x_par, con2 == con[2], gia_ok, (con_h - I_L) % lib.q == x_par


def demo():
    tieu_de("KICH BAN 3: TAN CONG KHOA LIEN QUAN")
    print("\n##### PHAN A: DICH KHOA CONG KHAI Y' = Y - aG, BIEN DOI CHU KY s' = s - a*e #####")
    sk = secrets.token_bytes(32)
    pk = lib.pubkey_gen(sk)
    Y = lib.lift_x(pk)
    buoc(1, "Nan nhan ky bang thach thuc KHONG chua khoa cong khai:  e = H(x_R || m)")
    sig = lib.schnorr_sign(MSG, sk, secrets.token_bytes(32), key_prefix=False)
    x_R, s = sig[:32], lib.bytes_to_int(sig[32:])
    e = lib.challenge(x_R, pk, MSG, key_prefix=False)
    print("  chu ky (x_R, s) cho Y:  x_R =", x_R.hex()); print("                          s   =", format(s, "064x"))
    print("  Xac minh voi Y:", lib.schnorr_verify(MSG, pk, sig, key_prefix=False))
    buoc(2, "Ke tan cong chon a bat ky; khong can biet x. Tinh Y' = Y - aG va s' = s - a*e")
    while True:
        a = secrets.randbelow(lib.q - 1) + 1
        Y2 = lib.point_add(Y, lib.point_neg(lib.point_mul(lib.G, a)))
        if lib.has_even_y(Y2):
            break
    s2 = (s - a * e) % lib.q
    print("  s' =", format(s2, "064x"))
    print("  Kiem tra: s'G - eY' = (s - ae)G - e(Y - aG) = sG - eY = R  (cung R, cung e)")
    ok = lib.schnorr_verify(MSG, lib.x_only(Y2), x_R + lib.int_to_bytes(s2), key_prefix=False)
    (that_bai if ok else thanh_cong)("  Chu ky (x_R, s') duoc chap nhan boi khoa Y' tren cung thong diep:", ok)
    buoc(3, "PHONG THU: key-prefixing (BIP-340)  e = H(x_R || x_Y || m)  -> doi Y thanh Y' lam e doi theo")
    ok2 = tan_cong_A(co_tien_to=True)
    (thanh_cong if not ok2 else that_bai)("  Cung phep bien doi tren BIP-340 duoc chap nhan:", ok2, "(phai la False)")

    print("\n##### PHAN B: PHAT SINH KHOA PHAN CAP KIEU BIP-32 (RUT GON) #####")
    buoc(4, "Phat sinh khoa con KHONG cung hoa:  x_con = x_cha + I_L, I_L tinh tu KHOA CONG KHAI cha")
    buoc(5, "Su co: lo khoa con so 1. Ke tan cong tinh lai I_L tu du lieu cong khai -> x_cha = x_con1 - I_L")
    cha, con2, gia, cung = tan_cong_B()
    (that_bai if cha else thanh_cong)("  Khoi phuc duoc khoa cha:", cha)
    print("  Tinh dung khoa con so 2 (chua tung bi lo):", con2)
    print("  Chu ky gia bang khoa con vua tinh duoc khoa cong khai that chap nhan:", gia)
    buoc(6, "PHONG THU: phat sinh CUNG HOA - dua KHOA BI MAT cha vao HMAC")
    (thanh_cong if not cung else that_bai)("  Cung cach tan cong khoi phuc duoc khoa cha:", cung, "(phai la False)")
    print("  Phep thu nay chi chung to cach tan cong cu the that bai; an toan cua cung hoa dua tren gia dinh ve HMAC-SHA512.")


def thong_ke(so_lan=200):
    tieu_de(f"THONG KE KICH BAN 3 ({so_lan} lan)")
    print("  Phan A (dich khoa Y' = Y - aG, s' = s - a*e):")
    print(f"     khong key-prefixing e = H(x_R||m)    : tan cong thanh cong {sum(tan_cong_A(False) for _ in range(so_lan))}/{so_lan}")
    print(f"     co key-prefixing (BIP-340)           : tan cong thanh cong {sum(tan_cong_A(True) for _ in range(so_lan))}/{so_lan}")
    kq = [tan_cong_B() for _ in range(so_lan)]
    print("  Phan B (phat sinh khoa phan cap):")
    print(f"     khong cung hoa: khoi phuc khoa cha {sum(r[0] for r in kq)}/{so_lan}; tinh dung khoa con khac {sum(r[1] for r in kq)}/{so_lan};"
          f" chu ky gia duoc chap nhan {sum(r[2] for r in kq)}/{so_lan}")
    print(f"     cung hoa (phong thu): tan cong thanh cong {sum(r[3] for r in kq)}/{so_lan}")


if __name__ == "__main__":
    thong_ke() if "--thong-ke" in sys.argv else demo()
