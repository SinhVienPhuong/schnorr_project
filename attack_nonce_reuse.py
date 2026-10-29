"""
attack_nonce_reuse.py - Kich ban 1 (muc 3.3.1): tai su dung nonce lam lo khoa bi mat.
Cach dung:
  python attack_nonce_reuse.py              chay 1 lan, in tung buoc
  python attack_nonce_reuse.py --thong-ke   lap 200 lan, in so lieu thong ke
"""
import secrets
import sys

import schnorr_lib as lib
from utils import tieu_de, buoc, thanh_cong, that_bai

M1, M2 = b"Chuyen 100 USD cho Bob", b"Chuyen 200 USD cho Eve"


def chuan_hoa(x0):
    """Khoa bi mat da chuan hoa (Y co tung do chan) - gia tri ma BIP-340 thuc su dung de ky."""
    return x0 if lib.has_even_y(lib.point_mul(lib.G, x0)) else lib.q - x0


def tan_cong():
    """Nan nhan ky M1, M2 voi CUNG nonce k. Tra ve (x that da chuan hoa, x tim duoc, pk, (e1,s1), (e2,s2))."""
    x0 = secrets.randbelow(lib.q - 1) + 1
    k = secrets.randbelow(lib.q - 1) + 1                        # nonce bi dung lai
    pk = lib.x_only(lib.point_mul(lib.G, x0))
    sg1 = lib.schnorr_sign_with_nonce(M1, x0, k)
    sg2 = lib.schnorr_sign_with_nonce(M2, x0, k)
    e1, e2 = lib.challenge(sg1[:32], pk, M1), lib.challenge(sg2[:32], pk, M2)
    s1, s2 = lib.bytes_to_int(sg1[32:]), lib.bytes_to_int(sg2[32:])
    x_tim = (s1 - s2) * pow(e1 - e2, -1, lib.q) % lib.q         # x = (s1-s2)/(e1-e2)
    return chuan_hoa(x0), x_tim, pk, (e1, s1), (e2, s2)


def phong_thu():
    """Nonce dan xuat tu khoa+thong diep: 2 thong diep khac nhau -> 2 R khac nhau -> cong thuc tan cong cho ket qua sai."""
    sk, aux = secrets.token_bytes(32), secrets.token_bytes(32)
    pk = lib.pubkey_gen(sk)
    sg1, sg2 = lib.schnorr_sign(M1, sk, aux), lib.schnorr_sign(M2, sk, aux)
    e1, e2 = lib.challenge(sg1[:32], pk, M1), lib.challenge(sg2[:32], pk, M2)
    s1, s2 = lib.bytes_to_int(sg1[32:]), lib.bytes_to_int(sg2[32:])
    x_tim = (s1 - s2) * pow(e1 - e2, -1, lib.q) % lib.q
    return sg1[:32] != sg2[:32], x_tim != chuan_hoa(lib.bytes_to_int(sk)), sg1, sg2


def demo():
    tieu_de("KICH BAN 1: TAN CONG TAI SU DUNG NONCE")
    buoc(1, "Nan nhan ky 2 thong diep khac nhau nhung DUNG CHUNG nonce k")
    x, x_tim, pk, (e1, s1), (e2, s2) = tan_cong()
    print("  Khoa bi mat that (ke tan cong KHONG biet) x =", format(x, "064x"))
    print("  chu ky 1: e1 =", format(e1, "064x")); print("            s1 =", format(s1, "064x"))
    print("  chu ky 2: e2 =", format(e2, "064x")); print("            s2 =", format(s2, "064x"))
    buoc(2, "Ke tan cong: s1 = k + x*e1, s2 = k + x*e2  ->  s1 - s2 = x*(e1 - e2)  ->  x = (s1-s2)/(e1-e2)")
    print("  x tim duoc =", format(x_tim, "064x"))
    (thanh_cong if x_tim == x else that_bai)("  Trung khoa bi mat that:", x_tim == x)
    buoc(3, "Dung khoa vua tim de ky gia mot thong diep moi")
    gia = lib.schnorr_sign(b"Chuyen toan bo tai san cho Eve", lib.int_to_bytes(x_tim), secrets.token_bytes(32))
    print("  Chu ky gia duoc chap nhan boi khoa cong khai that:",
          lib.schnorr_verify(b"Chuyen toan bo tai san cho Eve", pk, gia))
    buoc(4, "PHONG THU: BIP-340 dan xuat nonce k tu (khoa, aux_rand, THONG DIEP) bang ham bam")
    khac, sai, sg1, sg2 = phong_thu()
    print("  x_R1 =", sg1[:32].hex()); print("  x_R2 =", sg2[:32].hex())
    thanh_cong("  Hai nonce khac nhau:", khac)
    thanh_cong("  Cong thuc tan cong cho ket qua SAI (khong lo khoa):", sai)


def thong_ke(so_lan=200):
    tieu_de(f"THONG KE KICH BAN 1 ({so_lan} lan)")
    kq = [tan_cong() for _ in range(so_lan)]
    a = sum(x == xt for x, xt, *_ in kq)
    b = sum(lib.schnorr_verify(b"gia mao", pk,
                               lib.schnorr_sign(b"gia mao", lib.int_to_bytes(xt), secrets.token_bytes(32)))
            for _, xt, pk, *_ in kq)
    print(f"  (a) Khong phong thu: khoi phuc dung x = (s1-s2)/(e1-e2): {a}/{so_lan};  chu ky gia duoc chap nhan: {b}/{so_lan}")
    r_khac = ct_sai = 0
    for _ in range(so_lan):
        khac, sai, *_ = phong_thu()
        r_khac += khac; ct_sai += sai
    print(f"  (b) Co phong thu (nonce dan xuat tu khoa + thong diep): x_R khac nhau {r_khac}/{so_lan}; cong thuc tan cong cho ket qua sai {ct_sai}/{so_lan}")


if __name__ == "__main__":
    thong_ke() if "--thong-ke" in sys.argv else demo()
