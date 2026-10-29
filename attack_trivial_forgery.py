"""
attack_trivial_forgery.py - Kich ban 2 (muc 3.3.2): tan cong gia mao tam thuong (Trivial Forgery, Chuong 2 muc 2.2.3).

Y tuong cua Chuong 2 (tan cong "khong can thong diep"):
   1. Ke tan cong chon tuy y s va e*, roi tinh nguoc  R* = s*G - e* * Y   (khong can khoa bi mat x).
   2. Tim thong diep m* sao cho  H(R* || Y || m*) = e*.   Neu tim duoc thi (e*, s) la chu ky hop le cua m*.
Buoc 2 chi kha thi khi ham bam yeu hoac khong gian thach thuc e nho (Bang 2.1: "khong gian thach thuc nho hoac ham bam yeu").

Cach dung:
  python attack_trivial_forgery.py              chay 1 lan, in tung buoc
  python attack_trivial_forgery.py --thong-ke   lap 200 lan (a, c) va 20 lan (b)
"""
import secrets
import sys

import schnorr_lib as lib
from utils import tieu_de, buoc, thanh_cong, that_bai

NGAN_SACH = 2 ** 14          # so thong diep ke tan cong thu o phan (a)
TOY = 2 ** 12                # khong gian thach thuc thu nho o phan (b)


def khoa():
    """Cap khoa (x, Y = xG) - ke tan cong chi dung Y."""
    x = secrets.randbelow(lib.q - 1) + 1
    return x, lib.point_mul(lib.G, x)


def H_day_du(R, Y, m):
    """Thach thuc cua BIP-340: e = H(x_R || x_Y || m), khong gian ~2^256."""
    return lib.challenge(lib.x_only(R), lib.x_only(Y), m)


def diem_cuoi(s, e, Y):
    """R' = s*G - e*Y."""
    return lib.point_add(lib.point_mul(lib.G, s), lib.point_mul(lib.point_neg(Y), e))


# ---------- (b) luoc do voi khong gian thach thuc thu nho ----------
def H_toy(R, Y, m):
    return H_day_du(R, Y, m) % TOY


def verify_toy(m, sig, Y):
    e, s = sig
    Rp = diem_cuoi(s, e, Y)
    return Rp is not None and 0 <= e < TOY and H_toy(Rp, Y, m) == e


# ---------- (c) ham bam yeu: bo qua R ----------
def H_yeu(m):
    return lib.bytes_to_int(lib.tagged_hash("Weak/challenge", m)) % lib.q


def verify_yeu(m, sig, Y):
    e, s = sig
    Rp = diem_cuoi(s, e, Y)
    return Rp is not None and H_yeu(m) == e


def tim_thong_diep(H, R_star, Y, e_star, gioi_han):
    """Buoc 2 cua tan cong: tim m* voi H(R*||Y||m*) = e*. Tra ve so lan thu hoac None."""
    for t in range(1, gioi_han + 1):
        if H(R_star, Y, t.to_bytes(8, "big")) == e_star:
            return t
    return None


def tan_cong_dung():
    """(a) Luoc do day du (e 256 bit): chuan bi buoc 1, thu NGAN_SACH thong diep o buoc 2."""
    x, Y = khoa()
    s = secrets.randbelow(lib.q - 1) + 1
    e_star = secrets.randbelow(lib.q - 1) + 1
    R_star = diem_cuoi(s, e_star, Y)
    t = tim_thong_diep(H_day_du, R_star, Y, e_star, NGAN_SACH)
    return t is not None


def tan_cong_toy():
    """(b) Khong gian thach thuc 2^12. Tra ve (so lan thu, chu ky gia qua xac minh DAY DU)."""
    x, Y = khoa()
    s = secrets.randbelow(lib.q - 1) + 1
    e_star = secrets.randbelow(TOY - 1) + 1
    R_star = diem_cuoi(s, e_star, Y)
    t = tim_thong_diep(H_toy, R_star, Y, e_star, 100 * TOY)
    return t, verify_toy(t.to_bytes(8, "big"), (e_star, s), Y)


def tan_cong_yeu():
    """(c) e = H(m): khong can tim gi, chon m roi dat e* = H(m)."""
    x, Y = khoa()
    m = b"Chuyen toan bo tai san cho Eve"
    return verify_yeu(m, (H_yeu(m), secrets.randbelow(lib.q - 1) + 1), Y)


def demo():
    tieu_de("KICH BAN 2: GIA MAO TAM THUONG (khong can thong diep)")
    print("  Ke tan cong chi biet khoa cong khai Y, KHONG biet x.")
    buoc(1, "Chon s va e* tuy y, tinh R* = s*G - e* * Y  (khong can x)")
    buoc(2, f"(a) Luoc do day du (e 256 bit): thu {NGAN_SACH} thong diep de tim m* voi H(R*||Y||m*) = e*")
    ok = tan_cong_dung()
    (that_bai if ok else thanh_cong)("  Tim duoc m*:", ok, "(phai la False: can ~2^256 lan thu)")
    buoc(3, f"(b) Khong gian thach thuc thu nho {TOY} gia tri: cung tan cong")
    t, hop_le = tan_cong_toy()
    print(f"  Tim duoc m* sau {t} lan thu (ky vong ~{TOY})")
    (that_bai if hop_le else thanh_cong)("  Chu ky gia (e*, s) qua xac minh DAY DU cua luoc do thu nho:", hop_le)
    print("  => khong gian thach thuc nho lam tan cong kha thi. Voi q ~ 2^256 thi bat kha thi.")
    buoc(4, "(c) Ham bam yeu e = H(m) (bo qua R): chon m, dat e* = H(m), s tuy y")
    ok = tan_cong_yeu()
    (that_bai if ok else thanh_cong)("  Gia mao duoc chap nhan ma khong can khoa bi mat:", ok)
    print("  PHONG THU: ham bam chuan (SHA-256), khong gian thach thuc ~2^256, dua R (va Y) vao dau vao ham bam.")


def thong_ke(so_lan=200):
    tieu_de(f"THONG KE KICH BAN 2 ({so_lan} lan)")
    a = sum(tan_cong_dung() for _ in range(so_lan))
    print(f"  (a) Luoc do day du, thu {NGAN_SACH} thong diep moi lan: tim duoc m* {a}/{so_lan}")
    kq = [tan_cong_toy() for _ in range(20)]
    print(f"  (b) Khong gian 2^12 (20 lan): tim duoc m* {len(kq)}/20, chu ky gia qua xac minh day du {sum(h for _, h in kq)}/20,"
          f" trung binh {sum(t for t, _ in kq)/len(kq):.0f} thong diep (ky vong ~{TOY})")
    c = sum(tan_cong_yeu() for _ in range(so_lan))
    print(f"  (c) Ham bam yeu e = H(m): gia mao thanh cong {c}/{so_lan}")


if __name__ == "__main__":
    thong_ke() if "--thong-ke" in sys.argv else demo()
