"""
schnorr_test.py - Kiem thu (muc 3.2.4):
  A. 19 test vector chinh thuc cua BIP-340 (test-vectors.csv)
  B. Phep thu ngau nhien (200 lan)
  C. Do hieu nang
  D. Xac minh hang loat (batch verification)
  E. So sanh Schnorr voi ECDSA (Chuong 1, muc 1.3)
Cach dung:  python schnorr_test.py
"""
import csv
import secrets
import statistics
import time

import schnorr_lib as lib
from utils import tieu_de, thanh_cong, that_bai

SO_LAN = 200


def A_test_vector():
    tieu_de("A. 19 TEST VECTOR CHINH THUC CUA BIP-340")
    rows = list(csv.DictReader(open("test-vectors.csv", encoding="utf-8")))
    dat = 0
    for r in rows:
        pk, msg, sig = (bytes.fromhex(r[c]) for c in ("public key", "message", "signature"))
        mong_doi = r["verification result"].strip().upper() == "TRUE"
        ok = True
        if r["secret key"]:
            sk, aux = bytes.fromhex(r["secret key"]), bytes.fromhex(r["aux_rand"])
            ok &= lib.pubkey_gen(sk) == pk and lib.schnorr_sign(msg, sk, aux) == sig
        try:
            kq = lib.schnorr_verify(msg, pk, sig)
        except Exception:
            kq = False
        ok &= kq == mong_doi
        dat += ok
        (thanh_cong if ok else that_bai)(f"  vector {int(r['index']):>2}: {'DAT' if ok else 'LOI'}"
                                         f"  (mong doi {mong_doi})  {(r.get('comment') or '')[:50]}")
    (thanh_cong if dat == len(rows) else that_bai)(f"=> {dat}/{len(rows)} vector dat")


def B_ngau_nhien():
    tieu_de(f"B. PHEP THU NGAU NHIEN ({SO_LAN} lan moi phep)")
    b1 = b2 = b3 = b4 = b6 = 0
    for _ in range(SO_LAN):
        sk, aux = secrets.token_bytes(32), secrets.token_bytes(32)
        pk, m = lib.pubkey_gen(sk), secrets.token_bytes(32)
        sig = lib.schnorr_sign(m, sk, aux)
        b1 += lib.schnorr_verify(m, pk, sig)
        m2 = bytes([m[0] ^ 1]) + m[1:]
        b2 += not lib.schnorr_verify(m2, pk, sig)
        bad = bytearray(sig); bad[40] ^= 1
        b3 += not lib.schnorr_verify(m, pk, bytes(bad))
        b4 += not lib.schnorr_verify(m, lib.pubkey_gen(secrets.token_bytes(32)), sig)
        sig6 = lib.schnorr_sign(m, sk, aux, key_prefix=False)      # bien the khong key-prefixing (chi dung o muc 3.3.3)
        b6 += lib.schnorr_verify(m, pk, sig6, key_prefix=False)
    print(f"  B1 chu ky hop le duoc chap nhan          : {b1}/{SO_LAN}")
    print(f"  B2 sua 1 bit thong diep -> bi tu choi    : {b2}/{SO_LAN}")
    print(f"  B3 sua 1 bit chu ky -> bi tu choi        : {b3}/{SO_LAN}")
    print(f"  B4 sai khoa cong khai -> bi tu choi      : {b4}/{SO_LAN}")
    print(f"  B6 bien the khong key-prefixing van dung    : {b6}/{SO_LAN}   (chi de lam doi chung o muc 3.3.3)")
    sk, m, aux = secrets.token_bytes(32), secrets.token_bytes(32), bytes(32)
    print(f"  B5 cung (sk, m, aux) -> cung chu ky      : {lib.schnorr_sign(m, sk, aux) == lib.schnorr_sign(m, sk, aux)}")


def C_hieu_nang():
    tieu_de(f"C. HIEU NANG ({SO_LAN} lan)")
    kg, sg, vf = [], [], []
    for _ in range(SO_LAN):
        sk, m, aux = secrets.token_bytes(32), secrets.token_bytes(32), secrets.token_bytes(32)
        t0 = time.perf_counter(); pk = lib.pubkey_gen(sk)
        t1 = time.perf_counter(); sig = lib.schnorr_sign(m, sk, aux)
        t2 = time.perf_counter(); lib.schnorr_verify(m, pk, sig)
        t3 = time.perf_counter()
        kg.append(t1 - t0); sg.append(t2 - t1); vf.append(t3 - t2)
    f = lambda a: f"{statistics.mean(a)*1000:.3f} ms (min {min(a)*1000:.3f} / max {max(a)*1000:.3f})"
    print(f"  KeyGen : {f(kg)}")
    print(f"  Sign   : {f(sg)}   (da gom 1 lan verify noi bo)")
    print(f"  Verify : {f(vf)}")
    print("  Kich thuoc: khoa cong khai 32 byte, chu ky 64 byte")


def D_batch():
    tieu_de("D. XAC MINH HANG LOAT (batch verification)")
    def tao(k):
        out = []
        for _ in range(k):
            sk, m = secrets.token_bytes(32), secrets.token_bytes(16)
            out.append((m, lib.pubkey_gen(sk), lib.schnorr_sign(m, sk, secrets.token_bytes(32))))
        return out
    ok = rej = 0
    for _ in range(50):
        lo = tao(8)
        ok += lib.schnorr_batch_verify(lo)
        m, pk, sg = lo[3]
        lo[3] = (m + b"x", pk, sg)                      # 1 chu ky trong lo bi sua thong diep
        rej += not lib.schnorr_batch_verify(lo)
    print(f"  Lo 8 chu ky hop le duoc chap nhan          : {ok}/50")
    print(f"  Lo co 1 chu ky sai bi tu choi              : {rej}/50")


def _der_len(r, s):
    f = lambda v: len(v.to_bytes((v.bit_length() + 7) // 8, "big")) + (1 if v.bit_length() % 8 == 0 else 0)
    return 6 + f(r) + f(s)


def E_so_sanh_ecdsa():
    tieu_de(f"E. SO SANH SCHNORR VOI ECDSA tren cung duong cong, cung ma Python ({SO_LAN} lan)")
    ss, sv, es, ev, der, ss0 = [], [], [], [], [], []
    for _ in range(SO_LAN):
        m = secrets.token_bytes(32)
        sk, aux = secrets.token_bytes(32), secrets.token_bytes(32)
        pk = lib.pubkey_gen(sk)
        Y = lib.point_mul(lib.G, lib.bytes_to_int(sk))             # Y = xG tinh san luc sinh khoa (nhu ECDSA co san khoa)
        xe, Ye = lib.ecdsa_keygen()
        ta = time.perf_counter(); lib.schnorr_sign(m, sk, aux, tu_kiem_tra=False)      # dung dac ta: tinh lai Y
        ss0.append(time.perf_counter() - ta)
        t0 = time.perf_counter(); sg = lib.schnorr_sign(m, sk, aux, tu_kiem_tra=False, Y_san=Y)
        t1 = time.perf_counter(); lib.schnorr_verify(m, pk, sg)
        t2 = time.perf_counter(); eg = lib.ecdsa_sign(m, xe)
        t3 = time.perf_counter(); lib.ecdsa_verify(m, eg, Ye)
        t4 = time.perf_counter()
        ss.append(t1 - t0); sv.append(t2 - t1); es.append(t3 - t2); ev.append(t4 - t3)
        der.append(_der_len(*eg))
    f = lambda a: statistics.mean(a) * 1000
    print(f"  {'':22}{'Ky (ms)':>10}{'Xac minh (ms)':>16}")
    print(f"  {'Schnorr (x_R,s)':22}{f(ss):>10.3f}{f(sv):>16.3f}")
    print(f"  {'Schnorr, tinh lai Y':22}{f(ss0):>10.3f}   (dung dac ta: them 1 phep nhan diem de tinh Y = xG)")
    print(f"  {'ECDSA (r,s)':22}{f(es):>10.3f}{f(ev):>16.3f}")
    print(f"  Ky: ECDSA / Schnorr = {f(es)/f(ss):.3f};   Xac minh: ECDSA / Schnorr = {f(ev)/f(sv):.3f}")
    print(f"  Kich thuoc chu ky: Schnorr 64 byte; ECDSA 64 byte (r||s) hoac DER trung binh {statistics.mean(der):.1f} byte")
    print("  Luu y: ca hai deu dung cung phep nhan diem; ECDSA them 1-2 phep nghich dao modulo (rat re so voi nhan diem).")


if __name__ == "__main__":
    A_test_vector()
    B_ngau_nhien()
    C_hieu_nang()
    D_batch()
    E_so_sanh_ecdsa()
