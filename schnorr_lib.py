"""
schnorr_lib.py - THU VIEN chu ky so Schnorr tren secp256k1 (EC-Schnorr theo dac ta BIP-340).

Viet tu dac ta BIP-340; khong dung thu vien mat ma ben ngoai.
Ky hieu dung nhu Chuong 1-2:  x (khoa bi mat), Y = xG (khoa cong khai), k (nonce), R = kG,
  e = H(x_R || x_Y || m) (thach thuc, co key-prefixing), s = (k + x*e) mod q.
Chu ky theo dinh dang BIP-340: x_R (32 byte) || s (32 byte) = 64 byte.
(Dac ta BIP-340 viet d, P, R_x, n thay cho x, Y, x_R, q.)

Gom 5 nhom:
  1. Tham so duong cong va so hoc diem        (point_add, point_mul, ...)
  2. Tien ich byte / bam / diem               (tagged_hash, lift_x, ...)
  3. Ba thuat toan:  pubkey_gen / schnorr_sign / schnorr_verify
  4. CHI DUNG CHO THI NGHIEM TAN CONG         (nonce chi dinh, tat key-prefixing)
  5. Xac minh hang loat va ECDSA (de so sanh)
"""
import hashlib
import secrets

# ---------------------------------------------------------------
# 1. Tham so secp256k1 va so hoc diem (toa do Jacobian)
# ---------------------------------------------------------------
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F      # truong F_p
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141      # bac nhom G (ky hieu q nhu trong luan van; dac ta BIP-340 goi la n)
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)     # diem sinh
# Diem o vo cuc bieu dien bang None; diem affine la tuple (x, y)


def _nhan_doi(pt):
    X, Y, Z = pt
    if Y == 0:
        return None
    S = (4 * X * Y * Y) % p
    M = (3 * X * X) % p
    X3 = (M * M - 2 * S) % p
    return (X3, (M * (S - X3) - 8 * pow(Y, 4, p)) % p, (2 * Y * Z) % p)


def _cong(a, b):
    if a is None:
        return b
    if b is None:
        return a
    X1, Y1, Z1 = a
    X2, Y2, Z2 = b
    Z1s, Z2s = Z1 * Z1 % p, Z2 * Z2 % p
    U1, U2 = X1 * Z2s % p, X2 * Z1s % p
    S1, S2 = Y1 * Z2s * Z2 % p, Y2 * Z1s * Z1 % p
    if U1 == U2:
        return None if S1 != S2 else _nhan_doi(a)
    H, R = (U2 - U1) % p, (S2 - S1) % p
    H2 = H * H % p
    H3 = H * H2 % p
    X3 = (R * R - H3 - 2 * U1 * H2) % p
    return (X3, (R * (U1 * H2 - X3) - S1 * H3) % p, H * Z1 * Z2 % p)


def _ve_affine(j):
    if j is None:
        return None
    X, Y, Z = j
    zi = pow(Z, -1, p)
    return (X * zi * zi % p, Y * zi * zi * zi % p)


def point_add(a, b):
    """a + b (hai diem affine hoac None)."""
    ja = None if a is None else (a[0], a[1], 1)
    jb = None if b is None else (b[0], b[1], 1)
    return _ve_affine(_cong(ja, jb))


def point_neg(a):
    return None if a is None else (a[0], (p - a[1]) % p)


def point_mul(pt, k):
    """k*pt bang double-and-add."""
    k %= q
    kq, cong = None, (None if pt is None else (pt[0], pt[1], 1))
    while k:
        if k & 1:
            kq = _cong(kq, cong)
        cong = _nhan_doi(cong) if cong is not None else None
        k >>= 1
    return _ve_affine(kq)


def has_even_y(pt):
    return pt[1] % 2 == 0


# ---------------------------------------------------------------
# 2. Tien ich
# ---------------------------------------------------------------
def int_to_bytes(v):
    return v.to_bytes(32, "big")


def bytes_to_int(b):
    return int.from_bytes(b, "big")


def x_only(pt):
    return int_to_bytes(pt[0])


def tagged_hash(tag, data):
    """SHA256(SHA256(tag) || SHA256(tag) || data)  - bam co gan nhan cua BIP-340."""
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + data).digest()


def lift_x(xb):
    """Hoanh do 32 byte -> diem co tung do chan (None neu khong nam tren duong cong)."""
    xi = bytes_to_int(xb)
    if xi >= p:
        return None
    c = (pow(xi, 3, p) + 7) % p
    y = pow(c, (p + 1) // 4, p)
    if y * y % p != c:
        return None
    return (xi, y if y % 2 == 0 else p - y)


def _khong(ten, gia_tri):
    pass


# ---------------------------------------------------------------
# 3. EC-Schnorr theo BIP-340:  KeyGen / Sign / Verify
# ---------------------------------------------------------------
def pubkey_gen(sk: bytes) -> bytes:
    """Khoa cong khai x_Y (32 byte, x-only) tu khoa bi mat x (32 byte)."""
    x0 = bytes_to_int(sk)
    if not 1 <= x0 <= q - 1:
        raise ValueError("khoa bi mat phai nam trong [1, q-1]")
    return x_only(point_mul(G, x0))


def challenge(x_R: bytes, x_Y: bytes, msg: bytes, key_prefix=True) -> int:
    """e = H(x_R || x_Y || m) mod q (tagged hash 'BIP0340/challenge').
    key_prefix=False (e = H(x_R || m)) CHI de lam thi nghiem khoa lien quan (muc 3.3.3)."""
    data = x_R + (x_Y if key_prefix else b"") + msg
    return bytes_to_int(tagged_hash("BIP0340/challenge", data)) % q


def schnorr_sign(msg: bytes, sk: bytes, aux_rand: bytes, trace=_khong, key_prefix=True,
                 tu_kiem_tra=True, Y_san=None) -> bytes:
    """Ky BIP-340. 'trace(ten, gia_tri)' (tuy chon) duoc goi o tung buoc de in gia tri trung gian.
    Cac tham so key_prefix, tu_kiem_tra, Y_san chi doi khi lam thi nghiem (muc 3.3.3, 3.2.4);
    mac dinh la dung dac ta (dac ta tinh lai Y = xG tu khoa bi mat)."""
    x0 = bytes_to_int(sk)
    if not 1 <= x0 <= q - 1:
        raise ValueError("khoa bi mat phai nam trong [1, q-1]")
    Y = Y_san if Y_san is not None else point_mul(G, x0)       # buoc 1: khoa cong khai Y = xG
    x = x0 if has_even_y(Y) else q - x0                        #   ep tung do Y chan
    trace("x (khoa bi mat da chuan hoa)", x)
    t = bytes(a ^ b for a, b in zip(int_to_bytes(x), tagged_hash("BIP0340/aux", aux_rand)))
    k0 = bytes_to_int(tagged_hash("BIP0340/nonce", t + x_only(Y) + msg)) % q   # buoc 2: nonce tat dinh
    if k0 == 0:
        raise RuntimeError("nonce bang 0")
    R = point_mul(G, k0)                                       # buoc 3: R = kG
    k = k0 if has_even_y(R) else q - k0                        #   ep tung do R chan
    trace("k (nonce)", k)
    trace("x_R", x_only(R))
    e = challenge(x_only(R), x_only(Y), msg, key_prefix)       # buoc 4: thach thuc
    trace("e = H(x_R||x_Y||m)", e)
    s = (k + x * e) % q                                        # buoc 5: phan hoi
    trace("s = k + x*e mod q", s)
    sig = x_only(R) + int_to_bytes(s)
    if tu_kiem_tra and not schnorr_verify(msg, x_only(Y), sig, key_prefix=key_prefix):   # buoc 6: tu kiem tra
        raise RuntimeError("chu ky vua tao khong qua duoc buoc xac minh")
    return sig


def schnorr_verify(msg: bytes, pk: bytes, sig: bytes, trace=_khong, key_prefix=True) -> bool:
    """Xac minh BIP-340: tinh R = sG - eY, kiem tra R khac O, tung do R chan va x_R trung voi chu ky."""
    if len(pk) != 32 or len(sig) != 64:
        return False
    Y = lift_x(pk)
    r, s = bytes_to_int(sig[:32]), bytes_to_int(sig[32:])
    if Y is None or r >= p or s >= q:
        return False
    e = challenge(sig[:32], pk, msg, key_prefix)
    trace("e = H(x_R||x_Y||m)", e)
    R = point_add(point_mul(G, s), point_mul(point_neg(Y), e))
    if R is None:
        return False
    trace("x_R tinh lai", x_only(R))
    return has_even_y(R) and R[0] == r


# ---------------------------------------------------------------
# 4. CHI DUNG CHO THI NGHIEM TAN CONG (khong dung trong he thong that)
# ---------------------------------------------------------------
def schnorr_sign_with_nonce(msg: bytes, sk_int: int, k_int: int) -> bytes:
    """Ky BIP-340 nhung nonce k do nguoi goi ep dung (de minh hoa tai su dung nonce)."""
    Y = point_mul(G, sk_int)
    x = sk_int if has_even_y(Y) else q - sk_int
    R = point_mul(G, k_int)
    k = k_int if has_even_y(R) else q - k_int
    e = challenge(x_only(R), x_only(Y), msg)
    return x_only(R) + int_to_bytes((k + x * e) % q)


# ---------------------------------------------------------------
# 5. Xac minh hang loat (batch verification) va ECDSA de so sanh
# ---------------------------------------------------------------
def schnorr_batch_verify(items) -> bool:
    """items = [(msg, pk, sig), ...]. Kiem tra:  (sum a_i*s_i) G == sum a_i R_i + sum (a_i e_i) Y_i
    voi he so ngau nhien a_i (a_1 = 1). Mot phep so sanh duy nhat cho ca lo."""
    lhs, rhs = 0, None
    for i, (msg, pk, sig) in enumerate(items):
        Y, R = lift_x(pk), lift_x(sig[:32])
        s = bytes_to_int(sig[32:])
        if Y is None or R is None or s >= q:
            return False
        a = 1 if i == 0 else secrets.randbelow(q - 1) + 1
        e = challenge(sig[:32], pk, msg)
        lhs = (lhs + a * s) % q
        rhs = point_add(rhs, point_add(point_mul(R, a), point_mul(Y, a * e % q)))
    return point_mul(G, lhs) == rhs


def ecdsa_keygen():
    x = secrets.randbelow(q - 1) + 1
    return x, point_mul(G, x)


def ecdsa_sign(msg: bytes, x: int):
    """ECDSA tren secp256k1 (de so sanh hieu nang): s = k^-1 (H(m) + r*x) mod q."""
    z = bytes_to_int(hashlib.sha256(msg).digest()) % q
    while True:
        k = secrets.randbelow(q - 1) + 1
        r = point_mul(G, k)[0] % q
        if r == 0:
            continue
        s = pow(k, -1, q) * (z + r * x) % q
        if s != 0:
            return r, s


def ecdsa_verify(msg: bytes, sig, Y) -> bool:
    r, s = sig
    if not (1 <= r < q and 1 <= s < q):
        return False
    z = bytes_to_int(hashlib.sha256(msg).digest()) % q
    w = pow(s, -1, q)
    X = point_add(point_mul(G, z * w % q), point_mul(Y, r * w % q))
    return X is not None and X[0] % q == r
