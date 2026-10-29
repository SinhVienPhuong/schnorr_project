# Thuc nghiem chu ky so Schnorr (BIP-340) - do an tot nghiep

Python 3.10+, khong can cai them thu vien. CHI de hoc/nghien cuu, KHONG dung cho he thong that
(Python thuan, khong constant-time, khoa bi mat luu dang ro trong keys.json).

## Cau truc
| File | Vai tro | Muc luan van |
|---|---|---|
| schnorr_lib.py | Thu vien: so hoc diem, tagged hash, KeyGen/Sign/Verify (EC-Schnorr theo BIP-340, ky hieu x, Y, q) | 3.2 |
| create_keypair.py | Tao cap khoa, luu keys.json | 3.2.1 |
| schnorr_sign.py | Ky thong diep, in tung buoc, luu signatures.json | 3.2.2 |
| schnorr_verify.py | Xac minh chu ky (kem phep thu sai) | 3.2.3 |
| schnorr_test.py | 19 test vector + phep thu ngau nhien + hieu nang + so sanh ECDSA | 3.2.4 |
| attack_nonce_reuse.py | Tan cong tai su dung nonce + phong thu | 3.3.1 |
| attack_trivial_forgery.py | Gia mao tam thuong + phong thu | 3.3.2 |
| attack_related_key.py | Khoa lien quan + phong thu | 3.3.3 |
| giao_dien_nonce.py | Giao dien mo phong tan cong tai su dung nonce | 3.3.1 |
| giao_dien_gia_mao.py | Giao dien mo phong gia mao tam thuong | 3.3.2 |
| giao_dien_khoa_lien_quan.py | Giao dien mo phong khoa lien quan (dich khoa + khoa con) | 3.3.3 |
| gui_chung.py | Thanh phan dung chung cua cac giao dien (khong chay truc tiep) |  |
| utils.py | In mau, doc/ghi JSON |  |
| test-vectors.csv | 19 test vector chinh thuc BIP-340 |  |

## Chay tung buoc
    python create_keypair.py 2
    python schnorr_sign.py user1 "Chuyen 100 USD cho Bob"
    python schnorr_verify.py
    python schnorr_test.py
    python attack_nonce_reuse.py
    python attack_trivial_forgery.py
    python attack_related_key.py

## Giao dien do hoa (tkinter)
    python giao_dien_nonce.py
    python giao_dien_gia_mao.py
    python giao_dien_khoa_lien_quan.py
