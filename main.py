import hashlib
import random


def mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
    hLen = hash_func().digest_size
    if length > (hLen << 32):
        raise ValueError("mask too long")
    T = b""
    counter = 0
    while len(T) < length:
        C = int.to_bytes(counter, 4, 'big')
        T += hash_func(seed + C).digest()
        counter += 1
    return T[:length]

def encrypt(p):
    modulus1 = 0x00af5466c26a6b662ac98c06023501c9df6036b065bd1f6804b1fc86307718da4048211fd68a06917de6f81dc018dcaf84b38ab77a6538ba2fe6664d3fb81e4a0886bbcdab071ad6823fe20df1cd67d33fb6cc5da519f69b11f3d48534074a83f03a5a9545427720a30a27432e94970155a026572e358072023061af65a2a18e85
    exponent1 = 0x10001
    res = square_and_multiply(p, exponent1, modulus1)
    return res

def square_and_multiply(base, exponent, modulus):
    res = 1
    binary_exponent = bin(exponent)[2:]
    for bit in binary_exponent:
        res = (res ** 2) % modulus
        if bit == '1':
            res = (res * base) % modulus

    return res

def to_bytes(x):
    temp1: bytearray = bytearray.fromhex(x)
    return temp1

def Rsa_OAEP(m, modulus_length=256):
    m_str = hex(m)[2:]

    padding = 0x00
    padding_str= padding.to_bytes(1,"big").hex()
    padding_len = 8

    data = 0x01
    data_str = data.to_bytes(1,"big").hex()
    data_len = 8


    seed = random.getrandbits(64)
    #seed = 0xaa1122fe0815beef
    seed_str = seed.to_bytes(8,"big").hex()
    seed_to_byte = to_bytes(seed_str)
    seed_len = 32

    length = (256 - padding_len) - seed_len
    diff = modulus_length - length
    db = data_str + m_str

    while len(db) < modulus_length - length:
        db = "0" + db

    db_num_hex = int(db, 16).to_bytes(diff,"big").hex()
    db_num = int(db, 16)

    msk_for_db = int((mgf1(seed_to_byte, 119).hex()),16)
    msk_for_db_str = msk_for_db.to_bytes(119, "big").hex()
    mskd_db = msk_for_db ^ db_num
    mskd_db_str = mskd_db.to_bytes(119,"big").hex()

    msk_for_seed = int((mgf1(to_bytes(mskd_db_str) , 8).hex()),16)
    msk_for_seed_str = msk_for_seed.to_bytes(8,"big").hex()
    mskd_seed = msk_for_seed ^ seed
    mskd_seed_str = mskd_seed.to_bytes(8,"big").hex()


    OEAP = padding_str + mskd_seed_str + mskd_db_str
    OEAP_num = int(OEAP,16)

    C = encrypt(OEAP_num)
    C = pow(OEAP_num, 0x10001, 0x00af5466c26a6b662ac98c06023501c9df6036b065bd1f6804b1fc86307718da4048211fd68a06917de6f81dc018dcaf84b38ab77a6538ba2fe6664d3fb81e4a0886bbcdab071ad6823fe20df1cd67d33fb6cc5da519f69b11f3d48534074a83f03a5a9545427720a30a27432e94970155a026572e358072023061af65a2a18e85)
    C_res = C.to_bytes(128,"big").hex()

    #Output with every step
    print(f"Ihr input war: {hex(m)}")
    print("-----------------------------------------------------")
    print(f"Länge des Moduls: {int(modulus_length/2)} Byte")
    print("-----------------------------------------------------")
    print(f"Datenblock: {db_num_hex}")
    print("-----------------------------------------------------")
    print(f"Maske für den Datenblock: {(msk_for_db_str)}")
    print("-----------------------------------------------------")
    print(f"Maskierter Datenblock: {mskd_db_str}")
    print("-----------------------------------------------------")
    print(f"Seed: {seed_str}")
    print("-----------------------------------------------------")
    print(f"Maske für Seed: {msk_for_seed_str}")
    print("-----------------------------------------------------")
    print(f"Maskierter Seed: {mskd_seed_str}")
    print("-----------------------------------------------------")
    print(f"OAEP(P): {(OEAP)}")
    print("-----------------------------------------------------")
    print(f"C: {(C_res)}")
    print("-----------------------------------------------------")

#converter.py
text = "Grafikkarten Gert"
m = text.encode().hex()
m = int(m,16)
#m = 0x466f6f62617220313233343536373839

Rsa_OAEP(m)



