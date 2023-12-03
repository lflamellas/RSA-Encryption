from random import randint
import os
import hashlib


def is_odd(num: int) -> bool:
    return num & 1 == 1


def find_factors(num: int) -> (int, int):
    exp = 0
    base = num - 1
    while not is_odd(base):
        base //= 2
        exp += 1
    return exp, base


def primality(num: int, rounds: int) -> bool:
    if not is_odd(num):
        return False
    exp, base = find_factors(num)
    for i in range(rounds):
        a = randint(2, num - 2)
        x = pow(a, base, num)
        for j in range(exp):
            y = pow(x, 2, num)
            if y == 1 and x != 1 and x != num - 1:
                return False
        if y != 1:
            return False
    return True


def generateProbablePrime(bits: int, rounds: int = 64) -> int:
    while True:
        n = randint(pow(2, bits - 1), pow(2, bits) - 1)
        if primality(n, rounds):
            return n


def extended_gcd(a: int, b: int):
    if not b:
        return 1, 0
    u, v = extended_gcd(b, a % b)
    return v, u - v * (a // b)


def calculatePrivateKey(e: int, p: int, q: int) -> int:
    private_key, _ = extended_gcd(e, (p - 1) * (q - 1))
    return private_key


def rsa_encrypt(plaintext: bytes, key: (int, int)) -> bytes:
    e, n = key
    plaintext = int.from_bytes(plaintext, "big")
    cipher = pow(plaintext, e, n)
    return cipher.to_bytes((n.bit_length() + 7) // 8, "big")


def rsa_decrypt(ciphertext: bytes, key: (int, int)) -> bytes:
    d, n = key
    ciphertext = int.from_bytes(ciphertext, "big")
    message = pow(ciphertext, d, n)
    return message.to_bytes((n.bit_length() + 7) // 8, "big")


def xor(data: bytes, mask: bytes) -> bytes:
    """Byte-by-byte XOR of two byte arrays"""
    masked = b""
    ldata = len(data)
    lmask = len(mask)
    for i in range(max(ldata, lmask)):
        if i < ldata and i < lmask:
            masked += (data[i] ^ mask[i]).to_bytes(1, byteorder="big")
        elif i < ldata:
            masked += data[i].to_bytes(1, byteorder="big")
        else:
            break
    return masked


def SHA(m: bytes) -> bytes:
    """SHA-3 hash function"""
    hasher = hashlib.sha3_256()
    hasher.update(m)
    return hasher.digest()


def mgf1(seed: bytes, length: int, hash_func=SHA) -> bytes:
    """Mask generation function."""
    hLen = len(hash_func(b""))
    if length > (hLen << 32):
        raise ValueError("mask too long")
    T = b""
    counter = 0
    while len(T) < length:
        C = int.to_bytes(counter, 4, "big")
        T += hash_func(seed + C)
        counter += 1
    return T[:length]


def oaep_encode(
    message: bytes,
    length: int,
    label: bytes = b"",
    f_hash=SHA,
    f_mgf=mgf1,
) -> bytes:
    mlen = len(message)
    lhash = f_hash(label)
    hlen = len(lhash)
    ps = b"\x00" * (length - mlen - 2 * hlen - 2)
    db = lhash + ps + b"\x01" + message
    seed = os.urandom(hlen)
    db_mask = f_mgf(seed, length - hlen - 1, f_hash)
    masked_db = xor(db, db_mask)
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    masked_seed = xor(seed, seed_mask)
    return b"\x00" + masked_seed + masked_db


def oaep_decode(
    cipher: bytes,
    length: int,
    label: bytes = b"",
    f_hash=SHA,
    f_mgf=mgf1,
) -> bytes:
    """OAEP decoding"""
    lhash = f_hash(label)
    hlen = len(lhash)
    _, masked_seed, masked_db = cipher[:1], cipher[1 : 1 + hlen], cipher[1 + hlen :]
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    seed = xor(masked_seed, seed_mask)
    db_mask = f_mgf(seed, length - hlen - 1, f_hash)
    db = xor(masked_db, db_mask)
    _lhash = db[:hlen]

    """Verification"""
    assert lhash == _lhash
    i = hlen
    while i < len(db):
        if db[i] == 0:
            i += 1
            continue
        elif db[i] == 1:
            i += 1
            break
        else:
            raise Exception()
    message = db[i:]
    return message


def encrypt_rsa_oaep(m: bytes, key: (int, int)) -> bytes:
    """Encrypt a byte array with OAEP padding"""
    _, n = key
    keyLen = (n.bit_length() + 7) // 8
    hlen = 256 // 8  # SHA-3 hash length
    assert len(m) <= keyLen - hlen - 2
    return rsa_encrypt(oaep_encode(m, keyLen), key)


def decrypt_rsa_oaep(c: bytes, key: (int, int)) -> bytes:
    """Decrypt a cipher byte array with OAEP padding"""
    _, n = key
    keyLen = (n.bit_length() + 7) // 8
    hlen = 256 // 8  # SHA-3 hash length
    assert len(c) == keyLen
    assert keyLen >= 2 * hlen + 2
    return oaep_decode(rsa_decrypt(c, key), keyLen)


keySize = 2048

p = generateProbablePrime(keySize // 2)
q = generateProbablePrime(keySize // 2)
n = p * q
e = 65537

public_key = (e, n)
private_key = (calculatePrivateKey(e, p, q), n)

plaintext = b"Sistema de Criptografia Assimetrico"

ciphertext = rsa_encrypt(plaintext, private_key)
recovered_plaintext = rsa_decrypt(ciphertext, public_key)

print(f"plaintext: \n{plaintext.decode()}\n")
print(f"ciphertext: \n{ciphertext}\n")
print(f"rsa_recovered_plaintext: \n{recovered_plaintext.decode()}\n")

plaintext_padded = oaep_encode(plaintext, keySize)
plaintext_unpadded = oaep_decode(plaintext_padded, keySize)

assert plaintext_unpadded == plaintext

rsa_oaep_ciphertext = encrypt_rsa_oaep(plaintext, private_key)
rsa_oaep_recovered_plaintext = decrypt_rsa_oaep(rsa_oaep_ciphertext, public_key)

assert plaintext == rsa_oaep_recovered_plaintext

print(f"rsa_oaep_ciphertext: \n{rsa_oaep_ciphertext}\n")
print(f"rsa_oaep_recovered_plaintext: \n{rsa_oaep_recovered_plaintext.decode()}\n")
