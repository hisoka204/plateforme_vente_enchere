from Crypto.Util.number import getPrime, inverse
import math
import hashlib

def gen_rsa_keypair(bits):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    if math.gcd(e, phi_n) != 1:
        raise ValueError("error: e invalide.")
    d = inverse(e, phi_n)
    return ((n, e), (n, d))

def rsa(m, key):
    return pow(m, key[1], key[0])

def rsa_enc(m, pk):
    if isinstance(m, bytes):
        m_int = int.from_bytes(m, 'big')
    elif isinstance(m, str):
        m_int = int.from_bytes(m.encode('utf-8'), 'big')
    else:   
        raise ValueError("rsa_enc: str or bytes arg")
    return rsa(m_int, pk)

def rsa_dec(m, sk):
    tmp = rsa(m, sk)
    return tmp.to_bytes((tmp.bit_length() + 7) // 8, 'big').decode('utf-8')

def rsa_dec_bytes(m, sk):
    tmp = rsa(m, sk)
    return tmp.to_bytes((tmp.bit_length() + 7) // 8, 'big')

def h(m_int):
    tmp = m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big')
    m_hash = hashlib.sha256(tmp).digest()
    return int.from_bytes(m_hash, 'big')

def rsa_sign(m, sk):
    tmp = int.from_bytes(m.encode('utf-8'), 'big')
    return rsa(h(tmp), sk)

def rsa_verify(s, m, pk):
    tmp = int.from_bytes(m.encode('utf-8'), 'big')
    return h(tmp) == rsa(s, pk)
