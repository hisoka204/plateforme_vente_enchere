from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_data_with_aes(data, key):
  nonce = get_random_bytes(8)
  cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
  ct_bytes = cipher.encrypt(data.encode('utf-8'))
  return nonce + ct_bytes

def decrypt_data_with_aes(nonce, ct_bytes, key):
  cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
  pt = cipher.decrypt(ct_bytes)
  return pt.decode('utf-8')
