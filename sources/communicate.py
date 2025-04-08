from rsa import rsa_enc, rsa_dec, rsa_dec_bytes, rsa_sign, rsa_verify
from aes import encrypt_data_with_aes, decrypt_data_with_aes
from Crypto.Random import get_random_bytes
import time
import socket
import pickle
import struct


def send_rsa(command, dest_public_key, sender_private_key, socket):
  try:
    encrypted_command = rsa_enc(command, dest_public_key)
    signature = rsa_sign(command, sender_private_key)
    socket.sendall(pickle.dumps((encrypted_command, signature)))

    print(f"Commande envoyée: {command}")
    print(f"Commande chiffrée: {encrypted_command}")
    print(f"Signature: {signature}")

  except Exception as e:
    raise ConnectionError({e})

def recv_rsa(sender_public_key, dest_private_key, socket):
  try:
    response = pickle.loads(socket.recv(4096))
    encrypted_response, signature = response
    decrypted_response = rsa_dec(encrypted_response, dest_private_key)
    if not rsa_verify(signature, decrypted_response, sender_public_key):
      print(f"Signature invalide")
      return None

    print(f"Réponse reçue chiffrée: {encrypted_response}")
    print(f"Réponse déchiffrée: {decrypted_response}")
    print(f"Signature reçue: {signature}")
    return decrypted_response
  except Exception as e:
    raise ConnectionError({e})
    return None

def send_aes(message, dest_public_key, sender_private_key, socket):
  try:
    symmetric_key = get_random_bytes(16)
    encrypted_key = rsa_enc(symmetric_key, dest_public_key)
    encrypted_message = encrypt_data_with_aes(message, symmetric_key)
    signature = rsa_sign(message, sender_private_key)
    aes_packet = pickle.dumps((encrypted_key, encrypted_message, signature))
    lenght = len(aes_packet)
    socket.sendall(struct.pack('>I', lenght))
    socket.sendall(aes_packet)

    print(f"Clé symétrique générée: {symmetric_key}")
    print(f"Réponse chiffrée avec AES: {encrypted_message}")
    print(f"Signature: {signature}")
  except Exception as e:
    raise ConnectionError({e})

def recv_aes(sender_public_key, dest_private_key, socket):
  try:
    lenght = socket.recv(4)
    if not lenght:
      raise ConnectionError("longueur non reçue")
    rlenght = struct.unpack('>I', lenght)[0]
    encrypted_message = b""
    while len(encrypted_message) < rlenght:
      packet = socket.recv(4096)
      if not packet:
        raise ConnectionError("reception interrompue")
      encrypted_message += packet
    encrypted_key, cipher, signature = pickle.loads(encrypted_message)
    symmetric_key = rsa_dec_bytes(encrypted_key, dest_private_key)
    nonce = cipher[:8]
    ct_bytes = cipher[8:]
    clair = decrypt_data_with_aes(nonce, ct_bytes, symmetric_key)
    if not rsa_verify(signature, clair, sender_public_key):
      print(f"Signature invalide")
      return None

    print(f"Réponse chiffrée: {encrypted_message}")
    print(f"Réponse déchiffrée avec AES: {clair}")
    print(f"Signature: {signature}")
    return clair
  except Exception as e:
    raise ConnectionError({e})

