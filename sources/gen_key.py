from rsa import gen_rsa_keypair

def save_keypair_to_file(filename, bits):
  try:
    private_key, public_key = gen_rsa_keypair(bits)
    with open(filename, 'w') as f:
      f.write(f"Public Key:\n{public_key}\n")
      f.write(f"Private Key:\n{private_key}\n")
  except Exception as e:
      print(f"Error:{e}")

if __name__ == "__main__":
  save_keypair_to_file("server_keys.txt", 1024) 
