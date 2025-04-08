import hashlib
import os

def generate_salt(length=16):
    """Génère un sel aléatoire."""
    return os.urandom(length).hex()

def hash_password(password, salt, iterations=100000):
    """Hache un mot de passe en utilisant un sel et un nombre d'itérations."""
    combined = (password + salt).encode('utf-8')
    hashed = hashlib.sha256(combined).digest()
    for _ in range(iterations - 1):
        hashed = hashlib.sha256(hashed).digest()
    return hashed.hex()

def create_hashed_password(password):
    """Crée un hash et un sel pour le mot de passe donné."""
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    return hashed_password, salt

def create_hashed_code(code, salt):
    """Crée un hash et un sel pour le mot de passe donné."""
    hashed_password = hash_password(code, salt)
    return hashed_password

def verify_password(password, salt, stored_hash):
    """Vérifie si un mot de passe correspond au hash stocké."""
    return hash_password(password, salt) == stored_hash

