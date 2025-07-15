from random import randint
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
import os

MODP_2048_HEX = ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43")
P = int(MODP_2048_HEX, 16)
G = 2

def generate_dh_keypair():
    private = randint(2, P - 2)
    public = pow(G, private, P)
    return private, public

def compute_shared_key(their_public: int, my_private: int):
    shared_secret = pow(their_public, my_private, P)
    return sha256(str(shared_secret).encode()).digest() 

def encrypt_message(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)  
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext

def decrypt_message(key: bytes, encrypted_data: bytes) -> bytes:
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext
