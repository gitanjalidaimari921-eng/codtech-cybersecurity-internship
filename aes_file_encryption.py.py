# AES-256 File Encryption & Decryption Tool
# Requires: pip install cryptography

import os
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
from getpass import getpass

backend = default_backend()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file, output_file, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(input_file, 'rb') as f:
        data = f.read()

    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)

    print("Encryption successful")

def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print("Decryption successful")

def main():
    print("1. Encrypt File")
    print("2. Decrypt File")
    choice = input("Choose option: ")

    infile = input("Input file path: ")
    outfile = input("Output file path: ")
    password = getpass("Password: ")

    if choice == "1":
        encrypt_file(infile, outfile, password)
    elif choice == "2":
        decrypt_file(infile, outfile, password)
    else:
        print("Invalid option")

if __name__ == "__main__":
    main()
