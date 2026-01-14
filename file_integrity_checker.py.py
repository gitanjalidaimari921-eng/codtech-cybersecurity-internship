import hashlib
import os

def calculate_hash(filename):
    sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

def save_hash(filename, hash_value):
    with open(filename + ".hash", "w") as f:
        f.write(hash_value)

def check_integrity(filename):
    if not os.path.exists(filename + ".hash"):
        print("No hash file found. Creating one.")
        hash_value = calculate_hash(filename)
        save_hash(filename, hash_value)
        print("Hash saved.")
        return

    old_hash = open(filename + ".hash").read()
    new_hash = calculate_hash(filename)

    if old_hash == new_hash:
        print("File is safe. No changes detected.")
    else:
        print("WARNING! File has been modified.")

file = input("Enter file name: ")
check_integrity(file)
