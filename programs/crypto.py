import hashlib
import bcrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import itertools
import string

def encrypt_file(filename):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    
    with open(filename, 'rb') as f:
        data = f.read()
    
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    with open(filename + '.enc', 'wb') as f:
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
    
    print(f"File encrypted. Key: {base64.b64encode(key).decode()}")

def decrypt_file(filename):
    with open(filename, 'rb') as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
    
    key = input("Enter decryption key: ").encode()
    key = base64.b64decode(key)
    
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    
    output_file = filename.replace('.enc', '.dec')
    with open(output_file, 'wb') as f:
        f.write(data)
    
    print("File decrypted successfully")

def generate_hashes(text):
    algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    results = {}
    
    for algo in algorithms:
        hash_func = getattr(hashlib, algo)()
        hash_func.update(text.encode())
        results[algo] = hash_func.hexdigest()
    
    for algo, hash_val in results.items():
        print(f"{algo.upper()}: {hash_val}")

def brute_force_hash(target_hash):
    chars = string.ascii_letters + string.digits + string.punctuation
    max_length = 6
    
    print(f"Brute forcing hash: {target_hash}")
    
    for length in range(1, max_length + 1):
        for attempt in itertools.product(chars, repeat=length):
            attempt_str = ''.join(attempt)
            attempt_hash = hashlib.sha256(attempt_str.encode()).hexdigest()
            
            if attempt_hash == target_hash:
                print(f"Password found: {attempt_str}")
                return
    
    print("Password not found")