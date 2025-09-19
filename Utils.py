# crypto_utils.py
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

SALT_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERS = 200000

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERS)

def encrypt_file(plaintext_bytes: bytes, password: str) -> bytes:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    # store: salt + nonce + tag + ciphertext
    return salt + cipher.nonce + tag + ciphertext

def decrypt_file(data: bytes, password: str) -> bytes:
    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE+16]
    tag = data[SALT_SIZE+16:SALT_SIZE+32]
    ciphertext = data[SALT_SIZE+32:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
