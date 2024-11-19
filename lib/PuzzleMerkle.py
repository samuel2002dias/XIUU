import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
from base64 import b64encode, b64decode

from sympy import re

class Merkle:
    def __init__(self):
        self.block_size = AES.block_size
        self.cipher = AES.new(get_random_bytes(self.block_size), AES.MODE_CBC)

    def random_string(self, length):
        k = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=length))
        return k

    def random_key(self, length=32):
        k = (self.random_string(length)).encode()
        return hashlib.sha256(k).digest()

    def encrypt(self, key, data):
        data = pad(data.encode('utf-8'), self.block_size)
        iv = get_random_bytes(self.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(data)
        return b64encode(iv + ciphertext).decode("utf-8")

    def decrypt(self, key, ciphertext):
        ciphertext = b64decode(ciphertext)
        iv = ciphertext[:self.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.decrypt(ciphertext[self.block_size:])
        plaintext = unpad(data, self.block_size).decode('utf-8')
        return plaintext
    
