# import random
# from Crypto.Cipher import DES
# from Crypto.Util.Padding import pad, unpad
# from Crypto.Random import get_random_bytes

# class Merkle:
#     def __init__(self):
#         self.cipher = DES.new(get_random_bytes(8))

#     def random_string(self, length):
#         k = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=length))
#         return k

#     def random_key(self, length):
#         k = (self.random_string(length) + "00000000").encode()
#         try:
#             sks = DES.new(k, DES.MODE_ECB)
#             return sks
#         except ValueError:
#             pass
#         return None

#     def encrypt(self, key, data):
#         try:
#             cipher = DES.new(key, DES.MODE_ECB)
#             utf8 = data.encode('utf-8')
#             ciphertext = cipher.encrypt(pad(utf8, 8))
#             return ciphertext
#         except ValueError:
#             pass
#         return None

#     def decrypt(self, key, ciphertext):
#         try:
#             cipher = DES.new(key, DES.MODE_ECB)
#             utf8 = cipher.decrypt(ciphertext)
#             plaintext = unpad(utf8, 8).decode('utf-8')
#             return plaintext
#         except ValueError:
#             pass
#         return None