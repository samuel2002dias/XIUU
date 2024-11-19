import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class PBKDF2:
    def __init__(self, password, hash_choice):
        self.salt = os.urandom(16) #garante que duas execuções do algoritmo PBKDF2 com a mesma senha não resultem na mesma chave
        self.iteration_count = 100000 #número de iterações do algoritmo PBKDF2, mais iterações = mais segurança mas mais lento 
        self.key_length = 32 
        self.iv = os.urandom(16)
        self.backend = default_backend()

        # Escolhe o algoritmo de hash com base na escolha do usuário
        if hash_choice == 1:
            self.algorithm = hashes.SHA1()
        elif hash_choice == 2:
            self.algorithm = hashes.SHA224()
        elif hash_choice == 3:
            self.algorithm = hashes.SHA256()
        elif hash_choice == 4:
            self.algorithm = hashes.SHA384()
        elif hash_choice == 5:
            self.algorithm = hashes.SHA512()

        # Cria um objeto PBKDF2HMAC que será usado para gerar a chave
        kdf = PBKDF2HMAC(
            algorithm=self.algorithm,
            length=self.key_length,
            salt=self.salt,
            iterations=self.iteration_count,
            backend=self.backend
        )
        self.key = kdf.derive(password.encode())
        self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)

    # criptografa usando AES e retorna o resultado em base64.
    def encrypt(self, data):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        encryptor = self.cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode()    