import base64
import json
import socket
import threading
import rsa
from .aescipher import AESCipher
from .PBKDF2 import PBKDF2


import sympy
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import datetime
import base64
import pickle
import socket
import threading
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, DES
import string
import random
from .PuzzleMerkle import Merkle
from cryptography.fernet import Fernet
import base64
import os



class Client:  
    def define_username(self, username):
        self.username = username
        print("Username: ", self.username)
    
    def define_port(self, host, port):
        
        
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
        except Exception as e:
            print("Socket could not be created", e)
            
        # save in the server the port and the public key, create a random key of the client and the port of the client
        self.given_port = self.client_socket.getsockname()[1]
        self.client_port = port
        self.client_public_key, self.client_private_key = rsa.newkeys(512)
        self.client_public_key = self.client_public_key.save_pkcs1().decode("utf-8")
        self.client_private_key = self.client_private_key.save_pkcs1().decode("utf-8")
        print("Client public key: ", self.client_public_key)
        print("Client private key: ", self.client_private_key)
        self.client_socket.send(self.client_public_key.encode("utf-8"))
        print("Client public key sent to server")
        
        # Start a thread to receive messages
        # receive_thread = threading.Thread(target=self.receive_messages)
        # receive_thread.start()

        self.thread = threading.Thread(target=self.run)
        self.thread.start()
        
    def receive_messages(self):
            try:
                # Receive message from server
                data = self.client_socket.recv(1024).decode("utf-8")
                if not data:
                    print("Server closed the connection")
                    return "Server closed the connection"
                # if data == "Merkel":
                #     print("VAIS RECEBER ALGO")
                
                print("Received: " + data)
                return data

            except ConnectionResetError:
                print("Connection to server lost")
                return "Connection to server lost"

    def send_messages(self, message, port):
        while True:
            try:
                # Send message to server
                data = f"{port}:{message}"
                self.client_socket.send(data.encode("utf-8"))
                print("Sent: " + str(message))
                break
            except ConnectionResetError:
                print("Connection to server lost")
                break  

    def run(self):
       # Gerar uma chave pré distribuida, tem de ser uma chave fixa pois sempre que fosse aberto um novo cliente, a chave seria diferente.
        pre_shared_key = "6tkX83bwy7fOc5iqoETf1S0dBI7RecQn9X23ubHapWs="
        while True:
            try: 
                print("\n-----MODO CLIENTE-----\n1-Comunicar com outro cliente\n2-Listar clientes ativos\n3-Gerar segredo criptográfico através de chave gerada por palavra-passe (PBKDF2)\n0-Sair\n")
                opcao = int(input("Escolha uma opção: "))
                if opcao == 0:
                    break
                elif opcao == 1:
                    print("1 - Cliente Remetente")
                    print("2 - Cliente Recetor")
                    print("0 - Sair")
                    opcaoComunicacao = int(input("Escolha uma opção: "))
                    if opcaoComunicacao == 0:
                        break
                    elif opcaoComunicacao == 1:
                        print("\n-----MODO CLIENTE REMETENTE -----\n"
                        "1- Troca de um segredo criptográfico usando o protocolo de acordo de chaves Diffie-Hellman;\n"
                        "2 Troca de um segredo criptográfico usando Puzzles de Merkle;\n"
                        "3- Troca de um segredo criptográfico usando o Rivest, Shamir e Adleman (RSA);\n"
                        "4- Distribuição de novas chaves de cifra a partir de chaves pré-distribuídas;\n"
                        "5- Distribuição de novas chaves de cifra usando um agente de confiança"
                        "(neste caso, a aplicação desenvolvida deve permitir que uma das instâncias possa ser configurada como agente de confiança).\n")
                        opcaoMensagem = int(input("Escolha a opção que pretende: "))
                        if opcaoMensagem == 1:
                            print ("Diffie-Hellman")
                            recipient_port = int(input(f"{self.client_port} Enter recipient's port number: "))
                            P = sympy.randprime(2**14, 2**18)
                            G = sympy.randprime(2**14, 2**18)
                            x = sympy.randprime(2**14, 2**18)

                            X = (G**x) % P
                            
                            print(f"P: {P}, \nG: {G}, \nX: {X}\n")
                            message = f"{P}:{G}:{X}"
                            if message.lower().strip() == 'adeus':
                                break
                            self.send_messages(message, recipient_port)
                            
                            # ficar à espera da pk do Bob
                            Y = self.receive_messages()
                            Y = int(Y)
                            
                            K = (Y**x) % P
                            print("K: ", K)
                            
                            message = input(" MSG -> ")

                            K = str(K)

                            var_AES = AESCipher(K)
                            encrypted_message = AESCipher.encrypt(var_AES, message)
                            self.send_messages(encrypted_message, recipient_port)
                            print("K: ", K)
                            print("Mensagem: ", message)
                            print("Mensagem encriptada: ", encrypted_message)
                            
                            # signature da encrypted message
                            client_private_key = rsa.PrivateKey.load_pkcs1(self.client_private_key.encode("utf-8"))
                            signature = rsa.sign(encrypted_message.encode("utf-8"), client_private_key, 'SHA-1')
                            signature = base64.b64encode(signature).decode("utf-8")
                            print("Signature: ", signature)
                            # send the signature
                            self.send_messages(signature, recipient_port)
                            
                           
                          
                        elif opcaoMensagem == 2:
                            print ("Puzzles de Merkle")
                            recipient_port = int(input("Enter recipient's port number: "))

                            # Cria a instancia de Merkle
                            merkle_instance = Merkle()

                            
                            num_puzzles = 12 # Número de puzzles a enviar
                            puzzles = [] # Lista de puzzles
                            keys = [] # Lista de chaves
                            # Ciclo for para criar os puzzles, encriptá-los e adicioná-los à lista de puzzles
                            for _ in range(num_puzzles):
                                key = merkle_instance.random_key()
                                puzzle = merkle_instance.random_string(16)
                                encrypted_puzzle = merkle_instance.encrypt(key, puzzle)
                                puzzles.append(encrypted_puzzle)
                                keys.append(key.hex())  # Converter bytes to hexadecimal string


                            # Envia para o recetor os puzzles e as chaves
                            print("Puzzles\n")
                            self.send_messages(puzzles, recipient_port)

                            # Envia as chaves
                            print("Keys\n")
                            self.send_messages(keys, recipient_port)
                        elif opcaoMensagem == 3:
                            '''Sharing a crypto secret using RSA'''
                            print ("RSA")
                            recipient_port = int(input(f"{self.client_port} Enter recipient's port number: "))
                            message = input("Enter message: ")
                            # given the recipent number, searches for the public key in the list from the server
                            self.client_socket.send("get_keys".encode("utf-8"))
                            keys = self.client_socket.recv(1024).decode("utf-8")
                            
                            # ident the keys dict
                            keys = json.loads(keys)
                            print(json.dumps(keys, indent=4, ensure_ascii=False))
                            for key in keys:
                                # print(key)
                                if key == str(recipient_port):
                                    recipient_public_key = keys[key]
                                    # recipient_public_key = rsa.PublicKey.load_pkcs1(recipient_public_key.encode("utf-8"))
                                    print("Recipient public key: ", recipient_public_key)
                                    break

                            client_private_key = rsa.PrivateKey.load_pkcs1(self.client_private_key.encode("utf-8"))
                            client_private_key_pem = client_private_key.save_pkcs1()

                            private_key = serialization.load_pem_private_key(
                                client_private_key_pem,
                                password=None,
                                backend=default_backend()
                            )
                            pem = private_key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()
                            )

                            print("------------------------------------")
                            print("PRIVATE KEY: ", pem)

                            builder = x509.CertificateBuilder()
                            builder = builder.subject_name(x509.Name([
                                x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
                                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"COVILHA"),
                                x509.NameAttribute(NameOID.LOCALITY_NAME, u"COVILHA"),
                                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UBI"),
                                x509.NameAttribute(NameOID.COMMON_NAME, u"client")
                            ]))
                            builder = builder.issuer_name(x509.Name([
                                x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
                                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"COVILHA"),
                                x509.NameAttribute(NameOID.LOCALITY_NAME, u"COVILHA"),
                                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UBI"),
                                x509.NameAttribute(NameOID.COMMON_NAME, u"client")
                            ]))

                            builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
                            builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(days=365))
                            builder = builder.serial_number(x509.random_serial_number())
                            client_public_key_pem = self.client_public_key.encode("utf-8")
                            client_public_key = serialization.load_pem_public_key(client_public_key_pem)

                            builder = builder.public_key(client_public_key)
                            builder = builder.add_extension(
                                                            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                                                            critical=False,
                                                            )  
                            
                            certificate = builder.sign(
                                private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
                            )

                            certt_pem = certificate.public_bytes(serialization.Encoding.PEM)
                            print(certt_pem)
                            key_pem = private_key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption()
                            )
                            load_key = load_pem_private_key(key_pem, password=None, backend=default_backend())

                            # encrypt the message with the recipient public key
                            recipient_public_key = rsa.PublicKey.load_pkcs1(recipient_public_key.encode("utf-8"))
                            encrypted_message = rsa.encrypt(message.encode("utf-8"), recipient_public_key)
                            #encrypted_message = rsa.encrypt(message.encode("utf-8"), recipient_public_key)
                            encrypted_message = base64.b64encode(encrypted_message).decode("utf-8")
                            print("Mensagem encriptada: ", encrypted_message)
                            
                            # send the encrypted message
                            self.send_messages(encrypted_message, recipient_port)        
                            
                            # send the certificate
                            self.send_messages(certt_pem.decode("utf-8"), recipient_port)

                        elif opcaoMensagem == 4:
                            print ("Distribuição de novas chaves de cifra a partir de chaves pré-distribuídas")
                            recipient_port = int(input("Enter recipient's port number: "))
                            session_key = base64.urlsafe_b64encode(os.urandom(32)).decode() # Gera uma chave de sessão, apenas e só para esta comunicação	
                            # print("session key", session_key) - debug
                            cipher_suite = AESCipher(pre_shared_key) # Cria uma instância de AESCipher com a chave pré-distribuída

                            encrypted_session_key = AESCipher.encrypt(cipher_suite,session_key) # Encripta a chave de sessão com a chave pré-distribuída
                            # Visto que é apenas distribuição de novas chaves de cifra, a única mensagem a enviar é a mensagem que contem a chave de sessão
                            self.send_messages(encrypted_session_key, recipient_port) # Envia a chave de sessão encriptada
                            print("NOVA CHAVE DE SESSÃO ENVIADA")

                            
                        elif opcaoMensagem == 5:
                            print ("Agente de confiança")
                            recipient_port = int(input(f"{self.client_port} Enter recipient's port number: "))

                        # Comunicação
                    elif opcaoComunicacao == 2:
                            print("\n-----MODO CLIENTE RECETOR -----\n"
                            "1- Troca de um segredo criptográfico usando o protocolo de acordo de chaves Diffie-Hellman;\n"
                            "2- Troca de um segredo criptográfico usando Puzzles de Merkle;\n"
                            "3- Troca de um segredo criptográfico usando o Rivest, Shamir e Adleman (RSA);\n"
                            "4- Distribuição de novas chaves de cifra a partir de chaves pré-distribuídas;\n"
                            "5- Distribuição de novas chaves de cifra usando um agente de confiança "
                            "(neste caso, a aplicação desenvolvida deve permitir que uma das instâncias possa ser configurada como agente de confiança).\n")
                            opcaoMensagem = int(input("Escolha a opção que pretende: "))
                            if opcaoMensagem == 1:
                                print ("Diffie-Hellman")
                                remetente_port = int(input(f"{self.client_port} Enter recipient's port number: "))
                                message = self.receive_messages()

                                P, G, X = message.split(":")
                                P = int(P)
                                G = int(G)
                                X = int(X)
                                print(f"O remetente enviou:\nP: {P}, \nG: {G}, \nX: {X}\n")
                                if message.lower().strip() == 'adeus':
                                    break
                                
                                y = sympy.randprime(2**14, 2**18)

                                Y = (G**y) % P
                                self.send_messages(Y, remetente_port)
                                
                                K = (X**y) % P
                                
                                ciphertext = self.receive_messages()
                                signature = self.receive_messages()
                                signature = base64.b64decode(signature)
                                print("Signature: ", signature)
                                K = str(K)
                                
                                print("K: ", K)
                                
                                self.client_socket.send("get_keys".encode("utf-8"))
                                keys = self.client_socket.recv(1024).decode("utf-8")
                                
                                # ident the keys dict
                                keys = json.loads(keys)
                                print(json.dumps(keys, indent=4, ensure_ascii=False))
                                for key in keys:
                                    # print(key)
                                    if key == str(remetente_port):
                                        remetente_public_key = keys[key]
                                        print("Remetente public key antes: ", remetente_public_key)
                                        remetente_public_key = rsa.PublicKey.load_pkcs1(remetente_public_key.encode("utf-8"))
                                        print("Remetente public key depois: ", remetente_public_key)
                                        break
                                    # print("Mensagem encriptada: ", ciphertext)
                                
                                # verify signature
                                if rsa.verify(ciphertext.encode("utf-8"), signature, remetente_public_key):
                                    print("Signature is valid")
                                    var_AES = AESCipher(K)
                                    encrypted_message = AESCipher.decrypt(var_AES, ciphertext)
                                    print("Mensagem desencriptada: ", encrypted_message)
                                    
                                else:
                                    print("Signature is invalid")
                                
                                
                               
                                
                            elif opcaoMensagem == 2:
                                print ("Recipient Merkel")
                                recipient_port = int(input("Enter recipient's port number: "))
                                # Receive the puzzles and keys from the sender
                                merkle_instance = Merkle()
                                print("A RECEBER PUZZLES")
                                puzzles = self.receive_messages()
                                print("\n")
                                print("A RECEBER KEYS")
                                keys = self.receive_messages()
                                # Após comprimir o puzzle, era suposto enviar para o recetor mas... Invalid base64-encoded string: number of data characters (1) cannot be 1 more than a multiple of 4
                                decoded_puzzles = [base64.b64decode(puzzle.encode('utf-8')).decode('utf-8') for puzzle in puzzles]
                                # Escolhe um puzzle aleatório
                                selected_puzzle = random.choice(decoded_puzzles)
                                print(f"Selected puzzle: {selected_puzzle}")
                                # Tenta desencriptar o puzzle com todas as chaves
                                for key in keys:
                                    decrypted_message = merkle_instance.decrypt(selected_puzzle,key)
                                    if decrypted_message is not None:
                                        print(f"Decrypted message: {decrypted_message}")
                                        break
                            elif opcaoMensagem == 3:
                                '''Receiving a crypto secret using RSA'''
                                print ("RSA")
                                recipient_port = int(input(f"{self.client_port} Enter recipient's port number: "))
                                
                                  # get the private key
                                private_key = rsa.PrivateKey.load_pkcs1(self.client_private_key.encode("utf-8"))
                                # get the encrypted message
                                encrypted_message = self.receive_messages()
                                
                                # get the certificate
                                print("A RECEBER CERTIFICADO")
                                certt_pem = self.receive_messages()
                                print("CERTIFICATE: ", certt_pem)
                                # load the certificate
                                cert = x509.load_pem_x509_certificate(certt_pem.encode("utf-8"), default_backend())
                                print("CERTIFICATE LOADED: ", cert)
                                # get the public key from the certificate
                                public_key = cert.public_key()
                                print("PUBLIC KEY: ", public_key)
                                # verify the certificate
                                try:
                                    print("Verifying certificate...")
                                    public_key.verify(
                                        cert.signature,
                                        cert.tbs_certificate_bytes,
                                        padding.PKCS1v15(),
                                        cert.signature_hash_algorithm,
                                    )
                                    print("Certificate is valid.")
                                except:
                                    print("Certificate is invalid.")
                                
                                # decrypt the message
                                encrypted_message = base64.b64decode(encrypted_message)
                                # decrypt the message
                                decrypted_message = rsa.decrypt(encrypted_message, private_key)
                                decrypted_message = decrypted_message.decode("utf-8")
                                print("Mensagem desencriptada: ", decrypted_message)
                                
                                
                            elif opcaoMensagem == 4:
                                recipient_port = int(input(f"{self.client_port} Enter recipient's port number: "))
                                encrypted_session_key = self.receive_messages() # Recebe a chave de sessão encriptada
                                cipher_suite = AESCipher(pre_shared_key) # Visto que é distribuição de novas chaves de cifra a partir de chaves pré-distribuidas, a chave  pré-distribuída serve para decifrar a chave de sessão
                                session_key = AESCipher.decrypt(cipher_suite,encrypted_session_key)
                                print("Nova chave de sessão: ", session_key, "\n")

                                pre_shared_key = session_key # Atualiza a chave pré-distribuída com a chave de sessão
                                # print("Nova chave pré-distribuída: ", pre_shared_key) - debug
                                
                            
                                # cipher_suite_message = AESCipher(session_key)
                                #  decrypted_message = cipher_suite_message.decrypt(encrypted_message)
                                # print("Decrypted message: ", decrypted_message)


                            
                     
                            elif opcaoMensagem == 5:
                                print ("Agente de confiança")
                                recipient_port = int(input(f"{self.client_port} Enter recipient's port number: "))
                elif opcao == 2:
                    print("Listar clientes ativos")
                    self.client_socket.send("get_clients".encode("utf-8"))
                    clients = self.client_socket.recv(1024).decode("utf-8")
                    clients = json.loads(clients)
                    print(json.dumps(clients, indent=4, ensure_ascii=False))
                    
                elif opcao == 3:
                    print("Introduza a palavra-passe:")
                    password = input()
                    print("Escreva o segredo:")
                    message = input()
                    hash_choice = 0
                    while hash_choice < 1 or hash_choice > 5:
                        print("Qual função de hash pretende utilizar?\n1-SHA1\n2-SHA224\n3-SHA256\n4-SHA384\n5-SHA512")
                        hash_choice = int(input())
                        if hash_choice < 1 or hash_choice > 5:
                            print("Opção inválida, tente novamente!\n")

                    pbkdf2 = PBKDF2(password, hash_choice)
                    encrypted = pbkdf2.encrypt(message)
                    print("Segredo encriptado: " + encrypted)  # Tamanho do resultado é o mesmo independentemente da função de hash usada, pois usa uma chave secreta para cifrar a mensagem. 
                        
                        
            except ConnectionResetError:
                print("Connection to server lost")
                break
