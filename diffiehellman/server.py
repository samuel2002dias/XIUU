import socket
import random
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256

def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024)
        if not data:
            # if data is not received break
            break
        print("from connected user: " + str(data))

        data_pieces = data.split(b',')
        if len(data_pieces) == 3:  # check if the data can be split into three pieces
            X, p, g = map(int, data_pieces)
            print(f"X: {X}, p: {p}, g: {g}")

            y = random.randint(1, p) # chave do Bob
            print("y: ", y)

            Y = pow(g, y, p) # chave partilhada
            print("Y: ", Y)

            K = pow(X, y, p) # chave partilhada
            print(f'K: {K}')

            conn.send(f'{Y}'.encode())  # send data to the client
        else:
            # decrypt the message
            hashed_K = SHA256.new(str(K).encode()).digest()
            encrypted_message = base64.b64decode(data)
            iv = encrypted_message[:16]  # the first 16 bytes are the IV
            ciphertext = encrypted_message[16:]  # the rest is the ciphertext
            cipher = AES.new(hashed_K, AES.MODE_CBC, iv=iv)
            decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
            print("plaintext: ", decrypted_message)



    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()