import socket
from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256
import random
import base64
from Crypto.Random import get_random_bytes


def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    p = number.getPrime(1024) # alice generates a prime number
    print("p: ", p)

    # fazer verificação para garantir que g é diferente de p
    g = random.randint(1, p)
    print("g: ", g)

    x = random.randint(1, p) # chave da Alice
    print("x: ", x)

    X = pow(g, x, p)
    print("X: ", X)
    

    message = f"{X},{p},{g}" 

    while message.lower().strip() != 'bye':
        client_socket.send(message.encode())  # send message
        data = client_socket.recv(1024).decode()  # receive response

        print('Received from server: ' + data)  # show in terminal

        if data.isdigit():  # check if the received data can be converted to an integer
            K = pow(int(data), x, p)  # calculate K
            print("K: ", K)

        message = input(" -> ")  # again take input

        # encrypt the message
        hashed_K = SHA256.new(str(K).encode()).digest()
        iv = get_random_bytes(16)  # generate a random IV
        cipher = AES.new(hashed_K, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
        message_with_iv = base64.b64encode(iv + ciphertext)  # prepend the IV to the ciphertext
        print("ciphertext: ", message_with_iv)

        client_socket.send(message_with_iv)   # send the encrypted message
        break
        

    client_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()