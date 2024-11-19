import json
import socket
import threading

class Server:
    def define_port(self, port):
        hostPC = socket.gethostname()
        host = socket.gethostbyname(hostPC)
        print("Host: ", host)

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((host, port))
            self.port = port
            
            self.server_socket.listen(5)
        except Exception as e:
            print("Socket could not be created", e)
        
        self.clients = {}
        self.keys = {}
        self.thread = threading.Thread(target=self.run)
        self.thread.start()
        
    def get_clients_list(self):
        return self.clients
        
    def get_port(self):
        return self.port
    
    def get_keys(self):
        return self.keys

    def handle_client(self, client_socket, address):
        while True:
            try:
                data = client_socket.recv(1024).decode("utf-8")
                if not data:
                    print(f"Connection closed by {address}")
                    self.clients.pop(address)
                    client_socket.close()
                    break
                
                if data == "get_keys":
                    client_socket.send(json.dumps(self.keys).encode("utf-8"))
                    continue
                    
                if data == "get_clients":
                    client_socket.send(json.dumps([f"{addr[0]}:{addr[1]}" for addr in self.clients.keys()]).encode("utf-8"))
                    continue
                    
                recipient_port, message = data.split(':', 1)
                recipient_port = int(recipient_port)
                
                for addr, sock in self.clients.items():
                    if addr[1] == recipient_port:
                        sock.send(message.encode("utf-8"))
                        break
                else:
                    client_socket.send("Invalid recipient".encode("utf-8"))
            except ConnectionResetError:
                print(f"Connection reset by {address}")
                self.clients.pop(address)
                client_socket.close()
                break

    def run(self):
        while True:
            client_socket, address = self.server_socket.accept()
            client_key = client_socket.recv(1024).decode("utf-8")
            print(f"Accepted connection from {address}")
            # print(client_key)
            
            self.clients[address] = client_socket
            
            client_ip, client_port = address
            self.keys[client_port] = client_key
        
            print(json.dumps(self.keys, indent=4, ensure_ascii=False))

            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
            client_thread.start()