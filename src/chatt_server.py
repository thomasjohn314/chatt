import socket
import threading
import json
from Crypto.PublicKey import RSA
from secure_socket import secure_socket
import sys

class server:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}

    def main(self):
        print('#-----------------')
        print('| CHATT Server')
        print('|')
        print('| C: Compact')
        print('| H: Helpful')
        print('| A: Asynchronous')
        print('| T: Text')
        print('| T: Transmission')
        print('|')
        print('#-----------------')
        print('')
        while True:
            try:
                f = open('server_config.json', 'r')
                break
            except:
                print('Creating server_config.json.')
                f = open('server_config.json', 'w')
                f.write('{"host":"localhost", "port":8000, "motd":"Welcome to my CHATT Server.", "load_rsa_from_file":false, "users":{"admin":"password", "thomasjohn":"password"}}')
                f.close()
        try:
            config = json.load(f)
            f.close()
            self.address = (config['host'], config['port'])
            self.motd = config['motd']
            self.users = config['users']
            load_rsa_from_file = config['load_rsa_from_file']
        except:
            print('Invalid configuration file. Delete server_config.json to restore default.')
            sys.exit()
        if load_rsa_from_file:
            while True:
                try:
                    f = open('server_rsa.pem', 'r')
                    break
                except:
                    print('Creating server_rsa.pem and generating RSA keys.')
                    f = open('server_rsa.pem', 'w')
                    f.write(RSA.generate(1024).exportKey().decode())
                    f.close()
            try:
                self.key_pair = RSA.importKey(f.read())
                f.close()
            except:
                print('Invalid RSA keys. Delete server_rsa.pem to regenerate. Randomly generated RSA keys will be used for now.')
                self.key_pair = RSA.generate(1024)
        else:
            print('Generating RSA keys.')
            self.key_pair = RSA.generate(1024)
        self.socket.bind(self.address)
        self.socket.listen()
        print('Server started @ {}:{}'.format(self.address[0], self.address[1]))
        print('')
        while True:
            socket, _ = self.socket.accept()
            threading.Thread(target=self.handle_client, args=(socket,)).start()
            
    def broadcast(self, message):
        print(message)
        for client in self.clients.values():
            client.sendall(message.encode())
            
    def handle_client(self, socket):
        try:
            secure = secure_socket(socket, self.key_pair)
            secure.handshake()
            username = secure.recv(1024).decode()
            secure.sendall(self.motd.encode())
            password = secure.recv(1024).decode()
            if not (username in self.users) or (self.users[username] != password):
                secure.sendall(bytes(0))
                socket.shutdown(1)
                socket.close()
                return
            elif username in self.clients:
                secure.sendall(bytes(1))
                socket.shutdown(1)
                socket.close()
                return
            else:
                secure.sendall(bytes(2))
                self.clients[username] = secure
                self.broadcast('SERVER: {} connected.'.format(username))
                while True:
                    try:
                        message = secure.recv(1024).decode()
                    except:
                        socket.shutdown(1)
                        socket.close()
                        self.clients.pop(username)
                        self.broadcast('SERVER: {} disconnected.'.format(username))
                        return
                    self.broadcast('{}: {}'.format(username, message))
        except:
            socket.shutdown(1)
            socket.close()
            return

if __name__ == '__main__':
    s = server()
    s.main()
