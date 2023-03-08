import socket
import threading
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP as RSA_cipher

class secure_socket:
    def __init__(self, socket, key_pair):
        self.socket = socket
        self.key_pair = key_pair
        
    def handshake(self):
        remote_public_key = RSA.importKey(self.socket.recv(1024))
        self.socket.sendall(self.key_pair.publickey().exportKey())
        self.encrypt = RSA_cipher.new(remote_public_key).encrypt
        self.decrypt = RSA_cipher.new(self.key_pair).decrypt
        
    def sendall(self, data):
        self.socket.sendall(self.encrypt(data))
        
    def recv(self):
        return self.decrypt(self.socket.recv(1024))

class server:
    def __init__(self, address, users, motd):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = address
        self.clients = {}
        self.motd = motd
        self.users = users
        self.key_pair = RSA.generate(1024)
        
    def start(self):
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
            username = secure.recv().decode()
            secure.sendall(self.motd.encode())
            password = secure.recv().decode()
            if (username in self.users) and (self.users[username] == password) and (username not in self.clients):
                secure.sendall(bytes(1))
                self.clients[username] = secure
                self.broadcast('SERVER: {} connected.'.format(username))
                while True:
                    try:
                        message = secure.recv().decode()
                    except:
                        self.clients.pop(username)
                        self.broadcast('SERVER: {} disconnected.'.format(username))
                        socket.close()
                        return
                    self.broadcast('{}: {}'.format(username, message))
            else:
                secure.sendall(bytes(0))
                socket.close()
                return
        except:
            socket.close()
            return

if __name__ == '__main__':
    print('#-------------------')
    print('| CHATT Server v1.0')
    print('|')
    print('| C: Compact')
    print('| H: Helpful')
    print('| A: Asynchronous')
    print('| T: Text')
    print('| T: Transmission')
    print('|')
    print('#-------------------')
    print('')
    try:
        f = open('config.json', 'r')
        config = json.load(f)
        f.close()
    except:
        f = open('config.json', 'w')
        f.write('{"host":"localhost", "port":8000, "motd":"Welcome to my CHATT Server."}')
        f.close()
        config = {'host': 'localhost', 'port': 8000, 'motd': 'Welcome to my CHATT Server.'}
    try:
        f = open('users.json', 'r')
        users = json.load(f)
        f.close()
    except:
        f = open('users.json', 'w')
        f.write('{"admin":"password", "user":"password"}')
        f.close()
        users = {'admin': 'password', 'user': 'password'}
    s = server((config['host'], config['port']), users, config['motd'])
    s.start()
