from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP as RSA_cipher

class secure_socket:
    def __init__(self, socket, key_pair):
        self.socket = socket
        self.key_pair = key_pair
        
    def handshake(self):
        self.socket.sendall(self.key_pair.publickey().exportKey())
        remote_public_key = RSA.importKey(self.socket.recv(304))
        self.encrypt = RSA_cipher.new(remote_public_key).encrypt
        self.decrypt = RSA_cipher.new(self.key_pair).decrypt
        
    def sendall(self, data):
        self.socket.sendall(self.encrypt(data))
        
    def recv(self, recv_size):
        return self.decrypt(self.socket.recv(recv_size))