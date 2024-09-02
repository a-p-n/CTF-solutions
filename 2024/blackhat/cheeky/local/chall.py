#!/usr/bin/env python3
import os
import time
import json
import socket
from hashlib import sha256
from Crypto.Cipher import AES

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c79-6d65726f-57617348-65726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()

class Database:
    def __init__(self, passkey: bytes):
        if isinstance(passkey, str):
            passkey = passkey.encode()
        self.key = sha256(b"::".join([b"KEY(_FLAG)", passkey, len(passkey).to_bytes(2, 'big')])).digest()
        self.uiv = int(sha256(b"::".join([b"UIV(_KEY)", self.key, len(self.key).to_bytes(2, 'big')])).hexdigest()[:24], 16)
        self.edb = {}

    def _GetUIV(self, f: str, l: int, t: int = 0) -> bytes:
        if not (0 < t < int(time.time())):
            t = int(time.time()); time.sleep(2)
        u = (self.uiv + t).to_bytes(12, 'big')
        v = sha256(b"::".join([b"UIV(_FILE)", f.encode(), l.to_bytes(2, 'big')])).digest()
        return t, bytes([i^j for i,j in zip(u, v)])

    def _Encrypt(self, f: str, x: bytes) -> bytes:
        if isinstance(x, str):
            x = x.encode()
        t, uiv = self._GetUIV(f, len(x))
        aes = AES.new(self.key, AES.MODE_CTR, nonce=uiv)
        return t.to_bytes(4, 'big') + aes.encrypt(x)
    
    def _Decrypt(self, f: str, x: bytes) -> bytes:
        t, x = int.from_bytes(x[:4], 'big'), x[4:]
        _, uiv = self._GetUIV(f, len(x), t=t)
        aes = AES.new(self.key, AES.MODE_CTR, nonce=uiv)
        return aes.decrypt(x)
    
    def Insert(self, f, i, j):
        if isinstance(j, str):
            j = j.encode()
        if isinstance(j, int):
            j = j.to_bytes(-(-len(bin(j)[:2])//8), 'big')
        if f in self.edb:
            x = self._Decrypt(f, self.edb[f])
        else:
            x = b""
        y = x[:i] + j + x[i:]
        z = self._Encrypt(f, y)
        self.edb[f] = z
        return z
    
    def Delete(self, f, i, j):
        if f not in self.edb:
            return b""
        x = self._Decrypt(f, self.edb[f])
        y = x[:i] + x[i+j:]
        z = self._Encrypt(f, y)
        self.edb[f] = z
        return z

# Initialize database
database = Database(FLAG)
database.Insert('flag', 0, FLAG)

# Server setup
def handle_client_connection(client_socket):
    client_socket.sendall(b"|\n|  Menu:\n|    [I]nsert\n|    [D]elete\n|    [Q]uit\n|")
    while True:
        try:
            client_socket.sendall(b"|  > ")
            choice = client_socket.recv(1024).decode().strip().lower()
            if not choice:
                break

            if choice == 'q':
                client_socket.sendall(b'\n|\n|  [~] Goodbye ~ !\n|')
                break

            elif choice == 'i':
                client_socket.sendall(b"|  > (JSON) ")
                uin = json.loads(client_socket.recv(1024).decode().strip())
                assert uin.keys() == {'f', 'i', 'j'}
                ret = database.Insert(uin['f'], uin['i'], uin['j'])
                client_socket.sendall(f"|  '{uin['f']}' updated to 0x{ret.hex()}\n".encode())

            elif choice == 'd':
                client_socket.sendall(b"|  > (JSON) ")
                uin = json.loads(client_socket.recv(1024).decode().strip())
                assert uin.keys() == {'f', 'i', 'j'}
                ret = database.Delete(uin['f'], uin['i'], uin['j'])
                client_socket.sendall(f"|  '{uin['f']}' updated to 0x{ret.hex()}\n".encode())

            else:
                client_socket.sendall(b'|  [!] Invalid choice.\n')

        except Exception as e:
            client_socket.sendall(f'|  [!] ERROR :: {e}\n'.encode())

    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))  # Bind to all interfaces on port 9999
    server.listen(5)
    print("Server listening on port 9999...")

    while True:
        client_socket, _ = server.accept()
        handle_client_connection(client_socket)

if __name__ == "__main__":
    main()
