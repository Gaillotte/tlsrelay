"""Échange 1 Mio via un tlsrelay client et vérifie l'écho (SHA-256).

Usage : exchange.py <port du client tlsrelay>
"""
import hashlib
import os
import socket
import sys
import threading

port = int(sys.argv[1])
data = os.urandom(1 << 20)
received = bytearray()
s = socket.create_connection(("127.0.0.1", port), timeout=10)


def reader():
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        received.extend(chunk)


t = threading.Thread(target=reader)
t.start()
s.sendall(data)
s.shutdown(socket.SHUT_WR)
t.join(15)
ok = hashlib.sha256(received).digest() == hashlib.sha256(data).digest()
print(f"échange : {len(received)} octets reçus, identiques : {ok}")
sys.exit(0 if ok else 1)
