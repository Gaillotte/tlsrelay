"""Exchanges 1 MiB through a tlsrelay client and checks the echo (SHA-256).

Usage: exchange.py <tlsrelay client port>
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
print(f"exchange: {len(received)} bytes received, identical: {ok}")
sys.exit(0 if ok else 1)
