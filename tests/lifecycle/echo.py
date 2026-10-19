"""TCP echo server for the lifecycle tests. Usage: echo.py <port>"""
import socket
import sys
import threading

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen()


def echo(c):
    with c:
        while True:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(d)


while True:
    conn, _ = srv.accept()
    threading.Thread(target=echo, args=(conn,), daemon=True).start()
