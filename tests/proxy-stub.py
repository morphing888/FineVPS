# Заглушка прозрачного прокси для стенда: узнаёт настоящий адрес и пересылает данные.
import os, socket, struct, sys, threading
SO_ORIGINAL_DST = 80
hits = os.environ.get("STUB_HITS")
def pump(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    for s in (a, b):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((sys.argv[1], int(sys.argv[2])))
srv.listen(50)
while True:
    c, _ = srv.accept()
    raw = c.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port, ip = struct.unpack("!2xH4s8x", raw)
    if hits:
        with open(hits, "a") as f:
            f.write("hit\n")
    try:
        r = socket.create_connection((socket.inet_ntoa(ip), port), timeout=5)
    except OSError:
        c.close()
        continue
    threading.Thread(target=pump, args=(c, r), daemon=True).start()
    threading.Thread(target=pump, args=(r, c), daemon=True).start()
