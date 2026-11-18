"""Anuncia una partida LAN falsa de BO2 hacia la PS5 (prueba de descubrimiento).

Toma el infoResponse real capturado de la PS5 (host_payloads.txt), cambia el
nombre del host y la IP local dentro de hostaddr, y lo emite por broadcast.

Uso: python fake_host.py <ip_ps5> [segundos] [nombre]
"""
import base64
import socket
import sys
import time

PS5 = sys.argv[1]
SECS = int(sys.argv[2]) if len(sys.argv) > 2 else 120
NAME = (sys.argv[3] if len(sys.argv) > 3 else "PC-TEST").encode()
PORT = 17476

tmpl = bytes.fromhex(open("host_payloads.txt").readline().strip())
header, body = tmpl[:7], tmpl[7:]
cmd, _, kv = body.partition(b"\n")
parts = kv.split(b"\\")[1:]
keys, vals = parts[0::2], parts[1::2]
d = dict(zip(keys, vals))

me = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
me.connect((PS5, 9))
local = me.getsockname()[0]
me.close()
bcast = local.rsplit(".", 1)[0] + ".255"

addr = bytearray(base64.b64decode(d[b"hostaddr"]))
# hostaddr (37 bytes): IP local(4) puerto(2) | 4 entradas de relleno (6 c/u) |
#                      IP publica(4) puerto(2) | tipo(1)
addr[0:4] = socket.inet_aton(local)
addr[30:34] = socket.inet_aton(local)
d[b"hostaddr"] = base64.b64encode(bytes(addr))
d[b"hostname"] = NAME

payload = header + cmd + b"\n" + b"".join(b"\\" + k + b"\\" + d[k] for k in keys)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind((local, PORT))
end = time.time() + SECS
n = 0
while time.time() < end:
    s.sendto(payload, (bcast, PORT))
    n += 1
    time.sleep(0.5)
print(f"anuncios enviados: {n} como {NAME.decode()} desde {local}:{PORT}")
