"""Imita el descubrimiento LAN de BO2 PS5: envia el getinfo exacto capturado.

Paquete real de la PS5 (UDP 17476 -> broadcast:17476):
    57 04 40 | ff ff ff ff 32 | "getinfo xxx"

Uso: python ps5_getinfo.py <ip_ps5> [segundos]
Las respuestas se capturan aparte con tshark (el firewall bloquea a Python).
"""
import socket
import sys
import time

PS5 = sys.argv[1]
SECS = int(sys.argv[2]) if len(sys.argv) > 2 else 60
PORT = 17476
PAYLOAD = bytes.fromhex("570440ffffffff32") + b"getinfo xxx"

me = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
me.connect((PS5, 9))
local = me.getsockname()[0]
me.close()
bcast = local.rsplit(".", 1)[0] + ".255"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind((local, PORT))
end = time.time() + SECS
n = 0
while time.time() < end:
    s.sendto(PAYLOAD, (bcast, PORT))
    s.sendto(PAYLOAD, (PS5, PORT))
    n += 1
    time.sleep(1)
print(f"enviadas {n} rondas desde {local}:{PORT}")
