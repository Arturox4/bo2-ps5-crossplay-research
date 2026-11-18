"""Escucha en (casi) todos los puertos UDP a la vez, sin necesitar admin ni Npcap.

Uso: python udp_listen_all.py <ip_origen> [segundos] [puerto_ini] [puerto_fin]
Solo muestra paquetes cuyo origen sea <ip_origen>.
"""
import select
import socket
import sys
import time

SRC = sys.argv[1]
SECS = int(sys.argv[2]) if len(sys.argv) > 2 else 25
P0 = int(sys.argv[3]) if len(sys.argv) > 3 else 1
P1 = int(sys.argv[4]) if len(sys.argv) > 4 else 65535


def hexdump(data, limit=512):
    out = []
    d = data[:limit]
    for i in range(0, len(d), 16):
        c = d[i:i + 16]
        out.append(f"    {i:04x}  {' '.join(f'{b:02x}' for b in c):<47}  "
                   f"{''.join(chr(b) if 32 <= b < 127 else '.' for b in c)}")
    if len(data) > limit:
        out.append(f"    ... ({len(data)} bytes en total)")
    return "\n".join(out)


socks = {}
failed = 0
for p in range(P0, P1 + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", p))
        s.setblocking(False)
        socks[s] = p
    except OSError:
        failed += 1
        s.close()
print(f"[i] escuchando en {len(socks)} puertos ({failed} ocupados), {SECS}s, origen {SRC}", flush=True)

lst = list(socks)
chunks = [lst[i:i + 500] for i in range(0, len(lst), 500)]
seen = {}
end = time.time() + SECS
while time.time() < end:
    for ch in chunks:
        r, _, _ = select.select(ch, [], [], 0)
        for s in r:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                continue
            if addr[0] != SRC:
                continue
            key = (addr[1], socks[s], data)
            seen[key] = seen.get(key, 0) + 1
            if seen[key] == 1:
                print(f"[RX] {addr[0]}:{addr[1]} -> puerto local {socks[s]} ({len(data)} bytes)")
                print(hexdump(data), flush=True)
    time.sleep(0.02)

print("[resumen]")
for (sp, dp, data), n in sorted(seen.items(), key=lambda kv: kv[0][1]):
    print(f"    origen :{sp} -> destino :{dp}  x{n}  {data[:40]!r}")
print(f"[fin] paquetes distintos: {len(seen)}")
