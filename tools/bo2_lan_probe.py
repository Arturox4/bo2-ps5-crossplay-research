"""Sonda LAN para BO2 (port de PS5).

Fases:
  1. Barrido de ping de la /24 para poblar la tabla ARP y listar dispositivos.
  2. Escucha pasiva en puertos UDP candidatos (broadcasts de descubrimiento de la PS5).
  3. Envio de 'getinfo' por broadcast a esos puertos (por si la PS5 esta de host).
  4. Barrido unicast de todos los puertos UDP de los hosts candidatos con 'getinfo'.

Uso: python bo2_lan_probe.py [segundos_escucha] [ip_ps5]
"""
import re
import select
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

LISTEN_SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 40
FORCED_IP = sys.argv[2] if len(sys.argv) > 2 else None

CAND_PORTS = [1000, 1001, 3074, 3075, 3076, 3478, 3479, 3658, 4976, 9302, 9308,
              27014, 27015, 27016, 27017, 28960, 28961]
PROBES = [
    b"\xff\xff\xff\xffgetinfo xxx",
    b"\xff\xff\xff\xff\x32getinfo xxx",
    b"\xff\xff\xff\xff\x32 getinfo xxx",
    b"\xff\xff\xff\xffgetinfo xxx\x00",
    b"\xff\xff\xff\xffgetstatus xxx",
]


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.168.1.1", 9))
        return s.getsockname()[0]
    finally:
        s.close()


def hexdump(data, limit=256):
    out = []
    d = data[:limit]
    for i in range(0, len(d), 16):
        chunk = d[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        tx = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"    {i:04x}  {hx:<47}  {tx}")
    if len(data) > limit:
        out.append(f"    ... ({len(data)} bytes en total)")
    return "\n".join(out)


def ping(ip):
    subprocess.run(["ping", "-n", "1", "-w", "400", ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def arp_table(prefix):
    txt = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                         errors="replace").stdout
    hosts = {}
    for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", txt):
        ip, mac = m.group(1), m.group(2).lower()
        if ip.startswith(prefix) and mac != "ff-ff-ff-ff-ff-ff" and not ip.endswith(".255"):
            hosts[ip] = mac
    return hosts


def main():
    me = local_ip()
    prefix = me.rsplit(".", 1)[0] + "."
    bcast = prefix + "255"
    print(f"[i] IP local {me}, broadcast {bcast}")

    print("[1] Barrido de ping...")
    with ThreadPoolExecutor(64) as ex:
        list(ex.map(ping, [f"{prefix}{i}" for i in range(1, 255)]))
    hosts = arp_table(prefix)
    for ip, mac in sorted(hosts.items(), key=lambda kv: int(kv[0].rsplit(".", 1)[1])):
        print(f"    {ip:<15} {mac}")

    socks = []
    for p in CAND_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.bind(("", p))
            socks.append(s)
        except OSError as e:
            print(f"    no pude abrir el puerto {p}: {e}")
            s.close()
    print(f"[2] Escuchando {LISTEN_SECS}s en {[s.getsockname()[1] for s in socks]}")

    seen = set()
    hits = []

    def drain(timeout):
        r, _, _ = select.select(socks, [], [], timeout)
        for s in r:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                continue
            # Ignora mis propios paquetes (eco por otras interfaces del PC).
            if addr[0] == me or not addr[0].startswith(prefix):
                continue
            key = (addr, s.getsockname()[1], data[:48])
            if key in seen:
                continue
            seen.add(key)
            hits.append((addr, s.getsockname()[1], data))
            print(f"[RX] {addr[0]}:{addr[1]} -> puerto local {s.getsockname()[1]} ({len(data)} bytes)")
            print(hexdump(data))

    end = time.time() + LISTEN_SECS
    nxt = 0
    while time.time() < end:
        if time.time() >= nxt:
            for s in socks:
                for p in CAND_PORTS:
                    for pr in PROBES[:2]:
                        for dst in (bcast, "255.255.255.255"):
                            try:
                                s.sendto(pr, (dst, p))
                            except OSError:
                                pass
            nxt = time.time() + 3
        drain(0.25)

    if not FORCED_IP:
        print("[4] Sin IP de la PS5: omito el barrido de puertos.")
        print(f"[fin] paquetes recibidos distintos: {len(hits)}")
        return
    targets = [FORCED_IP]
    print(f"[4] Barrido unicast de todos los puertos UDP en: {targets}")
    scan = socks[0] if socks else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in targets:
        for pr in PROBES[:2]:
            for port in range(1, 65536):
                try:
                    scan.sendto(pr, (ip, port))
                except OSError:
                    pass
                if port % 512 == 0:
                    drain(0.01)
        t = time.time() + 2
        while time.time() < t:
            drain(0.2)

    print(f"[fin] paquetes recibidos distintos: {len(hits)}")


if __name__ == "__main__":
    main()
