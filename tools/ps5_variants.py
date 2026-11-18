"""Mide de que depende el bloque de 14 bytes del saludo 0x0d de la PS5.

Anuncia partidas falsas DE A UNA (la PS5 muestra solo una por IP) y pasa a
la siguiente al recibir su saludo. Cada una usa un puerto distinto en
hostaddr, asi que la PS5 le manda el saludo a ese puerto y se distingue sola:

  PC-A 3074  seckey original,  secid original   (linea base: compara con el
                                                  bloque 5ec18b26... de antes)
  PC-B 3075  igual que A, solo cambia el puerto
  PC-C 3076  secid nuevo
  PC-D 3077  seckey nuevo
  PC-E 3078  seckey original con el ultimo byte cambiado

Contesta cada 0x0d con 0x0c para que la PS5 avance y registra tambien el 0x01.
Todo queda en variants_log.jsonl.

Uso: python ps5_variants.py <ip_ps5> [segundos]
"""
import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time

PS5 = sys.argv[1]
SECS = int(sys.argv[2]) if len(sys.argv) > 2 else 420
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
DISC_PORT = 17476

me = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
me.connect((PS5, 9))
LOCAL = me.getsockname()[0]
me.close()
BCAST = LOCAL.rsplit(".", 1)[0] + ".255"

tmpl = bytes.fromhex(open("host_payloads.txt").readline().strip())
header, body = tmpl[:7], tmpl[7:]
cmd, _, kv = body.partition(b"\n")
parts = kv.split(b"\\")[1:]
KEYS = parts[0::2]
BASE = dict(zip(KEYS, parts[1::2]))
K0 = base64.b64decode(BASE[b"seckey"])
I0 = base64.b64decode(BASE[b"secid"])
K1, I1 = os.urandom(16), os.urandom(8)
K0x = K0[:-1] + bytes([K0[-1] ^ 0x01])

VARIANTS = {
    3074: ("PC-A", K0, I0),
    3075: ("PC-B", K0, I0),
    3076: ("PC-C", K0, I1),
    3077: ("PC-D", K1, I0),
    3078: ("PC-E", K0x, I0),
}

log = open("variants_log.jsonl", "a", encoding="utf-8")
t0 = time.time()


def rec(**kw):
    kw["t"] = round(time.time() - t0, 3)
    log.write(json.dumps(kw) + "\n")
    log.flush()


rec(event="start", variants={p: [n, k.hex(), i.hex()] for p, (n, k, i) in VARIANTS.items()})


def announce(port, name, key, sid):
    d = dict(BASE)
    addr = bytearray(base64.b64decode(d[b"hostaddr"]))
    p = port.to_bytes(2, "little")
    addr[0:4], addr[4:6] = socket.inet_aton(LOCAL), p
    addr[30:34], addr[34:36] = socket.inet_aton(LOCAL), p
    d[b"hostaddr"] = base64.b64encode(bytes(addr))
    d[b"hostname"] = name.encode()
    d[b"seckey"] = base64.b64encode(key)
    d[b"secid"] = base64.b64encode(sid)
    return header + cmd + b"\n" + b"".join(b"\\" + k + b"\\" + d[k] for k in KEYS)


ANN = {p: announce(p, *v) for p, v in VARIANTS.items()}
# La PS5 muestra una sola partida por IP: se anuncian de a una y se pasa a la
# siguiente cuando llega el saludo de la actual. PC-A va al principio y al final.
ORDER = [3074, 3075, 3076, 3077, 3078, 3074, 3074]
cur = {"i": 0, "switch_at": None}
stop = threading.Event()


def current_port():
    return ORDER[min(cur["i"], len(ORDER) - 1)]


def announcer():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((LOCAL, DISC_PORT))
    shown = None
    while not stop.is_set():
        if cur["switch_at"] and time.time() >= cur["switch_at"]:
            cur["switch_at"] = None
            cur["i"] += 1
            if cur["i"] >= len(ORDER):
                print("[i] todas las variantes probadas", flush=True)
                stop.set()
                cap.terminate()
                break
        p = current_port()
        if p != shown:
            shown = p
            print(f"[{time.time() - t0:6.1f}s] ahora se anuncia {VARIANTS[p][0]} "
                  f"(paso {cur['i'] + 1}/{len(ORDER)})", flush=True)
            rec(event="announce", name=VARIANTS[p][0], port=p, step=cur["i"])
        s.sendto(ANN[p], (BCAST, DISC_PORT))
        stop.wait(0.5)


threading.Thread(target=announcer, daemon=True).start()

socks = {}
for p in VARIANTS:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((LOCAL, p))
    socks[p] = s

cap = subprocess.Popen(
    [TSHARK, "-l", "-n", "-i", "Wi-Fi", "-f", f"udp and src host {PS5} and dst host {LOCAL}",
     "-T", "fields", "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.payload"],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
threading.Timer(SECS, lambda: (stop.set(), cap.terminate())).start()

print(f"[i] anunciando PC-A..PC-E desde {LOCAL} durante {SECS}s", flush=True)
seen = set()
for line in cap.stdout:
    f = line.rstrip("\n").split("\t")
    if len(f) < 3 or not f[2]:
        continue
    sport, dport, data = int(f[0]), int(f[1]), bytes.fromhex(f[2])
    if dport not in VARIANTS:
        continue
    name = VARIANTS[dport][0]
    rec(event="in", name=name, sport=sport, dport=dport, hex=data.hex())
    key = (dport, data if data[0] == 0x0D else data[:1] + data[8:])
    if key not in seen:
        seen.add(key)
        extra = f"  bloque {data[3:17].hex()}" if data[0] == 0x0D and len(data) == 29 else ""
        print(f"[{time.time() - t0:6.1f}s] {name} :{dport} tipo {data[0]:02x} len {len(data)}: "
              f"{data.hex(' ')}{extra}", flush=True)
    if data[0] == 0x0D and len(data) == 29:
        socks[dport].sendto(b"\x0c" + data[1:29], (PS5, sport))
        if dport == current_port() and cur["switch_at"] is None:
            rec(event="block", name=name, step=cur["i"], block=data[3:17].hex())
            cur["switch_at"] = time.time() + 10

print("[fin] detalle en variants_log.jsonl")
