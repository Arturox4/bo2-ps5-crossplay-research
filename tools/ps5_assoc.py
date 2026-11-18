"""Asociacion DTLS completa de Demonware contra una PS5 host (cliente = PC).

Formato sacado de t6zm.exe (copia de Plutonium) con Ghidra; ver resumen 4.11.

  PC  -> 0x0d  saludo NAT (bloque: 10 al azar + tiger(dir_pub_PS5)[:4])
  PS5 -> 0x0c  eco
  PC  -> 0x01  Init       = cab(01,tag 0) | initTag(2) | secid_host(8)
  PS5 -> 0x02  InitAck    = cab(02,initTag) | hora(4) | firma(4) | 5 x u16 | dir(6) | secid(8)
  PC  -> 0x03  CookieEcho = cab(03,tagPS5) | InitAck completo (38) | commonaddr(37) |
                            secid_host(8) | clave ECC publica DER (relleno a 100)
  PS5 -> 0x04  CookieAck  = cab(04,..) | clave ECC publica del host (100) | 8 bytes
  Clave de sesion = Tiger192(secreto ECDH (x, 28 bytes) || seckey del host (16))

cab(tipo, vtag) = tipo(1) 02 vtag(2, little endian) 0000

Uso: python ps5_assoc.py <ip_ps5> [segundos_escucha_final]
Antes: PS5 en el lobby de una partida LAN de zombies.
"""
import base64
import json
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import time

from cryptography.hazmat.primitives.asymmetric import ec

from bd_tiger import addr_tag, tiger
from ps5_assoc_lib import CURVE, ecc_export_public, ecc_import_public, hdr

PS5 = sys.argv[1]
LISTEN = int(sys.argv[2]) if len(sys.argv) > 2 else 20
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
DISC_PORT, GAME_PORT = 17476, 3074
GETINFO = bytes.fromhex("570440ffffffff32") + b"getinfo xxx"
# --- red ----------------------------------------------------------------------
me = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
me.connect((PS5, 9))
LOCAL = me.getsockname()[0]
me.close()
BCAST = LOCAL.rsplit(".", 1)[0] + ".255"
log = open("assoc_log.jsonl", "a", encoding="utf-8")
t0 = time.time()


def rec(**kw):
    kw["t"] = round(time.time() - t0, 3)
    log.write(json.dumps(kw) + "\n")
    log.flush()


pcap = subprocess.Popen([TSHARK, "-q", "-n", "-i", "Wi-Fi", "-f", f"udp and host {PS5}",
                         "-w", "assoc_run.pcapng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
cap = subprocess.Popen([TSHARK, "-l", "-n", "-i", "Wi-Fi", "-f", f"udp and src host {PS5}",
                        "-T", "fields", "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.payload"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
disc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
disc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
disc.bind((LOCAL, DISC_PORT))
game = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
game.bind((LOCAL, GAME_PORT))
inq = queue.Queue()
info = {}


def send(data, note):
    game.sendto(data, (PS5, GAME_PORT))
    rec(dir="out", hex=data.hex(), note=note)


def reader():
    for line in cap.stdout:
        f = line.rstrip("\n").split("\t")
        if len(f) < 3 or not f[2]:
            continue
        sport, dport, data = int(f[0]), int(f[1]), bytes.fromhex(f[2])
        rec(dir="in", sport=sport, dport=dport, hex=data.hex())
        if dport == DISC_PORT and b"infoResponse" in data and not info:
            kv = data[7:].partition(b"\n")[2].split(b"\\")[1:]
            info.update({k.decode(): v for k, v in zip(kv[0::2], kv[1::2])})
        elif sport == GAME_PORT:
            if data[0] == 0x0D and len(data) == 29:
                send(b"\x0c" + data[1:], "eco 0c")
            inq.put(data)


def wait_for(pred, secs):
    end = time.time() + secs
    while time.time() < end:
        try:
            d = inq.get(timeout=max(0.05, end - time.time()))
        except queue.Empty:
            break
        if pred(d):
            return d
        if d[0] not in (0x02, 0x0C, 0x0D):
            print(f"   (otro) tipo {d[0]:02x} len {len(d)}: {d.hex(' ')}", flush=True)
    return None


def stop(code=0):
    for proc in (cap, pcap):  # tshark deja hijos dumpcap: matar el arbol completo
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    sys.exit(code)


threading.Thread(target=reader, daemon=True).start()
time.sleep(1.5)
end = time.time() + 20
while not info and time.time() < end:
    disc.sendto(GETINFO, (BCAST, DISC_PORT)); disc.sendto(GETINFO, (PS5, DISC_PORT)); time.sleep(1)
if not info:
    print("[x] la PS5 no anuncio partida; esta en el lobby?"); stop(1)

secid = base64.b64decode(info["secid"])
seckey = base64.b64decode(info["seckey"])
ha = base64.b64decode(info["hostaddr"])
pub = ha[30:36]
me6 = socket.inet_aton(LOCAL) + GAME_PORT.to_bytes(2, "little")
common = me6 + bytes.fromhex("00ff00ff0000") * 4 + me6 + b"\x02"   # 37 bytes, como hostaddr
print(f"[i] PS5 secid {secid.hex()} seckey {seckey.hex()} pub {socket.inet_ntoa(pub[:4])}", flush=True)

# 1. saludo NAT
hello = b"\x0d\x02\x00" + os.urandom(10) + addr_tag(pub[:4], GAME_PORT) + me6 + pub
for _ in range(5):
    send(hello, "0d")
    if wait_for(lambda d: d[0] == 0x0C, 1.0):
        print("[1] eco 0c recibido", flush=True); break
else:
    print("[1] sin eco 0c (puede que la PS5 ya conozca esta direccion); sigo", flush=True)

priv = ec.generate_private_key(CURVE)
my_pub = ecc_export_public(priv.public_key())

for attempt in range(1, 4):
    # 2. Init -> InitAck
    tag = os.urandom(2)
    send(b"\x01\x02\x00\x00\x00\x00" + tag + secid, "init")
    ack = wait_for(lambda d: d[0] == 0x02 and len(d) == 38 and d[2:4] == tag, 2.0)
    if not ack:
        print(f"[2] intento {attempt}: sin InitAck"); continue
    host_tag = ack[14:16]
    print(f"[2] InitAck: {ack.hex(' ')}", flush=True)
    # 3. CookieEcho
    echo = hdr(3, host_tag) + ack + common + secid + my_pub
    send(echo, "cookie echo")
    print(f"[3] CookieEcho enviado ({len(echo)} bytes)", flush=True)
    cack = wait_for(lambda d: d[0] == 0x04, 3.0)
    if not cack:
        print(f"[3] intento {attempt}: sin CookieAck", flush=True); continue
    print(f"[4] CookieAck ({len(cack)} bytes): {cack.hex(' ')}", flush=True)
    ks, host_pub = ecc_import_public(cack[6:106])
    shared = priv.exchange(ec.ECDH(), host_pub)
    session = tiger(shared + seckey)
    print(f"[4] clave ECC del host: tamano {ks}; ultimos 8 bytes del CookieAck {cack[106:114].hex()}")
    print(f"[4] secreto ECDH {shared.hex()}")
    print(f"[4] CLAVE DE SESION (Tiger192) {session.hex()}", flush=True)
    rec(event="session", shared=shared.hex(), session=session.hex(), host_tag=host_tag.hex(),
        my_tag=tag.hex(), cookieack=cack.hex())
    break
else:
    print("[x] no se completo la asociacion"); stop(2)

# 5. escuchar lo que venga despues (datos cifrados, heartbeats...)
print(f"[5] escuchando {LISTEN}s lo que mande la PS5...", flush=True)
seen = set()
end = time.time() + LISTEN
while time.time() < end:
    try:
        d = inq.get(timeout=0.5)
    except queue.Empty:
        continue
    k = (d[0], len(d))
    if k not in seen:
        seen.add(k)
        print(f"   tipo {d[0]:02x} len {len(d)}: {d[:64].hex(' ')}{' ...' if len(d) > 64 else ''}", flush=True)
stop(0)
