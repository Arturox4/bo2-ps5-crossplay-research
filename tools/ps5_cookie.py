"""Tercer paso del saludo contra una PS5 host: probar el CookieEcho (0x03).

Ya sabemos (ver resumen, seccion 4.10):
  PC  -> 0x0d  saludo NAT: 0d 02 00 | 10 al azar | tiger(dir_pub_PS5)[:4] | dir_PC | dir_pub_PS5
  PS5 -> 0x0c  eco del mismo paquete con tipo 0c
  PC  -> 0x01  Init:    01 02 0000 0000 | tagPC(2) | secid_host(8)
  PS5 -> 0x02  InitAck: 02 02 tagPC 0000 | hora_ms(4 LE) | firma?(4) | tagPS5 | tagPS5 | tagPC |
                        00000000 | dir_PC(6) | secid(8)          (38 bytes)

Para cada variante de CookieEcho: Init nuevo -> espera InitAck -> envia 0x03
armado a partir de ese InitAck -> registra cualquier respuesta que no sea 0x02.

Uso: python ps5_cookie.py <ip_ps5> [repeticiones_por_variante]
Antes: PS5 en el lobby de una partida LAN de zombies.
"""
import base64
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time

from bd_tiger import addr_tag

PS5 = sys.argv[1]
REPS = int(sys.argv[2]) if len(sys.argv) > 2 else 2
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
DISC_PORT, GAME_PORT = 17476, 3074
GETINFO = bytes.fromhex("570440ffffffff32") + b"getinfo xxx"


def hdr(t, tag):
    return bytes([t, 0x02]) + tag + b"\x00\x00"


# Cada variante recibe el InitAck (38 bytes) y devuelve el CookieEcho a enviar.
VARIANTS = {
    "hdrT+todo":        lambda a: hdr(3, a[14:16]) + a[6:],
    "hdrT+sin_secid":   lambda a: hdr(3, a[14:16]) + a[6:30],
    "hdrT+hasta_ceros": lambda a: hdr(3, a[14:16]) + a[6:24],
    "hdrT+cookie14":    lambda a: hdr(3, a[14:16]) + a[6:20],
    "hdrPC+todo":       lambda a: hdr(3, a[2:4]) + a[6:],
    "hdr0+todo":        lambda a: hdr(3, b"\0\0") + a[6:],
    "solo_tipo_03":     lambda a: b"\x03" + a[1:],
    "hdrT+desde_T":     lambda a: hdr(3, a[14:16]) + a[16:],
}

me = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
me.connect((PS5, 9))
LOCAL = me.getsockname()[0]
me.close()
BCAST = LOCAL.rsplit(".", 1)[0] + ".255"
log = open("cookie_log.jsonl", "a", encoding="utf-8")
t0 = time.time()


def rec(**kw):
    kw["t"] = round(time.time() - t0, 3)
    log.write(json.dumps(kw) + "\n")
    log.flush()


pcap = subprocess.Popen([TSHARK, "-q", "-n", "-i", "Wi-Fi", "-f", f"udp and host {PS5}",
                         "-w", "cookie_run.pcapng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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


def send(data, note):
    game.sendto(data, (PS5, GAME_PORT))
    rec(dir="out", hex=data.hex(), note=note)


threading.Thread(target=reader, daemon=True).start()
time.sleep(1.5)
end = time.time() + 20
while not info and time.time() < end:
    disc.sendto(GETINFO, (BCAST, DISC_PORT))
    disc.sendto(GETINFO, (PS5, DISC_PORT))
    time.sleep(1)
if not info:
    print("[x] la PS5 no anuncio partida; esta en el lobby?")
    cap.terminate(); pcap.terminate(); sys.exit(1)

secid = base64.b64decode(info["secid"])
ha = base64.b64decode(info["hostaddr"])
pub = ha[30:36]
me6 = socket.inet_aton(LOCAL) + GAME_PORT.to_bytes(2, "little")
print(f"[i] PS5 secid {secid.hex()} dir publica {socket.inet_ntoa(pub[:4])}", flush=True)


def wait_for(pred, secs):
    end = time.time() + secs
    got = []
    while time.time() < end:
        try:
            d = inq.get(timeout=max(0.05, end - time.time()))
        except queue.Empty:
            break
        got.append(d)
        if pred(d):
            return d, got
    return None, got


# saludo NAT
hello = b"\x0d\x02\x00" + os.urandom(10) + addr_tag(pub[:4], GAME_PORT) + me6 + pub
for _ in range(5):
    send(hello, "0d")
    d, _ = wait_for(lambda d: d[0] == 0x0C, 1.0)
    if d:
        print("[ok] eco 0c recibido", flush=True)
        break
else:
    print("[!] sin eco 0c; sigo igual con el Init", flush=True)

results = {}
for name, build in VARIANTS.items():
    for rep in range(REPS):
        while not inq.empty():
            inq.get_nowait()
        tag = os.urandom(2)
        send(b"\x01\x02\x00\x00\x00\x00" + tag + secid, f"init {name}")
        ack, _ = wait_for(lambda d: d[0] == 0x02 and len(d) == 38 and d[2:4] == tag, 1.5)
        if not ack:
            print(f"[{name}] sin InitAck", flush=True)
            continue
        echo = build(ack)
        send(echo, f"cookie {name}")
        _, got = wait_for(lambda d: d[0] not in (0x02, 0x0C, 0x0D), 2.5)
        new = [d for d in got if d[0] not in (0x02,)]
        tipos = sorted({f"{d[0]:02x}/{len(d)}" for d in new})
        results.setdefault(name, set()).update(tipos)
        print(f"[{name} #{rep + 1}] envie {echo.hex()} -> respuestas {tipos or 'ninguna'}", flush=True)
        for d in new:
            if d[0] not in (0x0C, 0x0D):
                print(f"      NUEVO tipo {d[0]:02x} len {len(d)}: {d.hex(' ')}", flush=True)

cap.terminate(); pcap.terminate()
print("[resumen]")
for k, v in results.items():
    print(f"   {k:<18} {sorted(v) or '-'}")
