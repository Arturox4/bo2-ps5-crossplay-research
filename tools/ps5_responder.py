"""Respondedor experimental del saludo de conexion de BO2 PS5.

- Anuncia la partida falsa (infoResponse por broadcast, puerto 17476).
- Lee con tshark (Npcap) todo lo que la PS5 envia por UDP al PC.
- Contesta el saludo tipo 0x0d desde el puerto 3074 probando variantes,
  y registra cualquier paquete nuevo que la PS5 emita como reaccion.

Formato del saludo (29 bytes), interpretacion de trabajo:
    tipo(1) version(2) hmac(10) seguimiento(4) dir_origen(6) dir_destino(6)

Uso: python ps5_responder.py <ip_ps5> [segundos_por_variante] [variantes]
     variantes: lista separada por comas de tipo[s], p.ej. "0e,0es,0c,0f,0d"
     (sufijo 's' = intercambia origen y destino en la respuesta)
"""
import base64
import socket
import subprocess
import sys
import threading
import time

PS5 = sys.argv[1]
PER = int(sys.argv[2]) if len(sys.argv) > 2 else 15
VARIANTS = (sys.argv[3] if len(sys.argv) > 3 else "0e,0es,0c,0cs,0f,0d").split(",")
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
DISC_PORT, GAME_PORT = 17476, 3074

me = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
me.connect((PS5, 9))
LOCAL = me.getsockname()[0]
me.close()
BCAST = LOCAL.rsplit(".", 1)[0] + ".255"

# --- anuncio de la partida falsa -------------------------------------------
tmpl = bytes.fromhex(open("host_payloads.txt").readline().strip())
header, body = tmpl[:7], tmpl[7:]
cmd, _, kv = body.partition(b"\n")
parts = kv.split(b"\\")[1:]
keys = parts[0::2]
d = dict(zip(keys, parts[1::2]))
addr = bytearray(base64.b64decode(d[b"hostaddr"]))
addr[0:4] = socket.inet_aton(LOCAL)
addr[30:34] = socket.inet_aton(LOCAL)
d[b"hostaddr"] = base64.b64encode(bytes(addr))
d[b"hostname"] = b"PC-TEST"
ANNOUNCE = header + cmd + b"\n" + b"".join(b"\\" + k + b"\\" + d[k] for k in keys)

stop = threading.Event()


def announcer():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((LOCAL, DISC_PORT))
    while not stop.is_set():
        s.sendto(ANNOUNCE, (BCAST, DISC_PORT))
        stop.wait(0.5)


threading.Thread(target=announcer, daemon=True).start()

# --- respondedor ------------------------------------------------------------
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tx.bind((LOCAL, GAME_PORT))

cap = subprocess.Popen(
    [TSHARK, "-l", "-n", "-i", "Wi-Fi",
     "-f", f"udp and src host {PS5} and dst host {LOCAL}",
     "-T", "fields", "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.payload"],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

t0 = time.time()
total = PER * len(VARIANTS)
seen = {}
counts = {}


def variant_now():
    i = min(int((time.time() - t0) // PER), len(VARIANTS) - 1)
    return VARIANTS[i]


def watchdog():
    while time.time() - t0 < total:
        time.sleep(0.5)
    stop.set()
    cap.terminate()


threading.Thread(target=watchdog, daemon=True).start()
print(f"[i] {LOCAL} respondiendo a {PS5}; variantes {VARIANTS}, {PER}s cada una", flush=True)

last_var = None
for line in cap.stdout:
    f = line.rstrip("\n").split("\t")
    if len(f) < 3 or not f[2]:
        continue
    sport, dport, data = int(f[0]), int(f[1]), bytes.fromhex(f[2])
    var = variant_now()
    if var != last_var:
        print(f"[{time.time() - t0:5.1f}s] --- variante {var} ---", flush=True)
        last_var = var
    key = (dport, data)
    counts[(var, data[0], len(data), dport)] = counts.get((var, data[0], len(data), dport), 0) + 1
    if key not in seen:
        seen[key] = var
        print(f"[{time.time() - t0:5.1f}s] NUEVO de PS5 :{sport}->:{dport} tipo {data[0]:02x} "
              f"len {len(data)} (variante {var}): {data.hex(' ')}", flush=True)
    if data[0] == 0x0D and len(data) == 29:
        rtype = int(var[:2], 16)
        src, dst = data[17:23], data[23:29]
        if var.endswith("s"):
            src, dst = dst, src
        reply = bytes([rtype]) + data[1:17] + src + dst
        tx.sendto(reply, (PS5, sport))

print("[resumen] (variante, tipo, len, puerto destino) -> cantidad")
for k, n in sorted(counts.items()):
    print(f"    {k[0]:<4} tipo {k[1]:02x} len {k[2]:<4} :{k[3]}  x{n}")
print(f"[fin] paquetes distintos de la PS5: {len(seen)}")
