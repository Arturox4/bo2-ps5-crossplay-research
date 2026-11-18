"""Hace que el PC se una como cliente a una partida LAN hospedada por la PS5.

Objetivo: ver como responde un host REAL al saludo, en vez de adivinarlo.

Pasos:
  1. Pide la info de la partida (getinfo) y lee el infoResponse de la PS5:
     secid, seckey y hostaddr.
  2. Envia el saludo 0x0d (29 bytes) desde el puerto 3074 del PC. El bloque
     lleva 10 bytes al azar + tiger(IP_destino+puerto)[:4] (ver bd_tiger.py).
     Fases: destino local, destino publico (de hostaddr) y, como control,
     el bloque capturado viejo.
  3. En cuanto la PS5 contesta algo distinto, pasa a enviar el 0x01
     (01 02 00 00 00 00 XX XX + secid del host) y registra lo que venga.
  4. Si la PS5 le manda su propio 0x0d al PC, lo contesta con 0x0c (una de
     las respuestas que hicieron avanzar a la PS5 en pruebas anteriores).

Todo lo que entra y sale queda en client_log.jsonl y en client_run.pcapng.

Uso: python ps5_client.py <ip_ps5> [segundos_por_fase] [segundos_totales]
Antes: en la PS5, crear partida LAN de zombies y quedarse en el lobby.
"""
import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time

from bd_tiger import addr_tag

PS5 = sys.argv[1]
PER = int(sys.argv[2]) if len(sys.argv) > 2 else 12
TOTAL = int(sys.argv[3]) if len(sys.argv) > 3 else 150
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
DISC_PORT, GAME_PORT = 17476, 3074
CAPTURED_BLOCK = bytes.fromhex("5ec18b2614f851f966c823838310")
GETINFO = bytes.fromhex("570440ffffffff32") + b"getinfo xxx"

me = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
me.connect((PS5, 9))
LOCAL = me.getsockname()[0]
me.close()
BCAST = LOCAL.rsplit(".", 1)[0] + ".255"

log = open("client_log.jsonl", "a", encoding="utf-8")
log_lock = threading.Lock()
t0 = time.time()


def rec(direction, sport, dport, data, note=""):
    entry = {"t": round(time.time() - t0, 3), "dir": direction, "sport": sport,
             "dport": dport, "type": f"{data[0]:02x}" if data else "", "len": len(data),
             "hex": data.hex(), "note": note}
    with log_lock:
        log.write(json.dumps(entry) + "\n")
        log.flush()


def addr6(ip, port):
    return socket.inet_aton(ip) + port.to_bytes(2, "little")


def parse_info(data):
    body = data[7:]
    _, _, kv = body.partition(b"\n")
    parts = kv.split(b"\\")[1:]
    return {k.decode(): v for k, v in zip(parts[0::2], parts[1::2])}


# --- captura (Npcap lee por debajo del firewall) ----------------------------
pcap = subprocess.Popen([TSHARK, "-q", "-n", "-i", "Wi-Fi", "-f", f"udp and host {PS5}",
                         "-w", "client_run.pcapng"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
cap = subprocess.Popen(
    [TSHARK, "-l", "-n", "-i", "Wi-Fi", "-f", f"udp and src host {PS5}",
     "-T", "fields", "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.payload"],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

disc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
disc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
disc.bind((LOCAL, DISC_PORT))
game = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
game.bind((LOCAL, GAME_PORT))


def send_game(data, note=""):
    game.sendto(data, (PS5, GAME_PORT))
    rec("out", GAME_PORT, GAME_PORT, data, note)


state = {"info": None, "stage": "info", "phase_t0": None, "got": set()}
stop = threading.Event()
seen = set()


def reader():
    for line in cap.stdout:
        f = line.rstrip("\n").split("\t")
        if len(f) < 3 or not f[2]:
            continue
        sport, dport, data = int(f[0]), int(f[1]), bytes.fromhex(f[2])
        rec("in", sport, dport, data)
        key = (dport, data[:1], len(data))
        if key not in seen:
            seen.add(key)
            print(f"[{time.time() - t0:6.1f}s] NUEVO de PS5 :{sport}->:{dport} tipo "
                  f"{data[0]:02x} len {len(data)}: {data.hex(' ')}", flush=True)
        if dport == DISC_PORT and b"infoResponse" in data and state["info"] is None:
            state["info"] = parse_info(data)
            print(f"[i] partida PS5: {state['info'].get('hostname', b'?')!r} "
                  f"mapa {state['info'].get('mapname', b'?')!r}", flush=True)
        elif sport == GAME_PORT:
            t = data[0]
            if t == 0x0D and len(data) == 29:
                # la PS5 tambien saluda: contestar como hicimos de host
                send_game(b"\x0c" + data[1:29], "respuesta 0c al 0d de la PS5")
            elif state["stage"] == "hello" and t != 0x0D:
                print(f"[>] la PS5 contesto el saludo con tipo {t:02x}; paso a 0x01", flush=True)
                state["stage"] = "init"
            state["got"].add(t)


threading.Thread(target=reader, daemon=True).start()
time.sleep(1.5)  # que tshark arranque

# --- 1. getinfo -------------------------------------------------------------
print(f"[i] {LOCAL} -> PS5 {PS5}: pidiendo info de la partida", flush=True)
end = time.time() + 20
while state["info"] is None and time.time() < end:
    disc.sendto(GETINFO, (BCAST, DISC_PORT))
    disc.sendto(GETINFO, (PS5, DISC_PORT))
    time.sleep(1)
if state["info"] is None:
    print("[x] la PS5 no anuncio ninguna partida. Esta en el lobby de una partida LAN?")
    cap.terminate(); pcap.terminate()
    sys.exit(1)

info = state["info"]
secid = base64.b64decode(info["secid"])
hostaddr = base64.b64decode(info["hostaddr"])
local_ip = socket.inet_ntoa(hostaddr[0:4])
public_ip = socket.inet_ntoa(hostaddr[30:34])
print(f"[i] secid {secid.hex()}  hostaddr local {local_ip} publica {public_ip}", flush=True)

# --- 2. saludo 0x0d por fases -----------------------------------------------
# Bloque = 10 bytes que cambian en cada intento + tiger(IP_destino + puerto)[:4]
phases = [("tiger", local_ip), ("tiger", public_ip), ("capturado", local_ip)]
me_addr = addr6(LOCAL, GAME_PORT)
state["stage"] = "hello"
phase_i = 0
phase_t0 = time.time()
rand10 = os.urandom(10)
while state["stage"] == "hello" and time.time() - t0 < TOTAL:
    if time.time() - phase_t0 > PER:
        phase_i = (phase_i + 1) % len(phases)
        phase_t0 = time.time()
    kind, dst_ip = phases[phase_i]
    if kind == "tiger":
        block = rand10 + addr_tag(socket.inet_aton(dst_ip), GAME_PORT)
    else:
        block = CAPTURED_BLOCK
    pkt = b"\x0d\x02\x00" + block + me_addr + addr6(dst_ip, GAME_PORT)
    send_game(pkt, f"0d fase {kind}/{dst_ip}")
    if time.time() - phase_t0 < 1.05:
        print(f"[{time.time() - t0:6.1f}s] saludo 0x0d: bloque {kind}, destino {dst_ip}", flush=True)
    time.sleep(1)

# --- 3. paquete 0x01 con el secid del host ----------------------------------
if state["stage"] == "init":
    print(f"[i] fase que funciono: bloque {phases[phase_i][0]}, destino {phases[phase_i][1]}", flush=True)
    while time.time() - t0 < TOTAL:
        pkt = b"\x01\x02\x00\x00\x00\x00" + os.urandom(2) + secid
        send_game(pkt, "01 con secid del host")
        time.sleep(1)

stop.set()
cap.terminate()
pcap.terminate()
print("[resumen] tipos recibidos de la PS5 en 3074:", sorted(f"{t:02x}" for t in state["got"]))
print("[fin] detalle en client_log.jsonl y client_run.pcapng")
