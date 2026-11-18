"""El PC hace de host DTLS completo y la PS5 se une: captura sus primeros datos.

Anuncia "PC-HOST" con seckey/secid propios y contesta todo el saludo:
  PS5 0x0d -> eco 0x0c
  PS5 0x01 Init       -> 0x02 InitAck (cookie con hora y firma inventadas)
  PS5 0x03 CookieEcho -> 0x04 CookieAck (clave ECC-224 propia + secid)
Clave de sesion = Tiger192(ECDH(x) || seckey_propio). Datos 0x06 =
cab | IV(8) | u16 largo | 3DES-CBC. El primer mensaje de la PS5 es "joinParty";
el script le contesta "partyaccept" probando varias formas de encapsularlo y
avisa si la PS5 manda un mensaje distinto.
Todo queda en host_log.jsonl y host_run.pcapng.

Uso: python ps5_host.py <ip_ps5> [segundos] [--probe]
  --probe: en vez de partyaccept, una sonda por asociacion para ver si la PS5
           rechaza nuestros paquetes de datos.
En la PS5: buscador de partidas LAN de zombies -> unirse a PC-HOST.
"""
import base64
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from bd_tiger import tiger
from ps5_assoc_lib import CURVE, ecc_export_public, ecc_import_public, hdr

PS5 = sys.argv[1]
SECS = int(sys.argv[2]) if len(sys.argv) > 2 else 240
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
DISC_PORT, GAME_PORT = 17476, 3074

me = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
me.connect((PS5, 9))
LOCAL = me.getsockname()[0]
me.close()
BCAST = LOCAL.rsplit(".", 1)[0] + ".255"
me6 = socket.inet_aton(LOCAL) + GAME_PORT.to_bytes(2, "little")

SECKEY, SECID = os.urandom(16), os.urandom(8)
PRIV = ec.generate_private_key(CURVE)
MY_PUB = ecc_export_public(PRIV.public_key())
MY_TAG = os.urandom(2)

# --- anuncio (plantilla real de la PS5, con nuestros datos) -----------------
tmpl = bytes.fromhex(open("host_payloads.txt").readline().strip())
header, body = tmpl[:7], tmpl[7:]
cmd, _, kv = body.partition(b"\n")
parts = kv.split(b"\\")[1:]
KEYS = parts[0::2]
d = dict(zip(KEYS, parts[1::2]))
addr = bytearray(base64.b64decode(d[b"hostaddr"]))
addr[0:6] = me6
addr[30:36] = me6
d[b"hostaddr"] = base64.b64encode(bytes(addr))
d[b"hostname"] = b"PC-HOST"
d[b"seckey"] = base64.b64encode(SECKEY)
d[b"secid"] = base64.b64encode(SECID)
ANNOUNCE = header + cmd + b"\n" + b"".join(b"\\" + k + b"\\" + d[k] for k in KEYS)

log = open("host_log.jsonl", "a", encoding="utf-8")
t0 = time.time()


def rec(**kw):
    kw["t"] = round(time.time() - t0, 3)
    log.write(json.dumps(kw) + "\n")
    log.flush()


rec(event="start", seckey=SECKEY.hex(), secid=SECID.hex(), my_tag=MY_TAG.hex())
stop = threading.Event()


def announcer():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((LOCAL, DISC_PORT))
    while not stop.is_set():
        s.sendto(ANNOUNCE, (BCAST, DISC_PORT))
        stop.wait(0.5)


threading.Thread(target=announcer, daemon=True).start()
game = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
game.bind((LOCAL, GAME_PORT))
pcap = subprocess.Popen([TSHARK, "-q", "-n", "-i", "Wi-Fi", "-f", f"udp and host {PS5}",
                         "-w", "host_run.pcapng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
cap = subprocess.Popen([TSHARK, "-l", "-n", "-i", "Wi-Fi", "-f", f"udp and src host {PS5} and dst port {GAME_PORT}",
                        "-T", "fields", "-e", "udp.srcport", "-e", "udp.payload"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
def shutdown():
    stop.set()
    for proc in (cap, pcap):  # tshark deja hijos dumpcap vivos: matar el arbol completo
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)


threading.Timer(SECS, shutdown).start()


def send(data, port, note):
    game.sendto(data, (PS5, port))
    rec(dir="out", hex=data.hex(), note=note)


def decrypt(pkt, key):
    """0x06 = cab(6) | IV(8) | u16 LE largo | 3DES-CBC(clave de sesion, IV)."""
    n = struct.unpack_from("<H", pkt, 14)[0]
    dec = Cipher(TripleDES(key), modes.CBC(pkt[6:14])).decryptor()
    return dec.update(pkt[16:16 + n]) + dec.finalize()


def encrypt_packet(pt, key, vtag, ctr):
    pt = pt + b"\0" * (-len(pt) % 8)
    iv = os.urandom(8)
    enc = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(pt) + enc.finalize()
    return bytes([6, 2]) + vtag + ctr.to_bytes(2, "little") + iv + len(ct).to_bytes(2, "little") + ct


# Formas de responder "partyaccept". El header de 8 bytes del texto plano es un
# nonce del emisor (PRNG de sesion; el receptor lo descarta o no lo reproducimos),
# asi que va al azar. El joinParty de la PS5 es DESNUDO: [8B nonce][cmd\0][args
# binarios]; NO lleva ffffffff ni digito inicial. Se imita esa estructura.
def R8():
    return os.urandom(8)


ACCEPT = b"2partyaccept 0 1"          # forma OOB estilo PC (para PROBES y variante raw)
PROTO = (2097).to_bytes(4, "little")  # 31 08 00 00, el protocolo que trae el joinParty


def jp_tail():
    """Cola binaria del joinParty de la PS5 tras el nombre 'joinParty\\0'."""
    b = st["base"] or b""
    i = b.find(b"\x00")
    return b[i + 1:] if i >= 0 else b""


# (nombre, modo, build) -- modo 'enc' = cifrada en el canal de datos; 'raw' = cruda.
VARIANTS = [
    ("enc desnudo partyaccept + cola joinParty", "enc", lambda: R8() + b"partyaccept\x00" + jp_tail()),
    ("enc desnudo partyaccept + proto + secid",  "enc", lambda: R8() + b"partyaccept\x00" + PROTO + SECID),
    ("enc desnudo partyaccept solo",             "enc", lambda: R8() + b"partyaccept\x00"),
    ("enc desnudo pha + cola joinParty",         "enc", lambda: R8() + b"pha\x00" + jp_tail()),
    ("raw OOB ffffffff 2partyaccept",            "raw", lambda: b"\xff\xff\xff\xff" + ACCEPT + b"\x00"),
    ("raw 570404 ffffffff 2partyaccept",         "raw", lambda: bytes.fromhex("570404") + b"\xff\xff\xff\xff" + ACCEPT + b"\x00"),
]
st = {"key": None, "vtag": None, "port": GAME_PORT, "ctr": 1, "base": None, "variant": "-", "cycling": False,
      "n_data": 0}


def send_data(pt, note):
    pkt = encrypt_packet(pt, st["key"], st["vtag"], st["ctr"])
    st["ctr"] += 1
    send(pkt, st["port"], note)


PROBE = "--probe" in sys.argv
PROBES = [
    ("control: no mandar nada", None),
    ("basura con cabecera valida", lambda: bytes([6, 2]) + st["vtag"] + st["ctr"].to_bytes(2, "little")
     + os.urandom(8) + (48).to_bytes(2, "little") + os.urandom(48)),
    ("cifrado bien: azar8+2partyaccept", lambda: encrypt_packet(R8() + ACCEPT + b"\0", st["key"], st["vtag"], st["ctr"])),
    ("vtag equivocado", lambda: encrypt_packet(R8() + ACCEPT + b"\0", st["key"], b"\x00\x00", st["ctr"])),
    ("control otra vez: nada", None),
]
st["probe_i"] = 0


def run_probe(assoc_t0):
    """Una prueba por asociacion: espera 4 s, manda 1 paquete y cuenta lo que sigue."""
    i = st["probe_i"]
    st["probe_i"] += 1
    if i >= len(PROBES):
        return
    name, build = PROBES[i]
    time.sleep(4)
    before = st["n_data"]
    t_send = time.time()
    if build:
        pkt = build()
        st["ctr"] += 1
        send(pkt, st["port"], f"sonda {name}")
    st["variant"] = name
    time.sleep(8)
    after = st["n_data"] - before
    print(f"[sonda {i + 1}] {name}: la PS5 mando {after} paquetes de datos en los 8 s siguientes", flush=True)
    rec(event="probe", name=name, data_after=after)


def cycle_variants():
    if PROBE:
        return
    for rnd in range(3):
        for name, mode, build in VARIANTS:
            if stop.is_set():
                return
            st["variant"] = name
            before = st["n_data"]
            print(f"[>] {name} (ronda {rnd + 1})", flush=True)
            for _ in range(2):            # como el host: mensaje no confiable, 2 veces
                data = build()
                if mode == "raw":
                    send(data, st["port"], f"raw {name}")
                else:
                    send_data(data, f"enc {name}")
                time.sleep(1.0)
            time.sleep(2.0)
            print(f"    (PS5 mando {st['n_data'] - before} paquetes mientras)", flush=True)


session = None
init_ack = None
seen = set()
print(f"[i] anunciando PC-HOST desde {LOCAL}; secid {SECID.hex()} seckey {SECKEY.hex()}", flush=True)
for line in cap.stdout:
    f = line.rstrip("\n").split("\t")
    if len(f) < 2 or not f[1]:
        continue
    sport, pkt = int(f[0]), bytes.fromhex(f[1])
    rec(dir="in", sport=sport, hex=pkt.hex())
    t = pkt[0]
    key = (t, len(pkt))
    if key not in seen:
        seen.add(key)
        print(f"[{time.time() - t0:6.1f}s] PS5 tipo {t:02x} len {len(pkt)}: {pkt[:60].hex(' ')}"
              f"{' ...' if len(pkt) > 60 else ''}", flush=True)
    if t == 0x0D and len(pkt) == 29:
        send(b"\x0c" + pkt[1:], sport, "eco 0c")
    elif t == 0x01 and len(pkt) == 16:
        peer_tag = pkt[6:8]
        ts = struct.pack("<I", int((time.time() - t0) * 1000) & 0xFFFFFFFF)
        ps5_addr = socket.inet_aton(PS5) + sport.to_bytes(2, "little")
        init_ack = (hdr(2, peer_tag) + ts + os.urandom(4) + MY_TAG + MY_TAG + peer_tag +
                    b"\0\0\0\0" + ps5_addr + SECID)
        send(init_ack, sport, "InitAck")
    elif t == 0x03 and len(pkt) == 189:
        echoed, common, sid, eccblob = pkt[6:44], pkt[44:81], pkt[81:89], pkt[89:189]
        ks, ps5_pub = ecc_import_public(eccblob)
        shared = PRIV.exchange(ec.ECDH(), ps5_pub)
        session = tiger(shared + SECKEY)
        peer_tag = echoed[2:4]
        send(hdr(4, peer_tag) + MY_PUB + SECID, sport, "CookieAck")
        print(f"[ok] CookieEcho valido (keysize {ks}, secid {'OK' if sid == SECID else sid.hex()}); "
              f"commonaddr PS5 {common.hex()}", flush=True)
        print(f"[ok] CLAVE DE SESION {session.hex()}", flush=True)
        rec(event="session", session=session.hex(), shared=shared.hex(), common=common.hex())
        st.update(key=session, vtag=peer_tag, port=sport, ctr=1)
        if PROBE:
            threading.Thread(target=run_probe, args=(time.time(),), daemon=True).start()
    elif t == 0x06 and session:
        st["n_data"] += 1
        pt = decrypt(pkt, session)
        body = pt[8:]
        rec(event="data", hex=pkt.hex(), pt=pt.hex(), variant=st["variant"])
        if st["base"] is None:
            st["base"] = body
            print(f"[ok] primer mensaje de la PS5: {body!r}", flush=True)
        elif body != st["base"] and body not in seen:
            seen.add(body)
            print(f"[!!] MENSAJE NUEVO tras '{st['variant']}' (len {len(pt)}): {pt.hex()}\n     {body!r}", flush=True)
        if not st["cycling"]:
            st["cycling"] = True
            threading.Thread(target=cycle_variants, daemon=True).start()

stop.set()
print("[fin] detalle en host_log.jsonl y host_run.pcapng")
