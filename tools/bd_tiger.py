"""Tiger-192 (variante original, relleno 0x01), como el bdHashTiger192 de Demonware.

Las tablas S se leen del propio t6zm.exe de BO2 (no se copian al proyecto).
Uso en el saludo 0x0d: los ultimos 4 bytes del bloque = tiger(IP_destino + puerto_LE)[:4].
"""
import os, struct

GAME_EXE = r"C:\Program Files (x86)\Steam\steamapps\common\Call of Duty Black Ops II\t6zm.exe"


def _load_sboxes():
    data = open(GAME_EXE, "rb").read()
    i = data.find(struct.pack("<Q", 0x02AAB17CF7E90C5E))
    if i < 0:
        raise RuntimeError("no se encontraron las tablas Tiger en t6zm.exe")
    return [struct.unpack_from("<256Q", data, i + k * 2048) for k in range(4)]


T = _load_sboxes()
M = (1 << 64) - 1

def _round(a, b, c, x, mul):
    c ^= x
    a = (a - (T[0][c & 0xff] ^ T[1][(c >> 16) & 0xff] ^ T[2][(c >> 32) & 0xff] ^ T[3][(c >> 48) & 0xff])) & M
    b = (b + (T[3][(c >> 8) & 0xff] ^ T[2][(c >> 24) & 0xff] ^ T[1][(c >> 40) & 0xff] ^ T[0][(c >> 56) & 0xff])) & M
    b = (b * mul) & M
    return a, b, c

def _pass(a, b, c, x, mul):
    a, b, c = _round(a, b, c, x[0], mul); b, c, a = _round(b, c, a, x[1], mul)
    c, a, b = _round(c, a, b, x[2], mul); a, b, c = _round(a, b, c, x[3], mul)
    b, c, a = _round(b, c, a, x[4], mul); c, a, b = _round(c, a, b, x[5], mul)
    a, b, c = _round(a, b, c, x[6], mul); b, c, a = _round(b, c, a, x[7], mul)
    return a, b, c

def _ks(x):
    x = list(x)
    x[0] = (x[0] - (x[7] ^ 0xA5A5A5A5A5A5A5A5)) & M; x[1] ^= x[0]; x[2] = (x[2] + x[1]) & M
    x[3] = (x[3] - (x[2] ^ ((~x[1] & M) << 19) & M)) & M; x[4] ^= x[3]; x[5] = (x[5] + x[4]) & M
    x[6] = (x[6] - (x[5] ^ ((~x[4] & M) >> 23))) & M; x[7] ^= x[6]
    x[0] = (x[0] + x[7]) & M; x[1] = (x[1] - (x[0] ^ ((~x[7] & M) << 19) & M)) & M; x[2] ^= x[1]
    x[3] = (x[3] + x[2]) & M; x[4] = (x[4] - (x[3] ^ ((~x[2] & M) >> 23))) & M; x[5] ^= x[4]
    x[6] = (x[6] + x[5]) & M; x[7] = (x[7] - (x[6] ^ 0x0123456789ABCDEF)) & M
    return x

def _compress(state, blk):
    a, b, c = state
    x = struct.unpack("<8Q", blk)
    aa, bb, cc = a, b, c
    a, b, c = _pass(a, b, c, x, 5); x = _ks(x)
    c, a, b = _pass(c, a, b, x, 7); x = _ks(x)
    b, c, a = _pass(b, c, a, x, 9)
    return (a ^ aa) & M, (b - bb) & M, (c + cc) & M

def tiger(msg):
    st = (0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187)
    m = msg + b"\x01" + b"\0" * ((55 - len(msg)) % 64) + struct.pack("<Q", len(msg) * 8)
    for i in range(0, len(m), 64):
        st = _compress(st, m[i:i + 64])
    return struct.pack("<3Q", *st)


def addr_tag(ip_bytes, port):
    """Ultimos 4 bytes del bloque del saludo 0x0d."""
    return tiger(ip_bytes + port.to_bytes(2, "little"))[:4]


if __name__ == "__main__":
    assert tiger(b"").hex().upper() == "3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3"
    import socket
    assert addr_tag(socket.inet_aton("192.168.1.84"), 3074).hex() == "23838310"
    print("ok")
