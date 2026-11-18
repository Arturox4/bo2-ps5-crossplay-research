"""Piezas comunes de la asociacion DTLS de Demonware (ECC-224 en formato libtomcrypt)."""
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP224R1()  # "ECC-224" de libtomcrypt; secreto de 28 bytes
KEYSIZE = 28


# --- DER minimo, como lo escribe/lee libtomcrypt (ecc_export PK_PUBLIC) -----
def der_len(n):
    return bytes([n]) if n < 0x80 else bytes([0x81, n])


def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\0" + b
    return b"\x02" + der_len(len(b)) + b


def ecc_export_public(pub):
    n = pub.public_numbers()
    body = b"\x03\x02\x07\x00" + der_int(KEYSIZE) + der_int(n.x) + der_int(n.y)
    out = b"\x30" + der_len(len(body)) + body
    assert len(out) <= 100
    return out + b"\0" * (100 - len(out))


def ecc_import_public(blob):
    assert blob[0] == 0x30
    i = 2 if blob[1] < 0x80 else 3
    vals = []
    while len(vals) < 4:
        tag, ln = blob[i], blob[i + 1]
        vals.append((tag, blob[i + 2:i + 2 + ln]))
        i += 2 + ln
    (_, flags), (_, ks), (_, x), (_, y) = vals
    return int.from_bytes(ks, "big"), ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), CURVE).public_key()


def hdr(t, vtag):
    return bytes([t, 0x02]) + vtag + b"\x00\x00"
