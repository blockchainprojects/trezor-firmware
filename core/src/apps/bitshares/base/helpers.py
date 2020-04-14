from trezor import wire
from trezor.crypto import base58

from apps.common import HARDENED


def base58_encode(prefix: str, data: bytes) -> str:
    return "{}{}".format(prefix, base58.encode(data))


def base58_decode(prefix: str, data: str) -> bytes:
    data = data.replace(prefix, "", 1)
    return base58.decode(data)


def unicodify(data: str):
    r = []
    for s in data:
        o = ord(s)
        if (o <= 7) or (o == 11) or (o > 13 and o < 32):
            r.append("u%04x" % o)
        elif o == 8:
            r.append("b")
        elif o == 9:
            r.append("\t")
        elif o == 10:
            r.append("\n")
        elif o == 12:
            r.append("f")
        elif o == 13:
            r.append("\r")
        else:
            r.append(s)
    return bytes("".join(r), "utf-8")


def validate_full_path(path: list) -> bool:
    """
    Validates derivation path to equal the one described in
    SLIP-0048.
    """
    if len(path) != 5:
        return False

    if path[0] != 48 | HARDENED:
        return False

    if path[1] != 1 | HARDENED:
        return False

    if not (
        (path[2] == 0 | HARDENED)
        or (path[2] == 1 | HARDENED)
        or (path[2] == 3 | HARDENED)
    ):
        return False

    if (path[3] < HARDENED) or (path[3] >= 2 ** 32):
        return False

    if (path[4] < HARDENED) or (path[4] >= 2 ** 32):
        return False

    return True


def compress(pub_key: bytes) -> str:
    if pub_key[0] == 0x04 and len(pub_key) == 65:
        head = b"\x03" if pub_key[64] & 0x01 else b"\x02"
        compressed_pub_key = head + pub_key[1:33]
    elif pub_key[0] in [0x02, 0x03] and len(pub_key) == 33:
        compressed_pub_key = pub_key
    else:
        raise wire.DataError("invalid public key")
    return base58_encode("BTS", compressed_pub_key)
