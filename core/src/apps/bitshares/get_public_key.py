from trezor import wire
from trezor.crypto.curve import secp256k1
from trezor.messages.BitSharesGetPublicKey import BitSharesGetPublicKey
from trezor.messages.BitSharesPublicKey import BitSharesPublicKey

from apps.common import paths
from . import CURVE
from .layout import ConfirmGetPublicKey
from .base.helpers import compress, validate_full_path

if False:
    from typing import Tuple
    from trezor.crypto import bip32
    from apps.common import seed


async def get_public_key(
    ctx: wire.Context, msg: BitSharesGetPublicKey, keychain: seed.Keychain
) -> BitSharesPublicKey:

    if not msg.address_n:
        raise wire.DataError("address_n is missing.")

    await paths.validate_path(ctx, validate_full_path, keychain, msg.address_n, CURVE)

    node = keychain.derive(msg.address_n)
    pub, raw_pub = _get_public_key(node)

    if msg.show_display:
        await ConfirmGetPublicKey(pub).require_confirm(ctx)

    return BitSharesPublicKey(pub, raw_pub)


def _get_public_key(node: bip32.HDNode) -> Tuple[str, bytes]:
    seckey = node.private_key()
    raw = secp256k1.publickey(seckey, True)
    pub = compress(raw)
    return pub, raw
