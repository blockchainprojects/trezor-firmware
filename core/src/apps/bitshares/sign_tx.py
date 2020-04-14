from trezor import wire
from trezor.crypto.curve import secp256k1
from trezor.crypto.hashlib import sha256
from trezor.utils import HashWriter

from trezor.messages.BitSharesSignTx import BitSharesSignTx
from trezor.messages.BitSharesSignedTx import BitSharesSignedTx

from apps.common import paths
from . import CURVE

from .base.client import SignTransaction
from .base.helpers import base58_encode, validate_full_path
from .layout import ConfirmSignTransaction

from ubinascii import hexlify

if False:
    from apps.common import seed


async def sign_tx(
    ctx: wire.Context, msg: BitSharesSignTx, keychain: seed.Keychain
) -> BitSharesSignedTx:

    await paths.validate_path(ctx, validate_full_path, keychain, msg.address_n, CURVE)
    private_key = keychain.derive(msg.address_n).private_key()

    stx = SignTransaction(msg).parse()

    await ConfirmSignTransaction(stx).require_confirm(ctx)

    sha = HashWriter(sha256())
    await stx.write(sha)

    signature = _sign(private_key, sha.get_digest())

    return BitSharesSignedTx(signature)

def _sign(private_key: bytes, digest: bytes) -> str:
    signature = secp256k1.sign(
        private_key,
        digest,
        True,
        secp256k1.CANONICAL_SIG_EOS,  # TODO maybe change to bitshares
    )
    signature = hexlify(signature).decode("utf-8")
    return signature
