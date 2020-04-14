from trezor import wire
from trezor.messages import MessageType

from apps.common import HARDENED

CURVE = "secp256k1"


def boot() -> None:
    ns = [[CURVE, 48 | HARDENED, 1 | HARDENED]]

    wire.add(MessageType.BitSharesGetPublicKey, __name__, "get_public_key", ns)
    wire.add(MessageType.BitSharesSignTx, __name__, "sign_tx", ns)