from trezor.messages.BitSharesTx import BitSharesTx
from trezor.messages.BitSharesTxHeader import BitSharesTxHeader

from .parsing import Node
from .operations import Operation
from .types import (
    Uint8,
    Uint16,
    Uint32,
    VarInt32,
    Bytes,
    Array,
    ChainId,
    Optional,
    EmptyExtension,
)

from ucollections import OrderedDict

if False:
    from typing import List


class Transaction(Node):
    def __init__(self, msg: BitSharesTx) -> None:
        self.data = msg

        self.nodes = OrderedDict(
            [
                ("header", TransactionHeader),
                ("operations", Array(Operation)),
                ("extensions", EmptyExtension),
            ]
        )


class TransactionHeader(Node):
    def __init__(self, msg: BitSharesTxHeader) -> None:
        self.data = msg

        self.nodes = OrderedDict(
            [
                ("ref_block_num", Uint16),
                ("ref_block_prefix", Uint32),
                ("expiration", Uint32),
            ]
        )
