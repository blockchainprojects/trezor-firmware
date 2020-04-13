from trezor import wire

from trezor.messages.BitSharesSignTx import BitSharesSignTx
from trezor.messages.BitSharesPublicKey import BitSharesPublicKey

from .parsing import Node
from .types import ChainId
from .transaction import Transaction

from ucollections import OrderedDict


class SignTransaction(Node):
    def __init__(self, msg: BitSharesSignTx, field="sign_tx") -> None:
        self.data = msg
        self.nodes = OrderedDict([("chain_id", ChainId), ("tx", Transaction)])

    def parse(self) -> "SignTransaction":
        try:
            super().parse()
        except ValueError as e:
            ex_msg = self._make_error_msg(e)
            raise wire.DataError(ex_msg)

        return self

    async def write(self, w: Writer) -> None:
        for node in self.nodes.values():
            node.write(w)

    # TODO own exception for that, split unnecessary
    def _make_error_msg(self, e: ValueError) -> str:
        path = str(e).split(":")
        missing_attr = path.pop(-1)
        if not missing_attr:
            missing_attr = path.pop(-1)

        path = ":".join(path)
        ex_msg = 'Attribute "{}" is missing from {}.'.format(missing_attr, path)
        return ex_msg
