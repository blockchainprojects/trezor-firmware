from common import *

from trezor.crypto.curve import secp256k1
from trezor.crypto.hashlib import sha256
from trezor.utils import HashWriter

from apps.bitshares import CURVE

from apps.bitshares.base.helpers import base58_encode, base58_decode
from apps.bitshares.base.types import *
from apps.bitshares.base.transaction import *
from apps.bitshares.base.operations import *
from apps.bitshares.base.client import *

# fmt:off
from trezor.messages.BitSharesPublicKey import BitSharesPublicKey
from trezor.messages.BitSharesPublicKey import BitSharesPublicKey
from trezor.messages.BitSharesSignTx import BitSharesSignTx
from trezor.messages.BitSharesTxHeader import BitSharesTxHeader
from trezor.messages.BitSharesTx import BitSharesTx
from trezor.messages.BitSharesOperation import BitSharesOperation
from trezor.messages.BitSharesTransferOperation import BitSharesTransferOperation
from trezor.messages.BitSharesLimitOrderCreateOperation import BitSharesLimitOrderCreateOperation
from trezor.messages.BitSharesLimitOrderCancelOperation import BitSharesLimitOrderCancelOperation
from trezor.messages.BitSharesAccountCreateOperation import BitSharesAccountCreateOperation
from trezor.messages.BitSharesAccountUpdateOperation import BitSharesAccountUpdateOperation
from trezor.messages.BitSharesAccountOptions import BitSharesAccountOptions
from trezor.messages.BitSharesPermission import BitSharesPermission
from trezor.messages.BitSharesAccountAuthority import BitSharesAccountAuthority
from trezor.messages.BitSharesKeyAuthority import BitSharesKeyAuthority
from trezor.messages.BitSharesMemo import BitSharesMemo
from trezor.messages.BitSharesAsset import BitSharesAsset
from trezor.messages.BitSharesSignedTx import BitSharesSignedTx
# fmt:on

from ubinascii import hexlify, unhexlify
import utime


class TestWriter:
    def __init__(self) -> None:
        self.buf = []

    def append(self, b: int) -> None:
        self.buf.append(b)

    def extend(self, buf: bytes) -> None:
        self.buf.extend(buf)

    def write(self, buf: bytes) -> None:  # alias for extend()
        self.buf.extend(buf)

    @property
    def buffer(self) -> bytes:
        return bytes(self.buf)


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestBitSharesSerialization(unittest.TestCase):
    def setUp(self):
        self.writer = TestWriter()

    def test_full_tx(self):
        msg_sign_tx = BitSharesSignTx(
            **{
                "chain_id": "4018d7844c78f6a6c41c6a552b898022310fc5dec06da467ee7905a8dad512c8",
                "tx": BitSharesTx(
                    **{
                        "header": BitSharesTxHeader(
                            **{
                                "ref_block_num": 64476,
                                "ref_block_prefix": 1034601640,
                                "expiration": 1580302522,
                            }
                        ),
                        "operations": [
                            BitSharesOperation(
                                **{
                                    "operation_name": "transfer",
                                    "fee": BitSharesAsset(91204, "1.3.0"),
                                    "transfer": BitSharesTransferOperation(
                                        **{
                                            "sender": "1.2.100",
                                            "receiver": "1.2.101",
                                            "amount": BitSharesAsset(133000, "1.3.0"),
                                        }
                                    ),
                                }
                            ),
                        ],
                    }
                ),
            }
        )

        sign_tx = SignTransaction(msg_sign_tx).parse()
        sign_tx.write(self.writer)

    def test_transfer_with_memo(self):
        expected = (
            b"\x00Dd\x01\x00\x00\x00\x00\x00\x00de\x88\x07\x02"
            + b"\x00\x00\x00\x00\x00\x00\x01\x02\xc0\xde\xd2\xbc\x1f"
            + b"\x13\x05\xfb\x0f\xaa\xc5\xe6\xc0>\xe3\xa1\x92B4\x98T'"
            + b"\xb6\x16|\xa5i\xd1=\xf45\xcf\x02\xc0\xde\xd2\xbc\x1f"
            + b"\x13\x05\xfb\x0f\xaa\xc5\xe6\xc0>\xe3\xa1\x92B4\x98T'"
            + b"\xb6\x16|\xa5i\xd1=\xf45\xcf|\nU\xfb\xc4\xc0\xfb\xf3"
            + b"\x10;7\xe71k^\xec\xf2\x06\xd8\xdd$\x01^\xf5\xf3\x00"
        )

        pub_key = "BTS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"

        transfer = BitSharesOperation(
            **{
                "operation_name": "transfer",
                "fee": BitSharesAsset(91204, "1.3.0"),
                "transfer": BitSharesTransferOperation(
                    **{
                        "sender": "1.2.100",
                        "receiver": "1.2.101",
                        "amount": BitSharesAsset(133000, "1.3.0"),
                        "memo": BitSharesMemo(
                            **{
                                "sender": BitSharesPublicKey(pub_key),
                                "receiver": BitSharesPublicKey(pub_key),
                                "nonce": 17580857522633640572,
                                "message": "3b37e7316b5eecf206d8dd24015ef5f3",
                                "prefix": "BTS",
                            }
                        ),
                    }
                ),
            }
        )

        op = Operation(transfer)
        op.parse()
        op.write(self.writer)

        self._print_test_results(self.writer.buffer, expected)
        self.assertEqual(self.writer.buffer, expected)

    def test_transfer_without_memo(self):
        expected = (
            b"\x00Dd\x01\x00\x00\x00\x00\x00\x00de\x88\x07\x02"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )

        transfer = BitSharesOperation(
            **{
                "operation_name": "transfer",
                "fee": BitSharesAsset(91204, "1.3.0"),
                "transfer": BitSharesTransferOperation(
                    **{
                        "sender": "1.2.100",
                        "receiver": "1.2.101",
                        "amount": BitSharesAsset(133000, "1.3.0"),
                    }
                ),
            }
        )

        op = Operation(transfer)
        op.parse()
        op.write(self.writer)

        self._print_test_results(self.writer.buffer, expected)
        self.assertEqual(self.writer.buffer, expected)

    def test_limit_order_create(self):
        expected = (
            b"\x01d\x00\x00\x00\x00\x00\x00\x00\x00\x1d\xa0\x86"
            + b"\x01\x00\x00\x00\x00\x00\x00\x10'\x00\x00\x00\x00\x00"
            + b"\x00i=4<W\x00\x00"
        )

        limit_order_create = BitSharesOperation(
            **{
                "operation_name": "limit_order_create",
                "fee": BitSharesAsset(100, "1.3.0"),
                "limit_order_create": BitSharesLimitOrderCreateOperation(
                    **{
                        "seller": "1.2.29",
                        "amount_to_sell": BitSharesAsset(100000, "1.3.0"),
                        "min_to_receive": BitSharesAsset(10000, "1.3.105"),
                        "expiration": 1463563325,
                        "fill_or_kill": False,
                    }
                ),
            }
        )

        op = Operation(limit_order_create)
        op.parse()
        op.write(self.writer)

        self._print_test_results(self.writer.buffer, expected)
        self.assertEqual(self.writer.buffer, expected)

    def test_limit_order_cancel(self):
        expected = b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00h\x80\x95" + b"\x03\x00"

        limit_order_cancel = BitSharesOperation(
            **{
                "operation_name": "limit_order_cancel",
                "fee": BitSharesAsset(**{"amount": 0, "asset_id": "1.3.0"}),
                "limit_order_cancel": BitSharesLimitOrderCancelOperation(
                    **{"fee_paying_account": "1.2.104", "order": "1.7.51840",}
                ),
            }
        )

        op = Operation(limit_order_cancel)
        op.parse()
        op.write(self.writer)

        self.assertEqual(self.writer.buffer, expected)
        self._print_test_results(self.writer.buffer, expected)

    def test_account_create(self):
        expected = (
            b"\x05\xf2d\x16\x00\x00\x00\x00\x00\x00!\x1b\x03"
            + b"\x00\x0bfoobar-f124\x01\x00\x00\x00\x00\x02\x02\xfe"
            + b"\x8c\xc1\x1c\xc8%\x1d\xe6\x97v6\xb5\\\x1a\xb8\xa9"
            + b"\xd1+\x0b&\x15J\xc7\x8eV\xe7\xc4%}\x8b\xcfi\x01\x00"
            + b"\x03\x14\xaa ,\x91X\x99\x0b>\xc5\x1a\x1a\xa4\x9b*\xb5"
            + b"\xd3\x00\xc9{9\x1d\xf3\xbe\xb3K\xb7O<bi\x9e\x01\x00"
            + b"\x00\x01\x00\x00\x00\x00\x03\x03\xb4S\xf4`\x13\xfd"
            + b"\xbc\xcb\x90\xb0\x9b\xa1i\xc3\x88\xc3M\x84EJ;\x9f\xbe"
            + b"\xc6\x8dZx\x19\xa74\xfc\xa0\x01\x00\x02\xfe\x8c\xc1"
            + b"\x1c\xc8%\x1d\xe6\x97v6\xb5\\\x1a\xb8\xa9\xd1+\x0b&"
            + b"\x15J\xc7\x8eV\xe7\xc4%}\x8b\xcfi\x01\x00\x03\x14"
            + b"\xaa ,\x91X\x99\x0b>\xc5\x1a\x1a\xa4\x9b*\xb5\xd3\x00"
            + b"\xc9{9\x1d\xf3\xbe\xb3K\xb7O<bi\x9e\x01\x00\x00\x02J"
            + b"\xb36\xb4\xb1K\xa6\xd8\x81g]\x1cx)\x12x<C\xdb\xbe1i:"
            + b"\xa7\x10\xac\x18\x96\xbd|=a\x05\x00\x00\x00\x00\x01"
            + b"\x01\x00\x00\x00\x00\x00"
        )

        pub_key1 = "BTS6pbVDAjRFiw6fkiKYCrkz7PFeL7XNAfefrsREwg8MKpJ9VYV9x"
        pub_key2 = "BTS6zLNtyFVToBsBZDsgMhgjpwysYVbsQD6YhP3kRkQhANUB4w7Qp"
        pub_key3 = "BTS8CemMDjdUWSV5wKotEimhK6c4dY7p2PdzC2qM1HpAP8aLtZfE7"
        memo_key = "BTS5TPTziKkLexhVKsQKtSpo4bAv5RnB8oXcG4sMHEwCcTf3r7dqE"

        account_create = BitSharesOperation(
            **{
                "operation_name": "account_create",
                "fee": BitSharesAsset(**{"amount": 1467634, "asset_id": "1.3.0"}),
                "account_create": BitSharesAccountCreateOperation(
                    **{
                        "registrar": "1.2.33",
                        "referrer": "1.2.27",
                        "referrer_percent": 3,
                        "name": "foobar-f124",
                        "owner": BitSharesPermission(
                            **{
                                "weight_threshold": 1,
                                "account_auths": [],
                                "key_auths": [
                                    BitSharesKeyAuthority(
                                        BitSharesPublicKey(pub_key1), 1
                                    ),
                                    BitSharesKeyAuthority(
                                        BitSharesPublicKey(pub_key2), 1
                                    ),
                                ],
                                "address_auths": [],
                            }
                        ),
                        "active": BitSharesPermission(
                            **{
                                "weight_threshold": 1,
                                "account_auths": [],
                                "key_auths": [
                                    BitSharesKeyAuthority(
                                        BitSharesPublicKey(pub_key1), 1
                                    ),
                                    BitSharesKeyAuthority(
                                        BitSharesPublicKey(pub_key2), 1
                                    ),
                                    BitSharesKeyAuthority(
                                        BitSharesPublicKey(pub_key3), 1
                                    ),
                                ],
                                "address_auths": [],
                            }
                        ),
                        "options": BitSharesAccountOptions(
                            **{
                                "memo_key": BitSharesPublicKey(memo_key),
                                "voting_account": "1.2.5",
                                "num_witness": 0,
                                "num_committee": 0,
                                "votes": ["1:0"],
                            }
                        ),
                        "prefix": "BTS",
                    }
                ),
            }
        )

        op = Operation(account_create)
        op.parse()
        op.write(self.writer)

        self._print_test_results(self.writer.buffer, expected)
        self.assertEqual(self.writer.buffer, expected)

    def test_account_update(self):
        expected = (
            b"\x06\xf2d\x16\x00\x00\x00\x00\x00\x00\x0f\x01"
            + b"\x01\x00\x00\x00\x01\xd6\xee\x05\x01\x00\x01\x02\xfe"
            + b"\x8c\xc1\x1c\xc8%\x1d\xe6\x97v6\xb5\\\x1a\xb8\xa9\xd1+"
            + b"\x0b&\x15J\xc7\x8eV\xe7\xc4%}\x8b\xcfi\x01\x00\x00\x01"
            + b"\x01\x00\x00\x00\x01\xd6\xee\x05\x01\x00\x01\x03\xb4S"
            + b"\xf4`\x13\xfd\xbc\xcb\x90\xb0\x9b\xa1i\xc3\x88\xc3M"
            + b"\x84EJ;\x9f\xbe\xc6\x8dZx\x19\xa74\xfc\xa0\x01\x00\x00"
            + b"\x01\x02J\xb36\xb4\xb1K\xa6\xd8\x81g]\x1cx)\x12x<C\xdb"
            + b"\xbe1i:\xa7\x10\xac\x18\x96\xbd|=a\x05\x00\x00\x00\x00"
            + b"\x00\x00\x00"
        )

        pub_key1 = "BTS6pbVDAjRFiw6fkiKYCrkz7PFeL7XNAfefrsREwg8MKpJ9VYV9x"
        pub_key2 = "BTS8CemMDjdUWSV5wKotEimhK6c4dY7p2PdzC2qM1HpAP8aLtZfE7"
        memo_key = "BTS5TPTziKkLexhVKsQKtSpo4bAv5RnB8oXcG4sMHEwCcTf3r7dqE"

        account_update = BitSharesOperation(
            **{
                "operation_name": "account_update",
                "fee": BitSharesAsset(**{"amount": 1467634, "asset_id": "1.3.0"}),
                "account_update": BitSharesAccountUpdateOperation(
                    **{
                        "account": "1.2.15",
                        "owner": BitSharesPermission(
                            **{
                                "weight_threshold": 1,
                                "account_auths": [
                                    BitSharesAccountAuthority("1.2.96086", 1),
                                ],
                                "key_auths": [
                                    BitSharesKeyAuthority(
                                        BitSharesPublicKey(pub_key1), 1
                                    )
                                ],
                                "address_auths": [],
                            }
                        ),
                        "active": BitSharesPermission(
                            **{
                                "weight_threshold": 1,
                                "account_auths": [
                                    BitSharesAccountAuthority("1.2.96086", 1),
                                ],
                                "key_auths": [
                                    BitSharesKeyAuthority(
                                        BitSharesPublicKey(pub_key2), 1
                                    )
                                ],
                                "address_auths": [],
                            }
                        ),
                        "new_options": BitSharesAccountOptions(
                            **{
                                "memo_key": BitSharesPublicKey(memo_key),
                                "voting_account": "1.2.5",
                                "num_witness": 0,
                                "num_committee": 0,
                                "votes": [],
                            }
                        ),
                        "prefix": "BTS",
                    }
                ),
            }
        )

        op = Operation(account_update)
        op.parse()
        op.write(self.writer)

        self._print_test_results(self.writer.buffer, expected)
        self.assertEqual(self.writer.buffer, expected)

    def _print_test_results(self, actual, expected):
        to_readable = lambda buf: [int(b) for b in buf]

        actual = to_readable(actual)
        expected = to_readable(expected)

        print("\nACTUAL:\n", actual)
        print("\nEXPECTED:\n", expected)


if __name__ == "__main__":
    unittest.main()
