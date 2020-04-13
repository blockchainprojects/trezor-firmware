from common import *

from trezor.crypto import bip32, bip39
from apps.common.paths import HARDENED

if not utils.BITCOIN_ONLY:
    from apps.bitshares.get_public_key import _get_public_key
    from apps.bitshares.helpers import validate_full_path, compress


@unittest.skipUnless(not utils.BITCOIN_ONLY, "altcoin")
class TestBitSharesGetPublicKey(unittest.TestCase):
    def test_get_public_key_scheme(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed = bip39.seed(mnemonic, "")

        PURPOSE = 48 | HARDENED  # 48' refering to SLIP48
        NETWORK = 1 | HARDENED  # network'
        OWNER = 0 | HARDENED  # owner' role
        ACTIVE = 1 | HARDENED  # active' role
        MEMO = 3 | HARDENED  # memo' role

        derivation_paths = [
            #                  role   acc_idx      key_idx
            [PURPOSE, NETWORK, OWNER, 0 | HARDENED, 0 | HARDENED],
            [PURPOSE, NETWORK, ACTIVE, 0 | HARDENED, 0 | HARDENED],
            [PURPOSE, NETWORK, MEMO, 0 | HARDENED, 0 | HARDENED],
            [PURPOSE, NETWORK, MEMO, 0 | HARDENED, 1 | HARDENED],
            [PURPOSE, NETWORK, OWNER, 1 | HARDENED, 0 | HARDENED],
        ]

        pub_keys = [
            b"0352144c2e443b7f06dce14fe5d5657e45d35b6d2caf8a552e539fd88ea1916f5e",
            b"02a2400b45a6b387ec371a8d9ba7e8980cb0d6602e9cfea1b3a4e24367311762b9",
            b"029e4437b7b1df284ca4f2f7b9f1da6827a2bd59c16f0f194b460bd72385fe8abe",
            b"0374add181296422af07e04a6aed4e2dfbf5078f69f2344385d96d9529819c6a27",
            b"038ea4578492d384c5be319ec38e5f1c85ae51f303482ee04fa73617b90993b4ad",
        ]

        compressed_pub_keys = [
            "BTS7TP8oMkfCuzQWGTfYvBvkQ2nqYj69yRxsg4RQxtsthtTKZHnXT",
            "BTS67wpK2gvNUHF5i666DGTJt8QqoHLW77oZqD1BycnmUQmyHaF3V",
            "BTS66C4LV27XHnxYc9u6Tt6mfTbidkHr3NX2X3tT3J3Tcca17K43t",
            "BTS7icwMW9GPfMihB7ctqqhEcND8h7HrjNwX9XaCEERz5f9iRjW2U",
            "BTS7v48M7TfZbWoeAPBkGEMija7XtADHGtieyAhurz6oQZotN2nZd",
        ]

        for index, path in enumerate(derivation_paths):
            node = bip32.from_seed(seed, "secp256k1")
            node.derive_path(path)
            compressed_pub_key, pub_key = _get_public_key(node)
            # print( "pub_key\n", str(pub_key) )
            # print( "compressed_pub_key\n", compressed_pub_key )

            self.assertEqual(hexlify(pub_key), pub_keys[index])
            self.assertEqual(compressed_pub_key, compressed_pub_keys[index])
            self.assertEqual(compress(pub_key), compressed_pub_keys[index])

    def test_paths(self):

        # incorrect
        WRONG_PURPOSE = 42 | HARDENED
        WRONG_NETWORK = 42 | HARDENED
        WRONG_ROLE = 42 | HARDENED
        WRONG_ACC_IDX1 = 42
        WRONG_ACC_IDX2 = 2 ** 31 | HARDENED
        WRONG_KEY_IDX1 = 42
        WRONG_KEY_IDX2 = 2 ** 31 | HARDENED

        # correct
        PURPOSE = 48 | HARDENED  # 48' refering to SLIP-0048
        NETWORK = 1 | HARDENED  # network'
        OWNER = 0 | HARDENED  # owner' role
        ACTIVE = 1 | HARDENED  # active' role
        MEMO = 3 | HARDENED  # memo' role

        incorrect_paths = [
            [PURPOSE],
            [PURPOSE, NETWORK],
            [PURPOSE, NETWORK, OWNER],
            [PURPOSE, NETWORK, OWNER, 0 | HARDENED],
            [WRONG_PURPOSE, NETWORK, OWNER, 0 | HARDENED, 0 | HARDENED],
            [PURPOSE, WRONG_NETWORK, OWNER, 0 | HARDENED, 0 | HARDENED],
            [PURPOSE, NETWORK, WRONG_ROLE, 0 | HARDENED, 0 | HARDENED],
            [PURPOSE, NETWORK, OWNER, WRONG_ACC_IDX1, 0 | HARDENED],
            [PURPOSE, NETWORK, OWNER, WRONG_ACC_IDX2, 0 | HARDENED],
            [PURPOSE, NETWORK, OWNER, 0 | HARDENED, WRONG_KEY_IDX1],
            [PURPOSE, NETWORK, OWNER, 0 | HARDENED, WRONG_KEY_IDX2],
        ]

        correct_paths = [
            [PURPOSE, NETWORK, OWNER, 0 | HARDENED, 0 | HARDENED],  # 48'/1'/0'/0'/0'
            [PURPOSE, NETWORK, ACTIVE, 0 | HARDENED, 0 | HARDENED],  # 48'/1'/1'/0'/0'
            [PURPOSE, NETWORK, MEMO, 0 | HARDENED, 0 | HARDENED],  # 48'/1'/3'/0'/0'
            [PURPOSE, NETWORK, MEMO, 0 | HARDENED, 1 | HARDENED],  # 48'/1'/3'/0'/1'
            [PURPOSE, NETWORK, OWNER, 1 | HARDENED, 0 | HARDENED],  # 48'/1'/0'/1'/0'
        ]

        for path in incorrect_paths:
            self.assertFalse(validate_full_path(path))

        for path in correct_paths:
            self.assertTrue(validate_full_path(path))


if __name__ == "__main__":
    unittest.main()
