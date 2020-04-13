from trezor import wire

from trezor.crypto.hashlib import sha512, ripemd160

from apps.common.writers import (
    write_bytes,
    write_uint8,
    write_uint16_le,
    write_uint32_le,
    write_uint64_le,
)

# fmt:off
from trezor.messages.BitSharesMemo import BitSharesMemo
from trezor.messages.BitSharesAsset import BitSharesAsset
from trezor.messages.BitSharesPublicKey import BitSharesPublicKey
from trezor.messages.BitSharesPermission import BitSharesPermission
from trezor.messages.BitSharesKeyAuthority import BitSharesKeyAuthority
from trezor.messages.BitSharesAccountAuthority import BitSharesAccountAuthority
from trezor.messages.BitSharesAddressAuthority import BitSharesAddressAuthority
from trezor.messages.BitSharesAccountOptions import BitSharesAccountOptions
# fmt:on

from .helpers import base58_decode, unicodify
from .parsing import AbstractNode, LeafNode, Node, WrapperNode

from ubinascii import unhexlify
from ucollections import OrderedDict

if False:
    from typing import Iterator

#######################
####  basic types  ####
#######################


class Uint8(LeafNode):
    def __init__(self, i: int) -> None:
        self.data = i

    def write(self, w: Writer) -> None:
        write_uint8(w, self.data)


class Uint16(LeafNode):
    def __init__(self, i: int) -> None:
        self.data = i

    def write(self, w: Writer) -> None:
        write_uint16_le(w, self.data)


class Uint32(LeafNode):
    def __init__(self, i: int) -> None:
        self.data = i

    def write(self, w: Writer) -> None:
        write_uint32_le(w, self.data)


class Uint64(LeafNode):
    def __init__(self, i: int) -> None:
        self.data = i

    def write(self, w: Writer) -> None:
        write_uint64_le(w, self.data)


class Bool(Uint8):
    def __init__(self, b: bool) -> None:
        self.data = b


class VarInt32(LeafNode):
    def __init__(self, i: int) -> None:
        self.data = i

    def write(self, w: Writer) -> None:
        write_bytes(w, self._to_varint(self.data))

    def _to_varint(self, n: int) -> bytes:
        data = b""
        while n >= 0x80:
            data += bytes([(n & 0x7F) | 0x80])
            n >>= 7
        data += bytes([n])
        return data


class Bytes(LeafNode):
    def __init__(self, b) -> None:
        self.data = b

    def write(self, w: Writer) -> None:
        d = unhexlify(bytes(self.data, "utf-8"))
        VarInt32(len(d)).write(w)
        write_bytes(w, d)


class String(LeafNode):
    def __init__(self, s: str) -> None:
        self.data = s

    def write(self, w: Writer) -> None:
        VarInt32(len(self.data)).write(w)
        write_bytes(w, unicodify(self.data))


class Optional(WrapperNode):
    def __init__(self, OptionalCls: AbstractNode) -> None:
        self.OptionalCls = OptionalCls
        self.node = None

    def __call__(self, msg):
        self.data = msg
        return self

    def parse(self) -> "Optional":
        if self.data is None:
            return self

        self.node = self.OptionalCls(self.data).parse()
        return self

    def write(self, w: Writer) -> None:
        if self.node is None:
            Bool(0).write(w)
            return

        Bool(1).write(w)
        self.node.write(w)

    def listify(self, arg: str = None) -> List[str]:
        if self.node is None:
            return []
        if arg is None:
            return self.node.listify()
        return self.node.listify(arg)


class Array(WrapperNode):
    def __init__(self, ArrayElementCls: AbstractNode) -> None:
        self.ArrayElementCls = ArrayElementCls

    def __call__(self, msg: list):
        self.data = msg
        return self

    def parse(self) -> "Array":
        self.nodes = [self.ArrayElementCls(d).parse() for d in self.data]
        return self

    def write(self, w: Writer) -> None:
        VarInt32(len(self.nodes)).write(w)
        for d in self.nodes:
            d.write(w)

    def __iter__(self) -> Iterator:
        return iter(self.nodes)


class SortedArray(Array):
    def __init__(
        self, ArrayElementCls: AbstractNode, key=None, reverse: bool = False
    ) -> None:
        super().__init__(ArrayElementCls)
        self.key = key
        self.reverse = reverse

    def parse(self) -> "SortedArray":
        super().parse()
        self.nodes = sorted(self.nodes, key=self.key, reverse=self.reverse)
        return self


###########################
####  bitshares types  ####
###########################


class ChainId(LeafNode):
    def __init__(self, msg) -> None:
        # super().__init__(msg)
        self.data = msg

    def write(self, w: Writer) -> None:
        write_bytes(w, unhexlify(self.data))


# TODO raw key handling
class PublicKey(LeafNode):
    def __init__(self, msg: str) -> None:
        self.data = msg

        if self.data.compressed is not None:
            self._compressed = self.data.compressed
            self.pub_key = base58_decode("BTS", self.data.compressed)[
                :-4
            ]  # TODO why are there 4 bytes more???
        elif self.data.raw is not None:
            self.pub_key = msg
        else:
            raise wire.DataError(
                "PublicKey either not specified or not base58 encoded or not raw."
            )

        self.data = self.pub_key

    def write(self, w: Writer) -> None:
        write_bytes(w, self.pub_key)

    def __str__(self) -> str:
        return self._compressed

    @property
    def address(self) -> bytes:
        sha_digest = sha512(self.pub_key).digest()
        ripemd_digest = ripemd160(sha_digest).digest()
        return ripemd_digest

    # TODO
    def _is_compressed(self, pub_key) -> bool:
        return pub_key.startswith("BTS")

    # TODO
    def _is_raw(self, pub_key) -> bool:
        return len(pub_key) == 33

    def __lt__(self, other) -> bool:
        return self.address < other.address


class ObjectId(VarInt32):
    def __init__(self, msg) -> None:
        self.data = self._readable = msg

    def parse(self) -> self:
        if self.data is None:
            raise ValueError

        self.data = self._get_instance(self.data)
        return self

    def __str__(self) -> str:
        # TODO currently returns full ID, probably return obj_id only
        return self._readable

    def _get_instance(self, oid) -> int:
        try:
            return int(oid.split(".")[2])
        except:
            raise wire.DataError("ObjectId {} wrong.".format(oid))


class VoteId(Uint32):
    def __init__(self, msg) -> None:
        self.data = self.readable = msg

    def parse(self) -> None:
        super().parse()

        self.data = self._serialize(self.data)
        return self

    def _serialize(self, vid: str) -> int:
        try:
            _type, _instance = vid.split(":")
            return int(_type) & 0xFF | int(_instance) << 8
        except:
            raise wire.DataError("Bad VoteId format.")

    def __str__(self) -> str:
        return self._readable


class OperationId(Uint8):
    def __init__(self, id: int) -> None:
        self.data = id


class EmptyExtension(Uint8):
    def __init__(self, msg) -> None:
        msg = 0
        super().__init__(msg)


class Memo(Node):
    def __init__(self, msg: BitSharesMemo) -> None:
        self.data = msg

        self.nodes = OrderedDict(
            [
                ("sender", PublicKey),
                ("receiver", PublicKey),
                ("nonce", Uint64),
                ("message", Bytes),
            ]
        )


class Asset(Node):
    def __init__(self, msg: BitSharesAsset) -> None:
        self.data = msg
        self.nodes = OrderedDict([("amount", Uint64), ("asset_id", ObjectId),])


class AccountAuthority(Node):
    def __init__(self, msg: BitSharesAccountAuthority) -> None:
        self.data = msg
        self.nodes = OrderedDict([("account", ObjectId), ("weight", Uint16),])


class KeyAuthority(Node):
    def __init__(self, msg: BitSharesKeyAuthority) -> None:
        self.data = msg
        self.nodes = OrderedDict([("key", PublicKey), ("weight", Uint16),])


class AddressAuthority(Node):
    def __init__(self, msg: BitSharesAddressAuthority) -> None:
        super().__init__(msg)
        self.nodes = OrderedDict(
            [("address", Bytes), ("weight", Uint16),]  # TODO rly bytes?
        )


class Permission(Node):
    def __init__(self, msg: BitSharesPermission) -> None:
        self.data = msg
        self.nodes = OrderedDict(
            [
                ("weight_threshold", Uint32),
                ("account_auths", Array(AccountAuthority)),
                (
                    "key_auths",
                    SortedArray(KeyAuthority, key=lambda key_auth: key_auth["key"]),
                ),
                ("address_auths", Array(AddressAuthority)),
            ]
        )

    def listify(self, prefix: str) -> List[str]:
        readable = []
        for idx, auth in enumerate(self["account_auths"]):
            readable.extend(
                ["{} account {}".format(prefix, idx + 1), str(auth["account"])]
            )

        for idx, auth in enumerate(self["key_auths"]):
            readable.extend(["{} key {}".format(prefix, idx + 1), str(auth["key"])])

        # TODO is broke
        for idx, auth in enumerate(self["address_auths"]):
            readable.extend(
                ["{} address {}".format(prefix, idx + 1), str(auth["address"])]
            )

        return readable


class AccountOptions(Node):
    def __init__(self, msg: BitSharesAccountOptions) -> None:
        self.data = msg

        self.nodes = OrderedDict(
            [
                ("memo_key", PublicKey),
                ("voting_account", ObjectId),
                ("num_witness", Uint16),
                ("num_committee", Uint16),
                ("votes", Array(VoteId)),
                ("extensions", EmptyExtension),
            ]
        )
