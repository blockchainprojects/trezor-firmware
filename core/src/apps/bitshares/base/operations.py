from trezor import wire

# fmt:off
from trezor.messages.BitSharesOperation import BitSharesOperation
from trezor.messages.BitSharesTransferOperation import BitSharesTransferOperation
from trezor.messages.BitSharesLimitOrderCreateOperation import BitSharesLimitOrderCreateOperation
from trezor.messages.BitSharesLimitOrderCancelOperation import BitSharesLimitOrderCancelOperation
from trezor.messages.BitSharesAccountCreateOperation import BitSharesAccountCreateOperation
from trezor.messages.BitSharesAccountUpdateOperation import BitSharesAccountUpdateOperation
# fmt:on

from .types import (
    Bool,
    Uint16,
    Uint32,
    String,
    Permission,
    OperationId,
    ObjectId,
    Optional,
    Asset,
    Memo,
    EmptyExtension,
    AccountOptions,
)
from .parsing import Node

from ucollections import OrderedDict

# Union type for all operations
class Operation(Node):
    def __init__(self, msg: BitSharesOperation) -> None:
        self.data = msg

        self.nodes = OrderedDict(
            [
                ("operation_id", OperationId),
                ("fee", Asset),
                # ("operation_name", OperationCls) is added in parse
            ]
        )

    def parse(self) -> "Operation":
        if self.data.operation_name is None:
            raise ValueError("operation_name")

        self.op_name = self.data.operation_name

        # add the operation_id to the msg such that Node.parse() can be applied
        op_id = OperationTable.get_id(self.op_name)
        setattr(self.data, "operation_id", op_id)

        # add the operation itself
        OperationCls = OperationTable.get_cls(self.op_name)
        self.nodes[self.op_name] = OperationCls

        return super().parse()

    def listify(self) -> (str, List[str]):
        return (self.op_name, self[self.op_name].listify())


class TransferOperation(Node):
    def __init__(self, msg: BitSharesTransferOperation) -> None:
        self.data = msg

        self.nodes = OrderedDict(
            [
                ("sender", ObjectId),
                ("receiver", ObjectId),
                ("amount", Asset),
                ("memo", Optional(Memo)),
                ("extensions", EmptyExtension),
            ]
        )

    def listify(self) -> List[str]:
        return [
            "from:",
            str(self["sender"]),
            "to:",
            str(self["receiver"]),
            "amount:",
            str(self["amount"]["amount"]),
            "asset:",
            str(self["amount"]["asset_id"]),
        ]


class LimitOrderCreateOperation(Node):
    def __init__(self, msg: BitSharesLimitOrderCreateOperation) -> None:
        self.data = msg

        self.nodes = OrderedDict(
            [
                ("seller", ObjectId),
                ("amount_to_sell", Asset),
                ("min_to_receive", Asset),
                ("expiration", Uint32),
                ("fill_or_kill", Bool),
                ("extensions", EmptyExtension),
            ]
        )

    def listify(self) -> List[str]:
        return [
            "asset to sell:",
            str(self["amount_to_sell"]["asset_id"]),
            "asset to receive:",
            str(self["min_to_receive"]["asset_id"]),
            "amount to sell:",
            str(self["amount_to_sell"]["amount"]),
            "price:",
            "{:.5f}".format(self.price),  # TODO enough precision?
        ]

    @property
    def price(self) -> float:
        return (
            self["amount_to_sell"]["amount"].data
            / self["min_to_receive"]["amount"].data
        )


class LimitOrderCancelOperation(Node):
    def __init__(self, msg: BitSharesLimitOrderCancelOperation) -> None:
        self.data = msg

        self.nodes = OrderedDict(
            [
                ("fee_paying_account", ObjectId),
                ("order", ObjectId),
                ("extensions", EmptyExtension),
            ]
        )

    def listify(self) -> List[str]:
        return [
            "order:",
            str(self["order"]),
        ]


class AccountCreateOperation(Node):
    def __init__(self, msg: BitSharesAccountCreateOperation = None) -> None:
        self.data = msg

        self.nodes = OrderedDict(
            [
                ("registrar", ObjectId),
                ("referrer", ObjectId),
                ("referrer_percent", Uint16),
                ("name", String),
                ("owner", Permission),
                ("active", Permission),
                ("options", AccountOptions),
                ("extensions", EmptyExtension),
            ]
        )

    def listify(self) -> List[str]:
        readable = [
            "name",
            str(self["name"]),
        ]
        readable.extend(self["owner"].listify("owner"))
        readable.extend(self["active"].listify("active"))
        return readable


class AccountUpdateOperation(Node):
    def __init__(self, msg: BitSharesAccountUpdateOperation) -> None:
        self.data = msg

        self.nodes = OrderedDict(
            [
                ("account", ObjectId),
                ("owner", Optional(Permission)),
                ("active", Optional(Permission)),
                ("new_options", Optional(AccountOptions)),
                ("extensions", EmptyExtension),
            ]
        )

    def listify(self) -> List[str]:
        readable = ["account", str(self["account"])]
        readable.extend(self["owner"].listify("owner"))
        readable.extend(self["active"].listify("active"))
        return readable


class OperationTable:
    @staticmethod
    def get_id(op_name: str) -> int:
        return OperationTable._table[op_name][0]

    @staticmethod
    def get_cls(op_name: str) -> Node:
        try:
            return OperationTable._table[op_name][1]
        except:
            raise KeyError("OperationTable: {} not in table.".format(op_name))

    @staticmethod  # TODO has to be called on OperationTable()
    def __contains__(key) -> bool:
        return key in OperationTable._table

    # op_name: (op_id, op_cls)
    _table = {
        "transfer": (0, TransferOperation),
        "limit_order_create": (1, LimitOrderCreateOperation),
        "limit_order_cancel": (2, LimitOrderCancelOperation),
        "account_create": (5, AccountCreateOperation),
        "account_update": (6, AccountUpdateOperation),
    }
