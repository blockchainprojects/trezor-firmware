from trezor import ui, wire, res
from trezor.messages import ButtonRequestType
from trezor.ui import scroll
from trezor.ui.confirm import Confirm
from trezor.ui.text import Text
from trezor.utils import chunks

from apps.common import confirm

from ..base.client import SignTransaction
from ..base.operations import Operation


if False:
    from typing import List


ICON_LEFT = res.load(ui.ICON_SWIPE_LEFT)
ICON_CONFIRM = Confirm.DEFAULT_CONFIRM


class ConfirmGetPublicKey:
    def __init__(self, pub: str) -> None:
        self._pub = pub

    async def require_confirm(self, ctx: wire.Context) -> None:
        await confirm.require_confirm(ctx, self._text, ButtonRequestType.PublicKey)

    @property
    def _text(self):
        text = Text("Confirm public Key", ui.ICON_RECEIVE, ui.GREEN)
        text.normal(self._pub)
        return text


class ConfirmSignTransaction:
    def __init__(self, sign_tx: SignTransaction) -> None:
        self.sign_tx = sign_tx

    async def require_confirm(self, ctx: wire.Context) -> None:
        await confirm.require_confirm(
            ctx, self._pages, ButtonRequestType.Other, ICON_LEFT
        )
        await self._require_confirm_operations(ctx)

    async def _require_confirm_operations(self, ctx: wire.Context):
        operations = self.sign_tx["tx"]["operations"]
        for op in operations[:-1]:
            await ConfirmOperation(op).require_confirm(ctx)

        await ConfirmOperation(operations[-1], last=True).require_confirm(ctx)

    @property
    def _pages(self) -> List[Text]:
        return Paginated.make_pages(
            header="Sign transaction", fields=self._fields, per_page=5,
        )

    @property
    def _fields(self) -> List[str]:
        fields = ["You are about to sign:"]
        fields.extend(
            op.op_name.replace("_", " ") for op in self.sign_tx["tx"]["operations"]
        )
        return fields


class ConfirmOperation:
    PER_PAGE = {
        "transfer": 4,
        "limit_order_create": 4,
        "limit_order_cancel": 2,
        "account_create": 2,
        "account_update": 2,
    }

    def __init__(self, op: Operation, last: bool = False) -> None:
        self.last = last
        self._op_name, self._fields = op.listify()
        self._per_page = ConfirmOperation.PER_PAGE[self._op_name]

    async def require_confirm(self, ctx: wire.Context) -> None:
        icon = ICON_LEFT if not self.last else ICON_CONFIRM

        await confirm.require_confirm(
            ctx, self._pages, ButtonRequestType.ConfirmOutput, icon
        )

    @property
    def _pages(self) -> List[Text]:
        return Paginated.make_pages(
            header="{}".format(self._op_name.replace("_", " ")),
            fields=self._fields,
            per_page=self._per_page,
        )


class Paginated:
    @staticmethod
    def make_pages(header: str, fields: List[str], per_page: int) -> scroll.Paginated:
        return scroll.Paginated(
            [Paginated._make_text(header, page) for page in chunks(fields, per_page)]
        )

    @staticmethod
    def _make_text(header: str, page: List[str]) -> Text:
        text = Text(header, ui.ICON_CONFIRM, ui.GREEN)
        for line in page:
            text.normal(line)
        return text
