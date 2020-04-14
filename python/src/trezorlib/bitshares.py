# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from datetime import datetime

from . import messages
from .tools import CallException, b58decode, expect, session
from .exceptions import Cancelled, TrezorFailure


def get_public_key(client, address, show_display=False, multisig=None):
    msg = messages.BitSharesGetPublicKey(address_n=address, show_display=show_display)
    res = client.call(msg)
    return "Pub: {}\nRaw: {}".format(res.compressed, res.raw.hex())


@session
def sign_tx(client, address, tx_json):
    sign_tx = SignTransaction.parse(address, tx_json)
    res = client.call(sign_tx)
    return "Signature: {}".format(res.signature)


class PublicKey:
    @staticmethod
    def parse(key: str):
        return messages.BitSharesPublicKey(compressed=key)


class Optional:
    @staticmethod
    def parse(json: dict, OptionalCls):
        return json if (json is None) or (not json) else OptionalCls.parse(json)


class Memo:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesMemo(
            sender=PublicKey.parse(json["from"]),
            receiver=PublicKey.parse(json["to"]),
            nonce=json["nonce"],
            message=json["message"],
            prefix=json["prefix"],
        )


class Asset:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesAsset(
            amount=int(json["amount"]), asset_id=json["asset_id"]
        )


class Time:
    @staticmethod
    def parse(time: str):
        now = datetime.strptime(time, "%Y-%m-%dT%H:%M:%S")
        epoch_begin = datetime(1970, 1, 1)
        return int((now - epoch_begin).total_seconds())


class AccountAuthority:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesAccountAuthority(
            account=str(json["account"]), weight=int(json["weight"])
        )


class KeyAuthority:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesKeyAuthority(
            key=PublicKey.parse(json["key"]), weight=int(json["weight"])
        )


class AddressAuthority:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesAddressAuthority(
            address=str(json["address"]), weight=int(json["weight"])
        )


class Permission:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesPermission(
            weight_threshold=int(json["weight_threshold"]),
            account_auths=[
                AccountAuthority.parse(auth) for auth in json["account_auths"]
            ],
            key_auths=[KeyAuthority.parse(auth) for auth in json["key_auths"]],
            address_auths=[
                AddressAuthority.parse(auth) for auth in json["address_auths"]
            ],
        )


class AccountOptions:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesAccountOptions(
            memo_key=PublicKey.parse(json["memo_key"]),
            voting_account=str(json["voting_account"]),
            num_witness=int(json["num_witness"]),
            num_committee=int(json["num_committee"]),
            votes=json["votes"],
            extensions=None,
        )


class Transfer:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesTransferOperation(
            sender=str(json["from"]),
            receiver=str(json["to"]),
            amount=Asset.parse(json["amount"]),
            memo=Optional.parse(json["memo"], Memo),
            extensions=None,
        )


class LimitOrderCreate:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesLimitOrderCreateOperation(
            seller=str(json["seller"]),
            amount_to_sell=Asset.parse(json["amount_to_sell"]),
            min_to_receive=Asset.parse(json["min_to_receive"]),
            expiration=Time.parse(json["expiration"]),
            fill_or_kill=bool(json["fill_or_kill"]),
            extensions=None,
        )


class LimitOrderCancel:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesLimitOrderCancelOperation(
            fee_paying_account=str(json["fee_paying_account"]),
            order=str(json["order"]),
            extensions=None,
        )


class AccountCreate:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesAccountCreateOperation(
            registrar=str(json["registrar"]),
            referrer=str(json["referrer"]),
            referrer_percent=int(json["referrer_percent"]),
            name=str(json["name"]),
            owner=Permission.parse(json["owner"]),
            active=Permission.parse(json["active"]),
            options=AccountOptions.parse(json["options"]),
            prefix=str(json["prefix"]),
            extensions=None,
        )


class AccountUpdate:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesAccountUpdateOperation(
            account=str(json["account"]),
            owner=Optional.parse(json["owner"], Permission),
            active=Optional.parse(json["active"], Permission),
            new_options=Optional.parse(json["new_options"], AccountOptions),
            prefix=str(json["prefix"]),
            extensions=None,
        )


class Operation:
    parsers = {
        "transfer": Transfer,
        "limit_order_create": LimitOrderCreate,
        "limit_order_cancel": LimitOrderCancel,
        "account_create": AccountCreate,
        "account_update": AccountUpdate,
    }

    @staticmethod
    def parse(op_name: str, op_data: dict):
        op_union = messages.BitSharesOperation(
            operation_name=op_name, fee=Asset.parse(op_data["fee"]),
        )
        setattr(op_union, op_name, Operation.parsers[op_name].parse(op_data))
        return op_union


class TransactionHeader:
    @staticmethod
    def parse(json: dict):
        return messages.BitSharesTxHeader(
            ref_block_num=json["ref_block_num"],
            ref_block_prefix=json["ref_block_prefix"],
            expiration=Time.parse(json["expiration"]),
        )


class Transaction:
    @staticmethod
    def parse(json):
        return messages.BitSharesTx(
            header=TransactionHeader.parse(json),
            operations=[
                Operation.parse(op_name, op_data)
                for op_name, op_data in json["operations"]
                # if op_name == "transfer"
                # if op_name == "limit_order_create"
                # if op_name == "limit_order_cancel"
                # if op_name == "account_create"
                # if op_name == "account_update"
            ],
            extensions=None,
        )


class SignTransaction:
    @staticmethod
    def parse(address, json):
        return messages.BitSharesSignTx(
            address_n=address, chain_id=json["chain_id"], tx=Transaction.parse(json),
        )
