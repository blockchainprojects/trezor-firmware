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

import json

import click

from .. import bitshares, tools

PATH_HELP = "SLIP-48 path, e.g. m/48'/1'/0'/0'/0'"


@click.group(name="bitshares")
def cli():
    """BitShares commands."""


@cli.command()
@click.option("-n", "--address", required=True, help=PATH_HELP)
@click.option("-d", "--show-display", is_flag=True)
@click.pass_obj
def get_public_key(connect, address, show_display):
    """Get BitShares public key."""
    client = connect()
    address_n = tools.parse_path(address)
    return bitshares.get_public_key(client, address_n, show_display)


@cli.command()
@click.option("-n", "--address", required=True, help=PATH_HELP)
@click.option(
    "-f",
    "--file",
    type=click.File("r"),
    required=True,
    help="Transaction in JSON format",
)
@click.pass_obj
def sign_transaction(connect, address, file):
    """Sign BitShares transaction."""
    client = connect()
    address_n = tools.parse_path(address)
    tx_json = json.load(file)
    return bitshares.sign_tx(client, address_n, tx_json)