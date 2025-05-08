from typing import (
    List,
)

import click
from eth_typing import (
    ChecksumAddress,
)
from jsonrpc import (
    ASGIHandler,
)
import uvicorn

from eth_tester import (
    EthereumTester,
)

app: ASGIHandler = ASGIHandler()

eth_tester = EthereumTester()


@app.dispatcher.register
async def get_accounts() -> List[ChecksumAddress]:
    """
    Returns a list of accounts.
    """
    return eth_tester.get_accounts()


@click.command()
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Host to run the server on.",
)
@click.option(
    "--port",
    default=5000,
    show_default=True,
    help="Port to run the server on.",
)
def run_server(host: str, port: int):
    click.secho(f"Starting JSON-RPC server on {host}:{port}", fg="green", bold=True)

    # List accounts
    accounts_response = eth_tester.get_accounts()
    click.secho("Accounts:", fg="yellow")
    for account in accounts_response:
        click.secho(account, fg="yellow")
    click.secho("\n", fg="yellow")

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
