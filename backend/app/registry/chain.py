"""Sends registry transactions from the server's testnet wallet, and reads the registry.

Configure with environment variables:
  REGISTRY_RPC_URL           JSON-RPC endpoint, e.g. https://ethereum-sepolia-rpc.publicnode.com
  REGISTRY_CONTRACT_ADDRESS  Deployed ThreatReportRegistry address
  REGISTRY_PRIVATE_KEY       Testnet-only wallet that pays for registrations
  REGISTRY_EXPLORER_URL      Optional, e.g. https://sepolia.etherscan.io
"""

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from web3 import Web3

ABI = json.loads((Path(__file__).parent / "abi.json").read_text(encoding="utf-8"))
RECEIPT_TIMEOUT_SECONDS = 90

_send_lock = threading.Lock()


class RegistryUnavailable(RuntimeError):
    pass


@dataclass
class Registration:
    transaction_hash: str
    block_number: int
    contract_address: str
    chain_id: int
    reporter: str
    explorer_url: str | None


def registry_configured() -> bool:
    return bool(os.getenv("REGISTRY_RPC_URL") and os.getenv("REGISTRY_CONTRACT_ADDRESS"))


def can_register() -> bool:
    return registry_configured() and bool(os.getenv("REGISTRY_PRIVATE_KEY"))


def _web3() -> Web3:
    return Web3(Web3.HTTPProvider(os.environ["REGISTRY_RPC_URL"], request_kwargs={"timeout": 20}))


def _contract(w3: Web3):
    return w3.eth.contract(address=Web3.to_checksum_address(os.environ["REGISTRY_CONTRACT_ADDRESS"]), abi=ABI)


def register(commitment: bytes, indicator: bytes, classification: int, kind: int) -> Registration:
    if not can_register():
        raise RegistryUnavailable("The registry is not configured on this server.")
    try:
        w3 = _web3()
        account = w3.eth.account.from_key(os.environ["REGISTRY_PRIVATE_KEY"])
        contract = _contract(w3)
        call = contract.functions.registerReport(commitment, indicator, classification, kind)
        # One transaction at a time, so concurrent requests do not reuse a nonce.
        with _send_lock:
            transaction = call.build_transaction(
                {
                    "from": account.address,
                    "nonce": w3.eth.get_transaction_count(account.address, "pending"),
                    "chainId": w3.eth.chain_id,
                }
            )
            signed = account.sign_transaction(transaction)
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=RECEIPT_TIMEOUT_SECONDS)
    except RegistryUnavailable:
        raise
    except Exception as error:  # web3 raises many unrelated exception types
        raise RegistryUnavailable(f"The blockchain transaction failed ({type(error).__name__}).") from error

    if receipt["status"] != 1:
        raise RegistryUnavailable("The blockchain transaction was reverted.")

    tx_hex = "0x" + bytes(receipt["transactionHash"]).hex().removeprefix("0x")
    explorer = os.getenv("REGISTRY_EXPLORER_URL", "").rstrip("/")
    return Registration(
        transaction_hash=tx_hex,
        block_number=receipt["blockNumber"],
        contract_address=contract.address,
        chain_id=transaction["chainId"],
        reporter=account.address,
        explorer_url=f"{explorer}/tx/{tx_hex}" if explorer else None,
    )


def report_count_for(indicator: bytes) -> int:
    """How many registered reports name this domain. Read-only; needs no wallet."""
    if not registry_configured():
        raise RegistryUnavailable("The registry is not configured on this server.")
    try:
        return int(_contract(_web3()).functions.indicatorReportCount(indicator).call())
    except Exception as error:
        raise RegistryUnavailable(f"Could not read the registry ({type(error).__name__}).") from error
