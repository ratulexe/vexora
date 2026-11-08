"""HTTP endpoint for adding a report to the on-chain registry."""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..rate_limit import REGISTRATION
from ..schemas import Report
from . import chain
from .package import (
    NotRegistrable,
    build_package,
    canonical_json,
    classification_code,
    commitment_of,
    indicator_hash,
    kind_code,
)

router = APIRouter()


class RegisterRequest(BaseModel):
    report: Report


class RegisterResponse(BaseModel):
    commitment: str
    indicator_hash: str
    transaction_hash: str
    block_number: int
    contract_address: str
    chain_id: int
    reporter: str
    explorer_url: str | None
    package: dict
    canonical_json: str


@router.post("/reports", response_model=RegisterResponse)
def register_report(body: RegisterRequest, request: Request) -> RegisterResponse:
    if not chain.can_register():
        raise HTTPException(503, "The threat registry is not configured on this server.")
    try:
        package = build_package(body.report)
    except NotRegistrable as error:
        raise HTTPException(400, str(error)) from error
    # Each registration spends testnet gas.
    REGISTRATION.check(request, "Too many reports registered from your connection.")

    commitment = commitment_of(package)
    indicator = indicator_hash(package["domains"][0] if package["domains"] else None)
    try:
        registration = chain.register(commitment, indicator, classification_code(package), kind_code(package))
    except chain.RegistryUnavailable as error:
        raise HTTPException(502, str(error)) from error

    return RegisterResponse(
        commitment="0x" + commitment.hex(),
        indicator_hash="0x" + indicator.hex(),
        transaction_hash=registration.transaction_hash,
        block_number=registration.block_number,
        contract_address=registration.contract_address,
        chain_id=registration.chain_id,
        reporter=registration.reporter,
        explorer_url=registration.explorer_url,
        package=package,
        canonical_json=canonical_json(package),
    )
