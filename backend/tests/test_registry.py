"""Offline tests for the threat registry backend. The blockchain is faked."""

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.rate_limit import REGISTRATION
from app.registry import chain
from app.registry.package import NotRegistrable, build_package, canonical_json, commitment_of, indicator_hash
from app.schemas import Classification, Indicator, Report, Severity

client = TestClient(app)


def make_report(classification=Classification.HIGH_RISK, message=False) -> Report:
    indicators = [
        Indicator(title="Asks for an OTP", severity=Severity.HIGH, evidence='"Share the OTP to 9876543210"', source="Vexora message rules"),
        Indicator(title="AI: Creates urgency", severity=Severity.LOW, evidence='"act now"', source="AI analysis"),
    ]
    details = (
        {"rules_matched": ["credential_request"], "links": [{"url": "https://sbi-kyc-update.in/login?id=42"}]}
        if message
        else {"normalized_url": "https://login.sbi-kyc-update.in/verify?user=7"}
    )
    return Report(
        input="Dear Rahul, share the OTP to 9876543210 https://sbi-kyc-update.in/login?id=42" if message
        else "https://login.sbi-kyc-update.in/verify?user=7",
        classification=classification,
        indicators=indicators,
        confidence="High",
        recommended_actions=[],
        limitations=[],
        analysed_at=datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc),
        details=details,
    )


# Package and commitment


def test_link_package_holds_only_shareable_fields():
    package = build_package(make_report())
    assert package["kind"] == "link"
    assert package["domains"] == ["sbi-kyc-update.in"]
    text = canonical_json(package)
    for private in ("user=7", "/verify", "9876543210", "Share the OTP", "AI: "):
        assert private not in text


def test_message_package_excludes_the_message_text():
    package = build_package(make_report(message=True))
    assert package["kind"] == "message"
    assert package["domains"] == ["sbi-kyc-update.in"]
    text = canonical_json(package)
    for private in ("Rahul", "9876543210", "id=42", "share the OTP"):
        assert private not in text


def test_canonical_json_is_sorted_and_compact():
    assert canonical_json({"b": 1, "a": {"d": [1, 2], "c": "ü"}}) == '{"a":{"c":"ü","d":[1,2]},"b":1}'


def test_commitment_changes_when_anything_changes():
    package = build_package(make_report())
    tampered = json.loads(json.dumps(package))
    tampered["classification"] = "Low Risk"
    assert commitment_of(package) == commitment_of(json.loads(json.dumps(package)))
    assert commitment_of(package) != commitment_of(tampered)


def test_each_package_gets_a_fresh_salt():
    report = make_report()
    assert build_package(report)["salt"] != build_package(report)["salt"]


@pytest.mark.parametrize("classification", [Classification.LOW_RISK, Classification.INCONCLUSIVE])
def test_reports_without_warnings_cannot_be_registered(classification):
    with pytest.raises(NotRegistrable):
        build_package(make_report(classification))


def test_indicator_hash_is_case_insensitive_and_empty_for_no_domain():
    assert indicator_hash("SBI-KYC-update.in") == indicator_hash("sbi-kyc-update.in")
    assert indicator_hash(None) == b"\x00" * 32


# Endpoint


@pytest.fixture
def fake_chain(monkeypatch):
    calls = []

    def register(commitment, indicator, classification, kind):
        calls.append((commitment, indicator, classification, kind))
        return chain.Registration(
            transaction_hash="0x" + "ab" * 32, block_number=7, contract_address="0x" + "11" * 20,
            chain_id=11155111, reporter="0x" + "22" * 20, explorer_url="https://sepolia.etherscan.io/tx/0xabab",
        )

    monkeypatch.setattr(chain, "can_register", lambda: True)
    monkeypatch.setattr(chain, "register", register)
    return calls


def post_report(report: Report, ip: str = "203.0.113.5"):
    body = {"report": json.loads(report.model_dump_json())}
    return client.post("/reports", json=body, headers={"X-Forwarded-For": ip})


def test_registers_report_and_returns_verifiable_package(fake_chain):
    response = post_report(make_report())
    assert response.status_code == 200
    data = response.json()
    assert data["commitment"] == "0x" + commitment_of(data["package"]).hex()
    assert data["canonical_json"] == canonical_json(data["package"])
    commitment, indicator, classification, kind = fake_chain[0]
    assert "0x" + commitment.hex() == data["commitment"]
    assert indicator == indicator_hash("sbi-kyc-update.in")
    assert (classification, kind) == (2, 0)


def test_low_risk_report_is_refused(fake_chain):
    response = post_report(make_report(Classification.LOW_RISK))
    assert response.status_code == 400
    assert fake_chain == []


def test_registry_not_configured(monkeypatch):
    monkeypatch.setattr(chain, "can_register", lambda: False)
    assert post_report(make_report()).status_code == 503


def test_rate_limit_per_visitor(fake_chain):
    for _ in range(REGISTRATION.limit):
        assert post_report(make_report()).status_code == 200
    assert post_report(make_report()).status_code == 429
    assert post_report(make_report(), ip="198.51.100.9").status_code == 200


def test_chain_failure_is_reported(fake_chain, monkeypatch):
    def fail(*args):
        raise chain.RegistryUnavailable("The blockchain transaction failed (TimeoutError).")

    monkeypatch.setattr(chain, "register", fail)
    response = post_report(make_report())
    assert response.status_code == 502
    assert "TimeoutError" in response.json()["detail"]
