"""Certificate authorities that browsers have publicly distrusted.

Matching is by issuer name, which is a simplification: a stronger version would
match certificate fingerprints. Every entry must cite a public source. Check each entry against the original
announcement before relying on it, and only add a CA (for example, after an
incident like eMudhra's) once a browser vendor or the CA has published details.

`issued_after` means only certificates issued on or after that date are affected,
which is how recent distrust decisions are applied.
"""

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class DistrustedCa:
    name: str
    match: tuple[str, ...]  # Lower-case text to find in the issuer's organisation or common name
    reason: str
    source: str
    issued_after: date | None = None


DISTRUSTED_CAS: tuple[DistrustedCa, ...] = (
    DistrustedCa(
        name="DigiNotar",
        match=("diginotar",),
        reason="Compromised in 2011 and used to issue fraudulent certificates. Removed from all major browsers.",
        source="Removal announcements by Mozilla, Google and Microsoft (September 2011)",
    ),
    DistrustedCa(
        name="WoSign and StartCom",
        match=("wosign", "startcom"),
        reason="Distrusted by Mozilla, Google and Apple in 2016-2017 after misissuance and backdating.",
        source="Mozilla Security Blog and Google Security Blog (October 2016)",
    ),
    DistrustedCa(
        name="CNNIC",
        match=("cnnic", "china internet network information center"),
        reason="Distrusted in 2015 after an intermediate it issued was used to impersonate Google domains.",
        source="Google Security Blog and Mozilla Security Blog (2015)",
    ),
    DistrustedCa(
        name="TrustCor",
        match=("trustcor",),
        reason="Root certificates removed by Mozilla in 2022 over concerns about its ownership and conduct.",
        source="Mozilla dev-security-policy discussion and root store change (2022)",
    ),
    DistrustedCa(
        name="Camerfirma",
        match=("camerfirma",),
        reason="Distrusted in 2021 after repeated compliance failures.",
        source="Chrome Root Program and Mozilla root store changes (2021)",
    ),
    DistrustedCa(
        name="Entrust",
        # Entrust's own roots only: Entrust now also issues through Sectigo's roots, which are trusted.
        match=("entrust root certification authority",),
        reason="Chrome and Mozilla distrust TLS certificates from Entrust's roots issued after November 2024.",
        source="Google Security Blog announcement (June 2024)",
        issued_after=date(2024, 11, 12),
    ),
    DistrustedCa(
        name="Chunghwa Telecom and Netlock",
        match=("chunghwa telecom", "netlock"),
        reason="Chrome distrusts TLS certificates from these CAs issued after July 2025.",
        source="Google Security Blog announcement (May 2025)",
        issued_after=date(2025, 8, 1),
    ),
)


def find_distrusted(issuer_names: list[str], issued_on: date | None) -> DistrustedCa | None:
    text = " | ".join(issuer_names).lower()
    for ca in DISTRUSTED_CAS:
        if not any(term in text for term in ca.match):
            continue
        if ca.issued_after and issued_on and issued_on < ca.issued_after:
            continue
        return ca
    return None
