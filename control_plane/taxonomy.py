from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar


@dataclass(frozen=True)
class AttackClassMapping:
    owasp_api: str
    wstg: str
    asvs: str
    cwe: int
    cvss_hint: str


class StandardsTaxonomy:
    """Maps attack class identifiers to security standard references."""

    _REGISTRY: ClassVar[dict[str, AttackClassMapping]] = {
        "broken_object_level_auth": AttackClassMapping(
            owasp_api="API1:2023",
            wstg="WSTG-ATHZ-01",
            asvs="4.2.1",
            cwe=639,
            cvss_hint="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        ),
        "broken_authentication": AttackClassMapping(
            owasp_api="API2:2023",
            wstg="WSTG-ATHN-04",
            asvs="2.1.1",
            cwe=287,
            cvss_hint="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        ),
        "broken_object_property_level_auth": AttackClassMapping(
            owasp_api="API3:2023",
            wstg="WSTG-ATHZ-02",
            asvs="4.3.2",
            cwe=213,
            cvss_hint="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        ),
        "unrestricted_resource_consumption": AttackClassMapping(
            owasp_api="API4:2023",
            wstg="WSTG-PERF-01",
            asvs="13.4.2",
            cwe=770,
            cvss_hint="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        ),
        "broken_function_level_auth": AttackClassMapping(
            owasp_api="API5:2023",
            wstg="WSTG-ATHZ-02",
            asvs="4.1.2",
            cwe=285,
            cvss_hint="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        ),
        "unrestricted_access_to_sensitive_business_flows": AttackClassMapping(
            owasp_api="API6:2023",
            wstg="WSTG-BUSL-01",
            asvs="1.11.1",
            cwe=841,
            cvss_hint="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
        ),
        "server_side_request_forgery": AttackClassMapping(
            owasp_api="API7:2023",
            wstg="WSTG-INPV-19",
            asvs="12.6.1",
            cwe=918,
            cvss_hint="AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
        ),
        "security_misconfiguration": AttackClassMapping(
            owasp_api="API8:2023",
            wstg="WSTG-CONF-01",
            asvs="14.1.1",
            cwe=16,
            cvss_hint="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
        ),
        "improper_inventory_management": AttackClassMapping(
            owasp_api="API9:2023",
            wstg="WSTG-CONF-10",
            asvs="14.1.2",
            cwe=1059,
            cvss_hint="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        ),
        "unsafe_consumption_of_apis": AttackClassMapping(
            owasp_api="API10:2023",
            wstg="WSTG-INPV-01",
            asvs="5.1.1",
            cwe=20,
            cvss_hint="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        ),
    }

    def get_mappings(self, attack_class: str) -> dict[str, object]:
        mapping = self._REGISTRY.get(attack_class)
        if mapping is None:
            return {}
        return {
            "owasp_api": mapping.owasp_api,
            "wstg": mapping.wstg,
            "asvs": mapping.asvs,
            "cwe": mapping.cwe,
            "cvss_hint": mapping.cvss_hint,
        }

    def get_cvss_hint(self, attack_class: str) -> str:
        mapping = self._REGISTRY.get(attack_class)
        return mapping.cvss_hint if mapping else ""

    def all_attack_classes(self) -> list[str]:
        return list(self._REGISTRY.keys())
