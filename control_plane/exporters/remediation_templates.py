from __future__ import annotations

from typing import Any, ClassVar


class RemediationTemplates:
    _TEMPLATES: ClassVar[dict[str, dict[str, Any]]] = {
        "broken_object_level_auth": {
            "summary": "API exposes resources of other users due to missing ownership validation.",
            "root_cause": "Server trusts client-supplied object identifiers without verifying the caller owns the resource.",
            "remediation_steps": [
                "Add ownership checks that compare the authenticated principal to the resource owner before returning or mutating data.",
                "Use indirect reference mapping so internal object identifiers are not exposed directly.",
                "Centralize authorization logic in a shared policy layer and enforce deny-by-default behavior.",
                "Add integration tests that attempt cross-user access for each object endpoint.",
            ],
            "verification": "Confirm authenticated user A cannot read or modify resources belonging to user B when using user B object identifiers.",
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                "https://cwe.mitre.org/data/definitions/639.html",
            ],
        },
        "broken_authentication": {
            "summary": "API allows attackers to impersonate legitimate users due to weak authentication controls.",
            "root_cause": "Identity proofing and session token handling are insufficiently protected against guessing, theft, or replay.",
            "remediation_steps": [
                "Require strong credential policies and enforce multi-factor authentication for sensitive operations.",
                "Implement short-lived signed tokens with secure rotation and immediate revocation on compromise signals.",
                "Rate-limit and monitor login, token refresh, and password reset flows to prevent brute-force attacks.",
                "Harden account recovery and enrollment workflows with step-up verification and anti-automation controls.",
            ],
            "verification": "Validate that invalid, expired, replayed, and brute-force authentication attempts are blocked and logged while valid users can authenticate normally.",
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                "https://cwe.mitre.org/data/definitions/287.html",
            ],
        },
        "broken_object_property_level_auth": {
            "summary": "API exposes or accepts sensitive object properties that should not be accessible for the caller.",
            "root_cause": "Field-level authorization is missing, allowing overexposure or mass assignment of restricted attributes.",
            "remediation_steps": [
                "Define allowlists for readable and writable fields per role and operation.",
                "Ignore or reject client-provided properties that are not explicitly permitted.",
                "Create dedicated input and output schemas that separate internal fields from public fields.",
                "Add tests covering unauthorized reads and writes of high-risk properties.",
            ],
            "verification": "Verify that unauthorized fields are neither returned in responses nor accepted in create or update requests.",
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                "https://cwe.mitre.org/data/definitions/213.html",
            ],
        },
        "unrestricted_resource_consumption": {
            "summary": "API can be abused to exhaust compute, memory, storage, or third-party quotas causing denial of service.",
            "root_cause": "No effective request throttling, workload bounds, or cost controls are enforced per client and endpoint.",
            "remediation_steps": [
                "Apply per-identity and per-endpoint rate limits with burst and sustained thresholds.",
                "Enforce payload size limits, pagination caps, and execution timeouts for expensive operations.",
                "Queue or reject non-critical high-cost jobs when capacity thresholds are reached.",
                "Monitor resource saturation metrics and trigger automated protective actions on anomaly thresholds.",
            ],
            "verification": "Confirm stress and abuse tests cannot degrade service availability beyond defined limits and that throttling responses are consistently returned.",
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                "https://cwe.mitre.org/data/definitions/770.html",
            ],
        },
        "broken_function_level_auth": {
            "summary": "API exposes privileged actions to users lacking permission for those functions.",
            "root_cause": "Endpoint-level authorization checks are absent or inconsistent across function routes.",
            "remediation_steps": [
                "Enforce authorization checks for every function endpoint before business logic executes.",
                "Adopt role and permission matrices mapped to explicit allow rules for each action.",
                "Hide or disable privileged routes in client-facing metadata unless caller is authorized.",
                "Add negative authorization tests for all privileged operations and roles.",
            ],
            "verification": "Ensure users with insufficient privileges receive access denied responses for every restricted function endpoint.",
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                "https://cwe.mitre.org/data/definitions/285.html",
            ],
        },
        "unrestricted_access_to_sensitive_business_flows": {
            "summary": "API allows abuse of high-value business workflows without adequate anti-automation or fraud controls.",
            "root_cause": "Business transactions rely on functional correctness but lack abuse detection and flow-level guardrails.",
            "remediation_steps": [
                "Identify sensitive workflows and apply per-user and per-entity velocity limits.",
                "Require step-up verification for high-risk actions and enforce transaction integrity constraints.",
                "Implement anti-automation controls such as progressive challenges and anomaly-based blocking.",
                "Instrument workflow telemetry to detect replay, sequencing abuse, and high-volume manipulation patterns.",
            ],
            "verification": "Demonstrate that scripted high-volume abuse attempts against sensitive flows are blocked or degraded before business impact occurs.",
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
                "https://cwe.mitre.org/data/definitions/841.html",
            ],
        },
        "server_side_request_forgery": {
            "summary": "API permits server-initiated requests to attacker-controlled destinations, enabling access to internal resources.",
            "root_cause": "Untrusted URLs or network targets are fetched without strict destination validation and network egress controls.",
            "remediation_steps": [
                "Allow outbound requests only to validated allowlisted hosts, ports, and protocols.",
                "Normalize and validate target addresses after DNS resolution to block private, loopback, and link-local ranges.",
                "Disable automatic redirect following unless each redirect target is revalidated against policy.",
                "Apply network segmentation and egress firewall rules to prevent access to internal control planes and metadata services.",
            ],
            "verification": "Confirm requests to internal or non-allowlisted destinations are blocked and cannot reach protected network ranges.",
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
                "https://cwe.mitre.org/data/definitions/918.html",
            ],
        },
        "security_misconfiguration": {
            "summary": "API exposes insecure defaults or operational gaps that increase the attack surface.",
            "root_cause": "Configuration baselines are incomplete, drift is unmanaged, and hardening controls are not consistently enforced.",
            "remediation_steps": [
                "Define secure baseline configurations for environments and enforce them through automated deployment checks.",
                "Remove unused features, endpoints, methods, and default accounts from all deployments.",
                "Require strong transport security, strict headers, and hardened error handling that avoids sensitive leakage.",
                "Continuously scan for configuration drift and fail builds or releases that violate baseline policies.",
            ],
            "verification": "Validate that all deployed environments pass configuration baseline checks and no insecure defaults remain accessible.",
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                "https://cwe.mitre.org/data/definitions/16.html",
            ],
        },
        "improper_inventory_management": {
            "summary": "Unknown, deprecated, or unmanaged API assets remain exposed and unprotected.",
            "root_cause": "The organization lacks complete API asset discovery, ownership tracking, and lifecycle governance.",
            "remediation_steps": [
                "Maintain a continuously updated inventory of API hosts, versions, endpoints, and owners.",
                "Require registration and risk classification before exposing new API surfaces to consumers.",
                "Deprecate and remove obsolete versions on a fixed schedule with enforced shutdown dates.",
                "Continuously discover and alert on unregistered internet-facing API assets.",
            ],
            "verification": "Verify that every reachable API endpoint is present in inventory with an owner and that deprecated versions are no longer accessible.",
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                "https://cwe.mitre.org/data/definitions/1059.html",
            ],
        },
        "unsafe_consumption_of_apis": {
            "summary": "API inherits security weaknesses from third-party or upstream APIs without sufficient validation and isolation.",
            "root_cause": "Trust is delegated to external services without enforcing contract validation, failure controls, and least privilege.",
            "remediation_steps": [
                "Validate all upstream response data against strict schemas before using it in downstream logic.",
                "Apply timeouts, retries with backoff, and circuit breaking to limit cascading failures.",
                "Use least-privilege credentials and isolate external integrations by scope and network boundaries.",
                "Track upstream dependency security posture and block integrations that fail trust requirements.",
            ],
            "verification": "Confirm malformed or malicious upstream responses are rejected safely and do not cause privilege abuse or unstable behavior.",
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
                "https://cwe.mitre.org/data/definitions/20.html",
            ],
        },
    }

    def get_template(self, attack_class: str) -> dict[str, Any] | None:
        return self._TEMPLATES.get(attack_class)

    def get_remediation_steps(self, attack_class: str) -> list[str]:
        template = self.get_template(attack_class)
        if template is None:
            return []
        steps = template.get("remediation_steps")
        return steps if isinstance(steps, list) else []

    def all_classes(self) -> list[str]:
        return list(self._TEMPLATES.keys())
