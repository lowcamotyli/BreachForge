from __future__ import annotations

from typing import Any

from execution_plane.validator.strategies.base import ValidationStrategy
from storage.db.models import AttackTask
from storage.db.models import ProofArtifact, RawProbe


class SstiStrategy(ValidationStrategy):
    _MIN_CONFIDENCE: float = 0.95
    MATH_RESULT: str = "49"
    PAYLOAD_ENGINE_MAP: dict[str, str] = {
        "{{7*7}}": "jinja2/twig",
        "${7*7}": "freemarker/el",
        "<%= 7*7 %>": "erb",
        "#{7*7}": "ruby/thymeleaf",
        "*{7*7}": "spring_el",
    }

    def validate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> ProofArtifact | None:
        candidate = self._extract_candidate(attack_probe=attack_probe, control_probe=control_probe)
        unauth_injectable = bool(getattr(candidate, "unauth_injectable", False))
        if not unauth_injectable and self._has_unauth_injectable_hint(candidate):
            unauth_injectable = True

        unauth_mode = self._is_unauth_mode(attack_probe=attack_probe, control_probe=control_probe)
        if unauth_mode and not unauth_injectable:
            return None
        if unauth_mode and unauth_injectable:
            self._clear_auth_credentials(attack_probe)
            if control_probe is not None:
                self._clear_auth_credentials(control_probe)

        attack_body = self._extract_body(attack_probe.response)
        if self.MATH_RESULT not in attack_body:
            return None

        confidence = self._MIN_CONFIDENCE

        engine = "unknown"
        body_lower = attack_body.lower()
        if "config" in body_lower:
            engine = "jinja2"
        elif "_self" in body_lower:
            engine = "twig"

        triggering_payload = next((payload for payload in self.PAYLOAD_ENGINE_MAP if payload in attack_body), "unknown")

        summary = f"SSTI confirmed: math eval result 49 found in response. Engine hint: {engine}."
        evidence_notes = (
            f"engine={engine},triggering_payload={triggering_payload[:64]},math_result={self.MATH_RESULT}"
        )

        return ProofArtifact(
            attack_task_id=attack_probe.attack_task_id,
            proof_type=self.expected_proof_type(),
            confidence_score=confidence,
            attack_probe_id=attack_probe.id,
            control_probe_id=control_probe.id if control_probe else None,
            summary=summary,
            evidence_notes=evidence_notes,
        )

    def expected_proof_type(self) -> str:
        return "ssti_math_eval"

    def expected_attack_class(self) -> str:
        return "ssti"

    def _extract_body(self, response: dict[str, object]) -> str:
        return str(response.get("body") or response.get("text") or "")

    def _extract_candidate(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> AttackTask | None:
        probe_task = getattr(attack_probe, "attack_task", None)
        if isinstance(probe_task, AttackTask):
            return probe_task
        if isinstance(control_probe, AttackTask):
            return control_probe
        for source in (attack_probe.request, attack_probe.response):
            candidate = source.get("attack_task")
            if isinstance(candidate, AttackTask):
                return candidate
        return None

    def _has_unauth_injectable_hint(self, candidate: AttackTask | None) -> bool:
        if candidate is None:
            return False
        hypothesis = getattr(candidate, "hypothesis", "")
        if not isinstance(hypothesis, str):
            return False
        return "unauth_injectable=true" in hypothesis.lower()

    def _is_unauth_mode(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> bool:
        context = self._extract_context(attack_probe=attack_probe, control_probe=control_probe)
        return bool(getattr(context, "unauth_mode", False))

    def _extract_context(self, attack_probe: RawProbe, control_probe: RawProbe | None) -> object:
        task = self._extract_candidate(attack_probe=attack_probe, control_probe=control_probe)
        task_context = getattr(task, "context", None)
        if task_context is not None:
            return task_context
        for source in (attack_probe.request, attack_probe.response):
            context = source.get("context")
            if context is not None:
                return context
            if "unauth_mode" in source:
                return _ContextProxy(unauth_mode=source.get("unauth_mode"))
        return _ContextProxy(unauth_mode=False)

    def _clear_auth_credentials(self, probe: RawProbe) -> None:
        for container in (probe.request, probe.response):
            headers = container.get("headers")
            if isinstance(headers, dict):
                for key in list(headers.keys()):
                    if key.lower() in {"authorization", "cookie"}:
                        headers.pop(key, None)
            if "cookies" in container:
                cookies = container.get("cookies")
                if isinstance(cookies, dict):
                    container["cookies"] = {}
                elif isinstance(cookies, list):
                    container["cookies"] = []
                else:
                    container["cookies"] = ""
            container["credentials"] = {}


class _ContextProxy:
    def __init__(self, unauth_mode: Any) -> None:
        self.unauth_mode = bool(unauth_mode)
