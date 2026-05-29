from __future__ import annotations

from enum import Enum
import re


class MissStage(str, Enum):
    CRAWLER = "crawler"
    AUTH = "auth"
    PLANNER = "planner"
    EXECUTION = "execution"
    VALIDATOR = "validator"
    UNSUPPORTED_CLASS = "unsupported_class"


class MissClassifier:
    SUPPORTED_CLASSES_NATIVE = [
        "BOLA",
        "BFLA",
        "TENANT_ISOLATION",
        "PRIVILEGE_ESCALATION",
        "RACE_CONDITION",
        "BUSINESS_LOGIC",
        "AUTH_BYPASS",
    ]

    @staticmethod
    def _normalize_endpoint(endpoint: str) -> str:
        try:
            from execution_plane.providers.normalizers import FindingNormalizer

            return FindingNormalizer.normalize_endpoint(endpoint)
        except ModuleNotFoundError:
            normalized = endpoint.split("?", 1)[0]
            uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
            digit_pattern = r"^\d+$"
            segments = normalized.split("/")
            normalized_segments: list[str] = []
            for segment in segments:
                if re.fullmatch(uuid_pattern, segment):
                    normalized_segments.append("{id}")
                elif re.fullmatch(digit_pattern, segment):
                    normalized_segments.append("{id}")
                else:
                    normalized_segments.append(segment)
            normalized = "/".join(normalized_segments).lower()
            if normalized != "/" and normalized.endswith("/"):
                normalized = normalized[:-1]
            return normalized

    @classmethod
    def classify(
        cls,
        vuln: dict[str, object],
        scan_result: dict[str, object],
        engine: str = "native",
    ) -> str:
        """
        Classify why engine missed this ground truth vulnerability.
        Returns MissStage value.
        """
        attack_class = str(vuln.get("type", "")).upper()
        endpoint = str(vuln.get("endpoint", ""))

        if engine != "native" and attack_class not in cls.SUPPORTED_CLASSES_NATIVE:
            return MissStage.UNSUPPORTED_CLASS.value

        discovered: list[str] = list(scan_result.get("discovered_endpoints") or [])
        norm_endpoint = cls._normalize_endpoint(endpoint)
        discovered_normalized = [cls._normalize_endpoint(e) for e in discovered]
        if discovered and norm_endpoint not in discovered_normalized:
            return MissStage.CRAWLER.value

        auth_health = float(scan_result.get("auth_health_rate") or 1.0)
        if auth_health < 0.5:
            return MissStage.AUTH.value

        probes: list[dict[str, object]] = list(scan_result.get("probes_generated") or [])
        if probes:
            probe_classes = {str(p.get("attack_class", "")).upper() for p in probes}
            if attack_class not in probe_classes:
                return MissStage.PLANNER.value

        executed: list[dict[str, object]] = list(scan_result.get("probes_executed") or [])
        if executed:
            failed = [p for p in executed if int(p.get("status_code") or 0) <= 0]
            if failed:
                return MissStage.EXECUTION.value

        return MissStage.VALIDATOR.value

    @classmethod
    def annotate_fn_list(
        cls,
        ground_truth_vulns: list[dict[str, object]],
        findings: list[dict[str, object]],
        scan_result: dict[str, object],
        engine: str = "native",
    ) -> list[dict[str, object]]:
        """
        For each ground truth vuln not covered by findings, return annotated FN dict with missing_detection_stage.
        """
        covered_types = {str(f.get("type", "")).upper() + "|" + str(f.get("endpoint", "")) for f in findings}
        fn_list: list[dict[str, object]] = []
        for vuln in ground_truth_vulns:
            key = str(vuln.get("type", "")).upper() + "|" + str(vuln.get("endpoint", ""))
            if key not in covered_types:
                stage = cls.classify(vuln, scan_result, engine)
                fn_list.append({**vuln, "missing_detection_stage": stage})
        return fn_list
