from __future__ import annotations

from pathlib import Path
from typing import Any


TEMPLATE_PATH = Path(__file__).with_name("scorecard-template.md")


class ScorecardRenderer:
    def __init__(self, template_path: Path | None = None) -> None:
        self.template_path = template_path or TEMPLATE_PATH

    def render(self, metrics: dict[str, Any], output_path: Path, fmt: str = "markdown") -> None:
        if fmt != "markdown":
            raise ValueError("Only markdown scorecard rendering is supported")

        template = self.template_path.read_text(encoding="utf-8")
        rendered = template
        rendered = rendered.replace(
            "<!-- [TEMPLATE] version_header: corpus_version, engine_config_version, schema_version -->",
            version_header(
                str(metrics.get("corpus_version", "unknown")),
                str(metrics.get("engine_config_version", "unknown")),
                str(metrics.get("schema_version", "unknown")),
            ),
        )
        rendered = rendered.replace(
            "<!-- [TEMPLATE] coverage_by_attack_class: class, tested, tp, fp, fn, covered_pct -->",
            self._coverage_rows(metrics),
        )
        rendered = rendered.replace(
            "<!-- [TEMPLATE] false_positive_false_negative_summary: class, fp_count, fn_count, notes -->",
            self._fp_fn_rows(metrics),
        )
        rendered = rendered.replace(
            "<!-- [TEMPLATE] proof_depth: class, proof_type, avg_confidence, min_confidence -->",
            self._proof_depth_rows(metrics),
        )
        rendered = rendered.replace(
            "<!-- [TEMPLATE] auth_discovery_health: auth_sessions_tested, discovery_coverage_pct, blind_spots_count, auth_failures -->",
            self._auth_discovery_rows(metrics),
        )
        rendered = rendered.replace(
            "<!-- [TEMPLATE] unsupported_classes: class, reason -->",
            self._unsupported_class_rows(metrics),
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")

    def _coverage_rows(self, metrics: dict[str, Any]) -> str:
        rows = metrics.get("coverage_by_attack_class", {})
        if not isinstance(rows, dict) or not rows:
            return "| _none_ | 0 | 0 | 0 | 0 | 0.00 |"

        rendered_rows = []
        for attack_class in sorted(rows):
            values = _mapping(rows[attack_class])
            rendered_rows.append(
                "| {attack_class} | {tested} | {tp} | {fp} | {fn} | {covered_pct} |".format(
                    attack_class=_escape_markdown(attack_class),
                    tested=_format_value(values.get("tested", 0)),
                    tp=_format_value(values.get("tp", values.get("TP", 0))),
                    fp=_format_value(values.get("fp", values.get("FP", 0))),
                    fn=_format_value(values.get("fn", values.get("FN", 0))),
                    covered_pct=_format_percent(values.get("covered_pct", values.get("covered_percent", 0))),
                )
            )
        return "\n".join(rendered_rows)

    def _fp_fn_rows(self, metrics: dict[str, Any]) -> str:
        rows = metrics.get("false_positive_false_negative_summary", {})
        if not isinstance(rows, dict) or not rows:
            return "| _none_ | 0 | 0 |  |"

        rendered_rows = []
        for attack_class in sorted(rows):
            values = _mapping(rows[attack_class])
            rendered_rows.append(
                "| {attack_class} | {fp_count} | {fn_count} | {notes} |".format(
                    attack_class=_escape_markdown(attack_class),
                    fp_count=_format_value(values.get("fp_count", 0)),
                    fn_count=_format_value(values.get("fn_count", 0)),
                    notes=_escape_markdown(str(values.get("notes", ""))),
                )
            )
        return "\n".join(rendered_rows)

    def _proof_depth_rows(self, metrics: dict[str, Any]) -> str:
        rows = metrics.get("proof_depth", {})
        if not isinstance(rows, dict) or not rows:
            return "| _none_ |  | 0.00 | 0.00 |"

        rendered_rows = []
        for attack_class in sorted(rows):
            values = _mapping(rows[attack_class])
            rendered_rows.append(
                "| {attack_class} | {proof_type} | {avg_confidence} | {min_confidence} |".format(
                    attack_class=_escape_markdown(attack_class),
                    proof_type=_escape_markdown(str(values.get("proof_type", ""))),
                    avg_confidence=_format_decimal(values.get("avg_confidence", 0)),
                    min_confidence=_format_decimal(values.get("min_confidence", 0)),
                )
            )
        return "\n".join(rendered_rows)

    def _auth_discovery_rows(self, metrics: dict[str, Any]) -> str:
        values = _mapping(metrics.get("auth_discovery_health", {}))
        fields = (
            "auth_sessions_tested",
            "discovery_coverage_pct",
            "blind_spots_count",
            "auth_failures",
        )
        return "\n".join(
            f"| {field} | {_format_percent(values.get(field, 0)) if field.endswith('_pct') else _format_value(values.get(field, 0))} |"
            for field in fields
        )

    def _unsupported_class_rows(self, metrics: dict[str, Any]) -> str:
        rows = metrics.get("unsupported_classes", [])
        if not isinstance(rows, list) or not rows:
            return "- _none_"

        rendered_rows = []
        for row in rows:
            values = _mapping(row)
            attack_class = _escape_markdown(str(values.get("class", "unknown")))
            reason = _escape_markdown(str(values.get("reason", "")))
            rendered_rows.append(f"- {attack_class}: {reason}")
        return "\n".join(rendered_rows)


def version_header(corpus_version: str, engine_config_version: str, schema_version: str) -> str:
    return "\n".join(
        (
            f"- corpus_version: {corpus_version}",
            f"- engine_config_version: {engine_config_version}",
            f"- schema_version: {schema_version}",
        )
    )


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _format_value(value: Any) -> str:
    if isinstance(value, float):
        return _format_decimal(value)
    return str(value)


def _format_percent(value: Any) -> str:
    if isinstance(value, int | float):
        if 0 <= float(value) <= 1:
            return f"{float(value) * 100:.2f}"
        return f"{float(value):.2f}"
    return str(value)


def _format_decimal(value: Any) -> str:
    if isinstance(value, int | float):
        return f"{float(value):.2f}"
    return str(value)


def _escape_markdown(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
