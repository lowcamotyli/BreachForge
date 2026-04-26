from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from execution_plane.planner.playbooks import AttackPlaybook, PlaybookValidationError

_BUILTIN_DIR = Path(__file__).resolve().parent / "playbooks"
_SUPPORTED_SUFFIXES = {".json", ".yaml", ".yml"}


def load_playbook(path: Path) -> AttackPlaybook:
    if path.suffix.lower() not in _SUPPORTED_SUFFIXES:
        raise PlaybookValidationError(f"unsupported playbook suffix: {path.suffix}")

    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PlaybookValidationError(f"malformed playbook {path.name}") from exc
    parsed = _parse_playbook_text(raw_text=raw_text, path=path)

    if not isinstance(parsed, dict):
        raise PlaybookValidationError(f"playbook {path.name} must be a JSON/YAML object")
    return AttackPlaybook.from_dict(parsed)


def load_builtin_playbooks() -> list[AttackPlaybook]:
    playbooks: list[AttackPlaybook] = []
    for path in sorted(_BUILTIN_DIR.iterdir()):
        if path.suffix.lower() not in _SUPPORTED_SUFFIXES:
            continue
        playbooks.append(load_playbook(path))
    return playbooks


def _parse_playbook_text(*, raw_text: str, path: Path) -> Any:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        pass

    try:
        import yaml  # type: ignore[import-not-found]
    except Exception as exc:
        raise PlaybookValidationError(f"malformed playbook {path.name}") from exc

    try:
        return yaml.safe_load(raw_text)
    except Exception as exc:
        raise PlaybookValidationError(f"malformed playbook {path.name}") from exc
