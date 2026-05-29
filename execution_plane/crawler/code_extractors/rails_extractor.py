from __future__ import annotations

import re

_RAILS_VERB_RE = re.compile(r"""^[ \t]*(get|post|put|delete|patch)[ \t]+["']([^"']+)["']""", re.MULTILINE)
_RAILS_RESOURCES_RE = re.compile(r"""^[ \t]*resources[ \t]+:(\w+)""", re.MULTILINE)


def extract_rails_routes(code: str) -> list[dict]:
    routes = [
        {"method": match.group(1).upper(), "path": _normalize_path(match.group(2))}
        for match in _RAILS_VERB_RE.finditer(code)
    ]

    for match in _RAILS_RESOURCES_RE.finditer(code):
        name = match.group(1)
        routes.extend(
            [
                {"method": "GET", "path": f"/{name}"},
                {"method": "POST", "path": f"/{name}"},
                {"method": "GET", "path": f"/{name}/{{id}}"},
                {"method": "PUT", "path": f"/{name}/{{id}}"},
                {"method": "PATCH", "path": f"/{name}/{{id}}"},
                {"method": "DELETE", "path": f"/{name}/{{id}}"},
            ]
        )

    return routes


def _normalize_path(path: str) -> str:
    if path.startswith("/"):
        return path
    return f"/{path}"
