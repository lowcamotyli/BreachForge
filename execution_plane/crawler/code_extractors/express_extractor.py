from __future__ import annotations

import re

_EXPRESS_ROUTE_RE = re.compile(r"""(?:app|router)\.(get|post|put|delete|patch|all)\(["']([^"']+)["']""")


def extract_express_routes(code: str) -> list[dict]:
    return [
        {"method": match.group(1).upper(), "path": _normalize_path(match.group(2))}
        for match in _EXPRESS_ROUTE_RE.finditer(code)
    ]


def _normalize_path(path: str) -> str:
    if path.startswith("/"):
        return path
    return f"/{path}"
