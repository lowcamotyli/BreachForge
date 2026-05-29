from __future__ import annotations

import re

_SPRING_MAPPING_RE = re.compile(r"""@(Get|Post|Put|Delete|Patch)Mapping\(["']([^"']+)["']""")
_SPRING_REQUEST_MAPPING_RE = re.compile(
    r"""@RequestMapping\((?:[^)]*value=)?["']([^"']+)["'][^)]*method=RequestMethod\.(\w+)"""
)


def extract_spring_routes(code: str) -> list[dict]:
    routes = [
        {"method": match.group(1).upper(), "path": _normalize_path(match.group(2))}
        for match in _SPRING_MAPPING_RE.finditer(code)
    ]
    routes.extend(
        {"method": match.group(2).upper(), "path": _normalize_path(match.group(1))}
        for match in _SPRING_REQUEST_MAPPING_RE.finditer(code)
    )
    return routes


def _normalize_path(path: str) -> str:
    if path.startswith("/"):
        return path
    return f"/{path}"
