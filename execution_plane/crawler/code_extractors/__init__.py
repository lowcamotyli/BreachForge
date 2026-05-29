from __future__ import annotations

from execution_plane.crawler.code_extractors.express_extractor import extract_express_routes
from execution_plane.crawler.code_extractors.fastapi_extractor import extract_fastapi_routes
from execution_plane.crawler.code_extractors.rails_extractor import extract_rails_routes
from execution_plane.crawler.code_extractors.spring_extractor import extract_spring_routes


def extract_routes(code: str, framework: str) -> list[dict]:
    extractors = {
        "fastapi": extract_fastapi_routes,
        "express": extract_express_routes,
        "rails": extract_rails_routes,
        "spring": extract_spring_routes,
    }
    extractor = extractors.get(framework.lower())
    if extractor is None:
        return []
    return extractor(code)
