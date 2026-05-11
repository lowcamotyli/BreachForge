from __future__ import annotations

import base64
import json
from typing import Any


class JwtAttackCorpus:
    def make_alg_none_vulnerable_response(self, request_headers: dict) -> dict:
        authorization = request_headers.get("Authorization", "")
        if self._authorization_has_alg_none(authorization):
            return {
                "status": 200,
                "body": {"user": {"id": 1, "role": "user"}, "data": [1, 2, 3]},
            }
        return {"status": 401, "body": {"error": "unauthorized"}}

    def make_claim_escalation_vulnerable_response(self, role_claim: str) -> dict:
        if role_claim == "admin":
            return {"status": 200, "body": {"admin_data": "secret"}}
        return {"status": 403, "body": {"error": "forbidden"}}

    def make_expired_token_vulnerable_response(self, exp_timestamp: int) -> dict:
        return {"status": 200, "body": {"data": "ok"}}

    def _authorization_has_alg_none(self, authorization: str) -> bool:
        scheme, _, token = authorization.partition(" ")
        if scheme != "Bearer" or not token:
            return False

        header_segment, _, _ = token.partition(".")
        try:
            padded_segment = header_segment + "=" * (-len(header_segment) % 4)
            decoded = base64.urlsafe_b64decode(padded_segment.encode("ascii"))
            header: Any = json.loads(decoded)
        except (ValueError, TypeError):
            return False

        return isinstance(header, dict) and header.get("alg") == "none"


def test_corpus_alg_none_vulnerable_accepts_alg_none_token() -> None:
    corpus = JwtAttackCorpus()
    response = corpus.make_alg_none_vulnerable_response(
        {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.payload."}
    )

    assert response["status"] == 200


def test_corpus_alg_none_rejects_valid_token() -> None:
    corpus = JwtAttackCorpus()
    response = corpus.make_alg_none_vulnerable_response({"Authorization": "Bearer payload.signature"})

    assert response["status"] == 401


def test_corpus_expired_token_accepted() -> None:
    corpus = JwtAttackCorpus()
    response = corpus.make_expired_token_vulnerable_response(exp_timestamp=1000000000)

    assert response["status"] == 200
