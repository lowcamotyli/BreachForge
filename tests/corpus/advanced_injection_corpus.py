from __future__ import annotations

from uuid import uuid4

from execution_plane.validator.strategies.advanced_injection import (
    HeaderInjectionStrategy,
    LdapInjectionStrategy,
)
from execution_plane.validator.strategies.nosql_injection import NoSqlInjectionStrategy
from execution_plane.validator.strategies.ssti import SstiStrategy
from storage.db.models import RawProbe


def test_nosql_corpus_auth_bypass() -> None:
    strategy = NoSqlInjectionStrategy()
    attack = RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        response={"status_code": 200, "body": "{token:abc,user:{id:1}}"},
    )
    control = RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        response={"status_code": 401, "body": "{error:Unauthorized}"},
    )
    result = strategy.validate(attack, control)
    assert result is not None and result.confidence_score >= 0.90 and result.proof_type == "nosql_operator_injection"


def test_ssti_corpus_jinja2() -> None:
    strategy = SstiStrategy()
    attack = RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        response={"status_code": 200, "body": "Welcome back! Result: 49. Config loaded."},
    )
    result = strategy.validate(attack, None)
    assert result is not None and result.confidence_score == 0.95


def test_ldap_corpus_bypass() -> None:
    strategy = LdapInjectionStrategy()
    attack = RawProbe(id=uuid4(), attack_task_id=uuid4(), response={"status_code": 200, "body": "Welcome admin"})
    control = RawProbe(id=uuid4(), attack_task_id=uuid4(), response={"status_code": 403, "body": "Forbidden"})
    result = strategy.validate(attack, control)
    assert result is not None and result.confidence_score == 0.88


def test_header_corpus_reflection() -> None:
    strategy = HeaderInjectionStrategy()
    attack = RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        response={"status_code": 302, "body": "", "headers": {"Location": "http://evil.com/redirect"}},
    )
    result = strategy.validate(attack, None)
    assert result is not None and result.confidence_score == 0.87
