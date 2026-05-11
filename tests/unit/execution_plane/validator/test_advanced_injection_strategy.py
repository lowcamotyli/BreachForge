from __future__ import annotations

from uuid import uuid4

from execution_plane.validator.strategies.advanced_injection import (
    HeaderInjectionStrategy,
    LdapInjectionStrategy,
    XpathInjectionStrategy,
)
from execution_plane.validator.strategies.nosql_injection import NoSqlInjectionStrategy
from execution_plane.validator.strategies.ssti import SstiStrategy
from storage.db.models import ProofArtifact, RawProbe


def _probe(status: int, body: str, control_probe_id=None) -> RawProbe:
    return RawProbe(id=uuid4(), attack_task_id=uuid4(), response={"status_code": status, "body": body})


def test_nosql_auth_bypass() -> None:
    strategy = NoSqlInjectionStrategy()
    attack = _probe(200, "ok")
    control = _probe(401, "unauthorized")

    result = strategy.validate(attack, control)

    assert result is not None
    assert result.confidence_score == 0.92


def test_nosql_body_diff() -> None:
    strategy = NoSqlInjectionStrategy()
    attack = _probe(200, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    control = _probe(200, "b")

    result = strategy.validate(attack, control)

    assert result is not None
    assert result.confidence_score == 0.90


def test_nosql_no_signal() -> None:
    strategy = NoSqlInjectionStrategy()
    attack = _probe(200, "same-body")
    control = _probe(200, "same-body")

    result = strategy.validate(attack, control)

    assert result is None


def test_nosql_no_control() -> None:
    strategy = NoSqlInjectionStrategy()
    attack = _probe(200, "ok")

    result = strategy.validate(attack, None)

    assert result is None


def test_ssti_math_eval() -> None:
    strategy = SstiStrategy()
    attack = _probe(200, "Hello 49 world")

    result = strategy.validate(attack, None)

    assert result is not None
    assert result.confidence_score == 0.95
    assert result.proof_type == "ssti_math_eval"


def test_ssti_no_match() -> None:
    strategy = SstiStrategy()
    attack = _probe(200, "Hello 7*7 world")

    result = strategy.validate(attack, None)

    assert result is None


def test_ssti_engine_hint() -> None:
    strategy = SstiStrategy()
    attack = _probe(200, "config 49 present")

    result = strategy.validate(attack, None)

    assert result is not None
    assert "jinja2" in result.evidence_notes


def test_ldap_auth_bypass() -> None:
    strategy = LdapInjectionStrategy()
    attack = _probe(200, "welcome")
    control = _probe(403, "forbidden")

    result = strategy.validate(attack, control)

    assert result is not None
    assert result.confidence_score == 0.88


def test_ldap_error_disclosure() -> None:
    strategy = LdapInjectionStrategy()
    attack = _probe(200, "ldap error invalid filter")
    control = _probe(200, "ok")

    result = strategy.validate(attack, control)

    assert result is not None
    assert result.confidence_score == 0.70


def test_ldap_no_signal() -> None:
    strategy = LdapInjectionStrategy()
    attack = _probe(200, "clean body")
    control = _probe(200, "clean body")

    result = strategy.validate(attack, control)

    assert result is None


def test_xpath_data_return() -> None:
    strategy = XpathInjectionStrategy()
    attack = _probe(200, "a" * 300)
    control = _probe(200, "b" * 100)

    result = strategy.validate(attack, control)

    assert result is not None
    assert result.confidence_score == 0.85


def test_xpath_error() -> None:
    strategy = XpathInjectionStrategy()
    attack = _probe(200, "XPathException invalid expression")
    control = _probe(200, "x" * 100)

    result = strategy.validate(attack, control)

    assert result is not None
    assert result.confidence_score == 0.75


def test_xpath_no_signal() -> None:
    strategy = XpathInjectionStrategy()
    attack = _probe(200, "ok")
    control = _probe(200, "ok")

    result = strategy.validate(attack, control)

    assert result is None


def test_header_host_reflection() -> None:
    strategy = HeaderInjectionStrategy()
    attack = _probe(200, "redirect to evil.com now")
    control = _probe(200, "normal")

    result = strategy.validate(attack, control)

    assert result is not None
    assert result.confidence_score == 0.87


def test_header_location_reflection() -> None:
    strategy = HeaderInjectionStrategy()
    attack = RawProbe(
        id=uuid4(),
        attack_task_id=uuid4(),
        response={"status_code": 302, "body": "", "headers": {"Location": "http://evil.com/x"}},
    )

    result = strategy.validate(attack, None)

    assert result is not None
    assert result.confidence_score == 0.87


def test_header_access_change() -> None:
    strategy = HeaderInjectionStrategy()
    attack = _probe(200, "normal body")
    control = _probe(403, "forbidden")

    result = strategy.validate(attack, control)

    assert result is not None
    assert result.confidence_score == 0.80


def test_header_no_signal() -> None:
    strategy = HeaderInjectionStrategy()
    attack = _probe(200, "safe response")
    control = _probe(200, "safe response")

    result = strategy.validate(attack, control)

    assert result is None
