from __future__ import annotations

from pathlib import Path
import sys

from api.models.requests import MethodClassPolicy, ScanPolicyV2

PROJECT_ROOT = Path(__file__).resolve().parents[4]
execution_plane_package = sys.modules.get("execution_plane")
if execution_plane_package is not None and hasattr(execution_plane_package, "__path__"):
    execution_plane_path = PROJECT_ROOT / "execution_plane"
    if str(execution_plane_path) not in execution_plane_package.__path__:
        execution_plane_package.__path__.append(str(execution_plane_path))

from execution_plane.policy.action_classifier import ActionClass, classify, is_allowed_by_policy


def test_scan_policy_v2_default_conservative():
    p = ScanPolicyV2()
    assert not p.method_classes.allow_destructive
    assert p.destructive_budget.max_destructive_probes == 0


def test_action_classifier_get_is_read():
    assert classify("GET", "/api/users") == ActionClass.READ


def test_action_classifier_delete_is_destructive():
    assert classify("DELETE", "/api/users/1") == ActionClass.DESTRUCTIVE


def test_action_classifier_post_auth_is_credential():
    assert classify("POST", "/auth/login") == ActionClass.CREDENTIAL_SENSITIVE


def test_action_classifier_patch_is_reversible():
    assert classify("PATCH", "/api/users/1") == ActionClass.WRITE_REVERSIBLE


def test_action_classifier_post_delete_suffix_is_destructive():
    assert classify("POST", "/api/users/delete") == ActionClass.DESTRUCTIVE


def test_is_not_allowed_destructive_on_conservative():
    assert not is_allowed_by_policy(ActionClass.DESTRUCTIVE, ScanPolicyV2())


def test_is_allowed_read_on_conservative():
    assert is_allowed_by_policy(ActionClass.READ, ScanPolicyV2())


from execution_plane.policy.preflight import PolicyPreflight, WillBlock


def test_preflight_blocks_delete_on_conservative():
    policy = ScanPolicyV2()
    result = PolicyPreflight.compute(policy, [{"method": "DELETE", "path": "/api/users/1"}])
    assert len(result.will_block) == 1
    assert result.will_block[0].reason.startswith("method_not_allowed")


def test_preflight_allows_get_on_conservative():
    policy = ScanPolicyV2()
    result = PolicyPreflight.compute(policy, [{"method": "GET", "path": "/api/users"}])
    assert len(result.will_test) == 1
    assert len(result.will_block) == 0


def test_preflight_blocks_denied_path_pattern():
    policy = ScanPolicyV2()
    policy.scope.denied_path_patterns = ["/admin/*"]
    result = PolicyPreflight.compute(policy, [{"method": "GET", "path": "/admin/settings"}])
    assert any(b.reason == "denied_path" for b in result.will_block)


from unittest.mock import MagicMock

from execution_plane.policy.kill_switch import KillSwitch, KillSwitchLevel


def test_kill_switch_activate_and_check():
    redis_mock = MagicMock()
    redis_mock.get.return_value = None
    ks = KillSwitch(redis_mock)
    ks.activate(KillSwitchLevel.SCAN, "scan-123")
    redis_mock.set.assert_called_once()


def test_kill_switch_is_active_when_set():
    redis_mock = MagicMock()
    redis_mock.get.return_value = b"1"
    ks = KillSwitch(redis_mock)
    assert ks.is_active("scan-123") is True


def test_kill_switch_not_active_when_cleared():
    redis_mock = MagicMock()
    redis_mock.get.return_value = None
    ks = KillSwitch(redis_mock)
    assert ks.is_active("scan-123") is False
