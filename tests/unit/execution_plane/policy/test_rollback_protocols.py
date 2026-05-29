from pathlib import Path
import importlib.util
import sys

_STATE_DIFF_PATH = Path(__file__).resolve().parents[4] / "execution_plane" / "validator" / "state_diff.py"
_STATE_DIFF_SPEC = importlib.util.spec_from_file_location("rollback_state_diff", _STATE_DIFF_PATH)
assert _STATE_DIFF_SPEC is not None and _STATE_DIFF_SPEC.loader is not None
_STATE_DIFF = importlib.util.module_from_spec(_STATE_DIFF_SPEC)
sys.modules["rollback_state_diff"] = _STATE_DIFF
_STATE_DIFF_SPEC.loader.exec_module(_STATE_DIFF)

RollbackProtocol = _STATE_DIFF.RollbackProtocol
RollbackableProbe = _STATE_DIFF.RollbackableProbe
is_rollback_safe = _STATE_DIFF.is_rollback_safe
mark_synthetic_identity = _STATE_DIFF.mark_synthetic_identity


def test_rollback_safe_identical_states():
    assert is_rollback_safe({"user": "alice"}, {"user": "alice"}) is True


def test_rollback_not_safe_auth_change():
    assert is_rollback_safe({"role": "user"}, {"role": "admin"}) is False


def test_rollback_not_safe_deletion():
    assert is_rollback_safe({"a": 1, "b": 2}, {"a": 1}) is False


def test_mark_synthetic_identity_sets_flag():
    result = mark_synthetic_identity("id-123", "scan-456")
    assert result["synthetic"] is True
    assert result["identity_id"] == "id-123"


def test_rollback_protocol_defaults_not_synthetic():
    rp = RollbackProtocol()
    assert not rp.is_synthetic_account
    assert rp.cleanup_requests == []
