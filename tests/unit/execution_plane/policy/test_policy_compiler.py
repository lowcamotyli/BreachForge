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

from execution_plane.policy.compiler import PlannerCaps, PolicyCompiler, WorkerCaps


def test_compiler_conservative_policy_no_destructive():
    c = PolicyCompiler()
    planner, worker, provider, rate = c.compile(ScanPolicyV2())
    assert "destructive" not in planner.allowed_action_classes
    assert not worker.destructive_allowed
    assert provider.destructive_budget == 0


def test_compiler_maps_allowed_domains():
    policy = ScanPolicyV2()
    policy.scope.allowed_domains = ["example.com", "api.example.com"]
    c = PolicyCompiler()
    planner, _, _, _ = c.compile(policy)
    assert "example.com" in planner.allowed_domains


def test_compiler_conservative_defaults_static():
    policy = PolicyCompiler.conservative_defaults()
    assert not policy.method_classes.allow_destructive
    assert policy.version == "2"


def test_compiler_write_safe_policy_adds_post():
    policy = ScanPolicyV2()
    policy.method_classes.allow_write_safe = True
    c = PolicyCompiler()
    _, worker, _, _ = c.compile(policy)
    assert "POST" in worker.allowed_methods
