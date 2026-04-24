from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from execution_plane.planner.rules.auth_bypass import AuthBypass


@pytest.fixture
def mock_asset_map() -> object:
    return SimpleNamespace(endpoints=[])


@pytest.fixture
def endpoint_with_resource_ids() -> object:
    return SimpleNamespace(
        id=uuid4(),
        method="GET",
        auth_required=True,
        url_pattern="/api/users/{user_id}/profile",
        parameters=[{"name": "user_id", "in": "path"}],
    )


@pytest.fixture
def mock_scan_context() -> object:
    return SimpleNamespace(scan_id=uuid4())


class TestAuthBypassCorpus:
    def test_generates_tasks_for_authenticated_resource_endpoint(
        self,
        endpoint_with_resource_ids: object,
        mock_scan_context: object,
        mock_asset_map: object,
    ) -> None:
        rule = AuthBypass()

        assert rule.matches(endpoint_with_resource_ids, mock_asset_map)

        tasks = rule.generate_tasks(endpoint_with_resource_ids, mock_scan_context)

        assert len(tasks) >= 1
        assert all(task.attack_class == "auth_bypass" for task in tasks)
        assert all(task.target_parameter == "Authorization" for task in tasks)
