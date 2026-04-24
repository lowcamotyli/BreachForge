from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from execution_plane.planner.rules.injection import InjectionSql


@pytest.fixture
def mock_asset_map() -> object:
    return SimpleNamespace(endpoints=[])


@pytest.fixture
def endpoint_with_resource_ids() -> object:
    return SimpleNamespace(
        id=uuid4(),
        method="POST",
        auth_required=True,
        url_pattern="/api/users/{user_id}/search",
        parameters=[
            {"name": "user_id", "in": "path", "type": "string"},
            {"name": "query", "in": "body", "type": "string"},
        ],
    )


@pytest.fixture
def mock_scan_context() -> object:
    return SimpleNamespace(scan_id=uuid4())


class TestInjectionCorpus:
    def test_generates_tasks_for_string_params_on_resource_endpoint(
        self,
        endpoint_with_resource_ids: object,
        mock_scan_context: object,
        mock_asset_map: object,
    ) -> None:
        rule = InjectionSql()

        assert rule.matches(endpoint_with_resource_ids, mock_asset_map)

        tasks = rule.generate_tasks(endpoint_with_resource_ids, mock_scan_context)

        assert tasks
        assert all(task.attack_class == "injection" for task in tasks)
        assert {task.target_parameter for task in tasks} >= {"user_id", "query"}
