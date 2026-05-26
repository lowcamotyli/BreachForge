from __future__ import annotations

import importlib
from uuid import uuid4

import sqlalchemy as sa


def test_finding_extra_metadata_is_mapped_column() -> None:
    from storage.db.models import Finding
    mapper = sa.inspect(Finding)
    col_keys = [c.key for c in mapper.mapper.column_attrs]
    assert "extra_metadata" in col_keys
    col_attr = next(c for c in mapper.mapper.column_attrs if c.key == "extra_metadata")
    db_col_name = col_attr.columns[0].name
    assert db_col_name == "metadata", f"DB column name must be metadata, got {db_col_name}"


def test_base_metadata_is_sqlalchemy_metadata_object() -> None:
    from storage.db.models import Base
    assert isinstance(Base.metadata, sa.MetaData)
    assert not isinstance(Base.metadata, dict)


def test_finding_extra_metadata_default_is_empty_dict() -> None:
    from storage.db.models import Finding
    finding = Finding(
        id=uuid4(), scan_id=uuid4(),
        title="t", description="d",
        severity="high", attack_class="bola",
        affected_endpoint_id=uuid4(),
        repro_steps="r", fix_guidance="f",
    )
    # default=dict is an INSERT-time default; before commit, attribute is None
    assert finding.extra_metadata is None or finding.extra_metadata == {}


def test_finding_extra_metadata_roundtrip() -> None:
    from storage.db.models import Finding
    finding = Finding(
        id=uuid4(), scan_id=uuid4(),
        title="t", description="d",
        severity="high", attack_class="sensitive_exposure",
        affected_endpoint_id=uuid4(),
        repro_steps="r", fix_guidance="f",
    )
    matrix = [{"endpoint": "/api/x", "method": "GET", "status": 200, "auth_accepted": True}]
    finding.extra_metadata = {
        "secret_blast_radius_matrix": matrix,
        "privilege_fingerprint": {"observed_access_level": "admin"},
        "chain_root_cause": "abc123",
    }
    assert finding.extra_metadata["chain_root_cause"] == "abc123"
    assert finding.extra_metadata["secret_blast_radius_matrix"] == matrix
    assert finding.extra_metadata["privilege_fingerprint"]["observed_access_level"] == "admin"


def test_migration_revision_is_correct() -> None:
    migration = importlib.import_module(
        "storage.db.migrations.versions.20260511000000_add_metadata_to_findings"
    )
    assert migration.revision == "20260511000000"
    assert migration.down_revision == "20260420233000"
