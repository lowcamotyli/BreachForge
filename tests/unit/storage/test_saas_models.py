from __future__ import annotations

from uuid import UUID

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from storage.db.models import APIKey, Base, OrgMember, OrgRole, Organization, Project, ServiceGroup, ServiceToken


def _create_saas_tables(engine) -> None:
    Base.metadata.create_all(
        engine,
        tables=[
            Organization.__table__,
            Project.__table__,
            ServiceGroup.__table__,
            OrgMember.__table__,
            APIKey.__table__,
            ServiceToken.__table__,
        ],
    )


def test_organization_model_creation_with_id_name_slug_fields() -> None:
    engine = create_engine("sqlite:///:memory:")
    _create_saas_tables(engine)

    with Session(engine) as session:
        org = Organization(name="ProofScan", slug="proofscan")
        session.add(org)
        session.flush()

        assert isinstance(org.id, UUID)
        assert org.name == "ProofScan"
        assert org.slug == "proofscan"


def test_project_is_linked_to_organization_via_org_id_fk() -> None:
    engine = create_engine("sqlite:///:memory:")
    _create_saas_tables(engine)

    with Session(engine) as session:
        org = Organization(name="ProofScan", slug="proofscan")
        project = Project(name="Core App", slug="core-app", org=org)
        session.add(project)
        session.flush()

        assert project.org_id == org.id
        assert project.org is org
        assert project in org.projects


def test_service_group_is_linked_to_project() -> None:
    engine = create_engine("sqlite:///:memory:")
    _create_saas_tables(engine)

    with Session(engine) as session:
        org = Organization(name="ProofScan", slug="proofscan")
        project = Project(name="Core App", slug="core-app", org=org)
        service_group = ServiceGroup(name="Public API", project=project)
        session.add(service_group)
        session.flush()

        assert service_group.project_id == project.id
        assert service_group.project is project
        assert service_group in project.service_groups


def test_org_member_has_role_from_org_role_enum() -> None:
    engine = create_engine("sqlite:///:memory:")
    _create_saas_tables(engine)

    with Session(engine) as session:
        org = Organization(name="ProofScan", slug="proofscan")
        member = OrgMember(org=org, user_email="owner@example.com", role=OrgRole.owner)
        session.add(member)
        session.flush()

        assert member.role is OrgRole.owner
        assert member.org_id == org.id


def test_api_key_has_hash_prefix_and_revoked_at_defaults_to_none() -> None:
    engine = create_engine("sqlite:///:memory:")
    _create_saas_tables(engine)

    with Session(engine) as session:
        org = Organization(name="ProofScan", slug="proofscan")
        api_key = APIKey(
            org=org,
            name="CI",
            key_hash="hash-value",
            key_prefix="abc12345...",
            scopes=["scans:read"],
            created_by="owner@example.com",
        )
        session.add(api_key)
        session.flush()

        assert api_key.key_hash == "hash-value"
        assert api_key.key_prefix == "abc12345..."
        assert api_key.revoked_at is None


def test_service_token_has_token_hash_and_scopes_as_list() -> None:
    engine = create_engine("sqlite:///:memory:")
    _create_saas_tables(engine)

    with Session(engine) as session:
        org = Organization(name="ProofScan", slug="proofscan")
        token = ServiceToken(
            org=org,
            name="Worker",
            token_hash="token-hash-value",
            token_prefix="svc12345...",
            scopes=["worker:run"],
            issued_to="worker-1",
        )
        session.add(token)
        session.flush()

        assert token.token_hash == "token-hash-value"
        assert token.scopes == ["worker:run"]
        assert isinstance(token.scopes, list)
