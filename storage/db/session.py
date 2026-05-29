from __future__ import annotations

import json
import os
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from storage.db.encryption import EncryptedBlob, EnvelopeEncryption
from storage.db.models import AuthBundle


def _normalize_database_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


_session_factory: async_sessionmaker[AsyncSession] | None = None


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        raw_url = os.getenv("DATABASE_URL")
        if not raw_url:
            raise RuntimeError("DATABASE_URL is required")
        _session_factory = async_sessionmaker(
            bind=create_async_engine(_normalize_database_url(raw_url), future=True, poolclass=NullPool),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


def AsyncSessionLocal() -> AsyncSession:
    """Lazy wrapper kept for workers that call AsyncSessionLocal() directly."""
    return _get_session_factory()()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with _get_session_factory()() as session:
        yield session


def _sanitize_redacted_preview(preview: dict[str, object] | None) -> dict[str, object]:
    if not preview:
        return {}
    safe: dict[str, object] = {}
    if "cookie_count" in preview:
        safe["cookie_count"] = max(0, int(preview["cookie_count"]))  # type: ignore[arg-type]
    if "has_bearer" in preview:
        safe["has_bearer"] = bool(preview["has_bearer"])
    if "csrf_present" in preview:
        safe["csrf_present"] = bool(preview["csrf_present"])
    return safe


async def save_auth_bundle(db: AsyncSession, bundle: AuthBundle) -> UUID:
    if not bundle.identity_label or not bundle.identity_label.strip():
        raise ValueError("identity_label is required")

    plaintext = bundle.encrypted_payload
    if isinstance(plaintext, bytes):
        plaintext_str = plaintext.decode("utf-8")
    else:
        plaintext_str = str(plaintext)
    encrypted = EnvelopeEncryption().encrypt_credential(
        plaintext=plaintext_str, scan_id=bundle.scan_id, identity_name=bundle.identity_label
    )
    bundle.encrypted_payload = json.dumps(
        {
            "_encrypted": "kms_envelope_v1",
            "encrypted_data_key": encrypted.encrypted_data_key,
            "ciphertext": encrypted.ciphertext,
        }
    ).encode("utf-8")
    bundle.redacted_preview = _sanitize_redacted_preview(bundle.redacted_preview)
    db.add(bundle)
    await db.commit()
    await db.refresh(bundle)
    return bundle.id


async def load_auth_bundle(db: AsyncSession, bundle_id: UUID) -> AuthBundle | None:
    result = await db.execute(select(AuthBundle).where(AuthBundle.id == bundle_id))
    bundle = result.scalar_one_or_none()
    if bundle is None:
        return None
    if bundle.expires_at and bundle.expires_at <= datetime.now(timezone.utc):
        return None

    payload = json.loads(bundle.encrypted_payload.decode("utf-8"))
    plaintext = EnvelopeEncryption().decrypt_credential(
        EncryptedBlob(
            encrypted_data_key=payload["encrypted_data_key"],
            ciphertext=payload["ciphertext"],
        ),
        scan_id=bundle.scan_id,
        identity_name=bundle.identity_label,
    )
    bundle.encrypted_payload = plaintext.encode("utf-8")
    bundle.redacted_preview = _sanitize_redacted_preview(bundle.redacted_preview)
    return bundle


async def list_auth_bundles(db: AsyncSession, scan_id: UUID) -> list[AuthBundle]:
    result = await db.execute(
        select(AuthBundle).where(AuthBundle.scan_id == scan_id).order_by(AuthBundle.created_at.desc())
    )
    bundles = list(result.scalars().all())
    for bundle in bundles:
        bundle.redacted_preview = _sanitize_redacted_preview(bundle.redacted_preview)
    return bundles
