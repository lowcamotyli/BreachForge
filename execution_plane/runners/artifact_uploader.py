from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from uuid import UUID, uuid4

CHUNK_SIZE_BYTES = 1 * 1024 * 1024


@dataclass
class ArtifactChunk:
    upload_id: UUID
    chunk_index: int
    total_chunks: int
    data: bytes
    chunk_hash: str = ""

    def __post_init__(self) -> None:
        if not self.chunk_hash:
            self.chunk_hash = hashlib.sha256(self.data).hexdigest()


@dataclass
class ArtifactUpload:
    upload_id: UUID = field(default_factory=uuid4)
    scan_id: UUID = field(default_factory=uuid4)
    runner_id: UUID = field(default_factory=uuid4)
    artifact_type: str = "evidence"
    total_size_bytes: int = 0
    total_chunks: int = 0
    received_chunks: set[int] = field(default_factory=set)
    failed_chunk_attempts: dict[int, int] = field(default_factory=dict)
    integrity_hash: str = ""
    is_complete: bool = False
    _assembled: bytes = field(default_factory=bytes, repr=False)


class ArtifactUploader:
    """Chunked artifact upload with integrity verification and retry tracking."""

    def __init__(self) -> None:
        self._uploads: dict[UUID, ArtifactUpload] = {}
        self._chunk_store: dict[tuple[UUID, int], bytes] = {}

    def initiate(
        self,
        scan_id: UUID,
        runner_id: UUID,
        artifact_type: str,
        total_size_bytes: int,
        integrity_hash: str,
    ) -> ArtifactUpload:
        upload = ArtifactUpload(
            scan_id=scan_id,
            runner_id=runner_id,
            artifact_type=artifact_type,
            total_size_bytes=total_size_bytes,
            total_chunks=max(1, -(-total_size_bytes // CHUNK_SIZE_BYTES)),
            integrity_hash=integrity_hash,
        )
        self._uploads[upload.upload_id] = upload
        return upload

    def upload_chunk(self, upload_id: UUID, chunk: ArtifactChunk, max_retries: int = 3) -> bool:
        upload = self._uploads.get(upload_id)
        if upload is None or upload.is_complete:
            return False
        if chunk.upload_id != upload_id or chunk.total_chunks != upload.total_chunks:
            return False
        if chunk.chunk_index < 0 or chunk.chunk_index >= upload.total_chunks:
            return False
        failed_attempts = upload.failed_chunk_attempts.get(chunk.chunk_index, 0)
        if failed_attempts and failed_attempts >= max_retries:
            return False
        expected_hash = hashlib.sha256(chunk.data).hexdigest()
        if expected_hash != chunk.chunk_hash:
            upload.failed_chunk_attempts[chunk.chunk_index] = upload.failed_chunk_attempts.get(chunk.chunk_index, 0) + 1
            return False
        self._chunk_store[(upload_id, chunk.chunk_index)] = chunk.data
        upload.received_chunks.add(chunk.chunk_index)
        upload.failed_chunk_attempts.pop(chunk.chunk_index, None)
        if len(upload.received_chunks) == upload.total_chunks:
            self._finalize(upload)
        return True

    def _finalize(self, upload: ArtifactUpload) -> None:
        assembled = b"".join(self._chunk_store[(upload.upload_id, i)] for i in range(upload.total_chunks))
        actual_hash = hashlib.sha256(assembled).hexdigest()
        if actual_hash != upload.integrity_hash:
            upload.is_complete = False
            return
        upload._assembled = assembled
        upload.is_complete = True

    def get_upload(self, upload_id: UUID) -> ArtifactUpload | None:
        return self._uploads.get(upload_id)

    def get_assembled(self, upload_id: UUID) -> bytes | None:
        upload = self._uploads.get(upload_id)
        if upload is None or not upload.is_complete:
            return None
        return upload._assembled
