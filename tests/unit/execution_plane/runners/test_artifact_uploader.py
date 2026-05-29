from __future__ import annotations

import hashlib
from uuid import uuid4

from execution_plane.runners.artifact_uploader import CHUNK_SIZE_BYTES, ArtifactChunk, ArtifactUploader


def test_initiate_creates_artifact_upload_with_correct_total_chunks() -> None:
    uploader = ArtifactUploader()
    total_size = CHUNK_SIZE_BYTES + 1

    upload = uploader.initiate(
        scan_id=uuid4(),
        runner_id=uuid4(),
        artifact_type="evidence",
        total_size_bytes=total_size,
        integrity_hash="unused",
    )

    assert upload.total_size_bytes == total_size
    assert upload.total_chunks == 2
    assert uploader.get_upload(upload.upload_id) == upload


def test_upload_chunk_accepts_valid_chunk_and_marks_received() -> None:
    uploader = ArtifactUploader()
    data = b"evidence"
    upload = uploader.initiate(
        scan_id=uuid4(),
        runner_id=uuid4(),
        artifact_type="evidence",
        total_size_bytes=len(data),
        integrity_hash=hashlib.sha256(data).hexdigest(),
    )
    chunk = ArtifactChunk(upload_id=upload.upload_id, chunk_index=0, total_chunks=1, data=data)

    assert uploader.upload_chunk(upload.upload_id, chunk) is True
    assert upload.received_chunks == {0}


def test_upload_chunk_rejects_chunk_with_wrong_hash() -> None:
    uploader = ArtifactUploader()
    data = b"evidence"
    upload = uploader.initiate(
        scan_id=uuid4(),
        runner_id=uuid4(),
        artifact_type="evidence",
        total_size_bytes=len(data),
        integrity_hash=hashlib.sha256(data).hexdigest(),
    )
    chunk = ArtifactChunk(upload_id=upload.upload_id, chunk_index=0, total_chunks=1, data=data, chunk_hash="bad")

    assert uploader.upload_chunk(upload.upload_id, chunk) is False
    assert upload.received_chunks == set()
    assert upload.failed_chunk_attempts == {0: 1}
    assert upload.is_complete is False


def test_upload_chunk_allows_retry_until_max_retries() -> None:
    uploader = ArtifactUploader()
    data = b"evidence"
    upload = uploader.initiate(
        scan_id=uuid4(),
        runner_id=uuid4(),
        artifact_type="evidence",
        total_size_bytes=len(data),
        integrity_hash=hashlib.sha256(data).hexdigest(),
    )
    bad_chunk = ArtifactChunk(upload_id=upload.upload_id, chunk_index=0, total_chunks=1, data=data, chunk_hash="bad")
    good_chunk = ArtifactChunk(upload_id=upload.upload_id, chunk_index=0, total_chunks=1, data=data)

    assert uploader.upload_chunk(upload.upload_id, bad_chunk, max_retries=2) is False
    assert uploader.upload_chunk(upload.upload_id, good_chunk, max_retries=2) is True
    assert upload.failed_chunk_attempts == {}
    assert upload.is_complete is True


def test_finalize_completes_upload_when_all_chunks_received_and_integrity_matches() -> None:
    uploader = ArtifactUploader()
    first = b"a" * CHUNK_SIZE_BYTES
    second = b"b"
    data = first + second
    upload = uploader.initiate(
        scan_id=uuid4(),
        runner_id=uuid4(),
        artifact_type="evidence",
        total_size_bytes=len(data),
        integrity_hash=hashlib.sha256(data).hexdigest(),
    )

    assert uploader.upload_chunk(
        upload.upload_id,
        ArtifactChunk(upload_id=upload.upload_id, chunk_index=0, total_chunks=2, data=first),
    )
    assert upload.is_complete is False
    assert uploader.upload_chunk(
        upload.upload_id,
        ArtifactChunk(upload_id=upload.upload_id, chunk_index=1, total_chunks=2, data=second),
    )

    assert upload.is_complete is True


def test_get_assembled_returns_bytes_for_completed_upload_none_for_incomplete() -> None:
    uploader = ArtifactUploader()
    complete_data = b"complete"
    incomplete_data = b"incomplete"
    complete_upload = uploader.initiate(
        scan_id=uuid4(),
        runner_id=uuid4(),
        artifact_type="evidence",
        total_size_bytes=len(complete_data),
        integrity_hash=hashlib.sha256(complete_data).hexdigest(),
    )
    incomplete_upload = uploader.initiate(
        scan_id=uuid4(),
        runner_id=uuid4(),
        artifact_type="evidence",
        total_size_bytes=len(incomplete_data) + CHUNK_SIZE_BYTES,
        integrity_hash=hashlib.sha256(incomplete_data).hexdigest(),
    )

    uploader.upload_chunk(
        complete_upload.upload_id,
        ArtifactChunk(upload_id=complete_upload.upload_id, chunk_index=0, total_chunks=1, data=complete_data),
    )

    assert uploader.get_assembled(complete_upload.upload_id) == complete_data
    assert uploader.get_assembled(incomplete_upload.upload_id) is None
