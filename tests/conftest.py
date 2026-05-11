from __future__ import annotations

import os


os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/proofscan")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("EVIDENCE_BUCKET", "proofscan-test-evidence")
