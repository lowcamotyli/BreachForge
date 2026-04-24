from __future__ import annotations

import os
import platform
import socket
from collections import namedtuple


if os.name == "nt":
    _UnameResult = namedtuple("uname_result", "system node release version machine processor")

    def _safe_machine() -> str:
        return os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or "AMD64"

    def _safe_uname() -> tuple[str, str, str, str, str, str]:
        machine = _safe_machine()
        return _UnameResult(
            "Windows",
            os.environ.get("COMPUTERNAME") or socket.gethostname(),
            "",
            "",
            machine,
            machine,
        )

    platform.machine = _safe_machine
    platform.uname = _safe_uname
