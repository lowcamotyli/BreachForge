from __future__ import annotations

import enum
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from api.models.requests import ScanPolicyV2


class ActionClass(enum.Enum):
    READ = "read"
    WRITE_SAFE = "write_safe"
    WRITE_REVERSIBLE = "write_reversible"
    DESTRUCTIVE = "destructive"
    CREDENTIAL_SENSITIVE = "credential_sensitive"


_CREDENTIAL_PATHS = re.compile(
    r"/(auth|token|credential|password|secret|login|logout|signin|signout|oauth|sso)",
    re.IGNORECASE,
)
_DESTRUCTIVE_SUFFIXES = re.compile(
    r"/(delete|remove|purge|wipe|drop|truncate|reset|destroy|erase)(\?|$|/)",
    re.IGNORECASE,
)


def classify(method: str, path: str, body: dict | None = None) -> ActionClass:
    m = method.upper()
    if _CREDENTIAL_PATHS.search(path):
        return ActionClass.CREDENTIAL_SENSITIVE
    if m == "DELETE":
        return ActionClass.DESTRUCTIVE
    if m == "POST" and _DESTRUCTIVE_SUFFIXES.search(path):
        return ActionClass.DESTRUCTIVE
    if m in ("PATCH", "PUT"):
        return ActionClass.WRITE_REVERSIBLE
    if m == "POST":
        return ActionClass.WRITE_SAFE
    if m in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return ActionClass.READ
    return ActionClass.WRITE_SAFE


def is_allowed_by_policy(action: ActionClass, policy: "ScanPolicyV2") -> bool:
    mapping = {
        ActionClass.READ: policy.method_classes.allow_read,
        ActionClass.WRITE_SAFE: policy.method_classes.allow_write_safe,
        ActionClass.WRITE_REVERSIBLE: policy.method_classes.allow_write_reversible,
        ActionClass.DESTRUCTIVE: policy.method_classes.allow_destructive,
        ActionClass.CREDENTIAL_SENSITIVE: policy.method_classes.allow_credential_sensitive,
    }
    return mapping.get(action, False)
