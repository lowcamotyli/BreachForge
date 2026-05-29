from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ZapArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: HttpUrl
    scan_mode: Literal["baseline", "full", "api"] = "baseline"
    max_depth: int = Field(3, ge=1, le=10)


class NucleiArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: HttpUrl
    templates: list[str] = Field(default_factory=list)
    severity: list[Literal["info", "low", "medium", "high", "critical"]] = Field(
        default_factory=list
    )
    rate_limit: int = Field(10, ge=1, le=100)


class HttpxArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: HttpUrl
    methods: list[Literal["GET", "POST", "HEAD", "OPTIONS"]] = Field(
        default_factory=lambda: ["GET"]
    )
    tech_detect: bool = True
    status_codes: list[int] = Field(default_factory=list)


class KatanaArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: HttpUrl
    max_depth: int = Field(2, ge=1, le=5)
    headless: bool = False
    js_crawl: bool = False


ToolArgs = ZapArgs | NucleiArgs | HttpxArgs | KatanaArgs
