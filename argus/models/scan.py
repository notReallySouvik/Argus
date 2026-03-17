from typing import List
from pydantic import BaseModel, Field
from argus.models.asset import Asset
from argus.models.finding import Finding


class ScanSummary(BaseModel):
    candidate_hosts: int = 0
    resolved_hosts: int = 0
    live_web_assets: int = 0
    assets_with_signals: int = 0


class ScanResult(BaseModel):
    target: str
    assets: List[Asset] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)