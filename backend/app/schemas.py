from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class SiteScanCreate(BaseModel):
    url: str = Field(min_length=4, max_length=2048)


class ScanAccepted(BaseModel):
    scan_id: UUID
    status: str
    message_ar: str


class FindingOut(BaseModel):
    code: str
    severity: str
    title_ar: str
    explanation_ar: str
    remediation_ar: str
    status: str
    evidence: dict

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: UUID
    target: str
    kind: str
    status: str
    score: int | None
    summary: str | None
    created_at: datetime
    completed_at: datetime | None
    findings: list[FindingOut]

    model_config = {"from_attributes": True}


class LinkAnalysisCreate(BaseModel):
    url: str = Field(min_length=4, max_length=2048)


class LinkIndicator(BaseModel):
    code: str
    severity: str
    title_ar: str
    explanation_ar: str


class LinkAnalysisOut(BaseModel):
    verdict: str
    risk_score: int
    message_ar: str
    indicators: list[LinkIndicator]
    limitation_ar: str
