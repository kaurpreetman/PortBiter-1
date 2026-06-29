from pydantic import BaseModel, Field
from typing import Optional


class Vulnerability(BaseModel):
    id: str
    type: str
    severity: str
    endpoint: str
    parameter: Optional[str] = None
    reason: Optional[str] = None
    impact: Optional[str] = None
    payload: Optional[str] = None
    fix: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0.0, le=100.0)
    cvss: float = Field(default=0.0, ge=0.0, le=10.0)
