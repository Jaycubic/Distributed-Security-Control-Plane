"""
Pydantic schemas for the Phase 6 Advisory Off-Path Reasoning Worker.
Enforces strict machine-readable JSON structure for all LLM inputs and outputs.
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class ThreatClassification(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNCERTAIN = "UNCERTAIN"


class RecommendedAction(str, Enum):
    NO_ACTION = "NO_ACTION"
    REVOKE_SESSION = "REVOKE_SESSION"
    THROTTLE_ACTOR = "THROTTLE_ACTOR"
    BLOCK_NETWORK = "BLOCK_NETWORK"
    REVOKE_CAPABILITY = "REVOKE_CAPABILITY"
    RESTRICT_SCOPE = "RESTRICT_SCOPE"
    ISOLATE_SERVICE = "ISOLATE_SERVICE"


class SecuritySignalSummary(BaseModel):
    rule_name: str
    severity: str
    description: str
    risk_weight: int


class EvidenceSummary(BaseModel):
    event_id: str
    event_type: str
    endpoint: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    source_ip: Optional[str] = None
    container_id: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None


class IncidentContextRequest(BaseModel):
    incident_id: str
    title: str
    description: str
    target_entity: str
    app_id: str
    risk_score: int
    severity: str
    signals: List[SecuritySignalSummary] = Field(default_factory=list)
    evidence: List[EvidenceSummary] = Field(default_factory=list)
    applicable_policies: List[str] = Field(default_factory=list)
    timestamp: Optional[str] = None


class AdvisoryRecommendationResponse(BaseModel):
    recommendation_id: Optional[str] = None
    incident_id: str
    target_entity: str
    app_id: str
    classification: ThreatClassification
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    reason_codes: List[str] = Field(default_factory=list, description="Machine-readable diagnostic codes")
    reasoning_summary: str = Field(..., min_length=5, description="Clear natural-language explanation")
    recommended_action: RecommendedAction
    capability: Optional[str] = None
    params: Dict[str, str] = Field(default_factory=dict)
    suggested_ttl_seconds: int = Field(default=300, ge=10, le=86400)
    model_provider: str = Field(default="heuristic-fallback")

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, round(v, 4)))
