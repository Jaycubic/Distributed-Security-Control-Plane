"""
FastAPI Server for Phase 6 Advisory Off-Path Reasoning Worker.
Exposes REST endpoints for incident analysis, health monitoring, and recommendation dispatch.
"""

import os
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
from reasoner import ProviderNeutralReasoner
from schemas import AdvisoryRecommendationResponse, IncidentContextRequest

app = FastAPI(
    title="Security Control Plane - Advisory Off-Path Reasoning Worker (Mode B)",
    description="Asynchronous investigation assistant for ambiguous incidents with zero execution authority.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

reasoner = ProviderNeutralReasoner()
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8080")


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "llm-advisory-worker",
        "mode": "Mode B (Advisory)",
        "provider": reasoner.provider_name,
    }


@app.post("/analyze", response_model=AdvisoryRecommendationResponse)
def analyze_incident(context: IncidentContextRequest):
    """
    Receives an ambiguous incident context, runs off-path reasoning,
    and returns a strictly validated machine-readable recommendation.
    """
    try:
        recommendation = reasoner.analyze(context)
        return recommendation
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Advisory reasoning error: {e}")


@app.post("/analyze/submit")
def analyze_and_submit(context: IncidentContextRequest):
    """
    Analyzes incident and immediately forwards the recommendation to the
    Control Plane Deterministic Policy Validation Gate for authorization.
    """
    recommendation = reasoner.analyze(context)
    payload = recommendation.model_dump()

    # Forward to Control Plane API
    dest_url = f"{CONTROL_PLANE_URL.rstrip('/')}/api/v1/advisory/recommendation"
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(dest_url, json=payload)
            return {
                "recommendation": payload,
                "control_plane_status": resp.status_code,
                "control_plane_response": resp.json() if resp.status_code == 200 else resp.text,
            }
    except Exception as e:
        return {
            "recommendation": payload,
            "control_plane_error": str(e),
            "fallback": "Recommendation generated but not submitted to control plane.",
        }


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
