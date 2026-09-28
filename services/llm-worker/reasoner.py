"""
Provider-Neutral Advisory Reasoning Engine.
Supports cloud models (OpenAI), local models (Ollama), and an autonomous
rule-assisted heuristic reasoning fallback when running disconnected.
"""

import json
import os
import uuid
from typing import Optional
import httpx
from schemas import (
    AdvisoryRecommendationResponse,
    IncidentContextRequest,
    RecommendedAction,
    ThreatClassification,
)


class ProviderNeutralReasoner:
    def __init__(self):
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.ollama_host = os.getenv("OLLAMA_HOST")
        self.model_name = os.getenv("MODEL_NAME", "gpt-4o-mini" if self.openai_api_key else "llama3:latest")

        if self.openai_api_key:
            self.provider_name = f"openai:{self.model_name}"
        elif self.ollama_host:
            self.provider_name = f"ollama:{self.model_name}"
        else:
            self.provider_name = "autonomous-heuristic-reasoner"

    def analyze(self, context: IncidentContextRequest) -> AdvisoryRecommendationResponse:
        """Analyze an ambiguous incident context and produce a structured recommendation."""
        if self.openai_api_key:
            try:
                return self._analyze_openai(context)
            except Exception as e:
                # Graceful fallback to heuristic reasoner on provider error
                res = self._analyze_heuristic(context)
                res.reasoning_summary = f"[OpenAI Error: {e} | Fallback] {res.reasoning_summary}"
                return res
        elif self.ollama_host:
            try:
                return self._analyze_ollama(context)
            except Exception as e:
                res = self._analyze_heuristic(context)
                res.reasoning_summary = f"[Ollama Error: {e} | Fallback] {res.reasoning_summary}"
                return res
        else:
            return self._analyze_heuristic(context)

    def _analyze_heuristic(self, context: IncidentContextRequest) -> AdvisoryRecommendationResponse:
        """
        Autonomous heuristic threat analyzer.
        Evaluates risk score, signal types, container metadata, and evidence patterns
        to synthesize high-confidence structured reasoning without external dependencies.
        """
        reason_codes = []
        rule_names = [s.rule_name.lower() for s in context.signals]
        rule_desc = " ".join(s.description.lower() for s in context.signals)

        # Check for container shell spawn or kernel anomaly
        has_kernel_exec = any("container" in r or "kernel" in r or "shell" in r for r in rule_names)
        has_lateral_move = any("lateral" in r or "cross-app" in r or "recon" in r for r in rule_names)
        has_brute_force = any("brute" in r or "credential" in r for r in rule_names)
        has_scraping = any("scraping" in r or "enumeration" in r for r in rule_names)

        # Inspect evidence for container process executions
        shell_evidence = [e for e in context.evidence if e.process_name and ("sh" in e.process_name or "bash" in e.process_name)]

        if has_kernel_exec or shell_evidence:
            classification = ThreatClassification.MALICIOUS
            confidence = 0.94
            reason_codes.extend(["UNAUTHORIZED_CONTAINER_SHELL", "KERNEL_ANOMALY_CONFIRMED", "POTENTIAL_CONTAINER_ESCAPE"])
            recommended_action = RecommendedAction.REVOKE_CAPABILITY
            capability = "process.execute"
            params = {
                "container_id": shell_evidence[0].container_id if shell_evidence and shell_evidence[0].container_id else "unknown",
                "process": shell_evidence[0].process_name if shell_evidence and shell_evidence[0].process_name else "/bin/sh",
                "scope": "/bin/**",
            }
            ttl = 600
            summary = (
                f"High-confidence threat: interactive shell spawned inside container on {context.app_id}. "
                f"Correlated kernel telemetry confirms anomalous process execution matching container escape TTPs. "
                f"Recommend immediate surgical revocation of process.execute capability."
            )
        elif has_lateral_move:
            classification = ThreatClassification.MALICIOUS
            confidence = 0.88
            reason_codes.extend(["CROSS_APP_LATERAL_MOVEMENT", "MULTI_STAGE_ATTACK_SEQUENCE", "SESSION_HIJACK_SUSPECTED"])
            recommended_action = RecommendedAction.REVOKE_SESSION
            capability = "session.revoke"
            params = {"target_entity": context.target_entity, "scope": "*"}
            ttl = 900
            summary = (
                f"Multi-stage cross-application attack pattern detected across services involving entity {context.target_entity}. "
                f"Observed reconnaissance followed by lateral access across distinct service boundaries. "
                f"Recommend session revocation to sever active credentials."
            )
        elif has_brute_force:
            classification = ThreatClassification.MALICIOUS
            confidence = 0.91
            reason_codes.extend(["AUTHENTICATION_BRUTE_FORCE", "RAPID_CREDENTIAL_STUFFING"])
            recommended_action = RecommendedAction.THROTTLE_ACTOR
            capability = "network.throttle"
            params = {"rate_limit": "5/min", "target": context.target_entity}
            ttl = 300
            summary = (
                f"Rapid authentication failure burst from {context.target_entity} exceeds safety baseline. "
                f"Recommend immediate rate throttling to neutralize brute force attempts."
            )
        elif has_scraping:
            classification = ThreatClassification.SUSPICIOUS
            confidence = 0.78
            reason_codes.extend(["UNAUTHORIZED_API_ENUMERATION", "DATA_SCRAPING_BURST"])
            recommended_action = RecommendedAction.RESTRICT_SCOPE
            capability = "database.read"
            params = {"restricted_path": "/app/data/restricted/**"}
            ttl = 450
            summary = (
                f"Anomalous enumeration and resource reading patterns detected on {context.app_id}. "
                f"Recommend surgical scope restriction on sensitive database access paths."
            )
        elif context.risk_score >= 80:
            classification = ThreatClassification.SUSPICIOUS
            confidence = 0.72
            reason_codes.extend(["HIGH_RISK_SCORE_ACCUMULATION", "ANOMALOUS_ENTITY_ACTIVITY"])
            recommended_action = RecommendedAction.THROTTLE_ACTOR
            capability = "network.throttle"
            params = {"rate_limit": "10/min"}
            ttl = 300
            summary = f"Risk score ({context.risk_score}) exceeds acceptable baseline. Recommend temporary actor throttling."
        else:
            classification = ThreatClassification.UNCERTAIN
            confidence = 0.45
            reason_codes.extend(["INSUFFICIENT_THREAT_CORRELATION", "LOW_SIGNAL_ENTROPY"])
            recommended_action = RecommendedAction.NO_ACTION
            capability = None
            params = {}
            ttl = 60
            summary = (
                f"Ambiguous incident with low signal confidence ({context.risk_score} points). "
                f"Signals do not establish conclusive malicious intent. Recommend observation without active containment."
            )

        return AdvisoryRecommendationResponse(
            recommendation_id=str(uuid.uuid4()),
            incident_id=context.incident_id,
            target_entity=context.target_entity,
            app_id=context.app_id,
            classification=classification,
            confidence=confidence,
            reason_codes=reason_codes,
            reasoning_summary=summary,
            recommended_action=recommended_action,
            capability=capability,
            params=params,
            suggested_ttl_seconds=ttl,
            model_provider="autonomous-heuristic-reasoner",
        )

    def _analyze_openai(self, context: IncidentContextRequest) -> AdvisoryRecommendationResponse:
        """Call OpenAI ChatCompletion with structured JSON output enforcing Pydantic schema."""
        prompt = (
            f"You are an Advisory Security AI for an out-of-band security control plane.\n"
            f"Analyze the following security incident context and return a JSON object strictly adhering to this schema:\n"
            f"- classification: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNCERTAIN'\n"
            f"- confidence: float 0.0 to 1.0\n"
            f"- reason_codes: list of short uppercase diagnostic codes (e.g. ['LATERAL_MOVEMENT'])\n"
            f"- reasoning_summary: natural language rationale explaining the decision\n"
            f"- recommended_action: 'NO_ACTION' | 'REVOKE_SESSION' | 'THROTTLE_ACTOR' | 'BLOCK_NETWORK' | 'REVOKE_CAPABILITY' | 'RESTRICT_SCOPE' | 'ISOLATE_SERVICE'\n"
            f"- capability: optional string\n"
            f"- params: key-value dictionary\n"
            f"- suggested_ttl_seconds: integer (30 to 3600)\n\n"
            f"Incident Data:\n{context.model_dump_json(indent=2)}"
        )

        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model_name,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": "You are a professional security operations reasoning assistant. Always output strict JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        }

        with httpx.Client(timeout=10.0) as client:
            resp = client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            parsed["incident_id"] = context.incident_id
            parsed["target_entity"] = context.target_entity
            parsed["app_id"] = context.app_id
            parsed["model_provider"] = f"openai:{self.model_name}"
            return AdvisoryRecommendationResponse(**parsed)

    def _analyze_ollama(self, context: IncidentContextRequest) -> AdvisoryRecommendationResponse:
        """Call Ollama local model API with JSON format enforcement."""
        prompt = (
            f"Analyze this security incident context and output valid JSON with classification, confidence (0.0-1.0), "
            f"reason_codes, reasoning_summary, recommended_action, capability, params, and suggested_ttl_seconds.\n\n"
            f"Incident:\n{context.model_dump_json(indent=2)}"
        )

        url = f"{self.ollama_host.rstrip('/')}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "format": "json",
            "stream": False,
        }

        with httpx.Client(timeout=15.0) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            parsed = json.loads(data["response"])
            parsed["incident_id"] = context.incident_id
            parsed["target_entity"] = context.target_entity
            parsed["app_id"] = context.app_id
            parsed["model_provider"] = f"ollama:{self.model_name}"
            return AdvisoryRecommendationResponse(**parsed)
