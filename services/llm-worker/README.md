# Advisory Off-Path Reasoning Worker (Mode B)

This service provides an asynchronous, off-path investigation assistant for ambiguous or high-entropy security incidents in the **Distributed Security Control Plane**.

---

## Safety Principles & Architectural Boundaries

1. **Zero Direct Execution Authority**:
   - The advisory worker has **zero network or execution access** to applications, databases, or local agents.
   - It outputs machine-readable JSON recommendations containing threat classifications, confidence scores, and proposed actions.
2. **Deterministic Policy Validation Gate**:
   - Every recommendation produced by this worker must pass through the Control Plane's Rust **Capability Policy Engine**.
   - **`DENY` strictly takes precedence over `ALLOW`**. If policy denies an action or target, the recommendation is rejected and no command is issued.
3. **Off-Path & Non-Blocking**:
   - The service runs strictly out-of-band. Normal application traffic never waits for this worker.
4. **Autonomous Fallback**:
   - If no external API keys (`OPENAI_API_KEY`) or local model hosts (`OLLAMA_HOST`) are configured, the service runs an autonomous rule-assisted heuristic reasoner that processes threat signals offline.

---

## Configuration & Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `8000` | Port for the worker HTTP API |
| `CONTROL_PLANE_URL` | `http://localhost:8080` | URL of the central Security Control Plane |
| `OPENAI_API_KEY` | *(None)* | Optional OpenAI API key for cloud reasoning |
| `OLLAMA_HOST` | *(None)* | Optional Ollama endpoint (e.g. `http://localhost:11434`) |
| `MODEL_NAME` | `gpt-4o-mini` / `llama3:latest` | Model identifier to invoke |

---

## Running the Worker

```powershell
cd services/llm-worker
pip install -r requirements.txt
python main.py
```

Check health:
```powershell
curl http://localhost:8000/health
```
