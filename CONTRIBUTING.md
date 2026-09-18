# Contributing to the Distributed Security Control Plane

Thank you for your interest in contributing to the **Distributed Security Control Plane**!

This project is a high-performance, out-of-band security intelligence and rapid threat containment platform designed to protect heterogeneous web applications without placing heavy security analysis in the synchronous request path.

---

## 1. Architectural Invariants (Must Read Before Contributing)

All contributions must respect our core architectural invariants:

1. **Hard Out-of-Band Invariant**:  
   Normal application requests must **never** wait for security ingestion, correlation, detection, or the security controller. Normal traffic is strictly `Client -> Application -> Response`. Telemetry is emitted asynchronously.
2. **Deterministic Mode by Default**:  
   The platform must be 100% operational, secure, and fast with the LLM disabled. AI is an advisory option for ambiguous incidents (Mode B), never the root of trust.
3. **Preserve Sensor Semantics**:  
   When integrating eBPF telemetry from **Tetragon**, **Falco**, or **Cilium Hubble**, do not over-flatten events into generic strings. Preserve source metadata and typed telemetry fields.
4. **Action Capabilities with TTL and Rollback**:  
   All containment commands must be modeled as explicit capabilities with mandatory expiration timestamps (TTLs), evidence references, and automated rollback routines.

---

## 2. Development Setup

### Prerequisites
- **Rust**: 1.80+ (`stable` toolchain)
- **Node.js**: 20+ and npm
- **Python**: 3.11+ (for mock apps and benchmark harnesses)

### Toolchain Setup (Windows)
If building on Windows with the GNU target:
```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:USERPROFILE\.llvm-mingw\llvm-mingw-20260616-ucrt-x86_64\bin;$env:PATH"
```

### Verification & Testing Commands
Before opening a pull request, ensure all verification checks pass:

```bash
# 1. Rust common model unit tests
cargo test -p security-control-plane-common

# 2. Check control plane and agent SDK crates
cargo check -p security-control-plane
cargo check -p security-control-plane-agent-sdk

# 3. Verify application latency overhead benchmark
python benchmarks/measure_overhead.py

# 4. Run Phase 1 integration test suite
python tests/test_phase1_slice.py

# 5. Typecheck & build the React dashboard
cd frontend
npm run build
```

---

## 3. Repository Structure

```text
├── crates/
│   ├── common/             # Canonical event schemas, typed models, validation
│   ├── control-plane/      # Axum HTTP/WS API, stream pipeline, selective persistence
│   └── agent-sdk/          # Non-blocking Rust client library with fail-open queue
├── frontend/               # React + TypeScript + Vite operations dashboard
├── services/
│   ├── mock-apps/          # Reference instrumented applications (FastAPI, Node.js)
│   └── llm-worker/         # Off-path Python advisory reasoning worker (Phase 6)
├── benchmarks/             # Empirical latency & throughput benchmark harnesses
└── tests/                  # Cross-tier integration test suites
```

---

## 4. Pull Request Guidelines

1. **Branch Naming**:  
   - `feature/issue-description`
   - `fix/bug-description`
   - `perf/optimization-description`
2. **Commit Messages**:  
   Follow Conventional Commits:  
   - `feat: add Tetragon socket connect parser`
   - `fix: prevent timestamp skew on boundary clock drift`
   - `perf: optimize in-memory ring buffer memory layout`
   - `docs: update Phase 2 roadmap deliverables`
3. **Tests Required**:  
   Every new event type, sensor adapter, or detection rule must be accompanied by unit tests.
