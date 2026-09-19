# Contributing to the Distributed Security Control Plane

Thank you for your interest in contributing to the **Distributed Security Control Plane**!

This project is a high-performance, out-of-band security intelligence and rapid threat containment platform designed to protect heterogeneous web applications without placing heavy security analysis in the synchronous request path.

> **License**: This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. By contributing, you agree that your contributions will be licensed under the same terms. See the [LICENSE](LICENSE) file for full details.

---

## Table of Contents

- [1. Architectural Invariants (Must Read)](#1-architectural-invariants-must-read-before-contributing)
- [2. Getting Started](#2-getting-started)
- [3. License & Contributor Agreement](#3-license--contributor-agreement)
- [4. Development Setup](#4-development-setup)
- [5. Repository Structure](#5-repository-structure)
- [6. Making Changes](#6-making-changes)
- [7. Pull Request Guidelines](#7-pull-request-guidelines)
- [8. Code Style & Standards](#8-code-style--standards)
- [9. Reporting Issues](#9-reporting-issues)
- [10. Community & Code of Conduct](#10-community--code-of-conduct)

---

## 1. Architectural Invariants (Must Read Before Contributing)

All contributions **must** respect our core architectural invariants. Pull requests that violate any of these will be declined:

1. **Hard Out-of-Band Invariant**:  
   Normal application requests must **never** wait for security ingestion, correlation, detection, or the security controller. Normal traffic is strictly `Client -> Application -> Response`. Telemetry is emitted asynchronously.

2. **Deterministic Mode by Default**:  
   The platform must be 100% operational, secure, and fast with the LLM disabled. AI is an advisory option for ambiguous incidents (Mode B), never the root of trust.

3. **Preserve Sensor Semantics**:  
   When integrating eBPF telemetry from **Tetragon**, **Falco**, or **Cilium Hubble**, do not over-flatten events into generic strings. Preserve source metadata and typed telemetry fields.

4. **Action Capabilities with TTL and Rollback**:  
   All containment commands must be modeled as explicit capabilities with mandatory expiration timestamps (TTLs), evidence references, and automated rollback routines.

5. **Deno-Style Capability Boundaries**:  
   Security context and permissions are inferred from event streams, not hard-coded. Contributions that touch identity or capability logic must preserve the dynamic, least-privilege model.

---

## 2. Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/Distributed-Security-Control-Plane.git
   cd Distributed-Security-Control-Plane
   ```
3. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. Make your changes, commit with a **DCO sign-off** (see below), and push.
5. Open a **Pull Request** against `main`.

---

## 3. License & Contributor Agreement

### AGPL-3.0 Compliance

This project uses the [GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0.html). This means:

- ✅ You **can** study, modify, distribute, and use the code commercially.
- ✅ You **can** sell copies or offer the software as a service.
- ⚠️ If you distribute modified versions, the source **must** remain available under AGPL-3.0.
- ⚠️ If you run a modified version as a **network service** (SaaS), you **must** make the corresponding source code available to users of that service (Section 13).

### Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin (DCO)](https://developercertificate.org/) instead of a Contributor License Agreement (CLA). This keeps the contribution process lightweight and transparent.

**Every commit must include a sign-off line** certifying that you have the right to submit the contribution under the project's license:

```
Signed-off-by: Your Name <your-email@example.com>
```

You can add this automatically with `git commit -s`:

```bash
git commit -s -m "feat: add Tetragon socket connect parser"
```

> **Note**: Commits without a valid `Signed-off-by` line will not be accepted.

### What the DCO Means

By signing off, you certify the [Developer Certificate of Origin v1.1](https://developercertificate.org/):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have
    the right to submit it under the open source license indicated in
    the file; or

(b) The contribution is based upon previous work that, to the best of
    my knowledge, is covered under an appropriate open source license
    and I have the right under that license to submit that work with
    modifications, whether created in whole or in part by me, under
    the same open source license; or

(c) The contribution was provided directly to me by some other person
    who certified (a), (b) or (c) and I have not modified it.

(d) I understand and agree that this project and the contribution are
    public and that a record of the contribution (including all
    personal information I submit with it) is maintained indefinitely
    and may be redistributed consistent with this project or the open
    source license(s) involved.
```

---

## 4. Development Setup

### Prerequisites

| Tool       | Minimum Version | Purpose                                     |
| :--------- | :-------------- | :------------------------------------------ |
| **Rust**   | 1.80+           | Core engine, control plane, agent SDK       |
| **Node.js**| 20+             | Frontend dashboard (React + Vite)           |
| **Python** | 3.11+           | Mock apps, benchmark harnesses, test suites |

### Toolchain Setup (Windows with GNU target)

If building on Windows with the GNU target:
```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:USERPROFILE\.llvm-mingw\llvm-mingw-20260616-ucrt-x86_64\bin;$env:PATH"
```

### Build & Verify

```bash
# Build all crates
cargo build --workspace

# Run all Rust unit tests
cargo test --workspace

# Build the frontend
cd frontend && npm install && npm run build
```

### Verification & Testing Commands

Before opening a pull request, ensure **all** verification checks pass:

```bash
# 1. Rust common model unit tests
cargo test -p security-control-plane-common

# 2. Phase 2: Detection engine unit tests
cargo test -p security-control-plane-engine

# 3. Phase 3: Correlator unit tests
cargo test -p security-control-plane-correlator

# 4. Check control plane and agent SDK crates compile
cargo check -p security-control-plane
cargo check -p security-control-plane-agent-sdk

# 5. Verify application latency overhead benchmark
python benchmarks/measure_overhead.py

# 6. Phase 1 integration test suite
python tests/test_phase1_slice.py

# 7. Phase 2 end-to-end detection & containment suite
python tests/test_phase2_engine.py

# 8. Phase 3 cross-application correlation & identity suite
python tests/test_phase3_correlation.py

# 9. Typecheck & build the React dashboard
cd frontend
npm run build
```

---

## 5. Repository Structure

```text
├── crates/
│   ├── common/             # Canonical event schemas, typed models, validation
│   ├── engine/             # Deterministic rule engine, risk scoring, incident lifecycle
│   ├── correlator/         # Identity resolution, context graph, cross-app sequence detection
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

## 6. Making Changes

### What We're Looking For

- **Bug fixes** with clear reproduction steps and tests.
- **New detection rules** with corresponding unit tests and documented thresholds.
- **Sensor adapters** for additional eBPF telemetry sources.
- **Performance improvements** backed by benchmark data.
- **Documentation** improvements, typo fixes, and example expansions.
- **Frontend enhancements** to the operations dashboard.

### What to Avoid

- Changes that violate the [Architectural Invariants](#1-architectural-invariants-must-read-before-contributing).
- Introducing synchronous blocking on the application request path.
- Adding dependencies without justification in the PR description.
- Changes that break existing tests without a clear reason.

---

## 7. Pull Request Guidelines

### Branch Naming

- `feature/issue-description`
- `fix/bug-description`
- `perf/optimization-description`
- `docs/topic-description`

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Tetragon socket connect parser
fix: prevent timestamp skew on boundary clock drift
perf: optimize in-memory ring buffer memory layout
docs: update Phase 2 roadmap deliverables
refactor: extract identity resolution into correlator crate
test: add cross-app attack sequence integration test
```

### PR Checklist

Before submitting, verify that:

- [ ] All existing tests pass (`cargo test --workspace`).
- [ ] New functionality includes corresponding tests.
- [ ] Commit messages follow Conventional Commits format.
- [ ] All commits are signed off (`Signed-off-by: ...`).
- [ ] The frontend builds without errors (`cd frontend && npm run build`).
- [ ] No unnecessary dependencies have been added.
- [ ] Documentation has been updated if applicable.

### Code Review

- All PRs require at least **one approving review** from a maintainer.
- Maintainers may request changes, ask questions, or suggest alternatives.
- Be responsive to feedback — we aim to merge quality contributions quickly.

---

## 8. Code Style & Standards

### Rust

- Format with `cargo fmt` before committing.
- Lint with `cargo clippy` — address all warnings.
- Use `#[must_use]` annotations on functions returning important values.
- Prefer typed errors over string-based error handling.
- Document all public APIs with doc comments (`///`).

### TypeScript / React

- Use strict TypeScript (`strict: true` in `tsconfig.json`).
- Follow the existing component patterns in the `frontend/src/` directory.
- Keep components focused and reusable.

### Python

- Follow PEP 8 style guidelines.
- Use type hints where applicable.
- Test scripts should use `unittest` and produce clear pass/fail output.

---

## 9. Reporting Issues

### Bug Reports

When filing a bug report, please include:

1. **Component affected**: (e.g., `crates/engine`, `crates/correlator`, `frontend`).
2. **Steps to reproduce**: Minimal set of commands or actions.
3. **Expected behavior**: What you expected to happen.
4. **Actual behavior**: What actually happened (include error logs).
5. **Environment**: OS, Rust version, Node.js version, Python version.

### Feature Requests

Feature requests are welcome! Please describe:

1. **The problem** you're trying to solve.
2. **Your proposed solution** and any alternatives considered.
3. **How it aligns** with the [Architectural Invariants](#1-architectural-invariants-must-read-before-contributing).

### Security Vulnerabilities

**Do NOT file security vulnerabilities as public issues.** See [SECURITY.md](SECURITY.md) for our responsible disclosure process.

---

## 10. Community & Code of Conduct

We are committed to providing a welcoming and inclusive experience for everyone. All participants are expected to:

- Be respectful and constructive in all interactions.
- Assume good intent from fellow contributors.
- Focus on technical merit and collaboration.
- Avoid personal attacks, harassment, or discriminatory language.

Violations may result in temporary or permanent exclusion from the project at the maintainers' discretion.

---

**Thank you for helping make the Distributed Security Control Plane better!** 🛡️
