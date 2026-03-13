# 🔬 Quantum Security Intelligence Platform (QSIP)

> **Quantum-Assisted Vulnerability Graph Analysis + Quantum-Inspired Automated Patch Synthesis** — a unified, end-to-end AI security pipeline that discovers multi-step attack paths across your entire software architecture and automatically synthesizes, validates, and proposes minimal patches.

![QSIP Banner](docs/assets/banner.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-00ffcc.svg)](LICENSE)
[![React](https://img.shields.io/badge/React-18.x-818cf8.svg)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5.x-f472b6.svg)](https://vitejs.dev)
[![Python](https://img.shields.io/badge/Python-3.11+-38bdf8.svg)](https://python.org)
[![Qiskit](https://img.shields.io/badge/Qiskit-1.x-f97316.svg)](https://qiskit.org)

---

## 📖 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Modules](#modules)
  - [Module 1 — Vulnerability Graph Analysis](#module-1--vulnerability-graph-analysis)
  - [Module 2 — Patch Synthesis](#module-2--patch-synthesis)
  - [Module 3 — AI Validation](#module-3--ai-validation)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Modern software architectures span dozens of microservices, APIs, databases, message queues, and admin interfaces — all interconnected. Classical security tools examine each component in isolation and miss **multi-step attack chains**: sequences of small weaknesses that together allow an attacker to traverse from a public endpoint straight to a sensitive datastore.

**QSIP** addresses this with two quantum-inspired innovations:

1. **Quantum Walk–based Graph Analysis** — encodes your architecture as a weighted security graph and uses quantum walk algorithms + QAOA to find the most dangerous attack paths across thousands of nodes faster than classical BFS/DFS methods.

2. **Quantum Annealing–inspired Patch Synthesis** — treats patch generation as a global optimization problem over all possible code modifications, finding the minimal set of changes that closes every link in an attack chain while preserving program behavior.

The result is a fully automated pipeline: **graph → attack paths → patches → validation → developer review**.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     QSIP Pipeline                            │
│                                                              │
│  Software Architecture                                       │
│         │                                                    │
│         ▼                                                    │
│  ┌─────────────────┐    Nodes: Services, DBs, APIs          │
│  │  Security Graph │    Edges: Data flows, API calls        │
│  │  Construction   │    Weights: Risk scores, CVE history   │
│  └────────┬────────┘                                        │
│           │                                                  │
│           ▼                                                  │
│  ┌─────────────────┐    Quantum walk in superposition       │
│  │  Quantum Walk   │    QAOA Hamiltonian minimization       │
│  │  + QAOA Search  │    16-qubit register simulation        │
│  └────────┬────────┘                                        │
│           │                                                  │
│           ▼                                                  │
│  ┌─────────────────┐    Ranked by severity                  │
│  │  Attack Path    │    CVE annotation per hop              │
│  │  Detection      │    Multi-hop chain visualization       │
│  └────────┬────────┘                                        │
│           │                                                  │
│           ▼                                                  │
│  ┌─────────────────┐    Patch space as energy landscape     │
│  │  Quantum        │    Simulated annealing (6 phases)      │
│  │  Annealing      │    Multi-objective optimization        │
│  └────────┬────────┘                                        │
│           │                                                  │
│           ▼                                                  │
│  ┌─────────────────┐    Static analysis (AST)               │
│  │  AI Validation  │    Fuzzing (AFL++)                     │
│  │  Suite          │    Symbolic execution                  │
│  └────────┬────────┘    Regression + side-channel           │
│           │                                                  │
│           ▼                                                  │
│  Ranked, Validated Patches → Developer Review → Apply       │
└──────────────────────────────────────────────────────────────┘
```

---

## Features

- **🌐 Interactive Architecture Graph** — Full SVG visualization of all services, APIs, databases, and data flows with risk heat-mapping
- **⚛️ Quantum Walk Simulation** — 16-qubit register with live superposition → decoherence → collapse animation
- **🔴 Attack Path Detection** — Multi-hop kill chain discovery with CVE annotation at each vulnerable node
- **🔧 Automated Patch Synthesis** — Quantum annealing over patch candidate space with 6-phase convergence
- **📊 Multi-Objective Scoring** — Security, behavioral parity, minimality, and confidence scoring per patch
- **✅ AI Validation Pipeline** — 6-stage automated test suite before any patch is surfaced
- **📈 Energy Convergence Tracking** — Real-time Hamiltonian component monitoring (H_problem, H_driver, H_mixer, H_walk)
- **🖥️ Real-Time Event Log** — Color-coded quantum, annealing, and validation event stream
- **🎨 Production-Grade UI** — Dark cyberpunk aesthetic, animated quantum orbs, scanline effects

---

## Modules

### Module 1 — Vulnerability Graph Analysis

The architecture is encoded as a directed weighted graph `G = (V, E, W)` where:

- **V** = all services, databases, APIs, infrastructure components
- **E** = network connections, data flows, API calls (typed: public/filtered/internal/privileged)
- **W** = edge risk weights derived from CVE history, exposure surface, and privilege level

**Quantum Walk Algorithm:**

The system runs a discrete-time quantum walk where the walker state exists in superposition across all nodes:

```
|ψ(t)⟩ = Σᵢ αᵢ(t)|nodeᵢ⟩
```

The walk operator `U = S · (C ⊗ I)` evolves the state, allowing simultaneous exploration of exponentially many paths before measurement.

**QAOA for Path Optimization:**

Attack-path finding is encoded as a QUBO (Quadratic Unconstrained Binary Optimization):

```
H_cost = Σᵢⱼ Jᵢⱼ σᵢᶻσⱼᶻ + Σᵢ hᵢ σᵢᶻ
H_mixer = Σᵢ σᵢˣ
H_total = γ·H_cost + β·H_mixer
```

Minimizing `H_total` yields the maximum-risk path through the architecture.

### Module 2 — Patch Synthesis

Patch generation is treated as optimization over a high-dimensional landscape:

```
minimize  f(p) = α·risk(p) + β·(1 - behavior(p)) + γ·delta(p)
subject to  behavior(p) ≥ threshold
            risk(p) ≤ max_risk
```

**Quantum Annealing phases:**

| Phase | Description |
|-------|-------------|
| 1. Energy Init | Encode patch candidates into qubit register |
| 2. Quantum Tunneling | Barrier penetration to escape local optima |
| 3. Superposition Sampling | Evaluate hundreds of combinations via \|ψ⟩ |
| 4. Decoherence | Entanglement entropy collapse |
| 5. Entanglement Scoring | Multi-objective fitness evaluation |
| 6. Optimal State | Global minimum patch combination extracted |

### Module 3 — AI Validation

Every synthesized patch passes through a 6-stage pipeline before surfacing to developers:

| Stage | Method | Purpose |
|-------|--------|---------|
| Static Analysis | AST transformation + linting | Syntax safety, type correctness |
| Bounds Check | Formal verification | Memory/buffer safety proof |
| Fuzzing | AFL++ (10k+ inputs) | Crash detection, edge cases |
| Regression | Full test suite | Behavioral preservation |
| Symbolic Execution | Path enumeration | Prove vulnerability path closed |
| Side-Channel | Timing + memory analysis | No new leaks introduced |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend UI | React 18, Vite 5 |
| Styling | Inline CSS with CSS variables, Bebas Neue + JetBrains Mono fonts |
| Graph Rendering | SVG with React-driven animation |
| Quantum Simulation (backend) | Qiskit 1.x, NumPy, SciPy |
| Graph Analysis (backend) | NetworkX, PyTorch Geometric |
| AI/ML Validation | scikit-learn, ONNX Runtime |
| API Server | FastAPI, Uvicorn |
| Static Analysis | libcst, tree-sitter |
| Fuzzing Integration | python-afl bindings |
| Containerization | Docker, Docker Compose |

---

## Installation

### Prerequisites

- Node.js 18+ and npm 9+
- Python 3.11+
- Docker (optional, for backend services)

### Frontend (React UI)

```bash
git clone https://github.com/YOUR_USERNAME/quantum-security-platform.git
cd quantum-security-platform

npm install
npm run dev
# → http://localhost:5173
```

### Backend (Python — Quantum Engine)

```bash
cd backend

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

uvicorn main:app --reload --port 8000
# → http://localhost:8000
```

### Full Stack with Docker

```bash
docker-compose up --build
# Frontend → http://localhost:5173
# Backend  → http://localhost:8000
# API Docs → http://localhost:8000/docs
```

---

## Usage

### 1. Run Architecture Scan

Click **▶ SCAN ARCHITECTURE** in the left sidebar. The quantum walk will traverse all nodes across 6 phases (~15 seconds). Detected attack paths appear in the sidebar ranked by severity.

### 2. Explore the Graph

Switch to the **Architecture Graph** tab. Click any node to inspect its risk score and associated CVEs. Active attack path nodes highlight in orange with animated hop indicators.

### 3. Investigate Attack Paths

Switch to **Attack Paths**. Select any detected path to see the full kill chain (hop by hop), all CVEs at each node, and severity ratings.

### 4. Synthesize Patches

Click **⚡ SYNTHESIZE PATCHES** from the Attack Paths tab (or the Patch Synthesis tab). Quantum annealing runs, followed by the 6-stage validation suite. Each patch shows security/behavior/minimality scores.

### 5. Apply Patches

Click **APPLY PATCH** on any validated patch. Applied patches are tracked and the corresponding node risk score updates in the graph.

### 6. Monitor Quantum State

The **Quantum State** tab shows the live 16-qubit register, Hamiltonian component values, energy convergence graph, and a full node risk heatmap sorted by criticality.

---

## Project Structure

```
quantum-security-platform/
├── src/
│   ├── App.jsx                  # Main React application (full QSIP UI)
│   ├── components/
│   │   ├── GraphView.jsx        # SVG architecture graph renderer
│   │   ├── QuantumState.jsx     # Qubit register + Hamiltonian display
│   │   ├── AttackPaths.jsx      # Path list and kill chain visualizer
│   │   ├── PatchSynthesis.jsx   # Annealing progress + patch cards
│   │   └── EventLog.jsx         # Real-time log component
│   ├── data/
│   │   ├── graphNodes.js        # Architecture node definitions
│   │   ├── graphEdges.js        # Edge/connection definitions
│   │   └── attackPaths.js       # Attack path + patch data
│   └── utils/
│       ├── quantum.js           # Quantum simulation helpers
│       └── scoring.js           # Multi-objective scoring functions
├── backend/
│   ├── main.py                  # FastAPI application entry point
│   ├── quantum/
│   │   ├── walk.py              # Quantum walk implementation (Qiskit)
│   │   ├── qaoa.py              # QAOA circuit construction
│   │   ├── annealing.py         # Simulated quantum annealing
│   │   └── hamiltonian.py       # Hamiltonian construction utilities
│   ├── graph/
│   │   ├── builder.py           # Architecture graph construction
│   │   ├── analyzer.py          # Classical pre-filtering
│   │   └── risk_scorer.py       # Node/edge risk weight computation
│   ├── validation/
│   │   ├── static_analysis.py   # AST-based patch validation
│   │   ├── fuzzer.py            # AFL++ integration
│   │   └── regression.py        # Test suite runner
│   └── models/
│       ├── graph.py             # Pydantic graph schema
│       ├── patch.py             # Patch candidate schema
│       └── results.py           # Scan result schema
├── tests/
│   ├── test_quantum_walk.py
│   ├── test_qaoa.py
│   ├── test_annealing.py
│   ├── test_patch_scoring.py
│   └── test_validation_pipeline.py
├── docs/
│   ├── architecture.md          # Deep-dive architecture documentation
│   ├── quantum_algorithms.md    # Quantum algorithm explanations
│   ├── api_reference.md         # REST API documentation
│   └── assets/
│       └── banner.png
├── docker-compose.yml
├── Dockerfile.frontend
├── Dockerfile.backend
├── package.json
├── vite.config.js
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Configuration

Copy `.env.example` to `.env` and configure:

```env
# Backend
QSIP_BACKEND_URL=http://localhost:8000
QSIP_QUANTUM_BACKEND=simulator          # simulator | ibm_quantum | aws_braket
QSIP_QUBITS=16
QSIP_ANNEALING_STEPS=1000
QSIP_ANNEALING_TEMP_START=100.0
QSIP_ANNEALING_TEMP_END=0.01

# IBM Quantum (optional — for real hardware)
IBM_QUANTUM_TOKEN=your_token_here
IBM_QUANTUM_INSTANCE=ibm-q/open/main

# AWS Braket (optional)
AWS_BRAKET_REGION=us-east-1
AWS_BRAKET_S3_BUCKET=your-bucket

# Validation
FUZZING_ITERATIONS=10000
REGRESSION_TIMEOUT_SEC=120
STATIC_ANALYSIS_DEPTH=5
```

---

## API Reference

Full docs at `http://localhost:8000/docs` (Swagger UI) when backend is running.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/graph/scan` | POST | Initiate quantum walk scan |
| `/api/graph/nodes` | GET | List all architecture nodes |
| `/api/paths` | GET | Get detected attack paths |
| `/api/paths/{id}` | GET | Get specific attack path details |
| `/api/patches/synthesize` | POST | Start patch synthesis for a path |
| `/api/patches/{path_id}` | GET | Get synthesized patches |
| `/api/patches/apply` | POST | Mark patch as applied |
| `/api/validation/run` | POST | Run validation suite on a patch |
| `/api/quantum/state` | GET | Get current qubit register state |

---

## Testing

```bash
# Frontend unit tests
npm run test

# Frontend e2e (Playwright)
npm run test:e2e

# Backend unit tests
cd backend
pytest tests/ -v

# Backend with coverage
pytest tests/ --cov=. --cov-report=html

# Specific module
pytest tests/test_quantum_walk.py -v
```

---

## Roadmap

- [ ] **v1.1** — Real IBM Quantum hardware integration via Qiskit Runtime
- [ ] **v1.2** — AWS Braket backend support (IonQ, Rigetti)
- [ ] **v1.3** — Kubernetes architecture graph auto-discovery (kubectl integration)
- [ ] **v1.4** — Terraform/CloudFormation graph ingestion
- [ ] **v2.0** — LLM-powered patch explanation and developer chat interface
- [ ] **v2.1** — CI/CD pipeline plugin (GitHub Actions, GitLab CI)
- [ ] **v2.2** — SBOM (Software Bill of Materials) integration for supply chain paths
- [ ] **v3.0** — Actual NISQ device experiments with error mitigation

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) first.

```bash
# Fork the repo, then:
git checkout -b feature/your-feature-name
git commit -m "feat: describe your change"
git push origin feature/your-feature-name
# Open a Pull Request
```

---

## License

MIT © 2024 — See [LICENSE](LICENSE) for details.

---

*Built with quantum curiosity and a deep dislike of unpatched CVEs.*
