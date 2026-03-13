# QSIP Architecture Deep Dive

## System Design

QSIP follows a clean three-layer architecture:

```
┌──────────────────────────┐
│   React Frontend (Vite)  │  Interactive graph + quantum state UI
├──────────────────────────┤
│   FastAPI Backend         │  REST API, task queue, orchestration
├──────────────────────────┤
│   Quantum Engine          │  Qiskit walk, QAOA, annealing
└──────────────────────────┘
```

## Graph Representation

Every element of your software architecture is modelled as a node in a directed weighted graph:

| Node Type  | Examples                              | Base Risk |
|------------|---------------------------------------|-----------|
| external   | Internet, CDN Edge                    | 0.9       |
| security   | WAF, IDS, API Gateway                 | 0.2       |
| infra      | Load Balancer, Message Queue, Redis   | 0.3       |
| service    | Auth Service, User API, Payment API   | 0.5       |
| data       | Databases, File Stores, Secrets Vault | 0.7       |

Edges carry a `type` (public / filtered / internal / privileged) and a `weight` used by both the quantum walk and QAOA.

## Quantum Walk Details

The system uses a **discrete-time quantum walk** (DTQW) with:
- A coin register (1 qubit) using Hadamard as the coin operator
- A position register (`⌈log₂ N⌉` qubits for N nodes)
- Shift operator S that moves the walker left/right based on the coin

After `t` steps the probability of being at node `v` reflects the graph topology, and is amplified by the node's risk weight before measurement.

## QAOA Encoding

Attack path finding is formulated as QUBO:

```
minimise  -Σᵢ rᵢxᵢ  -  λ Σ_{(i,j)∈E} wᵢⱼ xᵢxⱼ
s.t.      xᵢ ∈ {0,1}
```

The QAOA ansatz alternates between the cost unitary `e^{-iγH_C}` and the mixer unitary `e^{-iβH_M}` for `p` layers (controlled by `QSIP_QAOA_REPS`).

## Annealing Schedule

Patch synthesis uses a quantum-inspired annealing schedule:

```
T(t) = T_start × (T_end/T_start)^(t/N)
```

Acceptance probability for an uphill move combines:
- Metropolis: `exp(-ΔE / T)`
- Quantum tunneling: `strength × exp(-|ΔE| / barrier)`

This tunneling term allows the optimizer to escape local minima that would trap classical SA.

## Data Flow

```
POST /api/graph/scan
  → GraphStore.load()
  → QuantumWalker.run()          # amplify risky nodes
  → QAOAPathFinder.find()        # extract attack paths
  → CVEAnnotator.annotate()      # tag CVEs per node
  → store results in PostgreSQL

POST /api/patches/synthesize/{path_id}
  → load attack path
  → PatchGenerator.candidates()  # generate options per vuln
  → quantum_anneal()             # optimize combination
  → ValidationPipeline.run()     # 6-stage test suite (Celery task)
  → store validated patches

GET /api/patches/{path_id}
  → return ranked, scored patches
```
