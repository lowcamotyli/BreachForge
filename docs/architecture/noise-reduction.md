# ProofScan — Noise Reduction
Source: `ARCHITECTURE.md` — Section 10 (all mechanisms), Section 3 (P4), Section 4 (`FindingScorer` dedup), Section 9 (Low-confidence signals handling).

### P4 — Deduplication is a first-class system concern

Deduplication happens before a finding is written — it is not a UI filter applied after the fact.

#### `FindingScorer`

- Receives validated `ProofArtifact` objects from the Validator
- Normalizes them against existing findings (same root cause? same parameter class? same endpoint pattern?)
- Assigns severity and confidence
- Writes to the Finding Store **only when dedup passes**

### Low-confidence signals handling

Probes that pass initial validation but score below 0.85 → go into a "signals requiring manual review" store. These are **never surfaced in the main findings report**. They may be included in a separate optional section (off by default). This boundary is **architecturally enforced**, not a UI toggle.

---

## 10. Noise-Reduction Strategy

### Mechanism 1 — Proof-gate at the Validator

Nothing without a `ProofArtifact` becomes a finding. This eliminates the majority of false positives by design.

### Mechanism 2 — Structural deduplication before write

Before creating a `Finding`, the scorer computes a structural fingerprint:

```python
fingerprint = (attack_class, normalize_url_pattern(endpoint), parameter_class)
```

If a finding with the same fingerprint already exists for this scan, the new evidence is attached to the existing finding instead of creating a duplicate. This prevents the "same IDOR on 47 different resource IDs" explosion.

### Mechanism 3 — No theoretical findings

The attack engine only queues tasks with feasible proof signals. There is no "this header is missing, therefore potentially vulnerable" category. Every `AttackTask` must have a defined `expected_proof_signal`.

### Mechanism 4 — Differential probing as default

Most validators run a control probe alongside the attack probe. The system reports only the delta. This catches cases where a generic response pattern looks like a finding but is how the endpoint behaves normally.

### Mechanism 5 — Scope enforcement

The crawler respects strict scope rules: target domain(s) defined at scan creation only. No attacks are issued against third-party domains, CDN origins, or OAuth providers even if linked from the target. Out-of-scope endpoints are recorded in `AssetMap` but never queued for attack.

### Mechanism 6 — Attack class gating

Some attack classes only activate when prerequisite conditions are met:
- BOLA/IDOR: requires either a second test account or observable resource ID patterns. If neither exists → class is noted as "not tested, prerequisite unmet" in the report.
- Injection: only queued when error output or timing differential is a feasible proof path.

---
