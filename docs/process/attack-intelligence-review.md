# Attack Intelligence — Ship-Gate Checklist

Used by Claude before every `ship: yes` decision for changes touching attack chain scoring, reporting, or validator strategies.

## P1 — Proof Gate

- [ ] Every `Finding` write is preceded by `confidence_score >= DEFAULT_PROOF_CONFIDENCE_THRESHOLD` check.
- [ ] No bypass path exists (no `if skip_gate` flag, no `force=True` shortcut).
- [ ] Chain confidence uses weak-link principle: `min(step_confidences)`.

## P2 — Dedup Before Write

- [ ] `FindingScorer._find_duplicate()` is called before `db.add()` in every scoring path.
- [ ] Chain root-cause fingerprint is derived from individual finding fingerprints.
- [ ] Variants correctly link to root_cause_id without creating duplicate DB rows.

## P3 — Worker Isolation

- [ ] Attack workers write only to Redis Evidence Buffer — no direct DB or S3 writes.
- [ ] `ReportingService` is the only path that writes chain output.
- [ ] `assemble_chain_report` does not spawn subprocesses or write evidence.

## P4 — Redaction at Export

- [ ] `assemble_chain_report` uses `finding.title` only — never `finding.description` raw.
- [ ] No `Authorization`, `Cookie`, `password`, `token` values appear in chain steps or remediation.
- [ ] `AttackChainStep.evidence_ref` is an opaque ID, not a URL with credentials.
- [ ] `ReportingService` redaction processor runs before any report dict is returned.

## P5 — Severity Integrity

- [ ] `Critical` severity requires `has_impact_evidence=True` — verified in `adjust_chain_severity`.
- [ ] Low chain confidence (`< 0.70`) always downgrades severity by one level.
- [ ] Upgrade to Critical requires: base=high, impact_evidence=True, step_count>=3, chain_conf>=0.85.

## P6 — Corpus Coverage

- [ ] All 5 corpus scenarios pass: C1 BOLA chain, C2 privilege blast, C3 secret exposure, C4 workflow skip, C5 negative control.
- [ ] `python -m pytest tests/corpus/attack_chains/ -q` exits 0.
- [ ] `python scripts/red_team_sim.py` exits 0.

## Final Ship Decision

```
Ship: yes
Evidence:
- pytest tests/ -q → N passed, 0 failed
- python scripts/red_team_sim.py → All N scenarios PASSED
- P1..P6 checklist: all PASS
- Redaction verified: no credentials in chain output
```
