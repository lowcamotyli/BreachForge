# Claims Policy (C3): Market-Facing Claims and Required Evidence

**Policy ID:** C3  
**Owner:** Benchmark Program (Technical Lead)  
**Applies to:** Marketing, Sales, Product Marketing, Partnerships, Executive Communications  
**Effective date:** 2026-05-28  
**Version:** 1.0

## 1. Policy Purpose

This policy exists to prevent non-reproducible or misleading market claims about BreachForge performance.
All public-facing performance, detection, quality, speed, coverage, or competitor comparison claims must be backed by reproducible benchmark evidence.

The benchmark evidence model in this policy is designed to ensure:
- Claims are derived from repeatable lab runs, not one-off observations.
- Claims can be independently re-checked from preserved artifacts.
- Competitor comparisons are fair and technically defensible.
- Marketing language reflects measured outcomes, not anecdotal testing.

Anecdotal testing, ad hoc internal scripts, or manually edited results are not acceptable claim support.
Any claim published without required evidence is blocked and must be removed or corrected.

## 2. Claim Categories and Evidence Requirements

The following claim types are allowed only when the exact minimum bar is met.
Evidence must come from benchmark runs executed in the last 30 calendar days at the time of approval.

| Claim Type | Example | Required Evidence | Minimum Bar |
| --- | --- | --- | --- |
| Detection superiority (`market-leading`, `detects more than X`) | "BreachForge detects more real issues than competing API scanners." | Benchmark result package showing true-positive (TP) outcomes per lab plus run manifest with run timestamp and benchmark hash. | TP rate `>= 0.90` in **each** of the 5 labs, from a run in the last 30 days, with signed manifest. |
| False positive rate (`zero false positives`, `lowest FP`) | "BreachForge produced zero false positives in independent benchmark labs." | FP breakdown per lab, proof-depth metrics, and signed scorecard bound to benchmark hash. | `FP == 0` across all labs **and** `proof_depth_avg >= 0.85`; signed scorecard required. |
| Speed claim (`fastest`, `X% faster than Y`) | "BreachForge is 28% faster than Tool Y on API attack simulation." | Wall-clock comparison package containing both runs, corpus ID, hardware spec, runtime settings, and environment metadata. | Same corpus version, same hardware spec, same concurrency/runtime profile, and repro bundle containing `env_metadata.json`. |
| Coverage claim (`covers OWASP API Top 10`) | "BreachForge covers OWASP API Top 10 attack classes." | Coverage export with attack-class mapping and signed scorecard tied to benchmark hash. | `coverage_by_attack_class` must map and show coverage for all 10 OWASP API categories; scorecard with class mapping required. |
| Comparison claim (`better than ZAP/Nuclei/HexStrike`) | "BreachForge outperforms ZAP, Nuclei, and HexStrike on detection quality." | Imports for each compared engine using engine adapters, same corpus for all engines, and signed scorecards per engine. | Must use engine adapters, same corpus version, and `breachforge-bench import-results` outputs for both engines; two signed scorecards plus engine configs required. |

### 2.1 General Rules That Apply to Every Claim Category

- Evidence artifacts must include benchmark hash, run timestamp, and operator identity.
- The benchmark corpus version must be explicitly recorded and immutable for the claim package.
- Any anti-gaming randomization settings used in benchmark labs must be preserved in evidence metadata.
- Results must be machine-generated from benchmark tooling; manual spreadsheet-only calculations are insufficient.
- Claims must match metric names exactly as produced by benchmark outputs; no relabeling of metrics.
- Claims must include scope qualifiers if evidence is limited to specific attack classes, corpus slices, or runtime modes.
- If claim wording is stronger than measured evidence (for example `best` vs measured `within confidence interval`), wording must be downgraded before approval.

## 3. Blocked Claims

The following claims are never allowed and are rejected even if partially supported:

- Claims based on unreproducible internal testing.
- Claims comparing against corpus versions older than 90 days at claim review time.
- Claims submitted without a signed manifest.
- Comparative claims where competitor configuration is not public and attached.

Additional hard blocks:
- Claims based on mixed hardware or unknown runtime configuration.
- Claims built from cherry-picked runs while excluding worse runs from the same period.
- Claims using benchmark outputs that cannot be tied to a benchmark hash and immutable artifact bundle.
- Claims that treat `unknown` or unmapped attack classes as covered categories.

Blocked means:
- The claim cannot be published.
- Existing published copy must be corrected or removed.
- A new evidence package must be submitted before reconsideration.

## 4. Evidence Submission Process

Every market-facing claim must be filed as a claim ticket with attached evidence.
Do not submit claims over chat or email without a ticket.

### 4.1 Required Steps

1. Run benchmark evaluation using `breachforge-bench` on the intended claim corpus.
2. Generate a reproducibility bundle that includes raw outputs, scorecard(s), benchmark hash, and environment metadata.
3. Sign the manifest for the run artifacts and scorecard bundle.
4. Create a claim ticket in `docs/process/claim-submissions/` and attach all evidence files.

### 4.2 Command-Level Submission Checklist

Use these minimum steps before opening the ticket:

1. Execute benchmark run and export score outputs.
2. For comparisons, import external scanner outputs using engine adapters and `breachforge-bench import-results`.
3. Build repro bundle including `env_metadata.json`, benchmark hash, and run parameters.
4. Produce signed manifest and signed scorecard artifacts.
5. Confirm evidence timestamps are within policy windows (30-day recency for primary claim evidence).
6. Open claim ticket and link all artifact files by path.

### 4.3 Claim Ticket Template

Create a new markdown file under `docs/process/claim-submissions/` using the following template.
All fields are required unless explicitly marked optional.

```md
# Claim Ticket: <short-claim-slug>

## Claim Text (Exact)
- Proposed public wording:

## Claim Category
- One of: detection-superiority | false-positive-rate | speed | coverage | comparison

## Evidence Window
- Run date(s):
- Review date:

## Benchmark Identity
- Benchmark hash:
- Corpus version:
- Lab set: 5-lab standard

## Metrics Summary
- TP rate by lab:
- FP by lab:
- proof_depth_avg:
- coverage_by_attack_class:
- Wall-clock metrics (if speed claim):

## Comparison Inputs (required for comparison claims)
- Compared engines:
- Engine adapter names used:
- Engine config files (public):
- Import command references:

## Attached Artifacts
- Signed manifest path:
- Signed scorecard path(s):
- Repro bundle path:
- env_metadata.json path:
- Raw outputs path:

## Compliance Checks
- [ ] Evidence generated in last 30 days
- [ ] Signed manifest attached
- [ ] Corpus version not older than 90 days for comparisons
- [ ] Same corpus + same hardware (if comparative or speed claim)
- [ ] Competitor/public engine configuration attached (if comparative)

## Requestor
- Name:
- Team:
- Date:
```

## 5. Review and Approval

### 5.1 Required Approvers

A claim is approved only when both checks pass:
- Technical Lead review confirms the claim text exactly matches measured evidence.
- Benchmark hash verification confirms artifacts map to immutable benchmark outputs and signed manifests.

No single-person self-approval is allowed.
If the requestor is the Technical Lead, a second designated reviewer must perform hash verification.

### 5.2 Review SLA

- Standard SLA: decision within 5 business days from complete ticket submission.
- Incomplete tickets stop the SLA clock until missing evidence is provided.
- Priority review can be requested for launch deadlines but does not waive evidence requirements.

### 5.3 Decision Outcomes

- **Approved:** claim text may be published exactly as approved.
- **Approved with edits:** claim wording is adjusted to match evidence limits.
- **Rejected:** claim is blocked until new compliant evidence is submitted.

Every decision must be recorded in the claim ticket with:
- Decision timestamp.
- Reviewer names.
- Verified benchmark hash.
- Any mandatory wording constraints.

### 5.4 Appeals Process

If a claim is rejected:
1. Requestor may file one appeal within 10 business days.
2. Appeal must include either corrected claim text or new evidence artifacts.
3. Appeal is reviewed by the Technical Lead plus one independent reviewer not involved in the first decision.
4. Appeal decision is final for that evidence set.

Appeals do not permit bypassing blocked-claim rules in Section 3.

## 6. Changelog

- **2026-05-28** — v1.0 — Initial release of Claims Policy (C3), defining claim categories, evidence bars, blocked claims, submission process, and approval workflow.
