# adversarylabs/adversary — issue catalog

This document is the **issue catalog** for this adversary: the classes of defects we aim to find, how we detect them (static vs LLM), public pattern references, and staff priority (P0 / P1 / LLM-only / Cut).

It is documentation and roadmap for contributors — not a runtime contract. Implemented detectors live in `src/` with fixtures under `fixtures/`; the **Review verdicts** section records what ships first.

Public examples cited below illustrate bad patterns only. Do not scrape secrets from them or copy copyrighted code into fixtures.

**Catalog id:** `adversarylabs/adversary`  
**Status:** public OSS documentation of the issue classes this adversary targets  
**Goal:** trusted, high-precision detections. Prefer missing a weak signal over a false positive.

## Mission
Make first-party adversaries trustworthy: SDK correctness, test discipline, evidence quality, and anti-hallucination gates.

## LLM strategy (required for world-class)
**Enhance:** judge whether an adversary is release-ready for precision.
**Discover:** missing FP strategy, LLM unbounded context, confidence mismatches.

### Division of labor
Static = precise facts. LLM = enhancement + evidence-gated discovery. When unsure, omit.

## Review verdicts (staff pass)

- **P0 implement:** `llm.no-evidence-gate`, `tests.missing-clean`, `tests.missing-vulnerable`, `evidence.missing-location`, `name.not-domain`, `determinism.unstable-output`
- **P1:** `sdk.legacy-api`, `sdk.manual-findings`, `rules.weak-id`, `tests.snapshot-brittle`, `fp.no-suppression`, `manifest.permissions-broad`, `manifest.model-without-static`, `pack.large-blob`, `evidence.weak-snippet`, `grouping.missing`, `confidence.mismatch`, `recommendation.generic`, `runtime.network-true`, `publish.unpinned-ci`, `version.drift`, `llm.unbounded-context`, `fixtures.real-looking-secrets`, `benchmark.missing`
- **LLM-only:** `detectors.regex-only` (architecture review)
- **Cut:** `rules.two-part-id` — merged into `rules.weak-id` (one id-shape rule).

## Issue catalog

---
### 1. `meta.sdk.legacy-api` — Uses deprecated SDK APIs

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Old @adversarylabs/sdk patterns — today that primarily means pre-0.1.8 APIs and adversaries not yet migrated to the ctx.change scope contract (go-cli is the reference migration).

**Static detection.** Import/API detect against known legacy list.

**LLM role.** Migration tips.

**False-positive guards.** None.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-sdk-typescript
  - https://github.com/adversarylabs/adversary-adversary — fixtures/legacy-sdk
  - https://github.com/adversarylabs/adversarylabs — docs

---
### 2. `meta.sdk.manual-findings` — Hand-builds findings instead of SDK helpers

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** Bypasses schema guarantees.

**Static detection.** AST detect raw finding object lits.

**LLM role.** Recommend helpers.

**False-positive guards.** Meta tests.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-adversary/fixtures
  - https://github.com/adversarylabs/adversary-sdk-typescript
  - https://github.com/adversarylabs/adversarylabs

---
### 3. `meta.rules.weak-id` — Weak/non-stable rule ids

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** rule ids like issue1 or changing strings.

**Static detection.** Detect id patterns; enforce three-segment `domain.object.failure` via ^[a-z0-9]+(\.[a-z0-9-]+){2,}$ (absorbs former `meta.rules.two-part-id`).

**LLM role.** domain.object.failure form.

**False-positive guards.** Experimental only.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-adversary
  - https://github.com/adversarylabs/go-security-adversary
  - https://github.com/adversarylabs/adversarylabs — docs

---
### 4. `meta.tests.missing-clean` — No clean/negative fixtures

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** FP risk — most critical for trust.

**Static detection.** Detect fixtures without clean counterparts.

**LLM role.** Hard require for release.

**False-positive guards.** Doc-only adversaries.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-adversary/fixtures
  - https://github.com/adversarylabs/go-cli-adversary/fixtures
  - https://github.com/adversarylabs/secrets-adversary

---
### 5. `meta.tests.missing-vulnerable` — No positive fixtures for rule

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Rule untested.

**Static detection.** Map rules to fixtures.

**LLM role.** Require coverage.

**False-positive guards.** LLM-only soft rules.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-adversary
  - https://github.com/adversarylabs/go-http-adversary/fixtures
  - https://github.com/adversarylabs/dockerfile-adversary

---
### 6. `meta.tests.snapshot-brittle` — Over-specific snapshots hide regressions

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Quality of tests.

**Static detection.** LLM review of snapshots.

**LLM role.** Assert rule ids not full prose.

**False-positive guards.** OK snapshotting messages carefully.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/go-cli-adversary
  - https://github.com/adversarylabs/engineering-review-adversary
  - https://github.com/adversarylabs/adversary-adversary

---
### 7. `meta.fp.no-suppression` — No documented FP strategy

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Trust killer.

**Static detection.** Detect missing false-positive tests/docs.

**LLM role.** Require FP section per high-severity rule.

**False-positive guards.** Tiny experimental.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/secrets-adversary/src/false-positives.ts
  - https://github.com/adversarylabs/adversary-adversary
  - https://github.com/gitleaks/gitleaks — allowlist patterns as inspiration

---
### 8. `meta.manifest.permissions-broad` — permissions.network true without need

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** Over-permissioned adversaries.

**Static detection.** Parse adversary.yaml permissions.

**LLM role.** Least privilege.

**False-positive guards.** Model true only when needed.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversarylabs — docs permissions
  - https://github.com/adversarylabs/go-security-adversary/adversary.yaml
  - https://github.com/adversarylabs/secrets-adversary/adversary.yaml

---
### 9. `meta.manifest.model-without-static` — Model-only without deterministic backbone

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Unreliable product.

**Static detection.** Detect model:true with few static rules.

**LLM role.** Require static baseline.

**False-positive guards.** Pure summarizers (rare).

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/engineering-review-adversary
  - https://github.com/adversarylabs/go-security-adversary
  - https://github.com/adversarylabs/adversarylabs

---
### 10. `meta.pack.large-blob` — Packs node_modules without vendor strategy

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** Bloated artifacts.

**Static detection.** Detect packed dependency heft.

**LLM role.** Recommend vendor/sdk bundling policy.

**False-positive guards.** Intentional fat images.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-adversary
  - https://github.com/adversarylabs/dockerfile-adversary
  - https://github.com/adversarylabs/adversary — pack docs

---
### 11. `meta.evidence.missing-location` — Findings without file locations

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Unactionable.

**Static detection.** Detect findings missing path/line.

**LLM role.** Hard fail quality gate.

**False-positive guards.** Repo-global config issues with path=.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-adversary/fixtures/poor-evidence
  - https://github.com/adversarylabs/adversary-sdk-typescript
  - https://github.com/adversarylabs/adversarylabs

---
### 12. `meta.evidence.weak-snippet` — Empty/misleading snippets

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** Trust.

**Static detection.** Snippet length/content checks.

**LLM role.** Must show bad pattern.

**False-positive guards.** Binary files.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-adversary/fixtures
  - https://github.com/adversarylabs/go-cli-adversary
  - https://github.com/adversarylabs/secrets-adversary

---
### 13. `meta.grouping.missing` — Duplicate findings not grouped

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Noise.

**Static detection.** Detect many identical rule spam.

**LLM role.** Group by rule+pattern.

**False-positive guards.** Intentionally separate instances.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-adversary/fixtures/weak-grouping
  - https://github.com/adversarylabs/depotci-adversary
  - https://github.com/adversarylabs/go-http-adversary

---
### 14. `meta.confidence.mismatch` — High confidence on heuristic rules

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** FP danger.

**Static detection.** Detect confidence:high on LLM-only rules.

**LLM role.** Cap confidence.

**False-positive guards.** Crypto detectors OK high.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-adversary/fixtures/confidence-mismatch
  - https://github.com/adversarylabs/secrets-adversary
  - https://github.com/adversarylabs/go-security-adversary

---
### 15. `meta.recommendation.generic` — Generic 'fix this' recommendations

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Low user value.

**Static detection.** LLM lint of recommendation text quality.

**LLM role.** Require concrete fix.

**False-positive guards.** None.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-adversary/fixtures/generic-recommendation
  - https://github.com/adversarylabs/go-cli-adversary
  - https://github.com/adversarylabs/dockerfile-adversary

---
### 16. `meta.runtime.network-true` — network permission for pure static adversary

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** Unnecessary capability.

**Static detection.** yaml vs code import analysis.

**LLM role.** Strip network.

**False-positive guards.** Needs OSV download intentional.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/secrets-adversary
  - https://github.com/adversarylabs/go-modules-adversary
  - https://github.com/adversarylabs/adversarylabs

---
### 17. `meta.publish.unpinned-ci` — Release workflow unpinned actions

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Dogfood GHA rules.

**Static detection.** Reuse gha checks on .depot/workflows.

**LLM role.** Pin SHAs.

**False-positive guards.** None.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/go-security-adversary/.depot/workflows
  - https://github.com/adversarylabs/adversary/.depot/workflows
  - https://docs.github.com/en/actions/reference/security/secure-use

---
### 18. `meta.name.not-domain` — adversary.yaml name not domain/name

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Catalog taxonomy.

**Static detection.** Parse name field for slash + domain list.

**LLM role.** Block publish of flat names.

**False-positive guards.** Private BYO OCI.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversarylabs/lib/catalog-ids.ts
  - https://github.com/adversarylabs/go-security-adversary/adversary.yaml
  - https://github.com/adversarylabs/go-cli-adversary/adversary.yaml

---
### 19. `meta.version.drift` — package.json version != adversary.yaml

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** Release confusion.

**Static detection.** Compare files.

**LLM role.** Sync.

**False-positive guards.** Non-node adversaries.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/go-cli-adversary
  - https://github.com/adversarylabs/adversarylabs/actions
  - https://github.com/adversarylabs/dockerfile-adversary

---
### 20. `meta.detectors.regex-only` — Only regex without AST for code domains

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** FP/FN risk for Go adversaries written poorly.

**Static detection.** LLM architecture review.

**LLM role.** Prefer tree-sitter/AST.

**False-positive guards.** Secrets OK regex.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/go-security-adversary
  - https://github.com/adversarylabs/secrets-adversary
  - https://github.com/tree-sitter/tree-sitter

---
### 21. `meta.llm.unbounded-context` — Sends whole repo to model

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Cost/leak risk.

**Static detection.** Detect model prompts with full tree dump.

**LLM role.** Chunk by evidence.

**False-positive guards.** Tiny repos.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/engineering-review-adversary
  - https://github.com/adversarylabs/go-security-adversary/src/model-review.ts
  - https://github.com/adversarylabs/adversarylabs

---
### 22. `meta.llm.no-evidence-gate` — LLM can emit findings without citations

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** Hallucination risk — trust killer.

**Static detection.** Validate output schema requires evidence[].

**LLM role.** Hard gate.

**False-positive guards.** None.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/go-security-adversary/src/model-review.ts
  - https://github.com/adversarylabs/adversary-sdk-typescript
  - https://github.com/adversarylabs/adversary-adversary

---
### 23. `meta.benchmark.missing` — No graded fixtures / corpus

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Can't measure precision.

**Static detection.** Detect missing benchmarks/.

**LLM role.** Require corpus for GA.

**False-positive guards.** Early experimental.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/go-cli-adversary/benchmarks
  - https://github.com/adversarylabs/go-security-adversary
  - https://github.com/adversarylabs/engineering-review-adversary

---
### 24. `meta.fixtures.real-looking-secrets` — Fixtures contain realistic secret material

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** Vulnerable fixtures with plausible key material trip customers' scanners and GitHub secret scanning (which can quarantine or auto-revoke). Fixtures must be structurally valid but canonically fake (documented example keys like AKIAIOSFODNN7EXAMPLE, EXAMPLE markers) plus scanner allow-annotations.

**Static detection.** Run the secrets detectors over fixtures/; flag hits lacking fake markers or allow-annotations.

**LLM role.** Judge whether a fixture value could pass as real.

**False-positive guards.** Intentional true-positive fixtures for the secrets adversary itself — require an annotation, not absence of the value.

**Public examples of the bad pattern:**
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html — documented example keys
  - https://github.com/gitleaks/gitleaks — gitleaks:allow annotation
  - https://docs.github.com/en/code-security/secret-scanning — quarantine behavior

---
### 25. `meta.determinism.unstable-output` — Findings not deterministic across identical runs

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Same input producing different findings (LLM temperature, map iteration order, timestamps or randomness in finding ids) destroys diffability, caching, and user trust — you cannot suppress or track a finding that changes identity every run.

**Static detection.** Check mode: run the adversary twice on fixtures and diff normalized findings; also statically detect Date.now/Math.random flowing into finding ids.

**LLM role.** None — this is a deterministic harness check; LLM stages must be pinned (temperature 0, stable prompts) or their outputs normalized.

**False-positive guards.** Ordering differences — normalize sort order before diffing.

**Public examples of the bad pattern:**
  - https://github.com/adversarylabs/adversary-adversary — double-run harness candidate
  - https://reproducible-builds.org/ — determinism principles
  - https://github.com/adversarylabs/adversary-sdk-typescript — id construction helpers

---

## Implementation roadmap (after approval)
P0 static rules + fixtures → LLM enhancement → discovery → precision bake-off on public repos.

**P0 priorities:** missing clean fixtures, LLM without evidence gate, non-deterministic output, weak rule ids, flat catalog names, high confidence heuristics.
