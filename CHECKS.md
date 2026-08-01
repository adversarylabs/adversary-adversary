# Checks — what adversarylabs/adversary detects

This file is the **public audit list** of detectors. If a rule id appears here, it is part of the product surface: it should fire on a vulnerable pattern, stay quiet on the documented clean case, and produce file:line evidence where applicable.

Runtime source of truth: `src/rules/` and model review path.
Regression entry: package tests under `test/`.

**Scope:** repositories that look like TypeScript adversary packages (adversary.yaml + SDK project layout).

---

## Identity & manifest

### `adversary.typescript.manifest.invalid`

| | |
| --- | --- |
| **What** | adversary.yaml invalid or incomplete |
| **Why** | Package cannot load/run |
| **Looks for** | Broken/missing required manifest fields |
| **Stays quiet when** | Valid v1 manifest |
| **Remediation** | Fix adversary.yaml against the schema |

### `adversary.typescript.identity.mismatch`

| | |
| --- | --- |
| **What** | Package identity fields disagree |
| **Why** | Publish/install confusion |
| **Looks for** | name/version mismatch across manifest and package.json |
| **Stays quiet when** | Single coherent identity |
| **Remediation** | Align names and versions |

### `adversary.typescript.name.not-domain`

| | |
| --- | --- |
| **What** | Name is not domain/name form |
| **Why** | Catalog ids should be domain/name |
| **Looks for** | Underscores/legacy names |
| **Stays quiet when** | domain/name catalog id |
| **Remediation** | Use catalog-style names (e.g. go/security) |

## SDK & permissions

### `adversary.typescript.sdk.legacy-api`

| | |
| --- | --- |
| **What** | Uses legacy SDK surfaces |
| **Why** | Breaks on current runtime |
| **Looks for** | Deprecated APIs |
| **Stays quiet when** | Current SDK observation/rule APIs |
| **Remediation** | Migrate to supported SDK |

### `adversary.typescript.sdk.reimplementation`

| | |
| --- | --- |
| **What** | Reimplements platform concerns |
| **Why** | Double grouping/ranking fights the SDK |
| **Looks for** | Local finding grouping/dedup/formatters |
| **Stays quiet when** | Emit observations; let SDK synthesize |
| **Remediation** | Delete local platform reimplementation |

### `adversary.typescript.sdk.structured`

| | |
| --- | --- |
| **What** | Unstructured result paths |
| **Why** | Renderers cannot present findings |
| **Looks for** | Freeform stdout without observations |
| **Stays quiet when** | Structured observations/findings |
| **Remediation** | Use ctx.observe / defineRule |

### `adversary.typescript.permissions.broad`

| | |
| --- | --- |
| **What** | Over-broad declared permissions |
| **Why** | Users must grant more than needed |
| **Looks for** | Filesystem/network/model flags wider than use |
| **Stays quiet when** | Least privilege in adversary.yaml |
| **Remediation** | Declare only required permissions |

## Tests & fixtures

### `adversary.typescript.tests.missing-clean-fixture`

| | |
| --- | --- |
| **What** | Missing clean fixture |
| **Why** | Cannot prove silence |
| **Looks for** | No clean/good fixture |
| **Stays quiet when** | Clean fixture that stays quiet |
| **Remediation** | Add clean fixtures |

### `adversary.typescript.tests.missing-vulnerable-fixture`

| | |
| --- | --- |
| **What** | Missing vulnerable fixture |
| **Why** | Cannot prove detection |
| **Looks for** | No vulnerable fixture for claimed rules |
| **Stays quiet when** | Vulnerable fixture that fires |
| **Remediation** | Add vulnerable fixtures |

### `adversary.typescript.tests.rule-coverage`

| | |
| --- | --- |
| **What** | Tests do not cover claimed rules |
| **Why** | Regressions ship silently |
| **Looks for** | Rules without behavioral tests |
| **Stays quiet when** | Per-rule tests or corpus coverage |
| **Remediation** | Cover each shipped rule id |

### `adversary.typescript.tests.behavioral`

| | |
| --- | --- |
| **What** | Tests are shallow / non-behavioral |
| **Why** | Green CI without product proof |
| **Looks for** | Snapshot-only without detector proof |
| **Stays quiet when** | Behavioral assertions on findings |
| **Remediation** | Assert rule ids and locations |

## Package & quality

### `adversary.typescript.package.contents`

| | |
| --- | --- |
| **What** | Package contents layout issues |
| **Why** | Runtime cannot load entrypoints |
| **Looks for** | Missing dist / wrong files field |
| **Stays quiet when** | Correct package.json files and main |
| **Remediation** | Ship the runtime entrypoint |

### `adversary.typescript.package.dependencies`

| | |
| --- | --- |
| **What** | Dependency problems for publish |
| **Why** | Install failures for consumers |
| **Looks for** | Missing/incorrect SDK dependency ranges |
| **Stays quiet when** | Declared, installable deps |
| **Remediation** | Fix dependency declarations |

### `adversary.typescript.publish.metadata`

| | |
| --- | --- |
| **What** | Publish metadata incomplete |
| **Why** | Catalog/registry listing quality |
| **Looks for** | Missing description/keywords/license signals |
| **Stays quiet when** | Complete package metadata |
| **Remediation** | Fill in package.json metadata |

### `adversary.typescript.recommendation.weak`

| | |
| --- | --- |
| **What** | Recommendations not actionable |
| **Why** | Users cannot fix findings |
| **Looks for** | Vague advice without next steps |
| **Stays quiet when** | Concrete remediation |
| **Remediation** | Say what to change |

### `adversary.typescript.observation.evidence`

| | |
| --- | --- |
| **What** | Observations lack evidence |
| **Why** | Findings are not auditable |
| **Looks for** | Missing file:line / snippets |
| **Stays quiet when** | Evidence on every observation |
| **Remediation** | Attach locations |

### `adversary.typescript.llm.no-evidence-gate`

| | |
| --- | --- |
| **What** | Model path without evidence gate |
| **Why** | Hallucinated issues |
| **Looks for** | LLM findings without citations |
| **Stays quiet when** | Require tool citations |
| **Remediation** | Gate model output on evidence |

### `adversary.typescript.determinism.unstable-output`

| | |
| --- | --- |
| **What** | Unstable non-deterministic output |
| **Why** | Flaky CI / unreviewable diffs |
| **Looks for** | Ordering/time in outputs |
| **Stays quiet when** | Stable sort and ids |
| **Remediation** | Make output deterministic |

### `adversary.typescript.types.strict`

| | |
| --- | --- |
| **What** | TypeScript not strict enough for an adversary |
| **Why** | Runtime surprises |
| **Looks for** | Loose tsconfig for shipping code |
| **Stays quiet when** | strict settings appropriate to SDK packages |
| **Remediation** | Enable strictness |
