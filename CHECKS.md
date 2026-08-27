# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `adversary.typescript.determinism.unstable-output` | Review | Unstable non-deterministic output |
| `adversary.typescript.identity.mismatch` | Review | Package identity fields disagree, allowing only the exact npm-safe `domain-name` spelling of canonical `domain/name` catalog identity |
| `adversary.typescript.llm.no-evidence-gate` | Review | Model path without evidence gate |
| `adversary.typescript.manifest.invalid` | Review | adversary.yaml invalid or incomplete |
| `adversary.typescript.name.not-domain` | Review | Name is not domain/name form |
| `adversary.typescript.observation.evidence` | Review | Observations lack evidence |
| `adversary.typescript.package.contents` | Review | Package contents layout issues |
| `adversary.typescript.package.dependencies` | Review | Dependency problems for publish |
| `adversary.typescript.permissions.broad` | Review | Over-broad declared permissions |
| `adversary.typescript.publish.metadata` | Review | Publish metadata incomplete |
| `adversary.typescript.recommendation.weak` | Review | Recommendations not actionable |
| `adversary.typescript.sdk.legacy-api` | Review | Uses legacy SDK surfaces |
| `adversary.typescript.sdk.reimplementation` | Review | Reimplements platform concerns |
| `adversary.typescript.sdk.structured` | Review | Unstructured result paths |
| `adversary.typescript.tests.behavioral` | Review | Tests are shallow / non-behavioral |
| `adversary.typescript.tests.missing-clean-fixture` | Review | Missing clean fixture |
| `adversary.typescript.tests.missing-vulnerable-fixture` | Review | Missing vulnerable fixture |
| `adversary.typescript.tests.rule-coverage` | Review | Tests do not cover claimed rules |
| `adversary.typescript.types.strict` | Review | TypeScript not strict enough for an adversary |
