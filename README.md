# adversary-adversary

`adversary` reviews TypeScript adversaries built with the Adversary SDK. It answers a narrow authoring question: is this project well designed, tested, packaged, and documented enough to publish?

It does not review application code or any broader Adversary Labs service, registry, CLI, billing, or infrastructure concern.

## Scope

A repository is reviewed only when it contains `adversary.yaml`, `package.json`, `tsconfig.json`, TypeScript under `src/`, and a dependency on or import from the Adversary TypeScript SDK. Unrelated TypeScript projects receive no findings.

The reviewer combines deterministic static review with model-backed product judgment. Deterministic analysis covers:

- canonical `adversary.manifest.v1` validity and cross-file identity;
- current structured SDK usage and SDK-owned presentation mechanics;
- stable rule IDs, evidence, confidence, recommendations, and grouping intent;
- clean fixtures, firing coverage, negative coverage, and grouping regressions;
- build entrypoints, runtime imports, package intent, and least-privilege permissions;
- README, license, provenance, runtime, and usage metadata.

The model review consumes those observations plus bounded source excerpts. It owns the questions that require engineering judgment: whether authority is coherent, prompts resist hallucination, findings are synthesized and prioritized, SDK capabilities are used effectively, and the adversary would provide enough value to justify enabling it. It returns no more than three evidence-linked observations.

Every model citation is grounded against prepared text, allowing only whitespace-equivalent formatting. An ungrounded response gets one repair attempt; if its citations still cannot be verified, model observations are omitted and the deterministic review completes with a visible note instead of failing the run.

The canonical manifest JSON schema is shipped in [`schema/adversary.manifest.v1.schema.json`](schema/adversary.manifest.v1.schema.json). Project-level checks add entrypoint existence and package/TypeScript consistency without redefining the manifest contract.

The reviewer never executes the target project’s build, tests, or source. A missing or stale build is reported from declared package intent and file evidence; final compilation remains the author’s explicit pre-publish step.

## Rules

| Rule ID | Severity |
| --- | --- |
| `adversary.typescript.identity.mismatch` | medium |
| `adversary.typescript.manifest.invalid` | high |
| `adversary.typescript.sdk.legacy-api` | medium |
| `adversary.typescript.presentation.manual` | medium |
| `adversary.typescript.rule.id-quality` | low |
| `adversary.typescript.rule.grouping` | low |
| `adversary.typescript.observation.evidence` | low |
| `adversary.typescript.confidence.calibration` | low |
| `adversary.typescript.recommendation.weak` | low |
| `adversary.typescript.sdk.reimplementation` | medium |
| `adversary.typescript.tests.missing-clean-fixture` | low |
| `adversary.typescript.tests.rule-coverage` | low |
| `adversary.typescript.tests.grouping` | low |
| `adversary.typescript.build.output` | medium |
| `adversary.typescript.package.contents` | medium |
| `adversary.typescript.package.dependencies` | high |
| `adversary.typescript.permissions.broad` | low |
| `adversary.typescript.publish.metadata` | low |

Related observations share one finding where they have one remediation. For example, all manifest schema violations aggregate together, as do identity conflicts, missing behavioral coverage, broad permissions, and undeclared runtime imports.

## Development

Node.js 22 or newer is required.

```bash
npm install
npm test
adversary validate .
adversary pack --check .
```

The test suite uses a complete clean project plus small overlays in [`test/fixtures`](test/fixtures). It covers all 18 rule IDs, unrelated-project suppression, multi-observation grouping, deterministic ordering, terminal redaction, and the canonical JSON run envelope.

## Usage

Build and review a local TypeScript adversary:

```bash
npm run build
adversary run . --path ../dockerfile-adversary \
  --model-provider fireworks \
  --model accounts/fireworks/models/your-model-id
```

After publication:

```bash
adversary run adversarylabs/adversary --repo .
```

The adversary emits structured observations only. The SDK owns synthesis, grouping, ranking, suppression, and terminal or JSON rendering.

Provider API tokens remain CLI configuration; they are not read by this adversary.

## Deliberate bootstrap limits

The deterministic implementation uses conservative source-pattern analysis rather than a full TypeScript semantic program. It only reports clear legacy APIs, direct presentation, dependency, evidence, confidence, and grouping patterns. The model reviews prepared evidence; it is explicitly constrained from inventing missing runtime behavior or catalog policy. The adversary does not execute target builds, score prose numerically, or claim proof of complete least privilege.

These boundaries keep the first release useful for dogfooding while avoiding generic TypeScript-linter behavior.

## Automatic detection

`adversary auto` selects the adversary adversary when changes include `adversary.yaml` or `.adversaryignore`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.
