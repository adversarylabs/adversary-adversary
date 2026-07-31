# meta/adversary

**meta/adversary** reviews TypeScript adversaries built with the Adversary SDK: is this project **well designed, tested, packaged, and documented enough to publish?**

It is a **meta reviewer for adversary packages**, not a general TypeScript or application-code adversary. Unrelated TS projects should receive no findings.

## What it does

1. **Detects** adversary packages via `adversary.yaml`, `package.json`, `tsconfig.json`, TypeScript under `src/`, and SDK usage.
2. **Runs deterministic static review** of identity, packaging, permissions, tests, and SDK usage.
3. **Applies model-backed product judgment** for recommendation quality, evidence gates, and authoring craft when a model is available.
4. **Synthesizes** publish-readiness findings through the SDK.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)** — the audit surface for “what does this adversary look for?”

Highlights:

| Area | Examples |
| --- | --- |
| Identity | Manifest name/domain alignment; invalid manifests |
| SDK | Legacy APIs; reimplementation of platform concerns; unstructured output |
| Tests | Missing clean/vulnerable fixtures; weak rule coverage |
| Package | Dependencies, publish metadata, build output layout |
| Quality | Weak recommendations; low evidence; unstable non-determinism |

### Ownership boundaries

Other official adversaries own adjacent classes so findings stay non-duplicative:

| Concern | Owned by |
| --- | --- |
| Language/framework security in the *target* repo the adversary reviews | the domain adversary under test (e.g. go/security) |
| General engineering judgment on arbitrary diffs | [`review/engineering`](https://github.com/adversarylabs/engineering-review-adversary) |

## Precision stance

- Only runs when the repository looks like an adversary package.
- Deterministic rules must be evidence-backed; model observations require citations.
- Prefer actionable publish blockers over style commentary.
