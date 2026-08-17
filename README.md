# Adversary authoring adversary

Reviews TypeScript adversaries for SDK usage, rule design, finding quality, tests, packaging, and publish readiness.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates TypeScript adversary packages: manifest identity, SDK usage, permissions, tests, packaging, evidence quality, and publish readiness.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It reviews adversary packages, not arbitrary TypeScript applications or the repositories those adversaries will eventually scan.
