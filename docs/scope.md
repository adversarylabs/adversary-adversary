# adversarylabs/adversary — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `adversary`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Adversary packages (TS)

## Mission

Review TypeScript adversaries for SDK usage, rule design, finding quality, tests, packaging.

## In scope (fair miss if humans raised it and we did not)

- Adversary package structure and SDK misuse
- Weak findings design
- Packaging/publish readiness of adversaries

## Out of scope (not a miss for this adversary)

- General product app review
- Unrelated CI

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
