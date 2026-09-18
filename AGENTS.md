# Adversary authoring reviewer

This project reviews TypeScript adversaries, not application code or the broader Adversary Labs platform.

Keep deterministic checks evidence-backed, then use bounded model review for prompt, authority, synthesis, and product-quality judgment. Use the canonical manifest schema, emit structured SDK observations, and prefer a few publish-blocking findings over speculative style feedback. Never execute code from the repository being reviewed.

Run `npm test`, `doomer validate .`, and `doomer pack --check .` before release.
