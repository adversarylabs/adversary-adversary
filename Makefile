# Local helpers for publishing adversarylabs/review/adversary.
# Pack/push use the adversary CLI; signing is secret-gated via Doppler.

.PHONY: sign-dev

# CLI used for sign-dev. Override if your build lives elsewhere:
#   make sign-dev ADVERSARY=/path/to/adversary REF=...
ADVERSARY ?= $(HOME)/go/src/github.com/adversarylabs/adversary/bin/adversary

# Sign a remote ref with the official-dev key from Doppler (adversarylabs/dev).
# Does not wrap build/pack — only injects ADVERSARY_OFFICIAL_SIGNING_SEED.
#
# Usage:
#   make sign-dev REF=localhost:8787/adversarylabs/review/adversary:0.0.30
#
# Requires: doppler auth, adversary CLI with `sign` (built from main / PR),
# registry login for the target host.
REF ?=

sign-dev:
	@test -n "$(REF)" || (echo 'usage: make sign-dev REF=<registry>/adversarylabs/review/adversary:<version>' >&2; exit 2)
	@test -x "$(ADVERSARY)" || (echo "ADVERSARY not executable: $(ADVERSARY)" >&2; exit 2)
	doppler run --project doomer --config dev -- \
		"$(ADVERSARY)" sign "$(REF)" --key-id official-dev
