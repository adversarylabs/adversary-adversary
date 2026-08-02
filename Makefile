# Local helpers for publishing adversarylabs/adversary.
# build/package is via npm + adversary CLI; signing is optional and secret-gated.

.PHONY: sign-dev

# Sign a remote ref with the official-dev key from Doppler (adversarylabs/dev).
# Does not wrap build/pack — only injects ADVERSARY_OFFICIAL_SIGNING_SEED.
#
# Usage:
#   make sign-dev REF=localhost:8787/adversarylabs/adversary:0.0.22
#   make sign-dev REF=registry.adversarylabs.ai/adversarylabs/adversary:0.0.22
#
# Requires: doppler auth, adversary CLI with `sign`, registry login.
REF ?=

sign-dev:
	@test -n "$(REF)" || (echo 'usage: make sign-dev REF=<registry>/adversarylabs/adversary:<version>' >&2; exit 2)
	doppler run --project adversarylabs --config dev -- \
		adversary sign "$(REF)" --key-id official-dev
