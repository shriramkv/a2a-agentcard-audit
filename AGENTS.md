# AGENTS.md

Guidance for coding agents working in this repository.

## Project

`a2a-agentcard-audit` lints, security-audits, signs and verifies A2A Agent Cards (A2A 1.0).
Zero runtime dependencies, Python 3.9+.

- `schema.py` holds the AgentCard message tree from `a2a.proto` (field kinds R/O/P/M/REP/MAP). It drives both structure validation and the section 8.4.1 default-value pruning.
- `jcs.py` is RFC 8785. `jose.py` is JWS with a cryptography backend and a pure-Python fallback.
- `card.py` holds the static checks, `signing.py` handles signing and verification, `fetch.py` handles discovery over HTTP, and `migrate.py` converts v0.3 cards.
- `rules.py` is the single registry: every rule has a spec section and requirement level.

## Commands

- Test: `python -m unittest discover -s tests -t .`
- Test the pure-Python crypto: `A2A_AUDIT_PURE_PYTHON=1 python -m unittest discover -s tests -t .`
- Demo: `python -m a2a_agentcard_audit demo`
- Regenerate the README rule table: `python scripts/build_readme.py`

## Rules for changes

- You must keep the package free of runtime dependencies; `cryptography` stays optional.
- You must keep Python 3.9 compatibility.
- Any change to `schema.py`, `jcs.py` or `prune` must keep `test_spec_example_byte_for_byte` passing; that test is the specification's own example.
- Any change to `jose.py` must keep the RFC 7515 and RFC 8032 vectors and the cross-backend interop test passing.
- Never commit a private key. `samples/jwks.json` is public; the key that signed `samples/good-card.json` was discarded on purpose. Re-sign the sample with a fresh key if the sample changes.
- New rules need a spec section, a requirement level, a positive and a negative test, and a README rule table refresh.
- Do not use em dashes in documentation.
