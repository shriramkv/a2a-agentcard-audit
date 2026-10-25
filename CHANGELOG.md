# Changelog

## 0.1.0 (2026-10-25)

First release, targeting A2A 1.0.

- 49 rules across structure, interfaces, security, signatures and discovery, each tied to an A2A 1.0 section and requirement level.
- Schema-driven structure validation and section 8.4.1 default-value pruning from `a2a.proto`.
- RFC 8785 canonicalization (byte-exact with the specification's example; fuzzed against the rfc8785 library) and JWS sign/verify for ES256, ES384, RS256/384/512 and EdDSA, with a pure-Python fallback cross-checked against pyca/cryptography.
- `audit`, `verify`, `sign`, `keygen`, `canonicalize`, `migrate`, `rules` and `demo` commands; well-known discovery and jku fetching.
- Documented upstream issues with reproductions in docs/upstream-notes.md.
