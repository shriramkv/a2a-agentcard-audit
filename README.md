# a2a-agentcard-audit

Lint, security-audit, **sign and verify** [A2A](https://a2a-protocol.org) Agent Cards against
the v1.0 specification. A2A is a project of the
[Agentic AI Foundation (AAIF)](https://aaif.io/projects).

[![CI](https://github.com/shriramkv/a2a-agentcard-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/shriramkv/a2a-agentcard-audit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![A2A](https://img.shields.io/badge/A2A-1.0-informational)
![License](https://img.shields.io/badge/license-MIT-green)

An Agent Card is how an A2A agent introduces itself: name, skills, endpoints, how to
authenticate, and since v1.0 an optional JWS signature proving who published it. Orchestrators
fetch these cards from `/.well-known/agent-card.json`, decide which agent to trust with a task,
and often paste the card's text straight into a model's context. That makes a card three things
at once: a schema document, a security declaration, and untrusted input to an LLM.

```text
$ a2a-agentcard-audit demo -q
a2a-agentcard-audit 0.1.0 | A2A 1.0 | 3 card(s)

ok   Invoice Reconciliation Agent  A (100)  signature: verified  samples/good-card.json
FAIL Helpful Router  F (0)  signature: invalid  samples/risky-card.json
FAIL Weather Agent  F (17)  signature: unsigned  samples/v03-card.json
Findings: 2 critical, 14 high, 6 medium, 4 low
Overall: F (0) worst-of
```

## What it does that existing tools do not

| | A2A Inspector | A2A TCK | a2a-agentcard-audit |
|---|---|---|---|
| Required fields and types | basic | yes | yes, from `a2a.proto` |
| ProtoJSON naming, oneofs, unknown fields | | partly | yes |
| Security scheme checks (deprecated OAuth flows, PKCE, HTTPS, undefined schemes and scopes, extended card without auth) | | | yes |
| Text aimed at the reading agent (prompt injection), hidden characters, leaked secrets and private keys | | | yes |
| JCS canonicalization (RFC 8785) | | marked NOT_AUTOMATABLE | yes, byte-exact with the spec's example |
| JWS signature verification (ES256, ES384, RS256/384/512, EdDSA) | | marked NOT_AUTOMATABLE | yes, with `--jwks` or `--fetch-jku` |
| Sign cards and generate keys | | | yes |
| Discovery headers (Content-Type, Cache-Control, ETag, HSTS) | | yes | yes |
| v0.3 to v1.0 migration | | | yes |
| Runs offline on a file, zero dependencies | | | yes |

Run the TCK to test your server's protocol behaviour. Run this to check the card you publish.

## Install

```bash
pip install git+https://github.com/shriramkv/a2a-agentcard-audit
pip install "a2a-agentcard-audit[crypto] @ git+https://github.com/shriramkv/a2a-agentcard-audit"   # optional, see below
```

No runtime dependencies. Signature verification and signing use
[pyca/cryptography](https://cryptography.io) when it is installed and a pure-Python
implementation otherwise. The pure-Python path is correct (tested against RFC 7515 and RFC 8032
vectors and against cryptography in both directions) but it is not constant-time. Use it freely
for verification and CI; install cryptography before signing with a production key.

## Audit

```bash
a2a-agentcard-audit audit agent.example.com              # fetches /.well-known/agent-card.json
a2a-agentcard-audit audit https://agent.example.com/custom/card.json --fetch-jku
a2a-agentcard-audit audit card.json --jwks jwks.json      # offline, with a local key set
a2a-agentcard-audit audit cards/*.json --format markdown -o report.md
a2a-agentcard-audit audit card.json --min-grade B --fail-on high   # CI gates, exit 1 on failure
```

`--allow-local` accepts localhost and private hosts for development. `--disable AC105,unsigned-card`
skips rules. Exit codes: `0` passed, `1` a gate failed, `2` usage error.

## Sign and verify

```bash
a2a-agentcard-audit keygen --kid agent-2026-10 --out-dir keys/     # ES256 by default; also ES384, EdDSA
a2a-agentcard-audit sign card.json --key keys/agent-2026-10.private.jwk.json \
    --jku https://agent.example.com/.well-known/jwks.json -o card.signed.json
a2a-agentcard-audit verify card.signed.json --jwks keys/jwks.json  # exit 0 only when verified
a2a-agentcard-audit canonicalize card.json                          # print the exact bytes that are signed
```

Signing follows section 8.4: remove default values according to protobuf field presence, drop
`signatures`, canonicalize with RFC 8785, and sign `BASE64URL(header).BASE64URL(payload)` with
`alg`, `typ: "JOSE"` and `kid` in the protected header. The pruning is driven by a table taken
from `a2a.proto`, so REQUIRED fields stay even when empty and `optional` fields stay when set.

## Migrate a v0.3 card

```bash
a2a-agentcard-audit migrate old-card.json -o card.json
a2a-agentcard-audit migrate old-card.json --target-version 1.0 -o card.json
```

This moves `url`, `preferredTransport` and `additionalInterfaces` into `supportedInterfaces`,
`supportsAuthenticatedExtendedCard` into `capabilities.extendedAgentCard`, rewrites OpenAPI-style
security schemes into the v1.0 wrapped form, and turns `security` into `securityRequirements`.

Two decisions are deliberate:

- Interfaces keep the protocol version the old card declared unless you pass `--target-version`.
  The card format is not the server's protocol, and announcing 1.0 for a 0.3 server breaks clients.
- A v0.3 OAuth scheme with several flows becomes one scheme per flow, and each requirement that
  named it becomes one alternative per flow. v1.0's `OAuthFlows` is a oneof, so packing the flows
  into one scheme would silently keep only one of them.

## Grading

Each card starts at 100: critical findings cost 40, high 20, medium 8, low 3. Any critical
finding caps the card at 69 (grade D). Grades: A 90+, B 80+, C 70+, D 60+, F below 60. With
several cards, the overall grade is the worst one.

## Rules

Each rule cites the A2A 1.0 section it enforces and the requirement level used there.

| Rule | Slug | Severity | Level | Spec | Checks |
|---|---|---|---|---|---|
| AC001 | `not-a-card` | critical | MUST | 4.4.1 | Document is not a JSON object |
| AC002 | `missing-required-field` | high | REQUIRED | 4.4 | A REQUIRED field is missing |
| AC003 | `wrong-type` | high | schema | 4.4 | A field has the wrong JSON type |
| AC004 | `empty-list` | medium | schema | 4.4.1 | supportedInterfaces, skills or the default modes list is empty |
| AC005 | `snake-case-field` | high | MUST | 5.5 | Field uses the proto name (snake_case) instead of its ProtoJSON camelCase name |
| AC006 | `unknown-field` | low | schema | 4.4 | Field is not defined in a2a.proto |
| AC007 | `legacy-v03-card` | high | MUST | What's new in v1.0 | Card uses v0.3 fields (url, preferredTransport, security, ...) |
| AC008 | `invalid-media-type` | medium | schema | 4.4.1 | Input or output mode is not a type/subtype media type |
| AC009 | `duplicate-skill-id` | high | schema | 4.4.5 | Two skills share the same id |
| AC010 | `oneof-violation` | high | schema | 4.5.1 | SecurityScheme or OAuthFlows sets zero or several of its oneof fields |
| AC101 | `unknown-protocol-binding` | low | open set | 4.4.6 | protocolBinding is not JSONRPC, GRPC or HTTP+JSON |
| AC102 | `protocol-version-format` | medium | schema | 3.6 | protocolVersion is not MAJOR.MINOR (for example 1.0) |
| AC103 | `insecure-interface-url` | high | MUST | 7.1 | HTTP interface URL is not https:// in production |
| AC104 | `invalid-interface-url` | high | MUST | 8.3.1 | Interface URL is not an absolute URL (or host:port for gRPC) |
| AC105 | `internal-url-exposed` | medium | SHOULD NOT | 13.3 | Public card exposes a localhost, private-network or internal hostname |
| AC106 | `duplicate-interface` | low | SHOULD | 8.3.1 | The same url and protocolBinding appear twice |
| AC107 | `no-v1-interface` | medium | SHOULD | 3.6 | No interface declares protocolVersion 1.x |
| AC201 | `no-security-schemes` | medium | SHOULD | 7.3 | Card declares no securitySchemes |
| AC202 | `undefined-scheme-reference` | high | MUST | 4.5 | securityRequirements names a scheme missing from securitySchemes |
| AC203 | `invalid-security-scheme` | high | schema | 4.5 | Security scheme is malformed (bad location, missing flow fields, v0.3 'type' form) |
| AC204 | `deprecated-oauth-flow` | high | deprecated | 4.5.7 | OAuth implicit or password flow (removed by OAuth BCP) |
| AC205 | `pkce-not-required` | medium | RECOMMENDED | 4.5.8 | Authorization code flow does not set pkceRequired: true |
| AC206 | `insecure-auth-url` | high | MUST | 4.5.4 | OAuth or OpenID Connect URL is not https:// |
| AC207 | `undefined-scope` | medium | schema | 4.5.8 | A requirement asks for an OAuth scope the flow does not define |
| AC208 | `api-key-in-query` | medium | SHOULD | 13.4 | API key travels in the query string, where logs and proxies record it |
| AC209 | `basic-auth` | low | SHOULD | 13.4 | HTTP Basic authentication sends a reusable password with every request |
| AC210 | `extended-card-without-auth` | high | MUST | 13.3 | extendedAgentCard is true but no authentication is declared |
| AC211 | `secret-in-card` | critical | MUST | 13.4 | Card text contains what looks like a credential |
| AC212 | `prompt-injection` | high | SHOULD | 13.4 | Card text tries to instruct the reading agent (cards are fed to orchestrator models) |
| AC213 | `hidden-content` | medium | SHOULD | 13.4 | Card text contains invisible or bidirectional control characters |
| AC214 | `extension-invalid` | medium | schema | 4.6.1 | Extension has no absolute uri, or is required but undocumented |
| AC215 | `insecure-metadata-url` | medium | SHOULD | 13.4 | provider, documentation or icon URL is not https:// |
| AC301 | `unsigned-card` | low | MAY / SHOULD | 8.4 | Card carries no signature, so clients cannot verify who published it |
| AC302 | `signature-malformed` | high | REQUIRED | 4.4.7 | Signature lacks protected or signature, or they are not base64url |
| AC303 | `header-missing-param` | high | MUST | 8.4.2 | Protected header lacks alg or kid |
| AC304 | `typ-not-jose` | low | SHOULD | 8.4.2 | Protected header typ is not JOSE |
| AC305 | `unsafe-alg` | critical | MUST | 8.4.2 | alg is none or a symmetric HMAC algorithm |
| AC306 | `insecure-jku` | high | SHOULD | 8.4.3 | jku is not an https:// URL |
| AC307 | `signature-invalid` | critical | MUST | 8.4.3 | Signature does not verify against the canonicalized card |
| AC308 | `key-not-found` | medium | MUST | 8.4.3 | No key in the JWKS matches the signature's kid |
| AC309 | `weak-key` | medium | SHOULD | 8.4.3 | RSA key shorter than 2048 bits, or the key is unusable for alg |
| AC310 | `unsupported-alg` | low | info | 8.4.2 | Signature algorithm is not one this tool can verify |
| AC401 | `fetch-failed` | critical | MUST | 8.1 | Agent Card could not be fetched |
| AC402 | `card-content-type` | medium | SHOULD | 14.1 | Card is not served as application/json or application/a2a+json |
| AC403 | `no-cache-control` | low | SHOULD | 8.6.1 | No Cache-Control max-age on the card |
| AC404 | `no-etag` | low | SHOULD | 8.6.1 | No ETag on the card |
| AC405 | `card-not-https` | high | MUST | 7.1 | Card served over plain http:// |
| AC406 | `no-hsts` | low | SHOULD | 13.4 | No Strict-Transport-Security header |
| AC407 | `jwks-fetch-failed` | medium | SHOULD | 8.4.3 | jku could not be fetched or is not a JWKS |

## Upstream contributions

Building this surfaced issues in the specification and reference code: a v0.3 conversion that
drops OAuth flows, v0.3 field names left in the specification text, and migration examples with
field names that do not exist. Each comes with a reproduction and a suggested fix in
[docs/upstream-notes.md](docs/upstream-notes.md).

## Part of an AAIF toolchain

This tool sits alongside the author's other open source checkers for AAIF projects, including
[`open-responses-conformance`](https://github.com/shriramkv/open-responses-conformance),
[`agent-skills-lint`](https://github.com/shriramkv/agent-skills-lint),
[`mcp-scorecard`](https://github.com/shriramkv/mcp-scorecard) and
[`agentgateway-lint`](https://github.com/shriramkv/agentgateway-lint). The full index is in
[`aaif-agentic-toolkit`](https://github.com/shriramkv/aaif-agentic-toolkit).

## Development

```bash
python -m unittest discover -s tests -t .
A2A_AUDIT_PURE_PYTHON=1 python -m unittest discover -s tests -t .   # force the pure-Python crypto
pip install cryptography rfc8785 "a2a-sdk[signing]"                  # enables the cross-checks and SDK interop tests
python scripts/build_readme.py
```

## License

MIT. Copyright (c) 2026 Dr. Shriram K Vasudevan.
