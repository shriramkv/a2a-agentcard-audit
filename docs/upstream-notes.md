# Upstream notes

Issues found in the A2A specification and reference code while building this tool. Each was
checked against these commits; confirm on the latest version before filing.

| Repository | Commit |
|---|---|
| a2aproject/A2A | `98279d6` (2026-10-20), spec 1.0.1 |
| a2aproject/a2a-python | `e12d494` (2026-10-24) |
| a2aproject/a2a-tck | `d4d6fae` (2026-10-22) |

## 1. a2a-python: v0.3 to v1.0 card conversion drops OAuth flows

**File:** `src/a2a/compat/v0_3/conversions.py`, `to_core_oauth_flows` (lines 475, 484, 493, 502).

In v1.0, `OAuthFlows` is a protobuf `oneof`. The converter copies each v0.3 flow into the same
message in turn, and every `CopyFrom` on a oneof member clears the member set before it. A v0.3
scheme that declares several flows therefore keeps only the last one, without a warning.

**Reproduce**

```python
from google.protobuf.json_format import MessageToDict
from a2a.compat.v0_3 import types as t03
from a2a.compat.v0_3.conversions import to_core_agent_card

v03 = {
  "protocolVersion": "0.3.0", "name": "Weather", "description": "d", "version": "1",
  "url": "https://weather.example.org/a2a", "capabilities": {},
  "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"], "skills": [],
  "securitySchemes": {"oauth": {"type": "oauth2", "flows": {
    "authorizationCode": {"authorizationUrl": "https://auth.example.org/authorize",
                          "tokenUrl": "https://auth.example.org/token", "scopes": {"r": "read"}},
    "clientCredentials": {"tokenUrl": "https://auth.example.org/token", "scopes": {"r": "read"}}}}},
}
print(MessageToDict(to_core_agent_card(t03.AgentCard.model_validate(v03)))["securitySchemes"])
# {'oauth': {'oauth2SecurityScheme': {'flows': {'clientCredentials': {...}}}}}
# authorizationCode, the interactive flow, is gone.
```

**Suggested fix:** emit one v1.0 scheme per flow (for example `oauth-authorizationCode`,
`oauth-clientCredentials`) and expand each security requirement that names the original scheme
into one alternative per flow. That keeps the meaning, because a list of security requirements
is a list of alternatives. `a2a-agentcard-audit migrate` does this.

Two smaller issues in the same function family:

- `to_core_agent_card` adds the primary `url` as an interface and then appends every
  `additionalInterfaces` entry, so the common v0.3 pattern of listing the primary URL again
  produces a duplicate interface.
- The primary interface copies `protocolVersion` verbatim (`"0.3.0"`), while the additional
  interfaces use `"0.3"`. The proto comment asks for MAJOR.MINOR.

## 2. Specification text still uses the v0.3 field name `security`

**File:** `docs/specification.md`, lines 423 (section 3.1.11) and 3172 (section 13.3).

Both say clients authenticate "using one of the schemes declared in the public
`AgentCard.securitySchemes` and `AgentCard.security` fields". In v1.0 the field is
`securityRequirements`; `security` no longer exists.

**Suggested fix:** replace `AgentCard.security` with `AgentCard.securityRequirements` in both places.

## 3. "What's new in v1.0" examples use non-existent field names

**File:** `docs/whats-new-v1.md`.

- Lines 527 and 535, OAuth migration example: the keys `implicitFlow` and `authorizationCodeFlow`
  do not exist. The proto fields are `implicit` and `authorization_code`, which ProtoJSON writes as
  `implicit` and `authorizationCode`, nested under `oauth2SecurityScheme.flows`.
- Line 849, extension example: `agentCard.extensions` should be `agentCard.capabilities.extensions`.

A developer copying either example produces a card that a strict parser rejects.

## 4. TCK: card-signing requirements are marked NOT_AUTOMATABLE

**File:** `tck/requirements/agent_card.py`.

Five agent-card requirements, including JCS canonicalization (CARD-SIGN-001), exclusion of the
`signatures` field (CARD-SIGN-002) and the protected-header parameters (CARD-SIGN-003), are tagged
`NOT_AUTOMATABLE`. They can be automated for any card that ships a signature and a reachable key
set, which is what `a2a-agentcard-audit audit --fetch-jku` does. Offering this as a TCK check (or
linking to an external checker) would let implementers catch signing bugs before release.
