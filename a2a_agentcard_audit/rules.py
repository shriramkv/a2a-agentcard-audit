"""Rule registry. Each rule cites the A2A v1.0 section it enforces and its requirement level."""

from collections import namedtuple

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
PENALTY = {"critical": 40, "high": 20, "medium": 8, "low": 3}
CRITICAL_CAP = 69

Rule = namedtuple("Rule", "id slug severity category level section summary fix")

_RULES = [
    # ---- structure ----
    Rule("AC001", "not-a-card", "critical", "structure", "MUST", "4.4.1",
         "Document is not a JSON object", "Serve the Agent Card as a single JSON object"),
    Rule("AC002", "missing-required-field", "high", "structure", "REQUIRED", "4.4",
         "A REQUIRED field is missing", "Add the field; see a2a.proto for the message"),
    Rule("AC003", "wrong-type", "high", "structure", "schema", "4.4",
         "A field has the wrong JSON type", "Use the type a2a.proto declares"),
    Rule("AC004", "empty-list", "medium", "structure", "schema", "4.4.1",
         "supportedInterfaces, skills or the default modes list is empty", "Declare at least one entry"),
    Rule("AC005", "snake-case-field", "high", "structure", "MUST", "5.5",
         "Field uses the proto name (snake_case) instead of its ProtoJSON camelCase name",
         "Rename, for example supported_interfaces to supportedInterfaces"),
    Rule("AC006", "unknown-field", "low", "structure", "schema", "4.4",
         "Field is not defined in a2a.proto", "Remove it or move it into an extension's params"),
    Rule("AC007", "legacy-v03-card", "high", "structure", "MUST", "What's new in v1.0",
         "Card uses v0.3 fields (url, preferredTransport, security, ...)",
         "Run `a2a-agentcard-audit migrate` to produce a v1.0 card"),
    Rule("AC008", "invalid-media-type", "medium", "structure", "schema", "4.4.1",
         "Input or output mode is not a type/subtype media type", "Use media types such as text/plain"),
    Rule("AC009", "duplicate-skill-id", "high", "structure", "schema", "4.4.5",
         "Two skills share the same id", "Give every skill a unique id"),
    Rule("AC010", "oneof-violation", "high", "structure", "schema", "4.5.1",
         "SecurityScheme or OAuthFlows sets zero or several of its oneof fields",
         "Set exactly one; declare a separate scheme per OAuth flow"),
    # ---- interfaces ----
    Rule("AC101", "unknown-protocol-binding", "low", "interfaces", "open set", "4.4.6",
         "protocolBinding is not JSONRPC, GRPC or HTTP+JSON", "Use a core binding unless you ship a custom one"),
    Rule("AC102", "protocol-version-format", "medium", "interfaces", "schema", "3.6",
         "protocolVersion is not MAJOR.MINOR (for example 1.0)", "Use the latest minor per major, e.g. \"1.0\""),
    Rule("AC103", "insecure-interface-url", "high", "interfaces", "MUST", "7.1",
         "HTTP interface URL is not https:// in production", "Serve the interface over HTTPS"),
    Rule("AC104", "invalid-interface-url", "high", "interfaces", "MUST", "8.3.1",
         "Interface URL is not an absolute URL (or host:port for gRPC)", "Use a full URL such as https://host/a2a/v1"),
    Rule("AC105", "internal-url-exposed", "medium", "interfaces", "SHOULD NOT", "13.3",
         "Public card exposes a localhost, private-network or internal hostname", "Publish only externally reachable URLs"),
    Rule("AC106", "duplicate-interface", "low", "interfaces", "SHOULD", "8.3.1",
         "The same url and protocolBinding appear twice", "List each combination once, in preference order"),
    Rule("AC107", "no-v1-interface", "medium", "interfaces", "SHOULD", "3.6",
         "No interface declares protocolVersion 1.x", "Expose at least one interface on protocol 1.0"),
    # ---- security ----
    Rule("AC201", "no-security-schemes", "medium", "security", "SHOULD", "7.3",
         "Card declares no securitySchemes", "Declare how clients authenticate, or document that the agent is public"),
    Rule("AC202", "undefined-scheme-reference", "high", "security", "MUST", "4.5",
         "securityRequirements names a scheme missing from securitySchemes", "Define the scheme or fix the name"),
    Rule("AC203", "invalid-security-scheme", "high", "security", "schema", "4.5",
         "Security scheme is malformed (bad location, missing flow fields, v0.3 'type' form)",
         "Follow the v1.0 wrapper form, e.g. {\"apiKeySecurityScheme\": {...}}"),
    Rule("AC204", "deprecated-oauth-flow", "high", "security", "deprecated", "4.5.7",
         "OAuth implicit or password flow (removed by OAuth BCP)", "Use authorizationCode with pkceRequired, or deviceCode"),
    Rule("AC205", "pkce-not-required", "medium", "security", "RECOMMENDED", "4.5.8",
         "Authorization code flow does not set pkceRequired: true", "Set pkceRequired: true"),
    Rule("AC206", "insecure-auth-url", "high", "security", "MUST", "4.5.4",
         "OAuth or OpenID Connect URL is not https://", "Serve authorization servers over TLS"),
    Rule("AC207", "undefined-scope", "medium", "security", "schema", "4.5.8",
         "A requirement asks for an OAuth scope the flow does not define", "Add the scope to the flow or fix the name"),
    Rule("AC208", "api-key-in-query", "medium", "security", "SHOULD", "13.4",
         "API key travels in the query string, where logs and proxies record it", "Send API keys in a header"),
    Rule("AC209", "basic-auth", "low", "security", "SHOULD", "13.4",
         "HTTP Basic authentication sends a reusable password with every request", "Prefer bearer tokens or OAuth"),
    Rule("AC210", "extended-card-without-auth", "high", "security", "MUST", "13.3",
         "extendedAgentCard is true but no authentication is declared", "Declare securitySchemes and securityRequirements"),
    Rule("AC211", "secret-in-card", "critical", "security", "MUST", "13.4",
         "Card text contains what looks like a credential", "Remove it and rotate the credential"),
    Rule("AC212", "prompt-injection", "high", "security", "SHOULD", "13.4",
         "Card text tries to instruct the reading agent (cards are fed to orchestrator models)",
         "Describe the agent; do not address instructions to other agents"),
    Rule("AC213", "hidden-content", "medium", "security", "SHOULD", "13.4",
         "Card text contains invisible or bidirectional control characters", "Remove them"),
    Rule("AC214", "extension-invalid", "medium", "security", "schema", "4.6.1",
         "Extension has no absolute uri, or is required but undocumented", "Give each extension a URI and description"),
    Rule("AC215", "insecure-metadata-url", "medium", "security", "SHOULD", "13.4",
         "provider, documentation or icon URL is not https://", "Use https:// URLs"),
    # ---- signatures ----
    Rule("AC301", "unsigned-card", "low", "signatures", "MAY / SHOULD", "8.4",
         "Card carries no signature, so clients cannot verify who published it", "Sign it: `a2a-agentcard-audit sign`"),
    Rule("AC302", "signature-malformed", "high", "signatures", "REQUIRED", "4.4.7",
         "Signature lacks protected or signature, or they are not base64url", "Regenerate the signature"),
    Rule("AC303", "header-missing-param", "high", "signatures", "MUST", "8.4.2",
         "Protected header lacks alg or kid", "Include alg and kid in the protected header"),
    Rule("AC304", "typ-not-jose", "low", "signatures", "SHOULD", "8.4.2",
         "Protected header typ is not JOSE", "Set typ to JOSE"),
    Rule("AC305", "unsafe-alg", "critical", "signatures", "MUST", "8.4.2",
         "alg is none or a symmetric HMAC algorithm", "Use ES256, RS256 or EdDSA"),
    Rule("AC306", "insecure-jku", "high", "signatures", "SHOULD", "8.4.3",
         "jku is not an https:// URL", "Publish the JWKS over HTTPS"),
    Rule("AC307", "signature-invalid", "critical", "signatures", "MUST", "8.4.3",
         "Signature does not verify against the canonicalized card", "Re-sign after the last edit, or fix canonicalization"),
    Rule("AC308", "key-not-found", "medium", "signatures", "MUST", "8.4.3",
         "No key in the JWKS matches the signature's kid", "Publish the key or fix the kid"),
    Rule("AC309", "weak-key", "medium", "signatures", "SHOULD", "8.4.3",
         "RSA key shorter than 2048 bits, or the key is unusable for alg", "Use RSA 2048+ or an EC/Ed25519 key"),
    Rule("AC310", "unsupported-alg", "low", "signatures", "info", "8.4.2",
         "Signature algorithm is not one this tool can verify", "Verify it with another JOSE library"),
    # ---- discovery ----
    Rule("AC401", "fetch-failed", "critical", "discovery", "MUST", "8.1",
         "Agent Card could not be fetched", "Serve it at /.well-known/agent-card.json"),
    Rule("AC402", "card-content-type", "medium", "discovery", "SHOULD", "14.1",
         "Card is not served as application/json or application/a2a+json", "Set the Content-Type header"),
    Rule("AC403", "no-cache-control", "low", "discovery", "SHOULD", "8.6.1",
         "No Cache-Control max-age on the card", "Add Cache-Control: max-age=..."),
    Rule("AC404", "no-etag", "low", "discovery", "SHOULD", "8.6.1",
         "No ETag on the card", "Derive an ETag from version or a content hash"),
    Rule("AC405", "card-not-https", "high", "discovery", "MUST", "7.1",
         "Card served over plain http://", "Serve the well-known card over HTTPS"),
    Rule("AC406", "no-hsts", "low", "discovery", "SHOULD", "13.4",
         "No Strict-Transport-Security header", "Enable HSTS"),
    Rule("AC407", "jwks-fetch-failed", "medium", "discovery", "SHOULD", "8.4.3",
         "jku could not be fetched or is not a JWKS", "Serve a JSON Web Key Set at the jku URL"),
]

RULES = {r.id: r for r in _RULES}
SLUGS = {r.slug: r.id for r in _RULES}


class Finding(object):
    __slots__ = ("rule_id", "message", "path")

    def __init__(self, rule_id, message, path=None):
        if rule_id not in RULES:
            raise KeyError(rule_id)
        self.rule_id, self.message, self.path = rule_id, message, path

    @property
    def rule(self):
        return RULES[self.rule_id]

    @property
    def severity(self):
        return RULES[self.rule_id].severity

    def to_dict(self):
        r = self.rule
        return {"rule": r.id, "slug": r.slug, "severity": r.severity, "category": r.category,
                "level": r.level, "section": r.section, "message": self.message, "path": self.path,
                "fix": r.fix}

    def __repr__(self):
        return "Finding(%s, %r, %r)" % (self.rule_id, self.message, self.path)


def resolve_rule(token):
    t = token.strip()
    if t.upper() in RULES:
        return t.upper()
    if t.lower() in SLUGS:
        return SLUGS[t.lower()]
    raise KeyError(token)


def score(findings):
    total = sum(PENALTY[f.severity] for f in findings)
    s = max(0, 100 - total)
    if any(f.severity == "critical" for f in findings):
        s = min(s, CRITICAL_CAP)
    return s


def grade_for(s):
    return "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 70 else "D" if s >= 60 else "F"


GRADE_ORDER = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
