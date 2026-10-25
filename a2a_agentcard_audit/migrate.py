"""Convert a v0.3 Agent Card to the v1.0 structure.

Changes follow the v1.0 release notes ("What's new in A2A Protocol v1.0"):
url / preferredTransport / additionalInterfaces / protocolVersion become
supportedInterfaces, supportsAuthenticatedExtendedCard moves to
capabilities.extendedAgentCard, OpenAPI-style security schemes become the
wrapped oneof form, and security becomes securityRequirements.

The card's format is not the server's protocol. Each interface keeps the
protocol version the v0.3 card declared unless you pass target_version,
because claiming "1.0" for a server that still speaks 0.3 breaks clients.
"""

import copy
import re

FLOW_PREFERENCE = ("authorizationCode", "deviceCode", "clientCredentials", "implicit", "password")
SCHEME_KEYS = {
    "apiKey": "apiKeySecurityScheme", "http": "httpAuthSecurityScheme", "oauth2": "oauth2SecurityScheme",
    "openIdConnect": "openIdConnectSecurityScheme", "mutualTLS": "mtlsSecurityScheme",
}


def _major_minor(v):
    m = re.match(r"^\D*(\d+)\.(\d+)", str(v or ""))
    return "%s.%s" % m.groups() if m else "0.3"


def _convert_scheme(name, s, notes):
    """Return a list of (new_name, v1_scheme). OAuth with several flows splits into one scheme per flow."""
    t = s.get("type")
    desc = {"description": s["description"]} if s.get("description") else {}
    if t == "apiKey":
        return [(name, {"apiKeySecurityScheme": dict(desc, location=s.get("in"), name=s.get("name"))})]
    if t == "http":
        body = dict(desc, scheme=s.get("scheme"))
        if s.get("bearerFormat"):
            body["bearerFormat"] = s["bearerFormat"]
        return [(name, {"httpAuthSecurityScheme": body})]
    if t == "openIdConnect":
        return [(name, {"openIdConnectSecurityScheme": dict(desc, openIdConnectUrl=s.get("openIdConnectUrl"))})]
    if t == "mutualTLS":
        return [(name, {"mtlsSecurityScheme": desc})]
    if t == "oauth2":
        flows = s.get("flows") or {}
        present = [f for f in FLOW_PREFERENCE if f in flows] + [f for f in flows if f not in FLOW_PREFERENCE]
        out = []
        for f in present:
            body = dict(desc, flows={f: copy.deepcopy(flows[f])})
            if s.get("oauth2MetadataUrl"):
                body["oauth2MetadataUrl"] = s["oauth2MetadataUrl"]
            new_name = name if len(present) == 1 else "%s-%s" % (name, f)
            out.append((new_name, {"oauth2SecurityScheme": body}))
            if f in ("implicit", "password"):
                notes.append("%s: the %s flow is deprecated in v1.0; replace it with authorizationCode "
                             "(pkceRequired: true) or deviceCode" % (new_name, f))
        if len(present) > 1:
            notes.append("%s declared %d OAuth flows; v1.0 allows one per scheme, so it became %s "
                         "(requirements now offer them as alternatives)"
                         % (name, len(present), ", ".join(n for n, _ in out)))
        return out
    notes.append("%s: unknown v0.3 scheme type %r was copied unchanged" % (name, t))
    return [(name, s)]


def _convert_requirements(reqs, renames):
    """v0.3 [{name: [scopes]}] -> v1.0 [{"schemes": {name: {"list": [...]}}}].

    A requirement naming a split OAuth scheme expands into one alternative per flow.
    """
    out = []
    for req in reqs or []:
        if not isinstance(req, dict):
            continue
        alternatives = [{}]
        for name, scopes in req.items():
            targets = renames.get(name, [name])
            expanded = []
            for alt in alternatives:
                for t in targets:
                    a = dict(alt)
                    a[t] = {"list": list(scopes)} if scopes else {}
                    expanded.append(a)
            alternatives = expanded
        out.extend({"schemes": a} for a in alternatives)
    return out


def is_v03(card):
    return isinstance(card, dict) and ("url" in card or "preferredTransport" in card or
                                       "supportsAuthenticatedExtendedCard" in card or
                                       any(isinstance(s, dict) and "type" in s
                                           for s in (card.get("securitySchemes") or {}).values()))


def migrate(card, target_version=None):
    """Return (v1_card, notes)."""
    notes = []
    old = copy.deepcopy(card)
    version = target_version or _major_minor(old.get("protocolVersion"))
    if not target_version:
        notes.append("interfaces keep protocolVersion %r from the v0.3 card; pass --target-version 1.0 once "
                     "the server implements A2A 1.0" % version)
    ifaces, seen = [], set()

    def add(url, binding):
        key = (url, binding)
        if url and key not in seen:
            seen.add(key)
            ifaces.append({"url": url, "protocolBinding": binding, "protocolVersion": version})

    add(old.get("url"), old.get("preferredTransport") or "JSONRPC")
    for it in old.get("additionalInterfaces") or []:
        if isinstance(it, dict):
            add(it.get("url"), it.get("transport") or it.get("protocolBinding") or "JSONRPC")

    new = {}
    for key in ("name", "description"):
        if key in old:
            new[key] = old[key]
    new["supportedInterfaces"] = ifaces
    for key in ("provider", "version", "documentationUrl"):
        if key in old:
            new[key] = old[key]

    caps = dict(old.get("capabilities") or {})
    if caps.pop("stateTransitionHistory", None) is not None:
        notes.append("capabilities.stateTransitionHistory was removed in v1.0 and was dropped")
    if old.get("supportsAuthenticatedExtendedCard") is not None:
        caps["extendedAgentCard"] = bool(old["supportsAuthenticatedExtendedCard"])
    new["capabilities"] = caps

    renames, schemes = {}, {}
    for name, s in (old.get("securitySchemes") or {}).items():
        if isinstance(s, dict) and "type" in s:
            converted = _convert_scheme(name, s, notes)
            renames[name] = [n for n, _ in converted]
            schemes.update(converted)
        else:
            schemes[name] = s
    if schemes:
        new["securitySchemes"] = schemes
    reqs = _convert_requirements(old.get("security"), renames) if "security" in old else \
        old.get("securityRequirements")
    if reqs:
        new["securityRequirements"] = reqs

    for key in ("defaultInputModes", "defaultOutputModes"):
        if key in old:
            new[key] = old[key]
    skills = []
    for sk in old.get("skills") or []:
        sk = dict(sk)
        if "security" in sk:
            sk["securityRequirements"] = _convert_requirements(sk.pop("security"), renames)
        skills.append(sk)
    new["skills"] = skills
    if "iconUrl" in old:
        new["iconUrl"] = old["iconUrl"]
    if old.get("signatures"):
        notes.append("signatures were dropped because the content changed; sign the new card again")
    known = {"name", "description", "url", "preferredTransport", "additionalInterfaces", "protocolVersion",
             "provider", "version", "documentationUrl", "capabilities", "supportsAuthenticatedExtendedCard",
             "securitySchemes", "security", "securityRequirements", "defaultInputModes", "defaultOutputModes",
             "skills", "iconUrl", "signatures", "supportedInterfaces"}
    for key in old:
        if key not in known:
            new[key] = old[key]
            notes.append("unknown field %r was copied unchanged" % key)
    return new, notes
