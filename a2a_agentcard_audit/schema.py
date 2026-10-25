"""The AgentCard message tree from a2a.proto (v1.0), in ProtoJSON (lowerCamelCase) form.

Each field is (kind, type):
  kind  R    required ([(google.api.field_behavior) = REQUIRED])
        O    proto3 `optional` scalar: has presence, kept when set even to the default
        P    plain scalar: no presence, omitted when equal to the default
        M    singular message: has presence
        REP  repeated
        MAP  map
  type  "string" | "bool" | "struct" | a message name
Messages whose name ends in "|oneof" hold exactly one of their fields.

This one table drives both structure validation and the default-value
pruning that A2A section 8.4.1 requires before JCS canonicalization.
"""

S, B = "string", "bool"

MESSAGES = {
    "AgentCard": {
        "name": ("R", S), "description": ("R", S),
        "supportedInterfaces": ("R", "REP:AgentInterface"),
        "provider": ("M", "AgentProvider"), "version": ("R", S),
        "documentationUrl": ("O", S), "capabilities": ("R", "AgentCapabilities"),
        "securitySchemes": ("MAP", "SecurityScheme"),
        "securityRequirements": ("REP", "SecurityRequirement"),
        "defaultInputModes": ("R", "REP:string"), "defaultOutputModes": ("R", "REP:string"),
        "skills": ("R", "REP:AgentSkill"), "signatures": ("REP", "AgentCardSignature"),
        "iconUrl": ("O", S),
    },
    "AgentInterface": {
        "url": ("R", S), "protocolBinding": ("R", S), "tenant": ("P", S), "protocolVersion": ("R", S),
    },
    "AgentProvider": {"url": ("R", S), "organization": ("R", S)},
    "AgentCapabilities": {
        "streaming": ("O", B), "pushNotifications": ("O", B),
        "extensions": ("REP", "AgentExtension"), "extendedAgentCard": ("O", B),
    },
    "AgentExtension": {
        "uri": ("P", S), "description": ("P", S), "required": ("P", B), "params": ("M", "struct"),
    },
    "AgentSkill": {
        "id": ("R", S), "name": ("R", S), "description": ("R", S), "tags": ("R", "REP:string"),
        "examples": ("REP", S), "inputModes": ("REP", S), "outputModes": ("REP", S),
        "securityRequirements": ("REP", "SecurityRequirement"),
    },
    "AgentCardSignature": {"protected": ("R", S), "signature": ("R", S), "header": ("M", "struct")},
    "SecurityRequirement": {"schemes": ("MAP", "StringList")},
    "StringList": {"list": ("REP", S)},
    "SecurityScheme|oneof": {
        "apiKeySecurityScheme": ("M", "APIKeySecurityScheme"),
        "httpAuthSecurityScheme": ("M", "HTTPAuthSecurityScheme"),
        "oauth2SecurityScheme": ("M", "OAuth2SecurityScheme"),
        "openIdConnectSecurityScheme": ("M", "OpenIdConnectSecurityScheme"),
        "mtlsSecurityScheme": ("M", "MutualTlsSecurityScheme"),
    },
    "APIKeySecurityScheme": {"description": ("P", S), "location": ("R", S), "name": ("R", S)},
    "HTTPAuthSecurityScheme": {"description": ("P", S), "scheme": ("R", S), "bearerFormat": ("P", S)},
    "OAuth2SecurityScheme": {"description": ("P", S), "flows": ("R", "OAuthFlows"), "oauth2MetadataUrl": ("P", S)},
    "OpenIdConnectSecurityScheme": {"description": ("P", S), "openIdConnectUrl": ("R", S)},
    "MutualTlsSecurityScheme": {"description": ("P", S)},
    "OAuthFlows|oneof": {
        "authorizationCode": ("M", "AuthorizationCodeOAuthFlow"),
        "clientCredentials": ("M", "ClientCredentialsOAuthFlow"),
        "implicit": ("M", "ImplicitOAuthFlow"),
        "password": ("M", "PasswordOAuthFlow"),
        "deviceCode": ("M", "DeviceCodeOAuthFlow"),
    },
    "AuthorizationCodeOAuthFlow": {
        "authorizationUrl": ("R", S), "tokenUrl": ("R", S), "refreshUrl": ("P", S),
        "scopes": ("R", "MAP:string"), "pkceRequired": ("P", B),
    },
    "ClientCredentialsOAuthFlow": {"tokenUrl": ("R", S), "refreshUrl": ("P", S), "scopes": ("R", "MAP:string")},
    "ImplicitOAuthFlow": {"authorizationUrl": ("P", S), "refreshUrl": ("P", S), "scopes": ("MAP", S)},
    "PasswordOAuthFlow": {"tokenUrl": ("P", S), "refreshUrl": ("P", S), "scopes": ("MAP", S)},
    "DeviceCodeOAuthFlow": {
        "deviceAuthorizationUrl": ("R", S), "tokenUrl": ("R", S), "refreshUrl": ("P", S),
        "scopes": ("R", "MAP:string"),
    },
}


def message(name):
    """Return (fields, is_oneof) for a message name."""
    if name in MESSAGES:
        return MESSAGES[name], False
    return MESSAGES[name + "|oneof"], True


def is_message(type_name):
    return type_name in MESSAGES or (type_name + "|oneof") in MESSAGES


def unwrap(kind, type_name):
    """Normalize a field spec to (kind, container, element_type).

    container is None, "REP" or "MAP".
    """
    if type_name.startswith("REP:"):
        return kind, "REP", type_name[4:]
    if type_name.startswith("MAP:"):
        return kind, "MAP", type_name[4:]
    if kind in ("REP", "MAP"):
        return kind, kind, type_name
    return kind, None, type_name


DEFAULTS = {S: "", B: False}


def prune(value, msg="AgentCard", top=True):
    """Remove default values per A2A 8.4.1 and drop `signatures` at the top level.

    Unknown fields are kept untouched: the signer may know about fields we do not.
    """
    if not isinstance(value, dict):
        return value
    fields, _ = message(msg)
    out = {}
    for key, v in value.items():
        if top and msg == "AgentCard" and key == "signatures":
            continue
        if key not in fields:
            out[key] = v
            continue
        kind, container, elem = unwrap(*fields[key])
        required = kind == "R"
        if container == "REP":
            if not isinstance(v, list):
                out[key] = v
                continue
            items = [prune(x, elem, False) if is_message(elem) else x for x in v]
            if items or required:
                out[key] = items
        elif container == "MAP":
            if not isinstance(v, dict):
                out[key] = v
                continue
            m = {k: (prune(x, elem, False) if is_message(elem) else x) for k, x in v.items()}
            if m or required:
                out[key] = m
        elif is_message(elem):
            out[key] = prune(v, elem, False)
        elif elem == "struct":
            out[key] = v
        elif kind == "P":
            if v != DEFAULTS.get(elem):
                out[key] = v
        else:  # R and O scalars are always kept when present
            out[key] = v
    return out
