"""Static checks on an Agent Card document: structure, interfaces, security, text."""

import ipaddress
import re

try:
    from urllib.parse import urlparse
except ImportError:  # pragma: no cover
    from urlparse import urlparse  # type: ignore

from .rules import Finding
from .schema import message, unwrap

LEGACY_TOP = ("url", "preferredTransport", "additionalInterfaces", "protocolVersion", "security",
              "supportsAuthenticatedExtendedCard")
CORE_BINDINGS = ("JSONRPC", "GRPC", "HTTP+JSON")
MEDIA_RE = re.compile(r"^[\w.+*-]+/[\w.+*-]+(\s*;.*)?$")
VERSION_RE = re.compile(r"^\d+\.\d+$")
INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home", ".localdomain", ".intranet")


def camel(name):
    head, *rest = name.split("_")
    return head + "".join(p[:1].upper() + p[1:] for p in rest)


def _type_ok(v, t):
    return {"string": isinstance(v, str), "bool": isinstance(v, bool), "struct": isinstance(v, dict)}.get(t, True)


def host_of(url):
    try:
        p = urlparse(url if "://" in url else "//" + url)
        return (p.hostname or "").lower()
    except ValueError:
        return ""


def is_internal_host(host):
    if not host:
        return False
    if host in ("localhost",) or host.endswith(".localhost") or host.endswith(INTERNAL_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified
    except ValueError:
        return False


def is_local_dev_host(host):
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ----------------------------------------------------------------------
# structure
# ----------------------------------------------------------------------


def check_structure(card):
    out = []
    if not isinstance(card, dict):
        return [Finding("AC001", "top level is %s, not an object" % type(card).__name__)]
    legacy = [k for k in LEGACY_TOP if k in card]
    if legacy:
        out.append(Finding("AC007", "v0.3 field(s) present: %s" % ", ".join(legacy)))
    _walk(card, "AgentCard", "", out, legacy=set(legacy))
    for key in ("supportedInterfaces", "skills", "defaultInputModes", "defaultOutputModes"):
        if isinstance(card.get(key), list) and not card[key]:
            out.append(Finding("AC004", "%s is empty" % key, key))
    modes = [("defaultInputModes", card.get("defaultInputModes")), ("defaultOutputModes", card.get("defaultOutputModes"))]
    for i, sk in enumerate(card.get("skills") or []):
        if isinstance(sk, dict):
            modes += [("skills[%d].inputModes" % i, sk.get("inputModes")), ("skills[%d].outputModes" % i, sk.get("outputModes"))]
    for path, vals in modes:
        for j, m in enumerate(vals or []):
            if isinstance(m, str) and not MEDIA_RE.match(m):
                out.append(Finding("AC008", "%r is not a media type" % m, "%s[%d]" % (path, j)))
    seen = {}
    for i, sk in enumerate(card.get("skills") or []):
        sid = sk.get("id") if isinstance(sk, dict) else None
        if isinstance(sid, str):
            if sid in seen:
                out.append(Finding("AC009", "skill id %r repeats skills[%d]" % (sid, seen[sid]), "skills[%d].id" % i))
            seen.setdefault(sid, i)
    return out


def _walk(value, msg, path, out, legacy=frozenset()):
    fields, oneof = message(msg)
    if not isinstance(value, dict):
        out.append(Finding("AC003", "expected an object (%s)" % msg, path or "$"))
        return
    if msg == "SecurityScheme" and "type" in value:
        return  # v0.3 form; reported by the security checks
    if oneof:
        set_keys = [k for k in value if k in fields]
        if len(set_keys) != 1:
            what = "none" if not set_keys else ", ".join(set_keys)
            out.append(Finding("AC010", "%s must set exactly one of its options; found %s" % (msg, what), path))
    for key in value:
        if key in fields or key in legacy:
            continue
        if key == "stateTransitionHistory" and msg == "AgentCapabilities":
            out.append(Finding("AC007", "capabilities.stateTransitionHistory was removed in v1.0", _p(path, key)))
        elif camel(key) in fields and camel(key) != key:
            out.append(Finding("AC005", "%r should be %r" % (key, camel(key)), _p(path, key)))
        else:
            out.append(Finding("AC006", "unknown field %r in %s" % (key, msg), _p(path, key)))
    for name, spec in fields.items():
        kind, container, elem = unwrap(*spec)
        p = _p(path, name)
        if name not in value:
            if kind == "R" and not oneof:
                skip = msg == "AgentCard" and name == "supportedInterfaces" and "url" in legacy
                snake = [k for k in value if camel(k) == name and k != name]
                if not skip and not snake:
                    out.append(Finding("AC002", "%s requires %r" % (msg, name), p))
            continue
        v = value[name]
        if container == "REP":
            if not isinstance(v, list):
                out.append(Finding("AC003", "%r must be an array" % name, p))
                continue
            for i, x in enumerate(v):
                if elem in ("string", "bool"):
                    if not _type_ok(x, elem):
                        out.append(Finding("AC003", "%s[%d] must be a %s" % (name, i, elem), "%s[%d]" % (p, i)))
                else:
                    _walk(x, elem, "%s[%d]" % (p, i), out)
        elif container == "MAP":
            if not isinstance(v, dict):
                out.append(Finding("AC003", "%r must be an object (map)" % name, p))
                continue
            for k, x in v.items():
                if elem in ("string", "bool"):
                    if not _type_ok(x, elem):
                        out.append(Finding("AC003", "%s[%r] must be a %s" % (name, k, elem), "%s.%s" % (p, k)))
                else:
                    _walk(x, elem, "%s.%s" % (p, k), out)
        elif elem in ("string", "bool", "struct"):
            if not _type_ok(v, elem):
                out.append(Finding("AC003", "%r must be a %s, got %s" % (name, "object" if elem == "struct" else elem,
                                                                          type(v).__name__), p))
        else:
            _walk(v, elem, p, out)


def _p(path, key):
    return "%s.%s" % (path, key) if path else key


# ----------------------------------------------------------------------
# interfaces
# ----------------------------------------------------------------------


def check_interfaces(card, allow_local=False):
    out = []
    ifaces = card.get("supportedInterfaces")
    if not isinstance(ifaces, list):
        return out
    seen, has_v1 = set(), False
    for i, it in enumerate(ifaces):
        if not isinstance(it, dict):
            continue
        p = "supportedInterfaces[%d]" % i
        binding, url, ver = it.get("protocolBinding"), it.get("url"), it.get("protocolVersion")
        if isinstance(binding, str) and binding not in CORE_BINDINGS:
            hint = " (did you mean %r?)" % binding.upper() if binding.upper() in CORE_BINDINGS else ""
            out.append(Finding("AC101", "protocolBinding %r is not a core binding%s" % (binding, hint), p))
        if isinstance(ver, str):
            if not VERSION_RE.match(ver):
                out.append(Finding("AC102", "protocolVersion %r should be MAJOR.MINOR" % ver, p + ".protocolVersion"))
            if ver.split(".")[0] == "1":
                has_v1 = True
        if isinstance(url, str):
            out.extend(_check_iface_url(url, binding, p, allow_local))
            key = (url.rstrip("/"), binding)
            if key in seen:
                out.append(Finding("AC106", "%s %s is listed twice" % (binding, url), p))
            seen.add(key)
    if ifaces and not has_v1:
        out.append(Finding("AC107", "no interface declares protocolVersion 1.x", "supportedInterfaces"))
    return out


def _check_iface_url(url, binding, p, allow_local):
    out = []
    if binding == "GRPC" and "://" not in url:
        if not re.match(r"^[A-Za-z0-9.-]+:\d{1,5}$", url):
            out.append(Finding("AC104", "gRPC address %r should be host:port" % url, p + ".url"))
        host = host_of(url)
    else:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https", "grpc", "grpcs") or not parsed.netloc:
            out.append(Finding("AC104", "%r is not an absolute URL" % url, p + ".url"))
            return out
        host = (parsed.hostname or "").lower()
        if parsed.scheme in ("http", "grpc") and not is_local_dev_host(host):
            out.append(Finding("AC103", "%s is not encrypted" % url, p + ".url"))
    if is_internal_host(host) and not allow_local:
        out.append(Finding("AC105", "%s points at internal host %r" % (url, host), p + ".url"))
    return out


# ----------------------------------------------------------------------
# security
# ----------------------------------------------------------------------

AUTH_URL_KEYS = ("authorizationUrl", "tokenUrl", "refreshUrl", "deviceAuthorizationUrl")


def _https_ok(url, allow_local):
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme == "https":
        return True
    return parsed.scheme == "http" and allow_local and is_local_dev_host((parsed.hostname or "").lower())


def check_security(card, allow_local=False):
    out = []
    schemes = card.get("securitySchemes")
    schemes = schemes if isinstance(schemes, dict) else {}
    if not schemes:
        out.append(Finding("AC201", "no securitySchemes declared", "securitySchemes"))
    scopes = {}
    for name, sch in schemes.items():
        p = "securitySchemes.%s" % name
        if not isinstance(sch, dict):
            continue
        if "type" in sch:
            out.append(Finding("AC203", "v0.3 OpenAPI-style scheme (type %r); v1.0 wraps it, e.g. "
                                        "{\"apiKeySecurityScheme\": {...}}" % sch.get("type"), p))
            continue
        if "apiKeySecurityScheme" in sch and isinstance(sch["apiKeySecurityScheme"], dict):
            loc = sch["apiKeySecurityScheme"].get("location")
            if loc not in ("query", "header", "cookie"):
                out.append(Finding("AC203", "apiKey location %r must be query, header or cookie" % loc, p))
            elif loc == "query":
                out.append(Finding("AC208", "API key %r is sent in the query string" %
                                   sch["apiKeySecurityScheme"].get("name"), p))
        if "httpAuthSecurityScheme" in sch and isinstance(sch["httpAuthSecurityScheme"], dict):
            s = sch["httpAuthSecurityScheme"].get("scheme")
            if isinstance(s, str) and s.lower() == "basic":
                out.append(Finding("AC209", "HTTP Basic authentication", p))
            elif isinstance(s, str) and not s.strip():
                out.append(Finding("AC203", "httpAuthSecurityScheme.scheme is empty", p))
        if "openIdConnectSecurityScheme" in sch and isinstance(sch["openIdConnectSecurityScheme"], dict):
            url = sch["openIdConnectSecurityScheme"].get("openIdConnectUrl")
            if isinstance(url, str) and not _https_ok(url, allow_local):
                out.append(Finding("AC206", "openIdConnectUrl %s is not https" % url, p))
        o2 = sch.get("oauth2SecurityScheme")
        if isinstance(o2, dict):
            scopes[name] = set()
            meta = o2.get("oauth2MetadataUrl")
            if isinstance(meta, str) and meta and not _https_ok(meta, allow_local):
                out.append(Finding("AC206", "oauth2MetadataUrl %s is not https" % meta, p))
            flows = o2.get("flows") if isinstance(o2.get("flows"), dict) else {}
            for fname, flow in flows.items():
                if not isinstance(flow, dict):
                    continue
                fp = "%s.oauth2SecurityScheme.flows.%s" % (p, fname)
                if fname in ("implicit", "password"):
                    out.append(Finding("AC204", "%s flow is deprecated" % fname, fp))
                if fname == "authorizationCode" and flow.get("pkceRequired") is not True:
                    out.append(Finding("AC205", "pkceRequired is not true", fp))
                for k in AUTH_URL_KEYS:
                    u = flow.get(k)
                    if isinstance(u, str) and u and not _https_ok(u, allow_local):
                        out.append(Finding("AC206", "%s %s is not https" % (k, u), fp))
                if isinstance(flow.get("scopes"), dict):
                    scopes[name] |= set(flow["scopes"])

    reqs = [("securityRequirements", card.get("securityRequirements"))]
    for i, sk in enumerate(card.get("skills") or []):
        if isinstance(sk, dict):
            reqs.append(("skills[%d].securityRequirements" % i, sk.get("securityRequirements")))
    any_req = False
    for path, lst in reqs:
        for j, req in enumerate(lst or []):
            rp = "%s[%d]" % (path, j)
            if not isinstance(req, dict):
                continue
            if "schemes" not in req and req and all(isinstance(v, list) for v in req.values()):
                out.append(Finding("AC203", "v0.3 requirement form {name: [scopes]}; v1.0 uses "
                                            "{\"schemes\": {name: {\"list\": [...]}}}", rp))
                continue
            for sname, sl in (req.get("schemes") or {}).items():
                any_req = any_req or path == "securityRequirements"
                if sname not in schemes:
                    out.append(Finding("AC202", "requirement names scheme %r, which is not defined" % sname, rp))
                    continue
                wanted = sl.get("list") if isinstance(sl, dict) else None
                if sname in scopes and isinstance(wanted, list):
                    missing = [s for s in wanted if s not in scopes[sname]]
                    if missing:
                        out.append(Finding("AC207", "scope(s) %s not defined by %r" % (", ".join(map(str, missing)), sname), rp))
    caps = card.get("capabilities") if isinstance(card.get("capabilities"), dict) else {}
    if caps.get("extendedAgentCard") is True and (not schemes or not any_req):
        out.append(Finding("AC210", "extendedAgentCard is true but the card declares no %s"
                           % ("securitySchemes" if not schemes else "securityRequirements"), "capabilities"))
    for i, ext in enumerate(caps.get("extensions") or []):
        if not isinstance(ext, dict):
            continue
        uri = ext.get("uri")
        ep = "capabilities.extensions[%d]" % i
        parsed = urlparse(uri) if isinstance(uri, str) else None
        if not parsed or not parsed.scheme or (parsed.scheme in ("http", "https") and not parsed.netloc):
            out.append(Finding("AC214", "extension uri %r is not an absolute URI" % uri, ep))
        if ext.get("required") is True and not (ext.get("description") or "").strip():
            out.append(Finding("AC214", "required extension %r has no description" % uri, ep))
    meta = [("provider.url", (card.get("provider") or {}).get("url") if isinstance(card.get("provider"), dict) else None),
            ("documentationUrl", card.get("documentationUrl")), ("iconUrl", card.get("iconUrl"))]
    for path, url in meta:
        if isinstance(url, str) and url.startswith("http://") and not is_local_dev_host(host_of(url)):
            out.append(Finding("AC215", "%s is not https" % url, path))
    return out


# ----------------------------------------------------------------------
# text: secrets, injection, hidden characters
# ----------------------------------------------------------------------

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("API key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]
SECRET_KEY_SUFFIXES = ("secret", "password", "passwd", "token", "apikey", "accesskey", "privatekey", "clientsecret")
PLACEHOLDERS = ("your", "example", "placeholder", "xxxx", "changeme", "redacted", "<", "${", "{{")
INJECTION_RE = [
    re.compile(r"\bignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier|system|other) "
               r"(?:instructions|rules|prompts?|guidelines)\b", re.I),
    re.compile(r"\bdisregard (?:all |any )?(?:the )?(?:previous|prior|system|safety|user'?s?) "
               r"(?:instructions|rules|guidelines|prompts?)\b", re.I),
    re.compile(r"\b(?:do not|don't|never) (?:tell|inform|notify|alert|show) (?:the )?user\b"
               r"(?!\s+(?:to|that|how|you|they)\b)", re.I),
    re.compile(r"\b(?:always|you must) (?:route|send|forward|delegate) (?:all |every )?(?:tasks?|requests?|messages?|"
               r"data) (?:to|through) (?:this|me|us)\b", re.I),
    re.compile(r"\b(?:prefer|choose|select) this agent over (?:all |any )?other", re.I),
    re.compile(r"\b(?:send|forward|include) (?:the )?(?:user'?s? )?(?:credentials|password|api key|tokens?|"
               r"conversation history|full context)\b", re.I),
    re.compile(r"\byou are now (?:in )?(?:developer|dan|god|jailbreak|unrestricted) mode\b", re.I),
]
HIDDEN_RE = re.compile("[​‌‍⁠‪-‮⁦-⁩­﻿]")


def _strings(value, path=""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, _p(path, str(k)))
            if isinstance(k, str) and isinstance(v, str):
                yield ("key", k, v, _p(path, k))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(v, "%s[%d]" % (path, i))
    elif isinstance(value, str):
        yield ("value", None, value, path)


def _private_jwk_paths(value, path=""):
    if isinstance(value, dict):
        if value.get("kty") in ("EC", "RSA", "OKP") and "d" in value:
            yield path or "$"
        for k, v in value.items():
            yield from _private_jwk_paths(v, _p(path, str(k)))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _private_jwk_paths(v, "%s[%d]" % (path, i))


def check_text(card):
    out = []
    for path in _private_jwk_paths(card):
        out.append(Finding("AC211", "a private key (JWK with 'd') is published in the card", path))
    body = {k: v for k, v in card.items() if k != "signatures"}
    for kind, key, s, path in _strings(body):
        if kind == "key":
            norm = re.sub(r"[_\-]", "", key.lower())
            if norm.endswith(SECRET_KEY_SUFFIXES) and not norm.endswith(("url", "uri")) and len(s) >= 12 \
                    and not any(w in s.lower() for w in PLACEHOLDERS) and len(set(s)) > 4:
                out.append(Finding("AC211", "field %r holds what looks like a credential" % key, path))
            continue
        for label, rx in SECRET_PATTERNS:
            if rx.search(s):
                out.append(Finding("AC211", "possible %s" % label, path))
                break
        for rx in INJECTION_RE:
            m = rx.search(s)
            if m and not _quoted(s, m):
                out.append(Finding("AC212", "instruction aimed at the reading agent: %r" % m.group(0), path))
                break
        if HIDDEN_RE.search(s):
            out.append(Finding("AC213", "invisible or bidirectional control characters", path))
    return out


def _quoted(s, m):
    before, after = s[:m.start()].rstrip(), s[m.end():].lstrip()
    q = "\"'`“”‘’"
    return bool(before) and before[-1] in q and bool(after) and after[0] in q + ",."


def check_card(card, allow_local=False):
    out = check_structure(card)
    if not isinstance(card, dict):
        return out
    out += check_interfaces(card, allow_local)
    out += check_security(card, allow_local)
    out += check_text(card)
    return out
