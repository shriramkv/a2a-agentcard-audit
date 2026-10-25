"""Agent Card signing and verification (A2A v1.0 section 8.4)."""

import copy
import json

from . import jose
from .card import is_local_dev_host, host_of
from .jcs import canonicalize
from .rules import Finding
from .schema import prune

try:
    from urllib.parse import urlparse
except ImportError:  # pragma: no cover
    from urlparse import urlparse  # type: ignore


def payload_bytes(card):
    """The bytes that are signed: defaults removed, signatures excluded, RFC 8785 canonical."""
    return canonicalize(prune(card))


def signing_input(protected_b64, card):
    return (protected_b64 + "." + jose.b64u_encode(payload_bytes(card))).encode("ascii")


def infer_alg(jwk):
    if jwk.get("alg"):
        return jwk["alg"]
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "EC":
        return {"P-256": "ES256", "P-384": "ES384"}.get(crv)
    if kty == "RSA":
        return "RS256"
    if kty == "OKP" and crv == "Ed25519":
        return "EdDSA"
    return None


def sign_card(card, jwk, kid=None, jku=None, alg=None, replace=False):
    alg = alg or infer_alg(jwk)
    kid = kid or jwk.get("kid")
    if not alg:
        raise jose.JoseError("cannot infer alg from the key; pass --alg")
    if not kid:
        raise jose.JoseError("the key has no kid; pass --kid (A2A requires kid in the protected header)")
    header = {"alg": alg, "typ": "JOSE", "kid": kid}
    if jku:
        header["jku"] = jku
    protected = jose.b64u_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = jose.sign(alg, jwk, signing_input(protected, card))
    out = copy.deepcopy(card)
    sigs = [] if replace else list(out.get("signatures") or [])
    sigs.append({"protected": protected, "signature": jose.b64u_encode(sig)})
    out["signatures"] = sigs
    return out


class Verification(object):
    def __init__(self):
        self.findings = []
        self.notes = []
        self.status = "unsigned"  # unsigned | unverified | verified | invalid
        self.verified_kids = []


def _keys_from(jwks):
    if isinstance(jwks, dict) and isinstance(jwks.get("keys"), list):
        return [k for k in jwks["keys"] if isinstance(k, dict)]
    if isinstance(jwks, dict) and "kty" in jwks:
        return [jwks]
    return []


def verify_card(card, jwks=None, jku_fetcher=None, allow_local=False):
    """Check every signature. jwks is a JWKS dict (or None); jku_fetcher(url) -> (jwks|None, error|None)."""
    v = Verification()
    sigs = card.get("signatures") if isinstance(card, dict) else None
    if not sigs:
        v.findings.append(Finding("AC301", "no signatures", "signatures"))
        return v
    if not isinstance(sigs, list):
        v.findings.append(Finding("AC302", "signatures must be an array", "signatures"))
        v.status = "invalid"
        return v
    keys = _keys_from(jwks)
    fetched = {}
    any_checked = any_bad = False
    for i, s in enumerate(sigs):
        p = "signatures[%d]" % i
        if not isinstance(s, dict) or not isinstance(s.get("protected"), str) or not isinstance(s.get("signature"), str):
            v.findings.append(Finding("AC302", "signature needs string 'protected' and 'signature'", p))
            any_bad = True
            continue
        try:
            header = jose.decode_protected(s["protected"])
            sig = jose.b64u_decode(s["signature"])
        except (jose.JoseError, ValueError) as exc:
            v.findings.append(Finding("AC302", str(exc), p))
            any_bad = True
            continue
        unprotected = s.get("header") if isinstance(s.get("header"), dict) else {}
        alg, kid = header.get("alg"), header.get("kid")
        missing = [k for k in ("alg", "kid") if not header.get(k)]
        if missing:
            where = " (kid is only in the unprotected header)" if "kid" in missing and unprotected.get("kid") else ""
            v.findings.append(Finding("AC303", "protected header lacks %s%s" % (", ".join(missing), where), p))
        if header.get("typ") != "JOSE":
            v.findings.append(Finding("AC304", "typ is %r" % header.get("typ"), p))
        if not isinstance(alg, str) or alg.lower() == "none" or alg in jose.SYMMETRIC_ALGS:
            v.findings.append(Finding("AC305", "alg %r cannot prove who published the card" % alg, p))
            any_bad = True
            continue
        jku = header.get("jku") or unprotected.get("jku")
        if isinstance(jku, str):
            parsed = urlparse(jku)
            if parsed.scheme != "https" and not (allow_local and is_local_dev_host(host_of(jku))):
                v.findings.append(Finding("AC306", "jku %s is not https" % jku, p))
        if alg not in jose.SUPPORTED_ALGS:
            v.findings.append(Finding("AC310", "alg %r" % alg, p))
            continue
        candidates = list(keys)
        if jku_fetcher and isinstance(jku, str):
            if jku not in fetched:
                fetched[jku] = jku_fetcher(jku)
            got, err = fetched[jku]
            if err:
                v.findings.append(Finding("AC407", "%s: %s" % (jku, err), p))
            candidates += _keys_from(got)
        if not candidates:
            v.notes.append("%s (%s, kid %s) not verified: pass --jwks or --fetch-jku" % (p, alg, kid))
            continue
        matching = [k for k in candidates if k.get("kid") == kid] if kid else candidates
        if not matching:
            v.findings.append(Finding("AC308", "no key with kid %r among %d key(s)" % (kid, len(candidates)), p))
            any_checked = True
            any_bad = True
            continue
        ok = False
        for k in matching:
            if k.get("kty") == "RSA" and jose.rsa_bits(k) < 2048:
                v.findings.append(Finding("AC309", "RSA key %r is %d bits" % (kid, jose.rsa_bits(k)), p))
            try:
                if jose.verify(alg, k, signing_input(s["protected"], card), sig):
                    ok = True
                    break
            except jose.JoseError as exc:
                v.findings.append(Finding("AC309", "key %r unusable: %s" % (kid, exc), p))
        any_checked = True
        if ok:
            v.verified_kids.append(kid)
            v.notes.append("%s verified (%s, kid %s, %s backend)" % (p, alg, kid, jose.backend()))
        else:
            any_bad = True
            v.findings.append(Finding("AC307", "signature with kid %r does not match the card content" % kid, p))
    if v.verified_kids:
        v.status = "verified"
    elif any_bad:
        v.status = "invalid"
    else:
        v.status = "unverified"
    return v
