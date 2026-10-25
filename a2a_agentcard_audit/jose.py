"""Minimal JWS for Agent Card signatures: ES256, ES384, RS256/384/512 and EdDSA (Ed25519).

Uses pyca/cryptography when it is installed. Otherwise falls back to a
pure-Python implementation, which is correct (tested against RFC vectors and
against cryptography) but NOT constant-time. The fallback is fine for
verification and for signing in CI with test keys. For production signing
keys, install cryptography (`pip install a2a-agentcard-audit[crypto]`).
"""

import base64
import hashlib
import hmac
import json
import os
import secrets

# ----------------------------------------------------------------------
# base64url
# ----------------------------------------------------------------------


def b64u_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text):
    if not isinstance(text, str) or any(c in text for c in "+/= \n"):
        raise ValueError("not base64url")
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _int(b64):
    return int.from_bytes(b64u_decode(b64), "big")


def _b64int(n, length=None):
    length = length or max(1, (n.bit_length() + 7) // 8)
    return b64u_encode(n.to_bytes(length, "big"))


class JoseError(ValueError):
    pass


SUPPORTED_ALGS = ("ES256", "ES384", "RS256", "RS384", "RS512", "EdDSA")
SYMMETRIC_ALGS = ("HS256", "HS384", "HS512")

# ----------------------------------------------------------------------
# elliptic curves (short Weierstrass, a = -3)
# ----------------------------------------------------------------------


class _Curve(object):
    def __init__(self, name, p, b, gx, gy, n, hashfn, size):
        self.name, self.p, self.a, self.b = name, p, p - 3, b
        self.g, self.n, self.hash, self.size = (gx, gy), n, hashfn, size


P256 = _Curve(
    "P-256", 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    hashlib.sha256, 32)
P384 = _Curve(
    "P-384", 2 ** 384 - 2 ** 128 - 2 ** 96 + 2 ** 32 - 1,
    0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    hashlib.sha384, 48)
CURVES = {"P-256": P256, "P-384": P384}
EC_ALG = {"ES256": P256, "ES384": P384}


def _inv(x, m):
    return pow(x, m - 2, m)  # m is prime


def _add(c, P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % c.p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + c.a) * _inv(2 * y1, c.p) % c.p
    else:
        lam = (y2 - y1) * _inv(x2 - x1, c.p) % c.p
    x3 = (lam * lam - x1 - x2) % c.p
    return (x3, (lam * (x1 - x3) - y1) % c.p)


def _mul(c, k, P):
    R = None
    while k:
        if k & 1:
            R = _add(c, R, P)
        P = _add(c, P, P)
        k >>= 1
    return R


def _on_curve(c, P):
    x, y = P
    return 0 <= x < c.p and 0 <= y < c.p and (y * y - (x * x * x + c.a * x + c.b)) % c.p == 0


def _bits2int(b, q):
    v = int.from_bytes(b, "big")
    extra = len(b) * 8 - q.bit_length()
    return v >> extra if extra > 0 else v


def _rfc6979_k(c, d, h):
    q, hf = c.n, c.hash
    rolen = (q.bit_length() + 7) // 8
    x = d.to_bytes(rolen, "big")
    h1 = (_bits2int(h, q) % q).to_bytes(rolen, "big")
    V, K = b"\x01" * hf().digest_size, b"\x00" * hf().digest_size
    K = hmac.new(K, V + b"\x00" + x + h1, hf).digest()
    V = hmac.new(K, V, hf).digest()
    K = hmac.new(K, V + b"\x01" + x + h1, hf).digest()
    V = hmac.new(K, V, hf).digest()
    while True:
        T = b""
        while len(T) < rolen:
            V = hmac.new(K, V, hf).digest()
            T += V
        k = _bits2int(T, q)
        if 1 <= k < q:
            return k
        K = hmac.new(K, V + b"\x00", hf).digest()
        V = hmac.new(K, V, hf).digest()


def _ecdsa_sign(c, d, msg):
    h = c.hash(msg).digest()
    z = _bits2int(h, c.n)
    k = _rfc6979_k(c, d, h)
    r = _mul(c, k, c.g)[0] % c.n
    s = _inv(k, c.n) * (z + r * d) % c.n
    return r.to_bytes(c.size, "big") + s.to_bytes(c.size, "big")


def _ecdsa_verify(c, Q, msg, sig):
    if len(sig) != 2 * c.size or not _on_curve(c, Q):
        return False
    r, s = int.from_bytes(sig[:c.size], "big"), int.from_bytes(sig[c.size:], "big")
    if not (1 <= r < c.n and 1 <= s < c.n):
        return False
    z = _bits2int(c.hash(msg).digest(), c.n)
    w = _inv(s, c.n)
    X = _add(c, _mul(c, z * w % c.n, c.g), _mul(c, r * w % c.n, Q))
    return X is not None and X[0] % c.n == r


# ----------------------------------------------------------------------
# RSA PKCS#1 v1.5
# ----------------------------------------------------------------------

_DIGEST_INFO = {
    "RS256": (hashlib.sha256, bytes.fromhex("3031300d060960864801650304020105000420")),
    "RS384": (hashlib.sha384, bytes.fromhex("3041300d060960864801650304020205000430")),
    "RS512": (hashlib.sha512, bytes.fromhex("3051300d060960864801650304020305000440")),
}


def _emsa_pkcs1(alg, msg, k):
    hf, prefix = _DIGEST_INFO[alg]
    t = prefix + hf(msg).digest()
    if k < len(t) + 11:
        raise JoseError("RSA modulus too short")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def _rsa_verify(alg, n, e, msg, sig):
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    return hmac.compare_digest(em, _emsa_pkcs1(alg, msg, k))


def _rsa_sign(alg, n, d, msg):
    k = (n.bit_length() + 7) // 8
    m = int.from_bytes(_emsa_pkcs1(alg, msg, k), "big")
    return pow(m, d, n).to_bytes(k, "big")


# ----------------------------------------------------------------------
# Ed25519 (RFC 8032 section 6 reference algorithm)
# ----------------------------------------------------------------------

_EP = 2 ** 255 - 19
_ED = -121665 * pow(121666, _EP - 2, _EP) % _EP
_EQ = 2 ** 252 + 27742317777372353535851937790883648493
_SQRT_M1 = pow(2, (_EP - 1) // 4, _EP)


def _ed_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _EP
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _EP
    C = 2 * P[3] * Q[3] * _ED % _EP
    D = 2 * P[2] * Q[2] % _EP
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _EP, G * H % _EP, F * G % _EP, E * H % _EP)


def _ed_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        s >>= 1
    return Q


def _ed_equal(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % _EP == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _EP == 0


def _ed_recover_x(y, sign):
    if y >= _EP:
        return None
    x2 = (y * y - 1) * pow(_ED * y * y + 1, _EP - 2, _EP)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_EP + 3) // 8, _EP)
    if (x * x - x2) % _EP != 0:
        x = x * _SQRT_M1 % _EP
    if (x * x - x2) % _EP != 0:
        return None
    if (x & 1) != sign:
        x = _EP - x
    return x


_EGY = 4 * pow(5, _EP - 2, _EP) % _EP
_EG = (_ed_recover_x(_EGY, 0), _EGY, 1, _ed_recover_x(_EGY, 0) * _EGY % _EP)


def _ed_compress(P):
    zinv = pow(P[2], _EP - 2, _EP)
    x, y = P[0] * zinv % _EP, P[1] * zinv % _EP
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _ed_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _EP)


def _ed_secret_expand(secret):
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _ed_public(secret):
    a, _ = _ed_secret_expand(secret)
    return _ed_compress(_ed_mul(a, _EG))


def _ed_sign(secret, msg):
    a, prefix = _ed_secret_expand(secret)
    A = _ed_compress(_ed_mul(a, _EG))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _EQ
    Rs = _ed_compress(_ed_mul(r, _EG))
    h = int.from_bytes(hashlib.sha512(Rs + A + msg).digest(), "little") % _EQ
    return Rs + int.to_bytes((r + h * a) % _EQ, 32, "little")


def _ed_verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _ed_decompress(public)
    R = _ed_decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _EQ:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _EQ
    return _ed_equal(_ed_mul(s, _EG), _ed_add(R, _ed_mul(h, A)))


# ----------------------------------------------------------------------
# JWK handling and the public API
# ----------------------------------------------------------------------


def _have_cryptography():
    if os.environ.get("A2A_AUDIT_PURE_PYTHON") == "1":
        return False
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def backend():
    return "cryptography" if _have_cryptography() else "pure-python"


def key_alg_ok(jwk, alg):
    """Return None if the JWK can be used with alg, else a reason string."""
    kty = jwk.get("kty")
    if alg in EC_ALG:
        if kty != "EC" or jwk.get("crv") != EC_ALG[alg].name:
            return "%s needs an EC key on %s" % (alg, EC_ALG[alg].name)
    elif alg in _DIGEST_INFO:
        if kty != "RSA":
            return "%s needs an RSA key" % alg
    elif alg == "EdDSA":
        if kty != "OKP" or jwk.get("crv") != "Ed25519":
            return "EdDSA needs an OKP Ed25519 key"
    else:
        return "unsupported alg %r" % alg
    if jwk.get("alg") and jwk["alg"] != alg:
        return "key is bound to alg %r" % jwk["alg"]
    if jwk.get("use") and jwk["use"] != "sig":
        return "key use is %r, not 'sig'" % jwk["use"]
    return None


def rsa_bits(jwk):
    try:
        return _int(jwk["n"]).bit_length()
    except (KeyError, ValueError):
        return 0


def verify(alg, jwk, signing_input, signature):
    """Verify a JWS signature. Returns True or False; raises JoseError on unusable keys."""
    reason = key_alg_ok(jwk, alg)
    if reason:
        raise JoseError(reason)
    try:
        if _have_cryptography():
            return _verify_cryptography(alg, jwk, signing_input, signature)
        if alg in EC_ALG:
            c = EC_ALG[alg]
            return _ecdsa_verify(c, (_int(jwk["x"]), _int(jwk["y"])), signing_input, signature)
        if alg in _DIGEST_INFO:
            return _rsa_verify(alg, _int(jwk["n"]), _int(jwk["e"]), signing_input, signature)
        return _ed_verify(b64u_decode(jwk["x"]), signing_input, signature)
    except (KeyError, ValueError) as exc:
        raise JoseError("malformed key: %s" % exc)


def sign(alg, jwk, signing_input):
    reason = key_alg_ok(jwk, alg)
    if reason:
        raise JoseError(reason)
    if "d" not in jwk:
        raise JoseError("the key has no private part ('d')")
    if _have_cryptography():
        return _sign_cryptography(alg, jwk, signing_input)
    if alg in EC_ALG:
        return _ecdsa_sign(EC_ALG[alg], _int(jwk["d"]), signing_input)
    if alg in _DIGEST_INFO:
        return _rsa_sign(alg, _int(jwk["n"]), _int(jwk["d"]), signing_input)
    return _ed_sign(b64u_decode(jwk["d"]), signing_input)


def generate_key(alg, kid):
    """Generate a private JWK for ES256, ES384 or EdDSA."""
    if alg in EC_ALG:
        c = EC_ALG[alg]
        d = secrets.randbelow(c.n - 1) + 1
        x, y = _mul(c, d, c.g)
        return {"kty": "EC", "crv": c.name, "x": _b64int(x, c.size), "y": _b64int(y, c.size),
                "d": _b64int(d, c.size), "kid": kid, "alg": alg, "use": "sig"}
    if alg == "EdDSA":
        sk = secrets.token_bytes(32)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(_ed_public(sk)), "d": b64u_encode(sk),
                "kid": kid, "alg": alg, "use": "sig"}
    raise JoseError("keygen supports ES256, ES384 and EdDSA")


def public_jwk(jwk):
    private = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
    return {k: v for k, v in jwk.items() if k not in private}


# ---- cryptography backend ----


def _crypto_public(jwk):
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    kty = jwk["kty"]
    if kty == "EC":
        curve = ec.SECP256R1() if jwk["crv"] == "P-256" else ec.SECP384R1()
        return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), curve).public_key()
    if kty == "RSA":
        return rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
    return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))


def _crypto_private(jwk):
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    kty = jwk["kty"]
    if kty == "EC":
        curve = ec.SECP256R1() if jwk["crv"] == "P-256" else ec.SECP384R1()
        return ec.derive_private_key(_int(jwk["d"]), curve)
    if kty == "RSA":
        n, e, d = _int(jwk["n"]), _int(jwk["e"]), _int(jwk["d"])
        if all(k in jwk for k in ("p", "q", "dp", "dq", "qi")):
            p, q = _int(jwk["p"]), _int(jwk["q"])
            dp, dq, qi = _int(jwk["dp"]), _int(jwk["dq"]), _int(jwk["qi"])
        else:
            p, q = rsa.rsa_recover_prime_factors(n, e, d)
            dp, dq, qi = rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q)
        return rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, rsa.RSAPublicNumbers(e, n)).private_key()
    return ed25519.Ed25519PrivateKey.from_private_bytes(b64u_decode(jwk["d"]))


def _hash(alg):
    from cryptography.hazmat.primitives import hashes
    return {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}[alg[2:]]


def _verify_cryptography(alg, jwk, msg, sig):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    try:
        key = _crypto_public(jwk)
    except ValueError as exc:
        raise JoseError("invalid key: %s" % exc)
    try:
        if alg in EC_ALG:
            size = EC_ALG[alg].size
            if len(sig) != 2 * size:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big"))
            key.verify(der, msg, ec.ECDSA(_hash(alg)))
        elif alg in _DIGEST_INFO:
            key.verify(sig, msg, padding.PKCS1v15(), _hash(alg))
        else:
            key.verify(sig, msg)
        return True
    except InvalidSignature:
        return False


def _sign_cryptography(alg, jwk, msg):
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    key = _crypto_private(jwk)
    if alg in EC_ALG:
        r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(_hash(alg))))
        size = EC_ALG[alg].size
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    if alg in _DIGEST_INFO:
        return key.sign(msg, padding.PKCS1v15(), _hash(alg))
    return key.sign(msg)


def decode_protected(protected):
    try:
        header = json.loads(b64u_decode(protected).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JoseError("protected header is not base64url JSON: %s" % exc)
    if not isinstance(header, dict):
        raise JoseError("protected header is not a JSON object")
    return header
