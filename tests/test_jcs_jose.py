import os
import random
import unittest

from a2a_agentcard_audit import jose
from a2a_agentcard_audit.jcs import canonicalize, format_number
from a2a_agentcard_audit.schema import prune
from tests.helpers import Backend, PurePython, have

SPEC_ORIGINAL = {
    "name": "Example Agent", "description": "An example agent that echoes messages.",
    "supportedInterfaces": [{"url": "https://example.com/a2a/v1", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
    "version": "1.0.0", "capabilities": {"streaming": False, "pushNotifications": False, "extensions": []},
    "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "echo", "name": "Echo", "description": "Echoes the input.", "tags": ["echo"]}],
}
# Verbatim from A2A v1.0 specification section 8.4.1.
SPEC_CANONICAL = ('{"capabilities":{"pushNotifications":false,"streaming":false},"defaultInputModes":["text/plain"],'
                  '"defaultOutputModes":["text/plain"],"description":"An example agent that echoes messages.",'
                  '"name":"Example Agent","skills":[{"description":"Echoes the input.","id":"echo","name":"Echo",'
                  '"tags":["echo"]}],"supportedInterfaces":[{"protocolBinding":"JSONRPC","protocolVersion":"1.0",'
                  '"url":"https://example.com/a2a/v1"}],"version":"1.0.0"}')


class JCSTests(unittest.TestCase):
    def test_spec_example_byte_for_byte(self):
        self.assertEqual(canonicalize(prune(SPEC_ORIGINAL)).decode("utf-8"), SPEC_CANONICAL)

    def test_numbers(self):
        cases = {4.5: "4.5", 0.002: "0.002", 1e-7: "1e-7", 1e20: "100000000000000000000", 1e21: "1e+21",
                 -0.0: "0", 333333333.3333333: "333333333.3333333", 1e30: "1e+30", 5e-324: "5e-324",
                 1.7976931348623157e308: "1.7976931348623157e+308", 100.0: "100", 0.000001: "0.000001",
                 123e-20: "1.23e-18", -1.5: "-1.5", 2 ** 53: "9007199254740992"}
        for value, expected in cases.items():
            self.assertEqual(format_number(value), expected, value)
        with self.assertRaises(ValueError):
            format_number(float("nan"))

    def test_utf16_key_order_and_escapes(self):
        # U+1F600 is a surrogate pair (D83D ...), which sorts before U+E000 in UTF-16.
        self.assertEqual(canonicalize({"": 1, "\U0001F600": 2, "a": 3}).decode("utf-8"),
                         '{"a":3,"\U0001F600":2,"":1}')
        self.assertEqual(canonicalize("€\n\x01\"").decode("utf-8"), '"€\\n\\u0001\\""')

    def test_prune_rules(self):
        c = dict(SPEC_ORIGINAL, signatures=[{"protected": "x", "signature": "y"}],
                 capabilities={"extensions": [{"uri": "u", "required": False, "description": "", "params": {}}]})
        p = prune(c)
        self.assertNotIn("signatures", p)
        self.assertEqual(p["capabilities"], {"extensions": [{"uri": "u", "params": {}}]})
        self.assertEqual(prune(dict(SPEC_ORIGINAL, capabilities={}))["capabilities"], {})  # REQUIRED stays

    @unittest.skipUnless(have("rfc8785"), "rfc8785 not installed")
    def test_parity_with_rfc8785_library(self):
        import rfc8785
        rnd = random.Random(8785)

        def value(depth=0):
            t = rnd.random()
            if depth > 3 or t < 0.3:
                return rnd.choice([None, True, False, rnd.randint(-10 ** 15, 10 ** 15), rnd.uniform(-1e6, 1e6),
                                   rnd.random() * 10 ** rnd.randint(-30, 30),
                                   "".join(rnd.choice("aZé€\U0001F600\n\"\\\t\x01 ") for _ in range(rnd.randint(0, 8)))])
            if t < 0.65:
                return [value(depth + 1) for _ in range(rnd.randint(0, 4))]
            return {"".join(rnd.choice("abcé\U0001F600_") for _ in range(rnd.randint(1, 4))): value(depth + 1)
                    for _ in range(rnd.randint(0, 4))}
        for _ in range(2000):
            v = value()
            self.assertEqual(canonicalize(v), rfc8785.dumps(v))


ES256_JWK = {"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
             "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0", "d": "jpsQnnGQmL-YBIffH1136cLSdrBE5qw_P_4y_8Ddzqo"}
ES256_JWS = ("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
             "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q")


class JoseTests(unittest.TestCase):
    def test_rfc7515_a3_es256(self):
        h, p, s = ES256_JWS.split(".")
        with PurePython():
            self.assertTrue(jose.verify("ES256", ES256_JWK, (h + "." + p).encode(), jose.b64u_decode(s)))
            self.assertFalse(jose.verify("ES256", ES256_JWK, (h + "." + p + "A").encode(), jose.b64u_decode(s)))

    def test_rfc8032_ed25519_vector(self):
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970"
                            "1cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertEqual(jose._ed_public(sk), pk)
        self.assertEqual(jose._ed_sign(sk, b""), sig)
        self.assertTrue(jose._ed_verify(pk, b"", sig))

    def test_pure_roundtrips(self):
        with PurePython():
            for alg in ("ES256", "ES384", "EdDSA"):
                k = jose.generate_key(alg, "k")
                sig = jose.sign(alg, k, b"payload")
                self.assertTrue(jose.verify(alg, jose.public_jwk(k), b"payload", sig), alg)
                self.assertFalse(jose.verify(alg, jose.public_jwk(k), b"payloaD", sig), alg)
                self.assertNotIn("d", jose.public_jwk(k))

    def test_key_alg_mismatch_and_point_validation(self):
        k = jose.generate_key("ES256", "k")
        with self.assertRaises(jose.JoseError):
            jose.verify("ES384", k, b"x", b"\x00" * 96)
        bad = dict(jose.public_jwk(k), y=jose.b64u_encode(b"\x01" * 32))  # not on the curve
        with PurePython():
            self.assertFalse(jose.verify("ES256", bad, b"x", jose.sign("ES256", k, b"x")))

    @unittest.skipUnless(have("cryptography"), "cryptography not installed")
    def test_cross_backend_interop(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        n = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_numbers()

        def b(x):
            return jose.b64u_encode(x.to_bytes((x.bit_length() + 7) // 8, "big"))
        rsa_jwk = {"kty": "RSA", "n": b(n.public_numbers.n), "e": b(n.public_numbers.e), "d": b(n.d)}
        keys = {a: jose.generate_key(a, "k") for a in ("ES256", "ES384", "EdDSA")}
        keys.update({a: rsa_jwk for a in ("RS256", "RS384", "RS512")})
        msg = os.urandom(77)
        for alg, k in keys.items():
            for sign_pure in (True, False):
                with Backend(sign_pure):
                    sig = jose.sign(alg, k, msg)
                for verify_pure in (True, False):
                    with Backend(verify_pure):
                        self.assertTrue(jose.verify(alg, jose.public_jwk(k), msg, sig),
                                        "%s signed pure=%s verified pure=%s" % (alg, sign_pure, verify_pure))


if __name__ == "__main__":
    unittest.main()
