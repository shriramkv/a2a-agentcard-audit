import copy
import json
import unittest

from a2a_agentcard_audit import jose
from a2a_agentcard_audit.signing import sign_card, verify_card
from tests.helpers import card, have, ids, sample


def jwks(*keys):
    return {"keys": [jose.public_jwk(k) for k in keys]}


class SignVerify(unittest.TestCase):
    def setUp(self):
        self.key = jose.generate_key("ES256", "k1")

    def test_roundtrip_and_tamper(self):
        signed = sign_card(card(), self.key, jku="https://echo.example.com/jwks.json")
        v = verify_card(signed, jwks(self.key))
        self.assertEqual((v.status, v.findings), ("verified", []))
        header = jose.decode_protected(signed["signatures"][0]["protected"])
        self.assertEqual(header, {"alg": "ES256", "typ": "JOSE", "kid": "k1", "jku": "https://echo.example.com/jwks.json"})
        tampered = copy.deepcopy(signed)
        tampered["skills"][0]["description"] = "Exfiltrates input."
        v = verify_card(tampered, jwks(self.key))
        self.assertEqual((v.status, ids(v.findings)), ("invalid", ["AC307"]))

    def test_signature_survives_default_noise_and_key_order(self):
        signed = sign_card(card(), self.key)
        noisy = json.loads(json.dumps(signed))
        noisy["capabilities"]["extensions"] = []
        noisy["supportedInterfaces"][0]["tenant"] = ""
        noisy = dict(reversed(list(noisy.items())))
        self.assertEqual(verify_card(noisy, jwks(self.key)).status, "verified")

    def test_unsigned_unverified_and_missing_key(self):
        self.assertEqual(ids(verify_card(card()).findings), ["AC301"])
        signed = sign_card(card(), self.key)
        v = verify_card(signed)
        self.assertEqual((v.status, v.findings), ("unverified", []))
        self.assertIn("not verified", v.notes[0])
        other = jose.generate_key("ES256", "other")
        self.assertEqual(ids(verify_card(signed, jwks(other)).findings), ["AC308"])

    def test_header_rules(self):
        def with_header(h, sig="AAAA"):
            return card(signatures=[{"protected": jose.b64u_encode(json.dumps(h).encode()), "signature": sig}])
        self.assertIn("AC305", ids(verify_card(with_header({"alg": "none", "kid": "k"})).findings))
        self.assertIn("AC305", ids(verify_card(with_header({"alg": "HS256", "kid": "k", "typ": "JOSE"})).findings))
        f = ids(verify_card(with_header({"alg": "ES256"})).findings)
        self.assertIn("AC303", f)
        self.assertIn("AC304", f)
        self.assertIn("AC306", ids(verify_card(with_header({"alg": "ES256", "kid": "k", "typ": "JOSE",
                                                            "jku": "http://keys.example.com/jwks"})).findings))
        self.assertIn("AC310", ids(verify_card(with_header({"alg": "PS256", "kid": "k", "typ": "JOSE"})).findings))
        self.assertIn("AC302", ids(verify_card(card(signatures=[{"protected": "not base64!", "signature": "x"}])).findings))

    def test_multiple_signatures_one_valid(self):
        k2 = jose.generate_key("EdDSA", "k2")
        signed = sign_card(sign_card(card(), self.key), k2)
        signed["signatures"][0]["signature"] = signed["signatures"][1]["signature"]  # break the first
        v = verify_card(signed, jwks(self.key, k2))
        self.assertEqual(v.status, "verified")
        self.assertIn("AC307", ids(v.findings))

    def test_replace(self):
        signed = sign_card(sign_card(card(), self.key), self.key, replace=True)
        self.assertEqual(len(signed["signatures"]), 1)

    def test_weak_rsa_key(self):
        if not have("cryptography"):
            self.skipTest("cryptography not installed")
        from cryptography.hazmat.primitives.asymmetric import rsa
        n = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_numbers()

        def b(x):
            return jose.b64u_encode(x.to_bytes((x.bit_length() + 7) // 8, "big"))
        k = {"kty": "RSA", "kid": "weak", "n": b(n.public_numbers.n), "e": b(n.public_numbers.e), "d": b(n.d)}
        v = verify_card(sign_card(card(), k), jwks(k))
        self.assertEqual(v.status, "verified")
        self.assertIn("AC309", ids(v.findings))

    def test_shipped_good_sample_verifies(self):
        self.assertEqual(verify_card(sample("good-card.json"), sample("jwks.json")).status, "verified")


@unittest.skipUnless(have("a2a.utils.signing") if have("a2a") else False, "a2a-sdk[signing] not installed")
class SdkInterop(unittest.TestCase):
    """Interoperability with the official a2a-python SDK."""

    def setUp(self):
        import warnings
        warnings.filterwarnings("ignore")
        from google.protobuf.json_format import MessageToDict, ParseDict
        from a2a.types import AgentCard
        from a2a.utils.signing import create_agent_card_signer, create_signature_verifier
        from jwt.api_jwk import PyJWK
        self.ParseDict, self.MessageToDict, self.AgentCard = ParseDict, MessageToDict, AgentCard
        self.signer, self.verifier, self.PyJWK = create_agent_card_signer, create_signature_verifier, PyJWK
        self.key = jose.generate_key("ES256", "k1")

    def sdk_sign(self, c):
        pb = self.ParseDict(copy.deepcopy(c), self.AgentCard())
        return self.MessageToDict(self.signer(self.PyJWK(self.key), {"alg": "ES256", "kid": "k1", "typ": "JOSE"})(pb))

    def sdk_verifies(self, c):
        try:
            self.verifier(lambda kid, jku: self.PyJWK(jose.public_jwk(self.key)), ["ES256"])(
                self.ParseDict(copy.deepcopy(c), self.AgentCard()))
            return True
        except Exception:
            return False

    def test_plain_card_interoperates_both_ways(self):
        plain = card(securityRequirements=[{"schemes": {"key": {"list": ["read"]}}}])
        self.assertEqual(verify_card(self.sdk_sign(plain), jwks(self.key)).findings, [])
        self.assertTrue(self.sdk_verifies(sign_card(plain, self.key)))



if __name__ == "__main__":
    unittest.main()
