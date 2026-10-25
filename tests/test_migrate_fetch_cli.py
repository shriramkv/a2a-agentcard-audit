import contextlib
import io
import json
import os
import shutil
import tempfile
import threading
import unittest

try:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
except ImportError:  # pragma: no cover
    ThreadingHTTPServer = None

from a2a_agentcard_audit import jose
from a2a_agentcard_audit.card import check_card
from a2a_agentcard_audit.cli import main
from a2a_agentcard_audit.fetch import card_url, fetch_card, make_jku_fetcher
from a2a_agentcard_audit.migrate import is_v03, migrate
from a2a_agentcard_audit.signing import sign_card, verify_card
from tests.helpers import SAMPLES, card, ids, sample


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Migrate(unittest.TestCase):
    def test_v03_sample(self):
        old = sample("v03-card.json")
        self.assertTrue(is_v03(old))
        new, notes = migrate(old)
        self.assertFalse(is_v03(new))
        found = ids(check_card(new))
        for rule in ("AC007", "AC203", "AC002", "AC010", "AC106"):
            self.assertNotIn(rule, found)
        self.assertIn("AC107", found)  # still 0.3 until told otherwise
        self.assertEqual([i["protocolVersion"] for i in new["supportedInterfaces"]], ["0.3", "0.3"])
        self.assertEqual(set(new["securitySchemes"]), {"oauth-authorizationCode", "oauth-clientCredentials", "key"})
        self.assertEqual(len(new["securityRequirements"]), 3)
        self.assertNotIn("stateTransitionHistory", new["capabilities"])
        self.assertEqual(new["capabilities"]["extendedAgentCard"], False)
        self.assertTrue(any("stateTransitionHistory" in n for n in notes))

    def test_target_version_and_and_requirements(self):
        old = sample("v03-card.json")
        old["security"] = [{"oauth": ["weather.read"], "key": []}]  # AND of two schemes
        new, _ = migrate(old, target_version="1.0")
        self.assertNotIn("AC107", ids(check_card(new)))
        self.assertEqual(new["securityRequirements"], [
            {"schemes": {"oauth-authorizationCode": {"list": ["weather.read"]}, "key": {}}},
            {"schemes": {"oauth-clientCredentials": {"list": ["weather.read"]}, "key": {}}}])

    def test_signatures_dropped(self):
        old = dict(sample("v03-card.json"), signatures=[{"protected": "x", "signature": "y"}])
        new, notes = migrate(old)
        self.assertNotIn("signatures", new)
        self.assertTrue(any("sign the new card" in n for n in notes))


class _CardServer(object):
    def __init__(self, routes):
        routes = routes

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                status, headers, body = routes.get(self.path, (404, {}, b"{}"))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return "http://127.0.0.1:%d" % self.srv.server_address[1]

    def __exit__(self, *e):
        self.srv.shutdown()
        self.srv.server_close()


class Fetch(unittest.TestCase):
    def test_card_url(self):
        self.assertEqual(card_url("agent.example.com"), "https://agent.example.com/.well-known/agent-card.json")
        self.assertEqual(card_url("https://a.example/custom/card.json"), "https://a.example/custom/card.json")

    def test_discovery_headers(self):
        body = json.dumps(card()).encode()
        good = {"Content-Type": "application/a2a+json", "Cache-Control": "max-age=300", "ETag": '"v1"'}
        routes = {"/.well-known/agent-card.json": (200, good, body), "/bare/card.json": (200, {"Content-Type": "text/plain"}, body)}
        with _CardServer(routes) as base:
            c, found, info = fetch_card(base, allow_local=True)
            self.assertEqual((c["name"], found), ("Echo", []))
            c, found, _ = fetch_card(base + "/bare/card.json", allow_local=True)
            self.assertEqual(ids(found), ["AC402", "AC403", "AC404"])
            _, found, _ = fetch_card(base + "/missing.json", allow_local=True)
            self.assertEqual(ids(found), ["AC401"])

    def test_jku_fetch(self):
        key = jose.generate_key("ES256", "k1")
        jwks = json.dumps({"keys": [jose.public_jwk(key)]}).encode()
        with _CardServer({"/jwks.json": (200, {"Content-Type": "application/json"}, jwks)}) as base:
            signed = sign_card(card(), key, jku=base + "/jwks.json")
            v = verify_card(signed, jku_fetcher=make_jku_fetcher(allow_local=True), allow_local=True)
            self.assertEqual(v.status, "verified")
            v = verify_card(signed, jku_fetcher=make_jku_fetcher(allow_local=False))
            self.assertIn("AC306", ids(v.findings))
            self.assertIn("AC407", ids(v.findings))


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="a2a-audit-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.tmp, name)

    def test_keygen_sign_verify_tamper(self):
        with open(self.path("card.json"), "w") as fh:
            json.dump(card(), fh)
        self.assertEqual(run("keygen", "--kid", "k1", "--out-dir", self.tmp)[0], 0)
        priv = self.path("k1.private.jwk.json")
        if os.name == "posix":
            self.assertEqual(oct(os.stat(priv).st_mode & 0o777), "0o600")
        self.assertEqual(run("sign", self.path("card.json"), "--key", priv, "-o", self.path("signed.json"))[0], 0)
        code, out, _ = run("verify", self.path("signed.json"), "--jwks", self.path("jwks.json"))
        self.assertEqual(code, 0, out)
        with open(self.path("signed.json")) as fh:
            signed = json.load(fh)
        signed["version"] = "9.9.9"
        with open(self.path("tampered.json"), "w") as fh:
            json.dump(signed, fh)
        code, out, _ = run("verify", self.path("tampered.json"), "--jwks", self.path("jwks.json"))
        self.assertEqual(code, 1)
        self.assertIn("AC307", out)
        code, out, _ = run("audit", self.path("signed.json"), "--jwks", self.path("jwks.json"), "--min-grade", "A",
                           "--fail-on", "low")
        self.assertEqual(code, 0, out)

    def test_canonicalize_and_migrate(self):
        code, out, _ = run("canonicalize", os.path.join(SAMPLES, "good-card.json"))
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith('{"capabilities"'))
        self.assertNotIn("signatures", out)
        code, out, err = run("migrate", os.path.join(SAMPLES, "v03-card.json"), "--target-version", "1.0")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["supportedInterfaces"][0]["protocolVersion"], "1.0")

    def test_demo_rules_and_formats(self):
        code, out, _ = run("demo", "-q")
        self.assertEqual(code, 0)
        self.assertIn("A (100)  signature: verified", out)
        code, out, _ = run("audit", os.path.join(SAMPLES, "risky-card.json"), "--format", "json", "--fail-on", "critical")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["overall"]["grade"], "F")
        _, md, _ = run("audit", os.path.join(SAMPLES, "good-card.json"), "--format", "markdown")
        self.assertIn("| Card | Source | Grade |", md)
        from a2a_agentcard_audit.rules import RULES
        self.assertEqual(len(json.loads(run("rules", "--format", "json")[1])), len(RULES))

    def test_disable_and_errors(self):
        code, out, _ = run("audit", os.path.join(SAMPLES, "v03-card.json"), "--disable", "AC007,invalid-security-scheme,AC301",
                           "--format", "json")
        self.assertEqual({f["rule"] for c in json.loads(out)["cards"] for f in c["findings"]}, set())
        self.assertEqual(run("audit", "x.json", "--disable", "AC999")[0], 2)
        self.assertEqual(run("verify", self.path("missing.json"))[0], 2)
        code, out, _ = run("audit", self.path("missing.json"), "--format", "json")
        self.assertIn("AC001", out)


if __name__ == "__main__":
    unittest.main()
