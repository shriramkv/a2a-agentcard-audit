import copy
import json
import os
import unittest

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "a2a_agentcard_audit", "samples")


def sample(name):
    with open(os.path.join(SAMPLES, name)) as fh:
        return json.load(fh)


BASE = {
    "name": "Echo", "description": "Echoes text back to the caller.", "version": "1.0.0",
    "supportedInterfaces": [{"url": "https://echo.example.com/a2a", "protocolBinding": "JSONRPC",
                             "protocolVersion": "1.0"}],
    "capabilities": {"streaming": True},
    "securitySchemes": {"key": {"apiKeySecurityScheme": {"location": "header", "name": "X-API-Key"}}},
    "securityRequirements": [{"schemes": {"key": {}}}],
    "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "echo", "name": "Echo", "description": "Echo the input.", "tags": ["echo"]}],
}


def card(**changes):
    c = copy.deepcopy(BASE)
    for k, v in changes.items():
        if v is None:
            c.pop(k, None)
        else:
            c[k] = v
    return c


def ids(findings):
    return sorted({f.rule_id for f in findings})


def have(module):
    try:
        __import__(module)
        return True
    except ImportError:
        return False


class PurePython(object):
    """Context manager forcing the pure-Python crypto backend."""

    def __enter__(self):
        self.old = os.environ.get("A2A_AUDIT_PURE_PYTHON")
        os.environ["A2A_AUDIT_PURE_PYTHON"] = "1"

    def __exit__(self, *exc):
        if self.old is None:
            os.environ.pop("A2A_AUDIT_PURE_PYTHON", None)
        else:
            os.environ["A2A_AUDIT_PURE_PYTHON"] = self.old


class Backend(object):
    def __init__(self, pure):
        self.pure = pure

    def __enter__(self):
        self.old = os.environ.get("A2A_AUDIT_PURE_PYTHON")
        os.environ["A2A_AUDIT_PURE_PYTHON"] = "1" if self.pure else "0"

    def __exit__(self, *exc):
        if self.old is None:
            os.environ.pop("A2A_AUDIT_PURE_PYTHON", None)
        else:
            os.environ["A2A_AUDIT_PURE_PYTHON"] = self.old


TestCase = unittest.TestCase
