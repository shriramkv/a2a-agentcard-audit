"""Fetch Agent Cards and JWKS over HTTP and check discovery headers (A2A 8.2, 8.6, 13.4)."""

import json

try:
    from urllib.error import HTTPError, URLError
    from urllib.parse import urlparse
    from urllib.request import Request, urlopen
except ImportError:  # pragma: no cover
    from urllib2 import HTTPError, Request, URLError, urlopen  # type: ignore
    from urlparse import urlparse  # type: ignore

from . import __version__
from .card import is_local_dev_host
from .rules import Finding

WELL_KNOWN = "/.well-known/agent-card.json"
MAX_BYTES = 2 * 1024 * 1024
CARD_TYPES = ("application/json", "application/a2a+json")


def card_url(target):
    """Turn 'example.com' or 'https://example.com' into the well-known card URL."""
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.path in ("", "/"):
        return target.rstrip("/") + WELL_KNOWN
    return target


def _get(url, accept, timeout):
    req = Request(url, headers={"Accept": accept, "User-Agent": "a2a-agentcard-audit/%s" % __version__})
    try:
        resp = urlopen(req, timeout=timeout)
        body = resp.read(MAX_BYTES + 1)
        return resp.status, resp.geturl(), dict(resp.headers.items()), body, None
    except HTTPError as exc:
        return exc.code, url, dict(exc.headers.items()) if exc.headers else {}, b"", "HTTP %d" % exc.code
    except (URLError, OSError, ValueError) as exc:
        return 0, url, {}, b"", str(getattr(exc, "reason", exc))


def _header(headers, name):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def fetch_card(target, timeout=15.0, allow_local=False):
    """Return (card_or_None, findings, info)."""
    url = card_url(target)
    status, final, headers, body, err = _get(url, "application/a2a+json, application/json", timeout)
    info = {"url": url, "final_url": final, "status": status, "headers": headers}
    out = []
    if err:
        return None, [Finding("AC401", "%s: %s" % (url, err), "discovery")], info
    if len(body) > MAX_BYTES:
        return None, [Finding("AC401", "card is larger than %d bytes" % MAX_BYTES, "discovery")], info
    host = (urlparse(final).hostname or "").lower()
    if urlparse(final).scheme != "https" and not (allow_local or is_local_dev_host(host)):
        out.append(Finding("AC405", "card served from %s" % final, "discovery"))
    ctype = (_header(headers, "Content-Type") or "").split(";")[0].strip().lower()
    if ctype not in CARD_TYPES:
        out.append(Finding("AC402", "Content-Type is %r" % (ctype or "missing"), "discovery"))
    cc = (_header(headers, "Cache-Control") or "").lower()
    if "max-age" not in cc and "s-maxage" not in cc:
        out.append(Finding("AC403", "Cache-Control is %r" % (cc or "missing"), "discovery"))
    if not _header(headers, "ETag"):
        out.append(Finding("AC404", "no ETag header", "discovery"))
    if urlparse(final).scheme == "https" and not _header(headers, "Strict-Transport-Security"):
        out.append(Finding("AC406", "no Strict-Transport-Security header", "discovery"))
    try:
        card = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        out.append(Finding("AC001", "card is not JSON: %s" % exc))
        return None, out, info
    return card, out, info


def make_jku_fetcher(timeout=15.0, allow_local=False):
    def fetch(jku):
        parsed = urlparse(jku)
        if parsed.scheme != "https" and not (allow_local and is_local_dev_host((parsed.hostname or "").lower())):
            return None, "refusing to fetch a key set over %s" % (parsed.scheme or "a relative URL")
        status, _, _, body, err = _get(jku, "application/jwk-set+json, application/json", timeout)
        if err:
            return None, err
        try:
            jwks = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None, "not JSON"
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            return None, "not a JWK Set (no 'keys' array)"
        return jwks, None
    return fetch
