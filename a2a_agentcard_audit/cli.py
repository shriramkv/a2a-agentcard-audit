"""Command line interface."""

import argparse
import json
import os
import sys

from . import SPEC_VERSION, __version__, jose
from .card import check_card
from .fetch import fetch_card, make_jku_fetcher
from .migrate import migrate
from .report import RENDERERS, Report, Result, render_rules
from .rules import GRADE_ORDER, SEVERITY_RANK, resolve_rule
from .signing import payload_bytes, sign_card, verify_card

COMMANDS = ("audit", "verify", "sign", "keygen", "canonicalize", "migrate", "rules", "demo", "version")
SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def _load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _write(text, path):
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)


def _is_url(s):
    """http(s) URLs and bare domains are fetched; anything else is a file path."""
    import re
    if s.startswith(("http://", "https://")):
        return True
    return (not os.path.exists(s) and not s.lower().endswith(".json")
            and bool(re.match(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(:\d+)?$", s)))


def audit_source(src, jwks=None, fetch_jku=False, allow_local=False, timeout=15.0, disabled=()):
    findings, notes = [], []
    if _is_url(src):
        card, found, info = fetch_card(src, timeout=timeout, allow_local=allow_local)
        findings += found
        target = info["url"]
    else:
        target = src
        try:
            card = _load_json(src)
        except (OSError, ValueError) as exc:
            card = None
            from .rules import Finding
            findings.append(Finding("AC001", "cannot read %s: %s" % (src, exc)))
    sig_status = "unsigned"
    if card is not None:
        findings += check_card(card, allow_local=allow_local)
        if isinstance(card, dict):
            v = verify_card(card, jwks=jwks, allow_local=allow_local,
                            jku_fetcher=make_jku_fetcher(timeout, allow_local) if fetch_jku else None)
            findings += v.findings
            notes += v.notes
            sig_status = v.status
    findings = [f for f in findings if f.rule_id not in disabled]
    return Result(target, card, findings, notes, sig_status)


def build_parser():
    p = argparse.ArgumentParser(prog="a2a-agentcard-audit",
                                description="Lint, security-audit, sign and verify A2A Agent Cards (A2A %s)." % SPEC_VERSION)
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("audit", help="audit card files or live agents (domain or URL)")
    a.add_argument("sources", nargs="+", help="card.json, a domain (fetches /.well-known/agent-card.json) or a URL")
    a.add_argument("--jwks", help="JWK Set file used to verify signatures")
    a.add_argument("--fetch-jku", action="store_true", help="fetch the key set named by each signature's jku (HTTPS only)")
    a.add_argument("--allow-local", action="store_true", help="treat localhost and private hosts as acceptable (development)")
    a.add_argument("--disable", default="", help="comma-separated rule ids or slugs to skip")
    a.add_argument("--timeout", type=float, default=15.0)
    a.add_argument("--format", choices=sorted(RENDERERS), default="console")
    a.add_argument("-o", "--output")
    a.add_argument("-q", "--quiet", action="store_true")
    a.add_argument("--min-grade", choices=list("ABCDF"))
    a.add_argument("--fail-on", choices=["critical", "high", "medium", "low"])

    v = sub.add_parser("verify", help="verify signatures only (exit 0 verified, 1 not)")
    v.add_argument("card")
    v.add_argument("--jwks", help="JWK Set file")
    v.add_argument("--fetch-jku", action="store_true")
    v.add_argument("--allow-local", action="store_true")

    s = sub.add_parser("sign", help="add a JWS signature to a card")
    s.add_argument("card")
    s.add_argument("--key", required=True, help="private JWK file (from keygen or your key management)")
    s.add_argument("--kid", help="key id (default: the JWK's kid)")
    s.add_argument("--jku", help="URL of the public JWK Set to put in the protected header")
    s.add_argument("--alg", choices=list(jose.SUPPORTED_ALGS), help="default: inferred from the key")
    s.add_argument("--replace", action="store_true", help="replace existing signatures instead of appending")
    s.add_argument("-o", "--output", help="write the signed card here (default stdout)")

    k = sub.add_parser("keygen", help="generate a signing key (private JWK + public JWKS)")
    k.add_argument("--alg", choices=["ES256", "ES384", "EdDSA"], default="ES256")
    k.add_argument("--kid", required=True)
    k.add_argument("--out-dir", default=".")

    c = sub.add_parser("canonicalize", help="print the exact bytes that a signature covers")
    c.add_argument("card")

    m = sub.add_parser("migrate", help="convert a v0.3 card to the v1.0 structure")
    m.add_argument("card")
    m.add_argument("--target-version", help="protocolVersion for the interfaces (default: keep the v0.3 value)")
    m.add_argument("-o", "--output")

    r = sub.add_parser("rules", help="list every rule")
    r.add_argument("--format", choices=["console", "json", "markdown"], default="console")

    d = sub.add_parser("demo", help="audit the bundled good, risky and v0.3 sample cards")
    d.add_argument("--format", choices=sorted(RENDERERS), default="console")
    d.add_argument("-q", "--quiet", action="store_true")
    d.add_argument("-o", "--output")

    sub.add_parser("version")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    cmd = args.command
    if cmd is None:
        parser.print_help()
        return 2
    try:
        return _dispatch(cmd, args)
    except jose.JoseError as exc:
        sys.stderr.write("a2a-agentcard-audit: %s\n" % exc)
        return 2
    except (OSError, ValueError) as exc:
        sys.stderr.write("a2a-agentcard-audit: %s\n" % exc)
        return 2


def _dispatch(cmd, args):
    if cmd == "version":
        print("a2a-agentcard-audit %s (A2A %s, crypto backend: %s)" % (__version__, SPEC_VERSION, jose.backend()))
        return 0
    if cmd == "rules":
        sys.stdout.write(render_rules(args.format))
        return 0
    if cmd == "keygen":
        jwk = jose.generate_key(args.alg, args.kid)
        os.makedirs(args.out_dir, exist_ok=True)
        priv = os.path.join(args.out_dir, "%s.private.jwk.json" % args.kid)
        pub = os.path.join(args.out_dir, "jwks.json")
        with open(priv, "w") as fh:
            json.dump(jwk, fh, indent=2)
        try:
            os.chmod(priv, 0o600)
        except OSError:  # pragma: no cover
            pass
        with open(pub, "w") as fh:
            json.dump({"keys": [jose.public_jwk(jwk)]}, fh, indent=2)
        sys.stderr.write("wrote %s (keep secret) and %s (publish at your jku URL)\n" % (priv, pub))
        if jose.backend() == "pure-python":
            sys.stderr.write("note: pure-Python crypto is not constant-time; install 'cryptography' for production keys\n")
        return 0
    if cmd == "canonicalize":
        sys.stdout.write(payload_bytes(_load_json(args.card)).decode("utf-8") + "\n")
        return 0
    if cmd == "sign":
        card = _load_json(args.card)
        signed = sign_card(card, _load_json(args.key), kid=args.kid, jku=args.jku, alg=args.alg, replace=args.replace)
        _write(json.dumps(signed, indent=2, ensure_ascii=False) + "\n", args.output)
        return 0
    if cmd == "migrate":
        new, notes = migrate(_load_json(args.card), target_version=args.target_version)
        _write(json.dumps(new, indent=2, ensure_ascii=False) + "\n", args.output)
        for n in notes:
            sys.stderr.write("note: %s\n" % n)
        return 0
    if cmd == "verify":
        card = _load_json(args.card)
        jwks = _load_json(args.jwks) if args.jwks else None
        v = verify_card(card, jwks=jwks, allow_local=args.allow_local,
                        jku_fetcher=make_jku_fetcher(15.0, args.allow_local) if args.fetch_jku else None)
        for f in v.findings:
            sys.stdout.write("%-8s %s %s: %s\n" % (f.severity.upper(), f.rule_id, f.path or "", f.message))
        for n in v.notes:
            sys.stdout.write("note: %s\n" % n)
        sys.stdout.write("signature: %s\n" % v.status)
        return 0 if v.status == "verified" else 1
    if cmd == "demo":
        names = ["good-card.json", "risky-card.json", "v03-card.json"]
        jwks = _load_json(os.path.join(SAMPLES, "jwks.json"))
        rep = Report([audit_source(os.path.join(SAMPLES, n), jwks=jwks) for n in names])
        for r in rep.results:
            r.target = "samples/" + os.path.basename(r.target)
        text = RENDERERS["console"](rep, verbose=not args.quiet) if args.format == "console" else RENDERERS[args.format](rep)
        _write(text, args.output)
        return 0

    # audit
    try:
        disabled = {resolve_rule(t) for t in args.disable.split(",") if t.strip()}
    except KeyError as exc:
        sys.stderr.write("unknown rule %s\n" % exc)
        return 2
    jwks = _load_json(args.jwks) if args.jwks else None
    rep = Report([audit_source(s, jwks=jwks, fetch_jku=args.fetch_jku, allow_local=args.allow_local,
                               timeout=args.timeout, disabled=disabled)
                  for s in args.sources])
    text = RENDERERS["console"](rep, verbose=not args.quiet) if args.format == "console" else RENDERERS[args.format](rep)
    _write(text, args.output)
    failed = False
    if args.min_grade and GRADE_ORDER[rep.grade] < GRADE_ORDER[args.min_grade]:
        sys.stderr.write("grade %s is below --min-grade %s\n" % (rep.grade, args.min_grade))
        failed = True
    worst = rep.worst_severity()
    if args.fail_on and worst and SEVERITY_RANK[worst] >= SEVERITY_RANK[args.fail_on]:
        sys.stderr.write("found %s findings (--fail-on %s)\n" % (worst, args.fail_on))
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
