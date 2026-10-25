"""Aggregation and rendering."""

import json

from . import SPEC_VERSION, __version__
from .rules import RULES, SEVERITY_RANK, grade_for, score

BADGE_COLORS = {"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red"}


class Result(object):
    def __init__(self, target, card=None, findings=None, notes=None, signature="unsigned"):
        self.target = target
        self.card = card
        self.findings = findings or []
        self.notes = notes or []
        self.signature = signature

    @property
    def name(self):
        return self.card.get("name") if isinstance(self.card, dict) and isinstance(self.card.get("name"), str) else None

    @property
    def score(self):
        return score(self.findings)

    @property
    def grade(self):
        return grade_for(self.score)

    def counts(self):
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def to_dict(self):
        return {"target": self.target, "name": self.name, "score": self.score, "grade": self.grade,
                "signature": self.signature, "counts": self.counts(), "notes": self.notes,
                "findings": [f.to_dict() for f in self.findings]}


class Report(object):
    def __init__(self, results):
        self.results = results

    @property
    def score(self):
        return min((r.score for r in self.results), default=0)

    @property
    def grade(self):
        return grade_for(self.score)

    def worst_severity(self):
        worst = None
        for r in self.results:
            for f in r.findings:
                if worst is None or SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]:
                    worst = f.severity
        return worst

    def counts(self):
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in self.results:
            for k, v in r.counts().items():
                c[k] += v
        return c


def render_console(rep, verbose=True):
    out = ["a2a-agentcard-audit %s | A2A %s | %d card(s)" % (__version__, SPEC_VERSION, len(rep.results)), ""]
    for r in rep.results:
        mark = "ok  " if r.grade in ("A", "B") and not r.counts()["critical"] else "FAIL"
        out.append("%s %s  %s (%d)  signature: %s  %s" % (mark, r.name or "(unnamed)", r.grade, r.score,
                                                          r.signature, r.target))
        if verbose:
            for f in sorted(r.findings, key=lambda f: -SEVERITY_RANK[f.severity]):
                rl = f.rule
                out.append("       %-8s %s %-30s %s%s" % (rl.severity.upper(), rl.id, rl.slug,
                                                         ("[%s] " % f.path) if f.path else "", f.message))
                out.append("                spec %s (%s). fix: %s" % (rl.section, rl.level, rl.fix))
            for n in r.notes:
                out.append("       note: %s" % n)
            out.append("")
    c = rep.counts()
    out.append("Findings: %d critical, %d high, %d medium, %d low" % (c["critical"], c["high"], c["medium"], c["low"]))
    out.append("Overall: %s (%d)%s" % (rep.grade, rep.score, " worst-of" if len(rep.results) > 1 else ""))
    return "\n".join(out) + "\n"


def to_dict(rep):
    return {"tool": "a2a-agentcard-audit", "version": __version__, "a2a_version": SPEC_VERSION,
            "overall": {"score": rep.score, "grade": rep.grade, "counts": rep.counts()},
            "cards": [r.to_dict() for r in rep.results]}


def render_json(rep):
    return json.dumps(to_dict(rep), indent=2) + "\n"


def badge_url(rep):
    return "https://img.shields.io/badge/agent%%20card-%s%%20%%28%d%%29-%s" % (rep.grade, rep.score, BADGE_COLORS[rep.grade])


def render_badge(rep):
    return json.dumps({"schemaVersion": 1, "label": "agent card", "message": "%s (%d)" % (rep.grade, rep.score),
                       "color": BADGE_COLORS[rep.grade]}) + "\n"


def _e(s):
    return str(s).replace("|", "\\|")


def render_markdown(rep):
    c = rep.counts()
    out = ["## A2A Agent Card audit", "", "![agent card](%s)" % badge_url(rep), "",
           "**Overall %s (%d).** Findings: %d critical, %d high, %d medium, %d low." %
           (rep.grade, rep.score, c["critical"], c["high"], c["medium"], c["low"]), "",
           "| Card | Source | Grade | Score | Signature |", "|---|---|---|---|---|"]
    for r in rep.results:
        out.append("| %s | `%s` | %s | %d | %s |" % (_e(r.name or "(unnamed)"), r.target, r.grade, r.score, r.signature))
    for r in rep.results:
        if not r.findings and not r.notes:
            continue
        out += ["", "### %s" % _e(r.name or r.target), ""]
        if r.findings:
            out += ["| Severity | Rule | Where | Finding | Spec | Fix |", "|---|---|---|---|---|---|"]
            for f in sorted(r.findings, key=lambda f: -SEVERITY_RANK[f.severity]):
                rl = f.rule
                out.append("| %s | %s `%s` | %s | %s | %s (%s) | %s |" % (
                    rl.severity, rl.id, rl.slug, ("`%s`" % f.path) if f.path else "", _e(f.message),
                    rl.section, rl.level, _e(rl.fix)))
        for n in r.notes:
            out.append("- %s" % _e(n))
    return "\n".join(out) + "\n"


def render_rules(fmt="console"):
    rules = sorted(RULES.values(), key=lambda r: r.id)
    if fmt == "json":
        return json.dumps([r._asdict() for r in rules], indent=2) + "\n"
    if fmt == "markdown":
        rows = ["| Rule | Slug | Severity | Level | Spec | Checks |", "|---|---|---|---|---|---|"]
        rows += ["| %s | `%s` | %s | %s | %s | %s |" % (r.id, r.slug, r.severity, r.level, r.section, _e(r.summary))
                 for r in rules]
        return "\n".join(rows) + "\n"
    out, cat = [], None
    for r in rules:
        if r.category != cat:
            cat = r.category
            out.append("\n[%s]" % cat)
        out.append("  %s %-30s %-8s %s" % (r.id, r.slug, r.severity, r.summary))
    return "\n".join(out).lstrip("\n") + "\n"


RENDERERS = {"console": render_console, "json": render_json, "markdown": render_markdown, "badge": render_badge}
