"""Regenerate README.md from README.template.md with the current rule table."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from a2a_agentcard_audit.report import render_rules  # noqa: E402


def main():
    with open(os.path.join(ROOT, "README.template.md")) as fh:
        text = fh.read()
    with open(os.path.join(ROOT, "README.md"), "w") as fh:
        fh.write(text.replace("<!-- RULES -->", render_rules("markdown").rstrip("\n")))
    print("README.md written")


if __name__ == "__main__":
    main()
