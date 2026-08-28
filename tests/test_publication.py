from __future__ import annotations

import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_whitepaper_status_matches_typeset_cover() -> None:
    markdown = (REPOSITORY_ROOT / "whitepaper" / "README.md").read_text(encoding="utf-8")
    latex = (REPOSITORY_ROOT / "whitepaper" / "main.tex").read_text(encoding="utf-8")

    markdown_match = re.search(r"^Status: (.+)$", markdown, flags=re.MULTILINE)
    latex_match = re.search(r"^\\newcommand\{\\umiStatus\}\{(.+)\}$", latex, flags=re.MULTILINE)

    assert markdown_match is not None
    assert latex_match is not None
    assert markdown_match.group(1) == latex_match.group(1)
