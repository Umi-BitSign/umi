from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_whitepaper_status_matches_typeset_cover() -> None:
    markdown = (REPOSITORY_ROOT / "whitepaper" / "README.md").read_text(encoding="utf-8")
    latex = (REPOSITORY_ROOT / "whitepaper" / "main.tex").read_text(encoding="utf-8")

    markdown_match = re.search(r"^Status: (.+)$", markdown, flags=re.MULTILINE)
    latex_match = re.search(r"^\\newcommand\{\\umiStatus\}\{(.+)\}$", latex, flags=re.MULTILINE)

    assert markdown_match is not None
    assert latex_match is not None
    assert markdown_match.group(1) == latex_match.group(1)


@pytest.fixture
def pandoc_convert():
    executable = shutil.which("pandoc")
    if executable is None:
        pytest.skip("Pandoc is required to check LaTeX conversion")

    def convert(markdown: str) -> str:
        return subprocess.run(
            [
                executable,
                "--from=gfm",
                "--to=latex",
                "--lua-filter=" + str(REPOSITORY_ROOT / "whitepaper/filters/whitepaper.lua"),
                "--syntax-highlighting=none",
                "--wrap=preserve",
            ],
            input=markdown,
            text=True,
            capture_output=True,
            check=True,
            cwd=REPOSITORY_ROOT / "whitepaper",
        ).stdout

    return convert


@pytest.mark.parametrize(
    ("target", "repository_path"),
    [
        ("../docs/OPEN_COMPETITION.md", "docs/OPEN_COMPETITION.md"),
        ("../src/umi/scoring.py", "src/umi/scoring.py"),
        ("LEGACY_V0_1.md", "whitepaper/LEGACY_V0_1.md"),
        ("./LEGACY_V0_1.md", "whitepaper/LEGACY_V0_1.md"),
        ("../docs/../README.md", "README.md"),
        ("../docs/./OPEN_COMPETITION.md#release-checks", "docs/OPEN_COMPETITION.md#release-checks"),
        ("main.tex?raw=1", "whitepaper/main.tex?raw=1"),
    ],
)
def test_latex_repository_links_resolve_from_markdown_source(
    pandoc_convert, target, repository_path
):
    latex = pandoc_convert(f"## Abstract\n\nSummary.\n\n## 1. Context\n\n[Source]({target})\n")
    expected = "https://github.com/Umi-BitSign/umi/blob/main/" + repository_path
    assert r"\href{" + expected.replace("#", r"\#") + "}{Source}" in latex


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://example.org/docs?q=1#part", r"\href{https://example.org/docs?q=1\#part}{Source}"),
        ("http://example.org/docs", r"\href{http://example.org/docs}{Source}"),
        ("mailto:contact@example.org", r"\href{mailto:contact@example.org}{Source}"),
        ("#1-context", r"\hyperref[1-context]{Source}"),
    ],
)
def test_latex_external_and_fragment_links_are_preserved(pandoc_convert, target, expected):
    latex = pandoc_convert(f"## Abstract\n\nSummary.\n\n## 1. Context\n\n[Source]({target})\n")
    assert expected in latex


def test_latex_references_are_unnumbered_and_remain_in_contents(pandoc_convert):
    latex = pandoc_convert(
        "## Abstract\n\nSummary.\n\n## 1. Context\n\nBody.\n\n## References\n\nSources.\n"
    )
    assert r"\section{Context}" in latex
    assert r"\section*{References}" in latex
    assert r"\addcontentsline{toc}{section}{References}" in latex
    assert r"\section{References}" not in latex


def test_current_whitepaper_has_public_repository_links_in_latex(pandoc_convert):
    markdown = (REPOSITORY_ROOT / "whitepaper/README.md").read_text(encoding="utf-8")
    latex = pandoc_convert(markdown)
    assert "https://github.com/Umi-BitSign/umi/blob/main/docs/BOOTSTRAP_WEIGHT_ADDENDUM.md" in latex
    assert "https://github.com/Umi-BitSign/umi/blob/main/docs/OPEN_COMPETITION.md" in latex
    assert "https://github.com/Umi-BitSign/umi/blob/main/whitepaper/LEGACY_V0_1.md" in latex
    assert r"\href{../" not in latex
    assert r"\section*{References}" in latex


def test_typeset_body_matches_current_markdown(pandoc_convert):
    markdown = (REPOSITORY_ROOT / "whitepaper/README.md").read_text(encoding="utf-8")
    body = (REPOSITORY_ROOT / "whitepaper/specification.tex").read_text(encoding="utf-8")
    assert body == pandoc_convert(markdown)
