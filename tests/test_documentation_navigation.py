"""Keep the reader-facing docs navigable without loading model dependencies."""

import hashlib
import re
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_MAIN = "https://github.com/Umi-BitSign/umi/blob/main/"


def prose(text):
    return re.sub(r"(?ms)^\s*(`{3,}|~{3,})[^\n]*\n.*?^\s*\1\s*$", "", text)


def anchors(text):
    found = set(re.findall(r'<a\s+id="([^"]+)"', text))
    counts = {}
    for heading in re.findall(r"(?m)^#{1,6}\s+(.+)$", prose(text)):
        heading = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", heading)
        key = re.sub(r"[^\w\-\s]", "", heading.lower()).replace(" ", "-")
        number = counts.get(key, 0)
        counts[key] = number + 1
        found.add(key + (f"-{number}" if number else ""))
    return found


class DocumentationNavigationTests(unittest.TestCase):
    def test_relative_and_current_github_links_resolve(self):
        paths = [
            ROOT / "README.md",
            *sorted((ROOT / "docs").rglob("*.md")),
            ROOT / "whitepaper/README.md",
        ]
        errors = []
        for source in paths:
            text = prose(source.read_text())
            targets = re.findall(r"!?\[[^\]\n]*\]\(([^\s)]+)\)", text)
            targets += re.findall(r"(?m)^\[[^\]\n]+\]:\s*(\S+)", text)
            for target in targets:
                absolute = target.startswith(PUBLIC_MAIN)
                parsed = urlsplit(target[len(PUBLIC_MAIN) :] if absolute else target)
                if parsed.scheme or parsed.netloc:
                    continue
                name = unquote(parsed.path)
                destination = (
                    ((ROOT if absolute else source.parent) / name).resolve() if name else source
                )
                if not destination.is_relative_to(ROOT):
                    errors.append(f"{source.relative_to(ROOT)}: outside repository: {target}")
                elif not destination.exists():
                    errors.append(f"{source.relative_to(ROOT)}: missing file: {target}")
                elif (
                    parsed.fragment
                    and destination.suffix == ".md"
                    and unquote(parsed.fragment) not in anchors(destination.read_text())
                ):
                    errors.append(f"{source.relative_to(ROOT)}: missing anchor: {target}")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_terms_remain_the_accepted_exact_version(self):
        self.assertEqual(
            hashlib.sha256((ROOT / "docs/MODEL_CONTRIBUTION_TERMS.md").read_bytes()).hexdigest(),
            "61f333f6105c8e8a06db9d51a7a47a3cf0c5c0c72d7794fe1e5e6744eafcca62",
        )

    def test_small_front_door_without_dated_runbooks(self):
        self.assertLessEqual(len(list((ROOT / "docs").glob("*.md"))), 8)
        self.assertEqual(
            [
                p.name
                for p in (ROOT / "docs").rglob("*.md")
                if re.search(r"20\d\d-\d\d-\d\d", p.name)
            ],
            [],
        )
        index = (ROOT / "docs/README.md").read_text()
        for section in ("miners/", "validators/", "contributors/", "operators/", "reference/"):
            self.assertIn(section, index)


if __name__ == "__main__":
    unittest.main()
