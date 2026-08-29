from __future__ import annotations

import json
import sys
import unittest
from fractions import Fraction
from importlib.metadata import version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from umi.scoring import (
    clamp_unit,
    grapheme_clusters,
    levenshtein,
    mean_score,
    normalization_trace,
    normalize_text,
    score_cer,
    score_cer_with_trace,
    score_wer,
    score_wer_with_trace,
    scoring_environment,
    utility_score,
    weighted_accuracy,
    weighted_accuracy_with_trace,
)


class ScoringEnvironmentTests(unittest.TestCase):
    def test_fingerprints_bittensor_chain_encoding_dependency(self) -> None:
        self.assertEqual(
            scoring_environment()["bittensor_distribution_version"],
            version("bittensor"),
        )


class NormalizationTests(unittest.TestCase):
    def test_nfkc_precedes_unicode_lowercase(self) -> None:
        trace = normalization_trace("\uff26\uff2f\uff2f \u2460")

        self.assertEqual(trace.nfkc, "FOO 1")
        self.assertEqual(trace.lowercased, "foo 1")
        self.assertEqual(trace.normalized, "foo 1")

    def test_unicode_letters_numbers_and_separators(self) -> None:
        self.assertEqual(
            normalize_text("  HéLLo,,,世界—42___βETA!!  "),
            "héllo 世界 42 βeta",
        )

    def test_only_internal_apostrophes_are_retained(self) -> None:
        self.assertEqual(
            normalize_text("'DON'T' dogs' rock''n \u2019TIS 3'4 DON\u2019T"),
            "don't dogs rock n tis 3'4 don\u2019t",
        )

    def test_emoji_is_one_extended_grapheme_cluster(self) -> None:
        emoji = "👩🏽‍💻"

        self.assertEqual(grapheme_clusters(emoji), (emoji,))
        self.assertEqual(grapheme_clusters(emoji + "a"), (emoji, "a"))
        self.assertEqual(
            levenshtein(grapheme_clusters("👩🏽‍💻"), grapheme_clusters("👨🏽‍💻")),
            1,
        )

    def test_non_alphanumeric_emoji_is_a_normalization_separator(self) -> None:
        trace = normalization_trace("A👩🏽‍💻B")

        self.assertEqual(trace.normalized, "a b")
        self.assertEqual(trace.graphemes_without_whitespace, ("a", "b"))


class MetricTests(unittest.TestCase):
    def test_wer_uses_best_of_five_references(self) -> None:
        score = score_wer(
            "the target",
            ("wrong", "not this", "a miss", "other", "the target"),
        )

        self.assertIsInstance(score, Fraction)
        self.assertEqual(score, Fraction(1, 1))

    def test_empty_or_punctuation_only_references_are_rejected(self) -> None:
        for references in (("", "", ""), ("!!!", "???", "...")):
            with self.assertRaisesRegex(ValueError, "canonical scoring unit"):
                score_wer("", references)
            with self.assertRaisesRegex(ValueError, "canonical scoring unit"):
                score_cer("", references)

    def test_wer_keeps_internal_apostrophe_as_token_content(self) -> None:
        references = ("don't stop", "do not stop", "dont stop")

        self.assertEqual(score_wer("DON'T, stop!", references), Fraction(1, 1))
        self.assertEqual(
            score_wer("dont stop", ("don't stop", "do not stop", "halt")),
            Fraction(1, 2),
        )

    def test_cer_removes_collapsed_whitespace_after_normalization(self) -> None:
        trace = score_cer_with_trace("A, B", ("ab", "a-b", "ac"))

        self.assertEqual(trace.hypothesis_units, ("a", "b"))
        self.assertEqual(trace.score, Fraction(1, 1))
        self.assertEqual(trace.best_reference_indices, (0, 1))

    def test_cer_uses_graphemes_after_nfkc(self) -> None:
        trace = score_cer_with_trace("café", ("café", "café", "cafe"))

        self.assertEqual(trace.hypothesis_units, ("c", "a", "f", "é"))
        self.assertEqual(trace.score, Fraction(1, 1))
        self.assertEqual(trace.best_reference_indices, (0, 1))

    def test_best_reference_tie_is_deterministic_and_recorded(self) -> None:
        trace = score_wer_with_trace(
            "Hello, world!",
            ("hello world", "HELLO... WORLD", "hello brave world"),
        )

        self.assertEqual(trace.score, Fraction(1, 1))
        self.assertEqual(trace.best_reference_index, 0)
        self.assertEqual(trace.best_reference_indices, (0, 1))

    def test_trace_record_is_json_friendly(self) -> None:
        trace = score_wer_with_trace("a", ("a", "a", "b"))

        encoded = json.dumps(trace.to_record(), sort_keys=True)
        self.assertIn('"numerator": 1', encoded)
        self.assertEqual(trace.to_record()["best_reference_indices"], [0, 1])

    def test_reference_count_is_enforced(self) -> None:
        with self.assertRaises(ValueError):
            score_wer("x", ("x", "x"))
        with self.assertRaises(ValueError):
            score_cer("x", ("x", "x", "x", "x", "x", "x"))


class ExactArithmeticTests(unittest.TestCase):
    def test_mean_and_weighted_accuracy_are_exact(self) -> None:
        short_mean = mean_score((Fraction(1, 3), Fraction(2, 3)))
        score = weighted_accuracy(Fraction(1, 1), short_mean, Fraction(0, 1))

        self.assertEqual(short_mean, Fraction(1, 2))
        self.assertEqual(score, Fraction(13, 40))
        self.assertIsInstance(score, Fraction)

    def test_accuracy_inputs_and_output_are_clamped(self) -> None:
        trace = weighted_accuracy_with_trace(Fraction(2, 1), Fraction(-1, 1), Fraction(1, 2))

        self.assertEqual(
            tuple(component.mean for component in trace.strata),
            (Fraction(1, 1), Fraction(0, 1), Fraction(1, 2)),
        )
        self.assertEqual(trace.score, Fraction(2, 5))

    def test_float_arithmetic_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            clamp_unit(0.5)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            weighted_accuracy(Fraction(1, 2), 0.5, Fraction(1, 2))  # type: ignore[arg-type]

    def test_utility_is_exact_and_clamped(self) -> None:
        self.assertEqual(utility_score(Fraction(3, 5), Fraction(1, 10)), Fraction(1, 4))
        self.assertEqual(utility_score(Fraction(1, 20), Fraction(1, 10)), Fraction(0, 1))


if __name__ == "__main__":
    unittest.main()
