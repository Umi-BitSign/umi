from __future__ import annotations

import hashlib
from fractions import Fraction

import pytest

from umi.protocol import base64url_encode
from umi.rolling import AssignmentScore, RollingScoreState, ScoredBatch

ROOT_A = b"A" * 32
ROOT_B = b"B" * 32
STRATA = ("fingerspelling", "short_utterance", "continuous")


def _challenge_id(pool: int, ordinal: int) -> str:
    return base64url_encode((pool * 100 + ordinal).to_bytes(16, "big"))


def _assignment(
    root: bytes,
    *,
    pool: int,
    ordinal: int,
    stratum: str,
    score: Fraction | None,
    canary: bool = False,
) -> AssignmentScore:
    challenge_id = _challenge_id(pool, ordinal)
    request_leaf = hashlib.sha256(
        b"test-request-leaf\0" + root + pool.to_bytes(2, "big") + ordinal.to_bytes(2, "big")
    ).digest()
    return AssignmentScore(
        miner_root=root,
        challenge_id=challenge_id,
        request_leaf=request_leaf,
        stratum=stratum,  # type: ignore[arg-type]
        canary=canary,
        score=score,
    )


def _batch(
    window: int,
    rank: int,
    pool: int,
    *,
    score_rows: dict[bytes, tuple[Fraction, Fraction, Fraction]] | None = None,
) -> ScoredBatch:
    rows = score_rows or {ROOT_A: (Fraction(1), Fraction(1), Fraction(1))}
    miners = tuple(sorted(rows))
    challenge_ids = tuple(_challenge_id(pool, ordinal) for ordinal in range(3))
    assignments = tuple(
        _assignment(
            root,
            pool=pool,
            ordinal=ordinal,
            stratum=STRATA[ordinal],
            score=rows[root][ordinal],
        )
        for root in miners
        for ordinal in range(3)
    )
    return ScoredBatch(
        window_index=window,
        batch_rank=bytes([rank]) * 32,
        pool_leaf=bytes([pool]) * 32,
        challenge_ids=challenge_ids,
        miner_roots=miners,
        assignments=assignments,
    )


def _two_miner_state(score_b: Fraction = Fraction(1, 2)) -> RollingScoreState:
    rows = {
        ROOT_A: (Fraction(1), Fraction(1), Fraction(1)),
        ROOT_B: (score_b, score_b, score_b),
    }
    return RollingScoreState((_batch(0, 1, 11, score_rows=rows), _batch(0, 2, 12, score_rows=rows)))


def test_valid_window_enters_as_an_atomic_ordered_two_batch_cohort() -> None:
    first = _batch(0, 1, 11)
    second = _batch(0, 2, 12)
    state = RollingScoreState().advance(
        0,
        new_batches=(first, second),
        rolling_batch_count=4,
        score_max_age_windows=4,
    )
    assert state.batches == (first, second)

    with pytest.raises(ValueError, match="ordered"):
        RollingScoreState().advance(
            0,
            new_batches=(second, first),
            rolling_batch_count=4,
            score_max_age_windows=4,
        )
    with pytest.raises(ValueError, match="two-batch"):
        RollingScoreState().advance(
            0,
            new_batches=(first,),
            rolling_batch_count=4,
            score_max_age_windows=4,
        )
    with pytest.raises(ValueError, match="complete two-batch"):
        RollingScoreState().advance(
            0,
            new_batches=(first, second),
            rolling_batch_count=3,
            score_max_age_windows=4,
        )


def test_skipped_window_does_not_enter_or_evict_and_valid_window_evicts_globally() -> None:
    old = RollingScoreState((_batch(0, 1, 11), _batch(0, 2, 12)))
    skipped = old.advance(1, rolling_batch_count=2, score_max_age_windows=4)
    assert skipped == old

    replacement = (_batch(2, 1, 21), _batch(2, 2, 22))
    advanced = skipped.advance(
        2,
        new_batches=replacement,
        rolling_batch_count=2,
        score_max_age_windows=4,
    )
    assert advanced.batches == replacement


def test_score_age_expires_at_the_exclusive_boundary_even_without_new_batches() -> None:
    state = RollingScoreState((_batch(0, 1, 11), _batch(0, 2, 12)))
    assert len(state.advance(3, rolling_batch_count=4, score_max_age_windows=4).batches) == 2
    assert state.advance(4, rolling_batch_count=4, score_max_age_windows=4).batches == ()


def test_miner_scores_include_assigned_zeros_and_use_exact_stratum_arithmetic() -> None:
    first_rows = {
        ROOT_A: (Fraction(1), Fraction(1, 2), Fraction(0)),
        ROOT_B: (Fraction(1), Fraction(0), Fraction(0)),
    }
    second_rows = {
        ROOT_A: (Fraction(1), Fraction(1, 2), Fraction(1)),
        ROOT_B: (Fraction(0), Fraction(0), Fraction(0)),
    }
    state = RollingScoreState(
        (
            _batch(0, 1, 11, score_rows=first_rows),
            _batch(0, 2, 12, score_rows=second_rows),
        )
    )
    scores = state.miner_scores(
        minimum_assigned_clips=6,
        minimum_clips_per_stratum=2,
        quality_floor=Fraction(1, 10),
    )
    by_root = {score.miner_root: score for score in scores}

    assert by_root[ROOT_A].assigned_clips == 6
    assert dict(by_root[ROOT_A].stratum_means) == {
        "fingerspelling": Fraction(1),
        "short_utterance": Fraction(1, 2),
        "continuous": Fraction(1, 2),
    }
    assert by_root[ROOT_A].accuracy == Fraction(23, 40)
    assert by_root[ROOT_A].utility == Fraction(361, 1600)
    assert by_root[ROOT_A].eligible
    assert by_root[ROOT_B].assigned_clips == 6
    assert dict(by_root[ROOT_B].stratum_means)["fingerspelling"] == Fraction(1, 2)
    assert by_root[ROOT_B].eligible
    assert by_root[ROOT_B].utility == 0


def test_scored_batch_requires_every_issued_assignment_once_and_excludes_canary_scores() -> None:
    batch = _batch(0, 1, 11)
    with pytest.raises(ValueError, match="complete issued cross-product"):
        ScoredBatch(
            window_index=batch.window_index,
            batch_rank=batch.batch_rank,
            pool_leaf=batch.pool_leaf,
            challenge_ids=batch.challenge_ids,
            miner_roots=batch.miner_roots,
            assignments=batch.assignments[:-1],
        )
    with pytest.raises(ValueError, match="duplicate miner/challenge"):
        ScoredBatch(
            window_index=batch.window_index,
            batch_rank=batch.batch_rank,
            pool_leaf=batch.pool_leaf,
            challenge_ids=batch.challenge_ids,
            miner_roots=batch.miner_roots,
            assignments=(*batch.assignments[:-1], batch.assignments[0]),
        )
    with pytest.raises(ValueError, match="must not carry"):
        _assignment(
            ROOT_A,
            pool=99,
            ordinal=0,
            stratum="fingerspelling",
            score=Fraction(1),
            canary=True,
        )
    with pytest.raises(ValueError, match="including zero"):
        _assignment(
            ROOT_A,
            pool=99,
            ordinal=0,
            stratum="fingerspelling",
            score=None,
        )


def test_weight_build_uses_only_state_derived_scores_and_chain_quantization() -> None:
    state = _two_miner_state()
    built = state.build_weights(
        minimum_assigned_clips=6,
        minimum_clips_per_stratum=2,
        quality_floor=Fraction(0),
        uid_by_root={ROOT_A: 9, ROOT_B: 2},
        minimum_positive_weights=2,
    )
    assert built.root_vector == ((ROOT_A, Fraction(4, 5)), (ROOT_B, Fraction(1, 5)))
    assert built.uid_vector == ((2, Fraction(1, 5)), (9, Fraction(4, 5)))
    assert built.quantized_row == ((2, 16_384), (9, 65_535))


def test_weight_build_fails_closed_after_resolution_or_quantization_collapse() -> None:
    state = _two_miner_state()
    common = {
        "minimum_assigned_clips": 6,
        "minimum_clips_per_stratum": 2,
        "quality_floor": Fraction(0),
        "minimum_positive_weights": 2,
    }
    with pytest.raises(ValueError, match="resolved positive destinations"):
        state.build_weights(uid_by_root={ROOT_A: 9, ROOT_B: None}, **common)
    with pytest.raises(ValueError, match="same UID"):
        state.build_weights(uid_by_root={ROOT_A: 9, ROOT_B: 9}, **common)

    tiny_state = _two_miner_state(Fraction(1, 1_000))
    with pytest.raises(ValueError, match="quantization drops"):
        tiny_state.build_weights(uid_by_root={ROOT_A: 1, ROOT_B: 2}, **common)


def test_weight_build_rejects_infeasible_live_maximum_and_checks_quantized_ratio() -> None:
    state = _two_miner_state()
    common = {
        "minimum_assigned_clips": 6,
        "minimum_clips_per_stratum": 2,
        "quality_floor": Fraction(0),
        "uid_by_root": {ROOT_A: 1, ROOT_B: 2},
        "minimum_positive_weights": 2,
    }
    with pytest.raises(ValueError, match="infeasible"):
        state.build_weights(maximum_weight_limit_u16=10_000, **common)
    with pytest.raises(ValueError, match="infeasible"):
        state.build_weights(maximum_weight_limit_u16=32_767, **common)

    with pytest.raises(ValueError, match="quantized row"):
        state.build_weights(maximum_weight_limit_u16=32_768, **common)

    built = state.build_weights(maximum_weight_limit_u16=33_000, **common)
    assert built.uid_vector == (
        (1, Fraction(2_200, 4_369)),
        (2, Fraction(2_169, 4_369)),
    )
    assert all(weight.denominator != 2**52 for _, weight in built.uid_vector)
    values = [value for _, value in built.quantized_row]
    assert max(values) * 65_535 <= 33_000 * sum(values)


def test_assignment_scores_require_exact_unit_interval_fractions() -> None:
    with pytest.raises(TypeError, match="Fraction"):
        _assignment(
            ROOT_A,
            pool=99,
            ordinal=0,
            stratum="continuous",
            score=0.5,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="between zero and one"):
        _assignment(
            ROOT_A,
            pool=99,
            ordinal=0,
            stratum="continuous",
            score=Fraction(2),
        )
