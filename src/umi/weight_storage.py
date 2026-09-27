"""Subtensor's stored u16 weights, separate from the signed call arguments."""

from collections.abc import Sequence


def subtensor_stored_weights(values: Sequence[int]) -> tuple[int, ...]:
    """Reproduce vec_u16_max_upscale_to_u16 using its I32F32 arithmetic.

    The pallet scales the maximum to 65535 and rounds each value. Its branch
    above 32768 divides before multiplying to avoid fixed-point overflow.
    Keep that truncation order: floating point and rational rounding can differ.
    """
    weights = tuple(values)
    if any(type(value) is not int or not 0 <= value <= 65535 for value in weights):
        raise ValueError("stored weight conversion requires u16 inputs")
    maximum = max(weights, default=0)
    if maximum == 0:
        return weights
    if maximum > 32768:
        scale = (65535 << 32) // maximum
        fixed = (value * scale for value in weights)
    else:
        fixed = ((value * 65535 << 32) // maximum for value in weights)
    return tuple(min(65535, (value + (1 << 31)) >> 32) for value in fixed)
