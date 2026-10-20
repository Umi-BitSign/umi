"""Rolling lease arithmetic never modifies an existing signed directive."""

import pytest

from umi.translation_reference_renewal import ReferenceDirectiveRenewal


def test_lifetime_is_from_each_native_block_with_explicit_renewal_margin():
    value = ReferenceDirectiveRenewal(
        schema="umi-reference-directive-renewal/1",
        lifetime_blocks=7200,
        renew_before_blocks=1200,
    )
    assert value.through_block(9327218) == 9334418
    assert value.through_block(9327219) == 9334419


@pytest.mark.parametrize("lifetime,margin", [(1, 1), (10, 10), (10, 11), (True, 1), (10, False)])
def test_invalid_rolling_windows_refuse(lifetime, margin):
    with pytest.raises(ValueError):
        ReferenceDirectiveRenewal(
            schema="umi-reference-directive-renewal/1",
            lifetime_blocks=lifetime,
            renew_before_blocks=margin,
        )


@pytest.mark.parametrize("block", [0, True, 2**53 - 1])
def test_current_block_must_fit_a_fresh_directive(block):
    value = ReferenceDirectiveRenewal(
        schema="umi-reference-directive-renewal/1",
        lifetime_blocks=7200,
        renew_before_blocks=1200,
    )
    with pytest.raises(ValueError, match="bounded current native block"):
        value.through_block(block)
