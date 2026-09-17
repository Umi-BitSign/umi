from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from umi.encoding import datetime_to_unix_ms
from umi.file_identity import delivery_file_identity, file_fingerprint, private_file_identity


@pytest.mark.parametrize(
    ("function", "fields"),
    [
        (
            file_fingerprint,
            (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_uid",
                "st_gid",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            ),
        ),
        (
            delivery_file_identity,
            (
                "st_dev",
                "st_ino",
                "st_uid",
                "st_gid",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            ),
        ),
        (
            private_file_identity,
            (
                "st_dev",
                "st_ino",
                "st_uid",
                "st_nlink",
                "st_mode",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            ),
        ),
    ],
)
def test_historical_identity_order_and_every_field(function, fields) -> None:
    values = {field: index + 10 for index, field in enumerate(fields)}
    identity = function(SimpleNamespace(**values))
    assert identity == tuple(range(10, 10 + len(fields)))
    for field in fields:
        changed = SimpleNamespace(**(values | {field: values[field] + 100}))
        assert function(changed) != identity, field


@pytest.mark.parametrize("offset", [-12, 0, 14])
def test_unix_milliseconds_are_timezone_independent(offset: int) -> None:
    instant = datetime(2026, 9, 17, 0, 0, 0, 999999, tzinfo=timezone.utc)
    local = instant.astimezone(timezone(timedelta(hours=offset)))
    assert datetime_to_unix_ms(local) == datetime_to_unix_ms(instant)
    assert datetime_to_unix_ms(local) % 1000 == 999


def test_unix_milliseconds_floor_before_epoch_without_floats() -> None:
    assert (
        datetime_to_unix_ms(datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)) == -1
    )


@pytest.mark.parametrize("value", [None, 123, "2026-09-17", datetime(2026, 9, 17)])
def test_unix_milliseconds_reject_non_aware_datetimes(value) -> None:
    with pytest.raises(TypeError, match="timezone-aware"):
        datetime_to_unix_ms(value)
