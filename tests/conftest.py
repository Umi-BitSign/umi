import pytest as _pytest_lineage


@_pytest_lineage.fixture(autouse=True)
def _isolate_policy_lineage_registry():
    """register_lineage() is process-wide; never let one test's lineage leak into another."""
    from umi.competition_policy_lineage import clear_lineage_registry

    clear_lineage_registry()
    yield
    clear_lineage_registry()
