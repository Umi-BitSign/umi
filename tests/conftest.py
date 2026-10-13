import pytest as _pytest_lineage


@_pytest_lineage.fixture(autouse=True)
def _isolate_policy_lineage_registry():
    """register_lineage() is process-wide; never let one test's lineage leak into another."""
    from umi.competition_policy_lineage import clear_lineage_registry

    clear_lineage_registry()
    yield
    clear_lineage_registry()


@_pytest_lineage.fixture(params=[False, True], ids=["standard_logs", "redacted_logs"])
def http_log_redaction(request):
    """Exercise emitted telemetry with both native entrypoint logging modes."""
    import logging

    from umi.http_logging import install_http_log_redaction

    # Entry points install this process-wide factory. Keep both modes explicit
    # and restore the previous factory without depending on suite test order.
    previous = logging.getLogRecordFactory()
    try:
        logging.setLogRecordFactory(logging.LogRecord)
        if request.param:
            install_http_log_redaction()
        yield
    finally:
        logging.setLogRecordFactory(previous)
