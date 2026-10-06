"""Short reads advance without starving queued work or overlapping owners."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from umi.thread_gate import ThreadGate


def queued(gate, *, normal, preferred):
    with gate._condition:
        assert gate._condition.wait_for(
            lambda: len(gate._normal) == normal and len(gate._preferred) == preferred,
            timeout=30,
        )


def test_short_reads_pass_background_backlog_but_do_not_starve_it():
    gate, order = ThreadGate(), []

    def work(label, preferred=False):
        with gate.hold(preferred=preferred):
            order.append(label)

    with ThreadPoolExecutor(max_workers=12) as pool:
        with gate.hold():
            background = pool.submit(work, "background")
            queued(gate, normal=1, preferred=0)
            reads = []
            for index in range(10):
                reads.append(pool.submit(work, index, True))
                queued(gate, normal=1, preferred=index + 1)
        for future in [background, *reads]:
            future.result(timeout=60)
    assert order == [*range(8), "background", 8, 9]
    assert not gate._normal and not gate._preferred and gate._owner is None


def test_normal_work_keeps_fifo_order_and_recursive_entry_does_not_release_owner():
    gate, order = ThreadGate(), []

    def work(index):
        with gate.hold():
            order.append(index)

    with ThreadPoolExecutor(max_workers=4) as pool:
        with gate.hold():
            first = pool.submit(work, 1)
            queued(gate, normal=1, preferred=0)
            with gate.hold(preferred=True):
                second = pool.submit(work, 2)
                queued(gate, normal=2, preferred=0)
                assert not order
            assert not order
        first.result(timeout=60)
        second.result(timeout=60)
    assert order == [1, 2]


def test_operation_failure_releases_exclusive_admission():
    gate = ThreadGate()
    with pytest.raises(ValueError, match="operation failed"), gate.hold(preferred=True):
        raise ValueError("operation failed")
    with gate.hold():
        assert gate._depth == 1
    assert gate._owner is None


def test_interrupted_wait_removes_ticket_and_keeps_existing_owner(monkeypatch):
    gate = ThreadGate()

    def interrupted(*args, **kwargs):
        raise InterruptedError("wait interrupted")

    def waiting():
        with (
            pytest.raises(InterruptedError, match="wait interrupted"),
            gate.hold(preferred=True),
        ):
            pytest.fail("interrupted waiter entered")

    with ThreadPoolExecutor(max_workers=1) as pool:
        with gate.hold():
            with monkeypatch.context() as patch:
                patch.setattr(gate._condition, "wait_for", interrupted)
                pool.submit(waiting).result(timeout=60)
            assert not gate._preferred and gate._depth == 1
        pool.submit(lambda: gate._owner).result(timeout=60)
    assert gate._owner is None
