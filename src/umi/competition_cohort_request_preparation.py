"""Keep native request preparation, observation and cleanup on one owned thread."""

import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from contextvars import copy_context
from functools import partial

from .concurrency import await_owned_task
from .host_memory_runtime import compact_memory_error, selected_memory


def _invoke_native(function, *args, **kwargs):
    # Return a compact failure as data: raising here gives its traceback new
    # worker/executor frames that retain the native callable and its graph.
    # Unselected runtimes preserve the caller's original exception object.
    if selected_memory() is None:
        return function(*args, **kwargs), None
    failure = None
    try:
        return function(*args, **kwargs), None
    except BaseException as error:
        failure = compact_memory_error(error)
    return None, failure


@asynccontextmanager
async def prepared_request_thread(context):
    """Yield one sampler while its native context owns thread-bound resources.

    Finality collection stays with the coordinator. Cancellation drains every
    started native operation before releasing its intake and admission leases.
    The context cannot escape this attempt or suppress a caller's exception.
    """
    loop = asyncio.get_running_loop()
    # One copied Context owns tokens created by __enter__ through __exit__.
    # Copying for each call would lose native context changes and make resets
    # cross contexts; omitting it would lose the selected policy and budgets.
    worker_context = copy_context()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="umi-request-prepare") as worker:

        async def invoke(function, *args, **kwargs):
            try:
                result, failure = await loop.run_in_executor(
                    worker, worker_context.run, partial(_invoke_native, function, *args, **kwargs)
                )
            finally:
                # A propagated failure can retain this completed coroutine.
                # Detach every reference to the native callable before raising.
                function = args = kwargs = None
            if failure is not None:
                raise failure from None
            return result

        operation = None

        def enter():
            nonlocal operation
            # A cancelled await retains its drained task in the traceback.
            # Keep the native sampler here, never in that task's result.
            operation = context.__enter__()

        entered = asyncio.create_task(invoke(enter))
        active, used = False, False
        try:
            await await_owned_task(entered)
            active = True

            async def sample(*args, **kwargs):
                nonlocal used
                if not active or used:
                    raise RuntimeError("prepared request observation is no longer available")
                used = True
                try:
                    return await await_owned_task(
                        asyncio.create_task(invoke(operation, *args, **kwargs))
                    )
                finally:
                    args = kwargs = None

            yield sample
        finally:
            active = False
            try:
                if entered.done() and not entered.cancelled() and entered.exception() is None:
                    await await_owned_task(
                        asyncio.create_task(invoke(context.__exit__, *sys.exc_info()))
                    )
            finally:
                # An escaped, disabled sampler must not retain the native
                # context or operation after its enclosing memory grant ends.
                operation = context = entered = None
